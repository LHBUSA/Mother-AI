import { escapeHtml, highlightJson, readError } from "./util";

type Decision = "allow" | "review" | "block";

interface DemoAgent {
  agent_id: string;
  display_name: string;
  environment: string;
  description: string;
}

interface EvaluateBody {
  agent_id: string;
  protocol?: "api" | "mcp";
  capability: string;
  operation: string;
  resource?: string;
  destination?: string;
  data_class?: string;
  environment?: string;
  context?: Record<string, unknown>;
  mcp?: { server: string; tool: string };
}

interface DemoScenario {
  id: string;
  label: string;
  description?: string;
  request: EvaluateBody;
}

interface Workspace {
  agents: DemoAgent[];
  scenarios: DemoScenario[];
}

interface EvaluateResult {
  decision: Decision;
  reason_code: string;
  reason: string;
  policy: { id: string; name: string; effect: Decision; priority: number } | null;
  matched: { policy_id: string; name: string; effect: Decision; indeterminate: boolean }[];
  evaluated_policies: number;
  eval_ms: number;
  engine_version: string;
}

const DECISIONS: Decision[] = ["allow", "review", "block"];

export function initDemo(): void {
  const root = document.querySelector<HTMLElement>("[data-demo]");
  if (!root) return;

  const form = root.querySelector<HTMLFormElement>("[data-demo-form]")!;
  const chips = root.querySelector<HTMLElement>("[data-demo-scenarios]")!;
  const agentSelect = root.querySelector<HTMLSelectElement>("[data-demo-agent]")!;
  const runBtn = root.querySelector<HTMLButtonElement>("[data-demo-run]")!;
  const runLabel = root.querySelector<HTMLElement>("[data-demo-run-label]")!;
  const status = root.querySelector<HTMLElement>("[data-demo-status]")!;
  const result = root.querySelector<HTMLElement>("[data-demo-result]")!;
  const reqCode = root.querySelector<HTMLElement>("[data-json-request]")!;
  const resCode = root.querySelector<HTMLElement>("[data-json-response]")!;
  const tabs = Array.from(root.querySelectorAll<HTMLButtonElement>("[data-json-tab]"));

  const out = {
    decision: result.querySelector<HTMLElement>("[data-r-decision]")!,
    ms: result.querySelector<HTMLElement>("[data-r-ms]")!,
    code: result.querySelector<HTMLElement>("[data-r-code]")!,
    reason: result.querySelector<HTMLElement>("[data-r-reason]")!,
    policy: result.querySelector<HTMLElement>("[data-r-policy]")!,
    evaluated: result.querySelector<HTMLElement>("[data-r-evaluated]")!,
    engine: result.querySelector<HTMLElement>("[data-r-engine]")!,
    matched: result.querySelector<HTMLElement>("[data-r-matched]")!,
    errorTitle: result.querySelector<HTMLElement>("[data-r-error-title]")!,
    error: result.querySelector<HTMLElement>("[data-r-error]")!,
  };

  let base: EvaluateBody | null = null;
  let busy = false;
  let ready = false;

  const field = (name: string) => form.elements.namedItem(name) as HTMLInputElement | HTMLSelectElement | null;

  // ---------------------------------------------------------------- tabs
  const selectTab = (name: string, focus = false) => {
    for (const tab of tabs) {
      const on = tab.dataset.jsonTab === name;
      tab.setAttribute("aria-selected", String(on));
      tab.tabIndex = on ? 0 : -1;
      const pane = document.getElementById(tab.getAttribute("aria-controls") ?? "");
      if (pane) pane.hidden = !on;
      if (on && focus) tab.focus();
    }
  };
  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => selectTab(tab.dataset.jsonTab!));
    tab.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
      event.preventDefault();
      const next = tabs[(i + (event.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length]!;
      selectTab(next.dataset.jsonTab!, true);
    });
  });

  // ---------------------------------------------------------------- request building
  const buildRequest = (): EvaluateBody => {
    const value = (name: string) => (field(name)?.value ?? "").trim();
    const body: EvaluateBody = {
      ...(base ?? {}),
      agent_id: value("agent_id"),
      capability: value("capability"),
      operation: value("operation"),
    };
    for (const key of ["resource", "destination", "data_class"] as const) {
      const v = value(key);
      if (v) body[key] = v;
      else delete body[key];
    }
    const context: Record<string, unknown> = { ...(base?.context ?? {}) };
    const amountRaw = value("amount").replace(/[,_\s]/g, "");
    if (amountRaw !== "" && Number.isFinite(Number(amountRaw))) context.amount = Number(amountRaw);
    else delete context.amount;
    if (Object.keys(context).length) body.context = context;
    else delete body.context;
    return body;
  };

  const renderRequest = () => {
    reqCode.innerHTML = highlightJson(buildRequest());
  };

  const fill = (req: EvaluateBody) => {
    base = structuredClone(req);
    if (!Array.from(agentSelect.options).some((o) => o.value === req.agent_id)) {
      agentSelect.add(new Option(req.agent_id, req.agent_id));
    }
    const set = (name: string, v: unknown) => {
      const el = field(name);
      if (!el) return;
      const str = v === undefined || v === null ? "" : String(v);
      if (el instanceof HTMLSelectElement && str && !Array.from(el.options).some((o) => o.value === str)) {
        el.add(new Option(str, str));
      }
      el.value = str;
    };
    set("agent_id", req.agent_id);
    set("capability", req.capability);
    set("operation", req.operation);
    set("resource", req.resource);
    set("destination", req.destination);
    set("data_class", req.data_class);
    const amount = req.context && typeof req.context.amount === "number" ? req.context.amount : undefined;
    set("amount", amount);
    renderRequest();
  };

  // ---------------------------------------------------------------- states
  const setState = (state: "idle" | "loading" | "done" | "error") => {
    result.dataset.state = state;
  };

  const showError = (title: string, message: string) => {
    out.errorTitle.textContent = title;
    out.error.textContent = message;
    setState("error");
  };

  const setBusy = (on: boolean) => {
    busy = on;
    runBtn.disabled = on || !ready;
    runLabel.textContent = on ? "Evaluating…" : "Evaluate request";
    result.setAttribute("aria-busy", String(on));
  };

  const renderResult = (data: EvaluateResult, roundTripMs: number) => {
    const decision = DECISIONS.includes(data.decision) ? data.decision : "block";
    out.decision.textContent = decision.toUpperCase();
    out.decision.className = `verdict verdict--${decision}`;
    out.ms.textContent = `${Math.max(1, Math.round(roundTripMs))} ms`;
    out.code.textContent = data.reason_code || "—";
    out.reason.textContent = data.reason || "—";
    out.policy.textContent = data.policy
      ? `${data.policy.name} · ${data.policy.effect} · priority ${data.policy.priority}`
      : "No policy matched — default applied";
    out.evaluated.textContent = `${data.evaluated_policies ?? 0} policies`;
    const evalMs = typeof data.eval_ms === "number" ? data.eval_ms : NaN;
    const evalText = Number.isFinite(evalMs) ? (evalMs < 1 ? "<1 ms" : `${Math.round(evalMs)} ms`) : "—";
    out.engine.textContent = `${data.engine_version ?? "—"} · policy evaluation ${evalText}`;

    const matched = Array.isArray(data.matched) ? data.matched : [];
    out.matched.innerHTML = matched.length
      ? matched
          .map((m) => {
            const eff = DECISIONS.includes(m.effect) ? m.effect : "block";
            const indet = m.indeterminate ? ' <span class="indet">indeterminate</span>' : "";
            return `<li><span class="pill pill--${eff}">${eff.toUpperCase()}</span><span>${escapeHtml(m.name)}${indet}</span></li>`;
          })
          .join("")
      : '<li class="none">No policies matched this request.</li>';
    setState("done");
  };

  // ---------------------------------------------------------------- run
  form.addEventListener("input", () => {
    if (ready) renderRequest();
  });
  form.addEventListener("change", () => {
    if (ready) renderRequest();
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || !ready) return;
    const body = buildRequest();
    const missing = (["agent_id", "capability", "operation"] as const).filter((k) => !body[k]);
    for (const name of ["agent_id", "capability", "operation"]) {
      field(name)?.setAttribute("aria-invalid", String(missing.includes(name as never)));
    }
    if (missing.length) {
      status.textContent = `Required: ${missing.join(", ")}`;
      status.classList.add("is-error");
      return;
    }
    status.textContent = "";
    status.classList.remove("is-error");
    renderRequest();
    setBusy(true);
    setState("loading");

    const t0 = performance.now();
    try {
      const res = await fetch("/api/demo/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(body),
      });
      const roundTrip = performance.now() - t0;
      if (!res.ok) {
        const err = await readError(res);
        resCode.innerHTML = highlightJson({ status: res.status, error: { code: err.code, message: err.message } });
        if (err.status === 429) {
          showError("Slow down a moment", "The demo is rate limited per visitor. Wait a few seconds and try again.");
        } else if (err.status === 400) {
          showError("Request rejected", err.message || "The engine rejected this request as malformed. Check the fields and try again.");
        } else {
          showError("Demo unavailable", "The demo engine didn't respond as expected. Please try again shortly.");
        }
        return;
      }
      const data = (await res.json()) as EvaluateResult;
      resCode.innerHTML = highlightJson(data);
      renderResult(data, roundTrip);
    } catch {
      resCode.textContent = "// Network error";
      showError("Connection problem", "We couldn't reach the demo engine. Check your connection and try again.");
    } finally {
      setBusy(false);
    }
  });

  // ---------------------------------------------------------------- workspace
  const renderScenarios = (scenarios: DemoScenario[]) => {
    chips.innerHTML = "";
    scenarios.forEach((scenario, i) => {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "chip";
      chip.setAttribute("aria-pressed", String(i === 0));
      if (scenario.description) chip.title = scenario.description;
      chip.innerHTML = `<span class="chip__dot" aria-hidden="true"></span><span></span>`;
      chip.lastElementChild!.textContent = scenario.label;
      chip.addEventListener("click", () => {
        for (const c of Array.from(chips.children)) c.setAttribute("aria-pressed", String(c === chip));
        fill(scenario.request);
        setState("idle");
        resCode.textContent = "// Evaluate a request to see the response";
        selectTab("request");
      });
      chips.appendChild(chip);
    });
  };

  const loadWorkspace = async () => {
    try {
      const res = await fetch("/api/demo/workspace", { headers: { Accept: "application/json" } });
      if (!res.ok) throw new Error(String(res.status));
      const data = (await res.json()) as Workspace;
      const agents = Array.isArray(data.agents) ? data.agents : [];
      const scenarios = Array.isArray(data.scenarios) ? data.scenarios : [];

      agentSelect.innerHTML = "";
      for (const agent of agents) {
        agentSelect.add(new Option(`${agent.agent_id} (${agent.environment})`, agent.agent_id));
      }
      agentSelect.disabled = false;
      ready = true;
      runBtn.disabled = false;

      if (scenarios.length) {
        renderScenarios(scenarios);
        fill(scenarios[0]!.request);
      } else {
        chips.innerHTML = '<span class="chips__placeholder">No preset scenarios — edit the request below.</span>';
        fill({ agent_id: agents[0]?.agent_id ?? "", capability: "", operation: "" });
      }
    } catch {
      chips.innerHTML = '<span class="chips__placeholder">Scenarios unavailable.</span>';
      agentSelect.disabled = true;
      runBtn.disabled = true;
      reqCode.textContent = "// Demo workspace unavailable";
      showError(
        "Demo workspace unavailable",
        "The live demo couldn't load right now. Everything below describes exactly how the engine decides — try the demo again in a moment.",
      );
    }
  };

  // Load when the demo approaches the viewport.
  let started = false;
  const begin = () => {
    if (started) return;
    started = true;
    void loadWorkspace();
  };
  if ("IntersectionObserver" in window) {
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          io.disconnect();
          begin();
        }
      },
      { rootMargin: "800px 0px" },
    );
    io.observe(root);
  } else {
    begin();
  }
}
