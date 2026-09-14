import { prefersReducedMotion } from "./util";

type Decision = "allow" | "review" | "block";

interface Beat {
  agent: number;
  tool: number;
  decision: Decision;
  text: string;
  code: string;
}

// Illustrative requests only — the figure caption says so.
const BEATS: Beat[] = [
  { agent: 0, tool: 0, decision: "allow", text: "billing-agent-prod · payments.refund · $180.00", code: "POLICY_ALLOW" },
  { agent: 1, tool: 2, decision: "block", text: "research-agent-prod · records.modify · table:orders", code: "OPERATION_NOT_ALLOWED" },
  { agent: 0, tool: 0, decision: "review", text: "billing-agent-prod · payments.refund · $4,200.00", code: "HUMAN_APPROVAL_REQUIRED" },
  { agent: 2, tool: 1, decision: "allow", text: "sales-agent-prod · mcp salesforce · contacts.update", code: "POLICY_ALLOW" },
  { agent: 3, tool: 4, decision: "block", text: "support-agent · files.export · restricted → external", code: "RESTRICTED_DATA_EGRESS" },
  { agent: 2, tool: 3, decision: "block", text: "sales-agent-prod · mcp github · merge_pull_request", code: "DEFAULT_DENY" },
];

export function initHero(): void {
  const root = document.querySelector<HTMLElement>("[data-gateway]");
  if (!root) return;

  const core = root.querySelector<HTMLElement>("[data-core]");
  const stamp = root.querySelector<HTMLElement>("[data-stamp]");
  const logRow = root.querySelector<HTMLElement>("[data-log]");
  const logDecision = root.querySelector<HTMLElement>("[data-log-decision]");
  const logText = root.querySelector<HTMLElement>("[data-log-text]");
  const logCode = root.querySelector<HTMLElement>("[data-log-code]");
  const agents = Array.from(root.querySelectorAll<HTMLElement>("[data-agent]"));
  const tools = Array.from(root.querySelectorAll<HTMLElement>("[data-tool]"));
  const wiresIn = Array.from(root.querySelectorAll<SVGPathElement>("[data-in]"));
  const wiresOut = Array.from(root.querySelectorAll<SVGPathElement>("[data-out]"));

  const clear = () => {
    for (const el of [...agents, ...tools]) el.classList.remove("is-active", "is-allow", "is-held");
    for (const el of [...wiresIn, ...wiresOut]) el.classList.remove("is-active", "is-allow", "is-held");
  };

  const show = (beat: Beat) => {
    clear();
    agents[beat.agent]?.classList.add("is-active");
    wiresIn[beat.agent]?.classList.add("is-active");
    if (beat.decision === "allow") {
      wiresOut[beat.tool]?.classList.add("is-allow");
      tools[beat.tool]?.classList.add("is-allow");
    } else if (beat.decision === "review") {
      wiresOut[beat.tool]?.classList.add("is-held");
      tools[beat.tool]?.classList.add("is-held");
    }
    if (core) core.dataset.decision = beat.decision;
    if (stamp) stamp.textContent = beat.decision.toUpperCase();
    if (logDecision) {
      logDecision.textContent = beat.decision.toUpperCase();
      logDecision.className = `pill pill--${beat.decision}`;
    }
    if (logText) logText.textContent = beat.text;
    if (logCode) logCode.textContent = beat.code;
    if (logRow) {
      logRow.classList.remove("is-in");
      void logRow.offsetWidth;
      logRow.classList.add("is-in");
    }
  };

  let index = 0;
  show(BEATS[0]!);

  if (prefersReducedMotion()) {
    show(BEATS[2]!);
    return;
  }

  let timer: number | undefined;
  let visible = true;

  const tick = () => {
    index = (index + 1) % BEATS.length;
    show(BEATS[index]!);
  };
  const run = () => {
    if (timer === undefined && visible && !document.hidden) timer = window.setInterval(tick, 2600);
  };
  const stop = () => {
    if (timer !== undefined) {
      window.clearInterval(timer);
      timer = undefined;
    }
  };

  new IntersectionObserver((entries) => {
    visible = entries.some((e) => e.isIntersecting);
    if (visible) run();
    else stop();
  }).observe(root);

  document.addEventListener("visibilitychange", () => (document.hidden ? stop() : run()));
  run();
}
