import { readError } from "./util";

interface TurnstileApi {
  render: (el: HTMLElement, opts: Record<string, unknown>) => string;
  reset: (id?: string) => void;
}
declare global {
  interface Window {
    turnstile?: TurnstileApi;
  }
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const AGENT_COUNTS = ["1-5", "6-25", "26-100", "100+", "unknown"];
const MCP = ["yes", "no", "evaluating"];

type Fields = "name" | "company" | "work_email" | "use_case" | "agent_count" | "uses_mcp";

export function initFoundingAccess(): void {
  const root = document.querySelector<HTMLElement>("[data-founding]");
  if (!root) return;
  const form = root.querySelector<HTMLFormElement>("[data-fa-form]")!;
  const submit = root.querySelector<HTMLButtonElement>("[data-fa-submit]")!;
  const status = root.querySelector<HTMLElement>("[data-fa-status]")!;
  const done = root.querySelector<HTMLElement>("[data-fa-done]")!;
  const turnstileBox = root.querySelector<HTMLElement>("[data-turnstile]")!;

  let formToken: string | null = null;
  let tokenPromise: Promise<void> | null = null;
  let turnstileToken: string | null = null;
  let turnstileId: string | undefined;
  let turnstileConfigured = false;
  let busy = false;

  const el = (name: string) =>
    form.elements.namedItem(name) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;

  const setStatus = (text: string, error = false) => {
    status.textContent = text;
    status.classList.toggle("is-error", error);
  };

  const loadTurnstile = (siteKey: string) => {
    turnstileConfigured = true;
    turnstileBox.hidden = false;
    const renderWidget = () => {
      if (!window.turnstile || turnstileId !== undefined) return;
      turnstileId = window.turnstile.render(turnstileBox, {
        sitekey: siteKey,
        theme: "dark",
        callback: (token: string) => {
          turnstileToken = token;
        },
        "expired-callback": () => {
          turnstileToken = null;
        },
        "error-callback": () => {
          turnstileToken = null;
        },
      });
    };
    if (window.turnstile) {
      renderWidget();
      return;
    }
    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    script.addEventListener("load", renderWidget);
    document.head.appendChild(script);
  };

  const fetchToken = (): Promise<void> => {
    if (tokenPromise) return tokenPromise;
    tokenPromise = (async () => {
      try {
        const res = await fetch("/api/founding-access/token", { headers: { Accept: "application/json" } });
        if (!res.ok) throw new Error(String(res.status));
        const data = (await res.json()) as { form_token?: string; turnstile_site_key?: string | null };
        formToken = data.form_token ?? null;
        if (data.turnstile_site_key) loadTurnstile(data.turnstile_site_key);
      } catch {
        tokenPromise = null; // allow retry on submit
      }
    })();
    return tokenPromise;
  };

  // Fetch lazily: when the form nears the viewport, or on first interaction.
  if ("IntersectionObserver" in window) {
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          io.disconnect();
          void fetchToken();
        }
      },
      { rootMargin: "600px 0px" },
    );
    io.observe(root);
  }
  form.addEventListener("focusin", () => void fetchToken(), { once: true });

  const setFieldError = (name: string, message: string) => {
    const err = root.querySelector<HTMLElement>(`[data-err="${name}"]`);
    const input = el(name);
    if (err) {
      err.textContent = message;
      if (!err.id) err.id = `fa-err-${name}`;
    }
    if (input) {
      input.setAttribute("aria-invalid", message ? "true" : "false");
      if (message && err) input.setAttribute("aria-describedby", err.id);
      else input.removeAttribute("aria-describedby");
    }
  };

  const validate = (): Record<Fields, string> | null => {
    const v = {
      name: el("name").value.trim(),
      company: el("company").value.trim(),
      work_email: el("work_email").value.trim(),
      use_case: el("use_case").value.trim(),
      agent_count: el("agent_count").value,
      uses_mcp: el("uses_mcp").value,
    };
    const errors: Partial<Record<Fields, string>> = {};
    if (v.name.length < 1) errors.name = "Enter your name.";
    else if (v.name.length > 120) errors.name = "Keep this under 120 characters.";
    if (v.company.length < 1) errors.company = "Enter your company.";
    else if (v.company.length > 160) errors.company = "Keep this under 160 characters.";
    if (!EMAIL_RE.test(v.work_email) || v.work_email.length > 254) errors.work_email = "Enter a valid work email.";
    if (v.use_case.length < 10) errors.use_case = "Tell us a little more (at least 10 characters).";
    else if (v.use_case.length > 2000) errors.use_case = "Keep this under 2,000 characters.";
    if (!AGENT_COUNTS.includes(v.agent_count)) errors.agent_count = "Choose an option.";
    if (!MCP.includes(v.uses_mcp)) errors.uses_mcp = "Choose an option.";

    for (const key of Object.keys(v) as Fields[]) setFieldError(key, errors[key] ?? "");
    const firstInvalid = (Object.keys(v) as Fields[]).find((k) => errors[k]);
    if (firstInvalid) {
      el(firstInvalid).focus();
      return null;
    }
    return v;
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    const values = validate();
    if (!values) {
      setStatus("Please fix the highlighted fields.", true);
      return;
    }

    busy = true;
    submit.disabled = true;
    submit.textContent = "Sending…";
    setStatus("");

    try {
      await fetchToken();
      if (!formToken) {
        setStatus("We couldn't prepare the form. Please try again in a moment.", true);
        return;
      }
      if (turnstileConfigured && !turnstileToken) {
        setStatus("Please complete the verification check.", true);
        return;
      }

      const res = await fetch("/api/founding-access", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({
          ...values,
          form_token: formToken,
          website: el("website").value,
          ...(turnstileToken ? { turnstile_token: turnstileToken } : {}),
        }),
      });

      if (res.status === 201 || res.ok) {
        form.hidden = true;
        done.hidden = false;
        done.focus();
        return;
      }

      const err = await readError(res);
      if (err.status === 400) {
        if (err.fields) {
          for (const [name, message] of Object.entries(err.fields)) setFieldError(name, message);
        }
        setStatus(err.message || "Please check the highlighted fields.", true);
      } else if (err.status === 403) {
        setStatus("Verification failed. Please refresh the page and try again.", true);
        formToken = null;
        tokenPromise = null;
        if (turnstileId !== undefined) window.turnstile?.reset(turnstileId);
        turnstileToken = null;
      } else if (err.status === 429) {
        setStatus("Too many attempts. Please wait a minute and try again.", true);
      } else {
        setStatus("Something went wrong on our side. Please try again shortly.", true);
      }
    } catch {
      setStatus("Network error. Check your connection and try again.", true);
    } finally {
      busy = false;
      submit.disabled = false;
      submit.textContent = "Request Founding Access";
    }
  });
}
