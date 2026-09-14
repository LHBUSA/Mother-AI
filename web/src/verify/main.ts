// Public badge verification page. Reads live state from the Mother AI API; it never
// shows a verified state unless the API returns status "active" for this token.

import "./verify.css";
import { apiUrl } from "../shared/site";

type Status = "active" | "setup" | "suspended" | "revoked";
type Failure = "notfound" | "malformed" | "limited" | "error";

interface PublicBadge {
  status: Status;
  organization: { display_name: string };
  controls: Array<{ label: string; met: boolean }>;
  checked_at: string;
  activated_on: string | null;
  last_gateway_activity_on: string | null;
  policy_engine: string;
  service_version: string;
  badge: { svg_url: string; svg_light_url: string; verify_url: string };
  disclaimer: string;
}

interface Copy {
  state: string;
  title: string;
  summary: string;
  cls: string;
}

const STATUS: Record<Status, Copy> = {
  active: { state: "VERIFIED · ACTIVE", title: "Mother AI Protected", summary: "This organization has Mother AI agent access controls configured and enabled.", cls: "s-active" },
  setup: { state: "NOT ACTIVE", title: "Badge not active", summary: "This organization has not completed Mother AI configuration. The badge is not active and is not evidence of Mother AI controls.", cls: "s-paused" },
  suspended: { state: "SUSPENDED", title: "Badge not active", summary: "Mother AI protection for this organization is currently suspended. The badge is not active and is not evidence of Mother AI controls.", cls: "s-paused" },
  revoked: { state: "REVOKED", title: "Badge not active", summary: "This Mother AI badge has been revoked and no longer represents active controls.", cls: "s-revoked" },
};

const FAILURE: Record<Failure, Copy> = {
  notfound: { state: "UNABLE TO VERIFY", title: "Unable to verify", summary: "This link does not match any Mother AI badge.", cls: "s-unable" },
  malformed: { state: "UNABLE TO VERIFY", title: "Unable to verify", summary: "This is not a valid Mother AI verification link.", cls: "s-unable" },
  limited: { state: "UNABLE TO VERIFY", title: "Unable to verify", summary: "Too many verification requests from your network. Wait a minute, then try again.", cls: "s-unable" },
  error: { state: "UNABLE TO VERIFY", title: "Unable to verify", summary: "Mother AI could not be reached to complete this check. Try again shortly.", cls: "s-unable" },
};

const root = document.getElementById("verify")!;
const q = <T extends HTMLElement>(sel: string) => root.querySelector<T>(sel)!;

function formatDate(value: string): string {
  return new Date(`${value}T00:00:00Z`).toLocaleDateString("en-US", { timeZone: "UTC", year: "numeric", month: "long", day: "numeric" });
}

function formatUtc(value: string): string {
  const d = new Date(value);
  return `${d.toLocaleString("en-US", { timeZone: "UTC", year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })} UTC`;
}

function applyCopy(c: Copy): void {
  root.className = `card ${c.cls}`;
  root.setAttribute("aria-busy", "false");
  q("[data-pill]").textContent = c.state;
  q("[data-title]").textContent = c.title;
  q("[data-summary]").textContent = c.summary;
}

function fail(kind: Failure): void {
  const c = FAILURE[kind];
  applyCopy(c);
  document.title = `${c.title} — Mother AI`;
  q("[data-link-hint]").hidden = kind === "limited" || kind === "error";
  q("[data-failure]").hidden = false;
}

function row(label: string, value: string, opts: { mono?: boolean; cls?: string } = {}): HTMLElement {
  const div = document.createElement("div");
  div.className = "receipt__row";
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  dd.textContent = value;
  if (opts.mono) dd.classList.add("mono");
  if (opts.cls) dd.classList.add(opts.cls);
  div.append(dt, dd);
  return div;
}

function render(data: PublicBadge, token: string): void {
  const c = STATUS[data.status];
  applyCopy(c);
  const name = data.organization.display_name;
  q("[data-org-name]").textContent = name;
  q("[data-org]").hidden = false;
  document.title = `${c.title} — ${name}`;

  q("[data-meta]").replaceChildren(
    row("Organization", name),
    row("Badge status", data.status.toUpperCase(), { mono: true, cls: "status" }),
    row("Verification ID", token, { mono: true, cls: "id" }),
    row("Checked at", formatUtc(data.checked_at)),
    row("First activated", data.activated_on ? formatDate(data.activated_on) : "Not activated"),
    row("Last gateway activity", data.last_gateway_activity_on ? formatDate(data.last_gateway_activity_on) : "None recorded yet"),
    row("Policy engine", `${data.policy_engine} · service v${data.service_version}`, { mono: true }),
  );

  const list = q<HTMLUListElement>("[data-controls]");
  list.replaceChildren();
  for (const control of data.controls) {
    const li = document.createElement("li");
    li.className = control.met ? "is-met" : "is-unmet";
    const mark = document.createElement("span");
    mark.className = "mark";
    mark.setAttribute("aria-hidden", "true");
    const label = document.createElement("span");
    label.className = "controls__label";
    label.textContent = control.label;
    const state = document.createElement("span");
    state.className = "controls__state";
    state.textContent = control.met ? "Met" : "Not met";
    li.append(mark, label, state);
    list.append(li);
  }
  const met = data.controls.filter((x) => x.met).length;
  q("[data-controls-count]").textContent = `${met} of ${data.controls.length} met`;
  q("[data-controls-wrap]").hidden = data.controls.length === 0;

  q<HTMLImageElement>("[data-badge-img]").src = data.badge.svg_url;
  q("[data-badge]").hidden = false;
  q("[data-disclaimer]").textContent = data.disclaimer;
  q("[data-body]").hidden = false;

  const copy = q<HTMLButtonElement>("[data-copy]");
  const status = q("[data-copy-status]");
  const link = `${location.origin}/verify/${token}`;
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(link);
      status.textContent = "Link copied.";
    } catch {
      status.textContent = link;
    }
  });
}

async function main(): Promise<void> {
  const match = /^\/verify\/([0-9A-Za-z]{32})\/?$/.exec(location.pathname);
  if (!match) return fail("malformed");
  const token = match[1]!;
  try {
    const res = await fetch(apiUrl(`/api/public/badges/${token}`), { credentials: "omit", cache: "no-store", headers: { Accept: "application/json" } });
    // Always drain the body, including on 404/429, so the request completes.
    const text = await res.text();
    if (res.status === 404) return fail("notfound");
    if (res.status === 429) return fail("limited");
    if (!res.ok) return fail("error");
    const data = JSON.parse(text) as PublicBadge;
    if (!data || !(data.status in STATUS) || !data.organization) return fail("error");
    render(data, token);
  } catch {
    fail("error");
  }
}

void main();
