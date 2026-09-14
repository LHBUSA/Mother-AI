// Public badge verification page. Reads live state from the Mother AI API; it never
// shows a verified state unless the API returns status "active" for this token.

import "./verify.css";
import { apiUrl } from "../shared/site";

type Status = "active" | "setup" | "suspended" | "revoked";

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

const COPY: Record<Status | "invalid" | "error" | "limited", { pill: string; title: string; summary: string; cls: string }> = {
  active: { pill: "ACTIVE", title: "Mother AI Protected", summary: "This organization has Mother AI agent access controls configured and enabled.", cls: "s-active" },
  setup: { pill: "NOT ACTIVE", title: "Mother AI badge not active", summary: "This organization has not completed Mother AI configuration. The badge is not active.", cls: "s-setup" },
  suspended: { pill: "SUSPENDED", title: "Mother AI badge not active", summary: "Mother AI protection for this organization is currently suspended. The badge is not active.", cls: "s-suspended" },
  revoked: { pill: "REVOKED", title: "Mother AI badge not active", summary: "This Mother AI badge has been revoked and no longer represents active controls.", cls: "s-revoked" },
  invalid: { pill: "NOT VERIFIED", title: "Verification not found", summary: "This link does not match any Mother AI badge. A badge displayed with this link should not be treated as evidence of Mother AI controls.", cls: "s-invalid" },
  limited: { pill: "NOT VERIFIED", title: "Verification temporarily unavailable", summary: "Too many verification requests from your network. Wait a minute and reload. Until then, do not treat a displayed badge as verified.", cls: "s-invalid" },
  error: { pill: "NOT VERIFIED", title: "Verification could not be completed", summary: "Mother AI could not be reached to verify this badge. Reload to try again. Until verification succeeds, do not treat a displayed badge as verified.", cls: "s-invalid" },
};

const root = document.getElementById("verify")!;
const q = <T extends HTMLElement>(sel: string) => root.querySelector<T>(sel)!;

function formatDate(value: string): string {
  return new Date(`${value}T00:00:00Z`).toLocaleDateString("en-US", { timeZone: "UTC", year: "numeric", month: "long", day: "numeric" });
}

function formatUtc(value: string): string {
  const d = new Date(value);
  return `${d.toLocaleString("en-US", { timeZone: "UTC", year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false })} UTC`;
}

function setState(key: keyof typeof COPY): void {
  const c = COPY[key];
  root.className = `card ${c.cls}`;
  root.setAttribute("aria-busy", "false");
  q("[data-pill]").textContent = c.pill;
  q("[data-title]").textContent = c.title;
  q("[data-summary]").textContent = c.summary;
  document.title = `${c.title} — Mother AI`;
}

function metaItem(label: string, value: string, mono = false): HTMLElement {
  const div = document.createElement("div");
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  dd.textContent = value;
  if (mono) dd.style.fontFamily = "var(--font-mono)";
  div.append(dt, dd);
  return div;
}

function render(data: PublicBadge): void {
  setState(data.status);
  const name = data.organization.display_name;
  q("[data-org-name]").textContent = name;
  q("[data-org]").hidden = false;
  document.title = `${COPY[data.status].title} — ${name}`;

  const list = q<HTMLUListElement>("[data-controls]");
  list.replaceChildren();
  for (const control of data.controls) {
    const li = document.createElement("li");
    const mark = document.createElement("span");
    mark.className = `mark ${control.met ? "ok" : "no"}`;
    mark.setAttribute("aria-hidden", "true");
    mark.textContent = control.met ? "✓" : "–";
    const label = document.createElement("span");
    label.textContent = control.met ? control.label : `${control.label} — not active`;
    li.append(mark, label);
    list.append(li);
  }
  q("[data-controls-wrap]").hidden = data.controls.length === 0;

  const meta = q("[data-meta]");
  meta.replaceChildren(
    metaItem("Last verified", formatUtc(data.checked_at)),
    metaItem("Last gateway activity", data.last_gateway_activity_on ? formatDate(data.last_gateway_activity_on) : "None recorded yet"),
    ...(data.activated_on ? [metaItem("First activated", formatDate(data.activated_on))] : []),
    metaItem("Policy engine", `${data.policy_engine} · v${data.service_version}`, true),
  );

  const img = q<HTMLImageElement>("[data-badge-img]");
  img.src = data.badge.svg_url;
  q("[data-badge]").hidden = false;
  q("[data-disclaimer]").textContent = data.disclaimer;
  q("[data-body]").hidden = false;
}

async function main(): Promise<void> {
  const match = /^\/verify\/([0-9A-Za-z]{32})\/?$/.exec(location.pathname);
  if (!match) {
    setState("invalid");
    return;
  }
  try {
    const res = await fetch(apiUrl(`/api/public/badges/${match[1]}`), { credentials: "omit", cache: "no-store", headers: { Accept: "application/json" } });
    if (res.status === 404) return setState("invalid");
    if (res.status === 429) return setState("limited");
    if (!res.ok) return setState("error");
    const data = (await res.json()) as PublicBadge;
    if (!data || !(data.status in COPY) || !data.organization) return setState("error");
    render(data);
  } catch {
    setState("error");
  }
}

void main();
