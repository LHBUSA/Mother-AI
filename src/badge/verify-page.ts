// Public verification page: GET /verify/{token}. Server-rendered, no scripts.

import site from "../../config/site.json";
import { ENGINE_VERSION } from "../gateway/policy-engine";
import { SERVICE_VERSION } from "../version";
import { BADGE_DISCLAIMER, type BadgeCriterion, type BadgeStatus } from "./status";
import { renderBadgeSvg } from "./svg";

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);
}

const STATUS_COPY: Record<BadgeStatus, { label: string; summary: string }> = {
  active: {
    label: "ACTIVE",
    summary: "This organization has Mother AI agent access controls configured and enabled.",
  },
  setup: {
    label: "NOT ACTIVE",
    summary: "This organization has not completed Mother AI configuration. The badge is not active.",
  },
  suspended: {
    label: "SUSPENDED",
    summary: "Mother AI protection for this organization is currently suspended. The badge is not active.",
  },
  revoked: {
    label: "REVOKED",
    summary: "This Mother AI badge has been revoked and no longer represents active controls.",
  },
};

function formatUtc(isoString: string): string {
  const d = new Date(isoString);
  return `${d.toLocaleString("en-US", { timeZone: "UTC", year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false })} UTC`;
}

function formatDate(isoString: string): string {
  return new Date(isoString).toLocaleDateString("en-US", { timeZone: "UTC", year: "numeric", month: "long", day: "numeric" });
}

const STYLES = `
@font-face{font-family:Inter;src:url(/fonts/inter-var-latin.woff2) format("woff2");font-weight:100 900;font-display:swap}
@font-face{font-family:"JetBrains Mono";src:url(/fonts/jetbrains-mono-var-latin.woff2) format("woff2");font-weight:100 800;font-display:swap}
:root{color-scheme:dark;--bg:#07080a;--surface:#0f1215;--line:rgba(233,240,228,.08);--line2:rgba(233,240,228,.14);--text:#e8ece6;--text2:#a4acb2;--text3:#6c747b;--acid:#b7ff4a;--amber:#e9b54a;--red:#ee6a5f}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:radial-gradient(1200px 600px at 50% -10%,rgba(183,255,74,.07),transparent 60%),var(--bg);color:var(--text);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;-webkit-font-smoothing:antialiased}
a{color:inherit}
.wrap{max-width:760px;margin:0 auto;padding:28px 20px 56px}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:40px}
.brand{display:flex;align-items:center;gap:10px;text-decoration:none;font-weight:650;letter-spacing:-.01em}
.brand img{width:26px;height:26px}
.eyebrow{font:500 11px/1 "JetBrains Mono",ui-monospace,monospace;letter-spacing:.14em;text-transform:uppercase;color:var(--text3)}
.card{background:linear-gradient(180deg,rgba(255,255,255,.025),rgba(255,255,255,0)),var(--surface);border:1px solid var(--line2);border-radius:18px;overflow:hidden;box-shadow:0 30px 80px -40px rgba(0,0,0,.8)}
.head{padding:32px 32px 28px;border-bottom:1px solid var(--line)}
.status-row{display:flex;flex-wrap:wrap;align-items:center;gap:14px;justify-content:space-between}
h1{margin:12px 0 6px;font-size:clamp(26px,5vw,34px);line-height:1.15;letter-spacing:-.02em;font-weight:680}
.org{font-size:18px;color:var(--text2);margin:0}
.org strong{color:var(--text);font-weight:600}
.pill{display:inline-flex;align-items:center;gap:8px;padding:7px 12px;border-radius:999px;font:600 12px/1 "JetBrains Mono",ui-monospace,monospace;letter-spacing:.12em;border:1px solid}
.pill i{width:8px;height:8px;border-radius:50%;display:block}
.s-active .pill{color:var(--acid);border-color:rgba(183,255,74,.35);background:rgba(183,255,74,.08)}
.s-active .pill i{background:var(--acid);box-shadow:0 0 0 4px rgba(183,255,74,.15)}
.s-setup .pill,.s-suspended .pill{color:var(--amber);border-color:rgba(233,181,74,.35);background:rgba(233,181,74,.08)}
.s-setup .pill i,.s-suspended .pill i{background:var(--amber)}
.s-revoked .pill,.s-invalid .pill{color:var(--red);border-color:rgba(238,106,95,.35);background:rgba(238,106,95,.08)}
.s-revoked .pill i,.s-invalid .pill i{background:var(--red)}
.summary{margin:18px 0 0;color:var(--text2);max-width:56ch}
.body{padding:28px 32px;display:grid;gap:28px}
h2{margin:0 0 12px;font:600 11px/1 "JetBrains Mono",ui-monospace,monospace;letter-spacing:.14em;text-transform:uppercase;color:var(--text3)}
ul{list-style:none;margin:0;padding:0;display:grid;gap:2px}
li{display:flex;align-items:center;gap:12px;padding:11px 0;border-bottom:1px solid var(--line)}
li:last-child{border-bottom:0}
.ok,.no{flex:none;width:22px;height:22px;border-radius:50%;display:grid;place-items:center}
.ok{background:rgba(183,255,74,.12);color:var(--acid)}
.no{background:rgba(233,240,228,.06);color:var(--text3)}
.ok svg,.no svg{width:12px;height:12px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
.meta div{background:rgba(255,255,255,.02);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.meta dt{font:500 11px/1.2 "JetBrains Mono",ui-monospace,monospace;letter-spacing:.1em;text-transform:uppercase;color:var(--text3);margin-bottom:6px}
.meta dd{margin:0;font-weight:560}
.badge{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.badge img{max-width:100%;height:auto}
.disclaimer{padding:22px 32px;border-top:1px solid var(--line);background:rgba(0,0,0,.25);color:var(--text3);font-size:13px}
footer{margin-top:28px;color:var(--text3);font-size:13px;display:flex;flex-wrap:wrap;gap:8px 18px;justify-content:space-between}
footer a{color:var(--text2);text-decoration:none}
footer a:hover{color:var(--text)}
@media (max-width:520px){.head,.body{padding:24px 20px}.disclaimer{padding:20px}}
`;

const CHECK = `<svg viewBox="0 0 12 12" aria-hidden="true"><path d="M2.5 6.2l2.3 2.3 4.7-5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
const DASH = `<svg viewBox="0 0 12 12" aria-hidden="true"><path d="M3 6h6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`;

function shell(title: string, bodyClass: string, inner: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#07080a">
<title>${escapeHtml(title)}</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>${STYLES}</style>
</head>
<body class="${bodyClass}">
<div class="wrap">
<header>
<a class="brand" href="/"><img src="/brand/mark.svg" alt="" width="26" height="26">Mother AI</a>
<span class="eyebrow">Public verification</span>
</header>
${inner}
<footer><span>Verified by Mother AI · ${escapeHtml(new URL(site.origin).host)}</span><span><a href="/">What is Mother AI?</a> · <a href="https://github.com/LHBUSA/Mother-AI/blob/main/docs/BADGE.md">Badge criteria</a></span></footer>
</div>
</body>
</html>`;
}

export interface VerifyPageInput {
  organizationName: string;
  status: BadgeStatus;
  criteria: BadgeCriterion[];
  checkedAt: string;
  activatedAt: string | null;
  lastActivity: string | null;
  token: string;
}

export function renderVerifyPage(input: VerifyPageInput): string {
  const copy = STATUS_COPY[input.status];
  const controls: Array<{ label: string; met: boolean }> = [
    { label: "Agent identity configured", met: input.criteria.find((c) => c.key === "active_agent")!.met },
    { label: "Policy enforcement enabled", met: input.criteria.filter((c) => c.key === "gateway_enabled" || c.key === "enabled_policy" || c.key === "live_api_key").every((c) => c.met) },
    { label: "Human approval capability enabled", met: input.criteria.find((c) => c.key === "gateway_enabled")!.met },
    { label: "Audit logging enabled", met: input.criteria.find((c) => c.key === "audit_enabled")!.met },
  ];
  const showControls = input.status !== "revoked";
  const badgeSvg = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(renderBadgeSvg(input.status, "dark"))}`;

  const inner = `
<main class="card s-${input.status}">
  <section class="head">
    <div class="status-row">
      <span class="eyebrow">Mother AI Protected</span>
      <span class="pill" role="status"><i></i>${copy.label}</span>
    </div>
    <h1>${input.status === "active" ? "Mother AI Protected" : "Mother AI badge not active"}</h1>
    <p class="org">Organization: <strong>${escapeHtml(input.organizationName)}</strong></p>
    <p class="summary">${copy.summary}</p>
  </section>
  <section class="body">
    ${
      showControls
        ? `<div><h2>Controls</h2><ul>${controls
            .map((c) => `<li><span class="${c.met ? "ok" : "no"}">${c.met ? CHECK : DASH}</span><span>${c.label}${c.met ? "" : ' <span style="color:var(--text3)">— not active</span>'}</span></li>`)
            .join("")}</ul></div>`
        : ""
    }
    <dl class="meta">
      <div><dt>Last verified</dt><dd>${formatUtc(input.checkedAt)}</dd></div>
      <div><dt>Last gateway activity</dt><dd>${input.lastActivity ? formatDate(input.lastActivity) : "None recorded yet"}</dd></div>
      ${input.activatedAt ? `<div><dt>First activated</dt><dd>${formatDate(input.activatedAt)}</dd></div>` : ""}
      <div><dt>Policy engine</dt><dd class="mono" style="font-family:'JetBrains Mono',monospace;font-size:13px">${ENGINE_VERSION} · v${SERVICE_VERSION}</dd></div>
    </dl>
    <div class="badge"><img src="${badgeSvg}" alt="" width="236" height="48"><span style="color:var(--text3);font-size:13px">Badge state is rendered live from this verification.</span></div>
  </section>
  <p class="disclaimer">${escapeHtml(BADGE_DISCLAIMER)}</p>
</main>`;
  return shell(`${input.status === "active" ? "Mother AI Protected" : "Mother AI badge not active"} — ${input.organizationName}`, `s-${input.status}`, inner);
}

export function renderInvalidVerifyPage(): string {
  const inner = `
<main class="card s-invalid">
  <section class="head">
    <div class="status-row">
      <span class="eyebrow">Mother AI Protected</span>
      <span class="pill" role="status"><i></i>NOT VERIFIED</span>
    </div>
    <h1>Verification not found</h1>
    <p class="summary">This link does not match any Mother AI badge. A badge displayed with this link should not be treated as evidence of Mother AI controls.</p>
  </section>
  <p class="disclaimer">${escapeHtml(BADGE_DISCLAIMER)}</p>
</main>`;
  return shell("Verification not found — Mother AI", "s-invalid", inner);
}
