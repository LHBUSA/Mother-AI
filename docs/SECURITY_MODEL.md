# Mother AI security model

Mother AI answers one question deterministically:

> Is this agent authorized to perform this specific action under the policies its organization configured?

It does not detect intent, "rogue AI", consciousness or sentience, and it does not use an LLM to make decisions. Policy evaluation is a pure function of the described action, the organization's stored policies and its default decision.

## What Mother AI protects

- **Authorization of described actions.** An integration asks before acting; Mother returns `allow`, `review` or `block` according to deterministic policies (see `docs/API.md#policy-precedence`).
- **Agent identity.** Actions are attributed to registered agents. Unknown or disabled agents, environment mismatches and test keys on production agents are blocked and recorded.
- **Human-in-the-loop for high-risk actions.** `review` creates an approval that expires, requires a human with the approver role or higher, and yields a single-use, time-limited grant.
- **Evidence.** Every decision is recorded before the response is returned, with agent, capability, operation, resource, destination, data class, environment, matched policies, the policy version that decided, reason, and redacted context. Control-plane actions (policy edits, key lifecycle, approvals, badge, members, settings) are appended as control events.
- **Credentials for the gateway itself.** API keys, sessions and invites are high-entropy random tokens stored only as SHA-256 digests.

## What Mother AI does not protect

- **Actions that never ask.** Mother is a policy decision point. Code paths that call tools without calling Mother are not governed. Put the check at the tool boundary your agents cannot bypass.
- **Misdescribed actions.** Mother evaluates the action as the integration describes it. If the integration lies (claims `read` and performs `delete`), Mother cannot know. Integrations belong in trusted code, not in model prompts.
- **Downstream enforcement.** Mother does not hold your downstream credentials or proxy your traffic (a transparent MCP proxy is future work). Your integration must honor the decision.
- **Your policies' correctness.** Mother enforces what you configure. The simulator helps; it does not write policy for you.
- **Your broader security program.** The badge is not a certification (see `docs/BADGE.md`).

## Fail-closed behavior

| Condition | Result |
|---|---|
| Missing, malformed, unknown or revoked API key | 401, `decision: "block"` |
| Organization suspended/revoked, gateway disabled | 403, `decision: "block"` |
| Unknown agent (registered-agent mode, the default), disabled agent, environment mismatch | recorded `block` |
| Malformed stored policy in scope | recorded `block` (`POLICY_INVALID`) |
| Numeric condition on missing/non-numeric value in a block/review policy | policy applies (`POLICY_CONDITION_INDETERMINATE`) |
| Engine exception | `block` (`POLICY_ENGINE_ERROR`) |
| D1 read failure | 503 `GATEWAY_UNAVAILABLE`, `decision: "block"` |
| Decision evidence cannot be written | 503 `AUDIT_WRITE_FAILED`, `decision: "block"` |
| Rate limit exceeded | 429, `decision: "block"` |
| Any unhandled error | 500, `decision: "block"`, no internals |

## Tenant isolation

- Every tenant-owned table carries `organization_id`. The organization is derived only from the authenticated principal (API key or console session), never from a request body or URL.
- Gateway reads join through `api_keys.key_hash`, so an agent, policy or prior decision can only be loaded for the key's organization. `request_id` uniqueness is per organization.
- Console queries filter by the session's organization. Resource ids from another organization return 404. Binding a policy to another organization's agent is rejected.
- Covered by `tests/integration/gateway.test.ts` and `tests/integration/console.test.ts` ("isolates tenants").

## Evidence integrity

- `decisions`, `control_events` and `policy_versions` reject `UPDATE` and `DELETE` via SQLite triggers in the committed migration.
- `approvals` allow only `pending → approved|denied|expired` and a single consumption of an approved grant; identity columns are immutable (trigger).
- The public API offers no way to modify or delete decision evidence.
- This is **tamper-resistant and append-oriented**, not cryptographically immutable: an operator with direct database access could drop triggers. Signed/hash-chained audit exports are on the roadmap. We do not call the audit trail "immutable".
- Retention/deletion, if legally required, will be implemented as an explicit, audited operator process.

## Control-plane authentication

- **Passkeys (WebAuthn) only.** No passwords are stored. User verification is required. Accounts are created only by redeeming a single-use invite (72 h expiry) that registers a passkey bound to the UI origin `https://mother.proptechusa.ai` (RP ID `mother.proptechusa.ai`). The ceremony endpoints live on the API host, but the RP ID and expected origin are fixed to the UI origin and never derived from the request host.
- Invite tokens travel in the URL **fragment** (`#token=`), which browsers do not send to servers or logs; only SHA-256 digests are stored.
- WebAuthn challenges are stored server-side, single-use, 5-minute expiry, referenced by an HttpOnly cookie.
- Sessions: 256-bit random token in a host-only `__Host-mai_session` cookie on the API host (`HttpOnly; Secure; SameSite=Strict; Path=/`, no `Domain`), 12 h absolute and 2 h idle expiry, revocable, digest stored. The UI never reads it; it calls the API with `credentials: "include"`. `SameSite=Strict` still applies because the UI and API hosts are the same site (`proptechusa.ai`).
- CSRF: `SameSite=Strict`, plus every cookie-authenticated mutation (and every passkey ceremony) requires `Origin` to exactly equal `https://mother.proptechusa.ai` and, when present, `Sec-Fetch-Site: same-site` or `same-origin`. Other proptechusa.ai subdomains are same-site but are rejected by the exact Origin check.
- Roles: `viewer` (read) < `approver` (approve/deny) < `security` (agents, policies) < `admin` (keys, badge, settings, members) < `owner`. Members cannot grant roles above their own, modify themselves, or remove the last owner. Enforced server-side.
- Cloudflare Access was evaluated for the first release; the available Cloudflare credentials did not include Access configuration scope, so passkeys were implemented rather than weakening authentication.

## Secrets

- No secrets in Git or in the browser bundle. Worker secrets: `FORM_SIGNING_KEY` (Founding Access form timing tokens and the IP-hash salt) and `SLACK_LEADS_WEBHOOK_URL` (Slack Incoming Webhook for `#leads`; never logged). The Vercel UI needs no secrets.
- API keys are never logged. Stored `context`/`resource` are redacted (see `src/lib/redact.ts`). Error responses never include stack traces or internal messages.
- Raw client IPs are not stored for Founding Access; a daily-salted hash is.

## Transport and browser hardening

Every response (Vercel UI via `vercel.json`, Worker via `src/lib/security-headers.ts`): `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` (camera, microphone, geolocation, payment, USB disabled), `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`, and a CSP that allows only the Mother API as an extra origin:

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data: https://api.mother.proptechusa.ai; font-src 'self'; connect-src 'self' https://api.mother.proptechusa.ai;
frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'; upgrade-insecure-requests
```

`/app/*` and `/verify/*` are `noindex`.

Badge SVGs are the exception: embeddable (`Cross-Origin-Resource-Policy: cross-origin`, no frame restrictions) with `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`.

**CORS** (Worker, `src/lib/cors.ts`) is endpoint-specific and never a wildcard:

| Endpoints | Allowed origin | Credentials |
|---|---|---|
| `/api/auth/*`, `/api/console/*` | `https://mother.proptechusa.ai` only | yes |
| `/api/demo/*`, `/api/founding-access`, `/api/founding-access/token`, `/api/public/badges/*` | `https://mother.proptechusa.ai` only | no |
| `/v1/evaluate`, `/v1/mcp/evaluate`, `/v1/approvals/*` | none (server-to-server) | — |
| `/badge/*.svg` | image embed (CORP cross-origin), no CORS | — |

Preflights from other origins get `403` with no CORS headers. Browser API traffic is never proxied through Vercel, so the Worker sees the real client IP for rate limits and IP hashing.

## Abuse controls

- Gateway: per-IP limit before key lookup, per-key limit after.
- Public demo: per-IP limit; stateless; runs against a fixed in-code workspace and never touches tenant data.
- Founding Access: 5/min per-IP limit, HMAC-signed form token (minimum 3 s, maximum 2 h age), honeypot field, 24 h duplicate suppression, strict validation, daily-salted IP hash (raw IPs are not stored). No CAPTCHA/Turnstile is used. Only a newly inserted lead notifies Slack (background, after the D1 insert); the Slack message carries lead fields only — never the IP, IP hash, form token or secrets.
- Sign-in: per-IP limit; single-use challenges.
- Public badge verification (`/badge/*.svg`, `/api/public/badges/*`): per-IP limit.
- Request bodies ≤ 32 KB; `context` ≤ 8 KB, depth ≤ 6.

Workers Rate Limiting counters are per Cloudflare location and eventually consistent. They are abuse controls, not exact quotas.

## Reporting a vulnerability

Email the repository owner. Please do not open public issues for security reports.
