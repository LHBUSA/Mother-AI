# Mother AI Gateway API

Base URL: `https://mother-ai.sales-fd3.workers.dev` (the canonical origin lives in `config/site.json`).

The gateway is a **policy decision point**. Your integration calls Mother AI *before* an agent executes a protected action, and executes the action only when Mother returns `allow` (or when a `review` has been approved and consumed).

- [Authentication](#authentication)
- [POST /v1/evaluate](#post-v1evaluate)
- [Decisions: allow, review, block](#decisions)
- [Policy precedence](#policy-precedence)
- [Conditions](#conditions)
- [Idempotency](#idempotency)
- [Human approval flow](#human-approval-flow)
- [MCP normalization — POST /v1/mcp/evaluate](#mcp-normalization)
- [Error codes](#error-codes)
- [Rate limits](#rate-limits)
- [API key security](#api-key-security)

---

## Authentication

Every gateway request carries a Mother AI API key in the `Authorization` header:

```
Authorization: Bearer mai_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

- Keys are created in the console (**Settings → API keys**) and shown **once**.
- `mai_live_…` keys may evaluate actions for any registered agent.
- `mai_test_…` keys may **not** evaluate actions for `production` agents (`API_KEY_ENVIRONMENT_MISMATCH`).
- Keys are never accepted in query strings or request bodies.
- `/v1/*` sends no CORS headers. It is a server-to-server API; do not call it from a browser.

## POST /v1/evaluate

```http
POST /v1/evaluate
Authorization: Bearer mai_live_…
Content-Type: application/json
```

```json
{
  "request_id": "req_customer_generated_123",
  "agent_id": "billing-agent-prod",
  "capability": "payments",
  "operation": "refund",
  "resource": "payment:pi_123",
  "destination": "internal",
  "data_class": "financial",
  "environment": "production",
  "context": { "amount": 4200, "currency": "USD" }
}
```

| Field | Required | Rules |
|---|---|---|
| `request_id` | recommended | `[A-Za-z0-9._:-]{1,128}`. Unique per organization. Enables [idempotency](#idempotency). Generated (`req_…`) if omitted. |
| `agent_id` | yes | Stable agent id registered in the console. Lowercased. `[a-z0-9][a-z0-9._-]{0,127}` |
| `capability` | yes | Tool or system, e.g. `payments`, `salesforce`, `records`. Lowercased. |
| `operation` | yes | Action on that capability, e.g. `refund`, `contacts.update`. Lowercased. |
| `resource` | no | Target identifier, up to 512 printable characters. Case preserved. |
| `destination` | no | e.g. `internal`, `external`. Lowercased. |
| `data_class` | no | e.g. `public`, `internal`, `confidential`, `restricted`, `financial`. Lowercased. |
| `environment` | no | `production` \| `staging` \| `development`. If sent, it must match the agent's registered environment. |
| `protocol` | no | `api` (default) or `mcp`. When `mcp`, `mcp: { server, tool }` is required. |
| `context` | no | JSON object, ≤ 8 KB serialized, ≤ 6 levels deep, ≤ 64 keys per object. Available to policies as `context.*`. |

Unknown fields are rejected (`INVALID_REQUEST`) so typos cannot silently change what is evaluated.

### Response

```json
{
  "decision_id": "dec_4hK…",
  "request_id": "req_customer_generated_123",
  "decision": "review",
  "reason_code": "HUMAN_APPROVAL_REQUIRED",
  "reason": "Refunds over $1,000 require human approval.",
  "policy_id": "pol_…",
  "policy_version": 3,
  "agent_id": "billing-agent-prod",
  "approval_id": "apr_…",
  "approval": {
    "approval_id": "apr_…",
    "status": "pending",
    "requested_at": "2026-09-14T12:00:00.000Z",
    "expires_at": "2026-09-14T12:15:00.000Z",
    "grant_expires_at": null,
    "consumed_at": null,
    "executable": false
  },
  "matched_policies": [
    { "policy_id": "pol_…", "effect": "review", "indeterminate": false },
    { "policy_id": "pol_…", "effect": "allow", "indeterminate": false }
  ],
  "engine_version": "mpe-1.0.0",
  "evaluated_at": "2026-09-14T12:00:00.000Z",
  "replayed": false,
  "latency_ms": { "policy": 0, "gateway": 7.1 }
}
```

The decision is **durably recorded before the response is returned**. If Mother AI cannot write decision evidence, the response is `503 AUDIT_WRITE_FAILED` with `decision: "block"`.

`latency_ms` and the `Server-Timing` header are server measurements. Cloudflare Workers do not advance timers during pure CPU work, so `policy` usually reads `0`; `gateway` includes the D1 reads.

## Decisions

**Treat anything other than `decision === "allow"` as "do not execute".** Every error response from `/v1/*` also carries `"decision": "block"`, so a naive integration that checks only `decision` fails closed.

| decision | Meaning | Your integration should |
|---|---|---|
| `allow` | A policy allows it (or a non-production agent defaults to allow). | Execute. |
| `review` | A human must approve. An approval was created. | Hold. Poll the approval, then consume it right before executing. |
| `block` | Denied by policy, identity gate, default deny, or a fail-closed condition. | Do not execute. Surface `reason_code`. |

Allow example:

```json
{ "decision_id": "dec_…", "decision": "allow", "reason_code": "POLICY_ALLOW", "policy_id": "pol_…", "request_id": "req_customer_generated_123" }
```

Block example:

```json
{ "decision_id": "dec_…", "decision": "block", "reason_code": "OPERATION_NOT_ALLOWED", "policy_id": "pol_…", "request_id": "req_customer_generated_123" }
```

### Decision reason codes

| reason_code | decision | Cause |
|---|---|---|
| `POLICY_ALLOW` | allow | Allow policy matched (default code). |
| `HUMAN_APPROVAL_REQUIRED` | review | Review policy matched (default code). |
| `POLICY_BLOCK` | block | Block policy matched (default code). |
| *custom* | any | A policy's own `reason_code`, e.g. `OPERATION_NOT_ALLOWED`, `RESTRICTED_DATA_EGRESS`. |
| `POLICY_CONDITION_INDETERMINATE` | review/block | A block/review policy could not be fully evaluated (e.g. `context.amount` missing or not a number) and failed closed. |
| `DEFAULT_DENY` | block | No enabled policy matched; default is block. |
| `DEFAULT_REVIEW` | review | No policy matched; default requires approval. |
| `DEFAULT_ALLOW` | allow | No policy matched; the (non-production) agent's default mode is allow. |
| `AGENT_UNKNOWN` | block | `agent_id` is not registered and the org requires registered agents (default). |
| `AGENT_DISABLED` | block | The agent is disabled. |
| `AGENT_ENVIRONMENT_MISMATCH` | block | Request `environment` differs from the agent's registered environment. |
| `API_KEY_ENVIRONMENT_MISMATCH` | block | A test key was used for a production agent. |
| `POLICY_INVALID` | block | An in-scope policy is malformed. The whole evaluation fails closed. |
| `POLICY_ENGINE_ERROR` | block | Unexpected engine failure. Fails closed. |

Identity-gate and fail-closed blocks are recorded as decisions like any other.

## Policy precedence

Deterministic, independent of the order policies were created or listed:

1. If **any** enabled, in-scope policy with effect `block` matches → **block**.
2. Else if any `review` policy matches → **review**.
3. Else if any `allow` policy matches → **allow**.
4. Else → the agent's `default_mode` (`block`/`review`/`allow`, production agents can never default to allow), or the organization's `default_decision` (`block` unless changed to `review`).

Within the winning effect, the reported policy is the one with the **lowest `priority` number**, then the **oldest `created_at`**, then the smallest id. Priority never lets an allow override a block.

A policy is in scope when it is enabled, not archived, and either organization-wide or bound to the calling agent.

## Conditions

A policy has one condition group:

```json
{
  "match": "all",
  "conditions": [
    { "field": "capability", "operator": "equals", "value": "payments" },
    { "field": "operation", "operator": "equals", "value": "refund" },
    { "field": "context.amount", "operator": "greater_than", "value": 1000 }
  ]
}
```

`match: "all"` (AND) or `"any"` (OR). Up to 50 conditions.

**Fields:** `agent`, `environment`, `protocol`, `capability`, `operation`, `resource`, `destination`, `data_class`, `mcp.server`, `mcp.tool`, and `context.<path>` (1–6 segments of `[A-Za-z0-9_-]`). `agent`, `environment`, `protocol`, `capability`, `operation`, `destination`, `data_class` compare case-insensitively; `resource`, `mcp.*` and `context.*` are exact.

**Operators:** `equals`, `not_equals`, `in`, `not_in`, `starts_with`, `glob` (`*` wildcard only), `greater_than`, `greater_than_or_equal`, `less_than`, `less_than_or_equal` (context fields only), `exists`, `not_exists`.

**Missing values** — deterministic, three-valued:

| Operator | Field missing |
|---|---|
| `equals`, `in`, `starts_with`, `glob`, `exists` | false |
| `not_equals`, `not_in`, `not_exists` | true |
| numeric operators (also when the value is not a finite number) | **indeterminate** |

In an `all` group, any false makes the group false; otherwise any indeterminate makes it indeterminate. In an `any` group, any true makes it true; otherwise any indeterminate makes it indeterminate. An indeterminate **block** or **review** policy applies (fail closed). An indeterminate **allow** policy does not.

Mother evaluates the action **as your integration describes it**. Put the integration at the tool boundary (your SDK wrapper or MCP client), not inside the model's prompt, so the described action is the executed action.

## Idempotency

Agent frameworks retry. Send a stable `request_id` per intended action.

- Same `request_id` + identical action → the **original decision** is returned with `"replayed": true` and header `Idempotent-Replayed: true`. No new decision or approval is created. For reviews, the response reflects the approval's current status.
- Same `request_id` + a different action → `409 IDEMPOTENCY_CONFLICT` (`decision: "block"`).
- "Identical" means the SHA-256 of the canonical normalized action (agent, protocol, capability, operation, resource, destination, data class, environment, MCP server/tool, context) matches. An MCP call made through `/v1/mcp/evaluate` and the same call expressed through `/v1/evaluate` have the same fingerprint.
- Scope: per organization, forever (decision records are append-only).
- Concurrent duplicates are resolved by a database uniqueness constraint; the loser returns the winner's decision.

## Human approval flow

```
POST /v1/evaluate                        → decision: review, approval_id, approval.status: pending
  (approver acts in the console: Approvals → Approve / Deny)
GET  /v1/approvals/{approval_id}         → status, executable
POST /v1/approvals/{approval_id}/consume → exactly once, immediately before executing
```

`GET /v1/approvals/{approval_id}`:

```json
{
  "approval_id": "apr_…",
  "status": "approved",
  "requested_at": "…",
  "expires_at": "…",
  "grant_expires_at": "…",
  "consumed_at": null,
  "executable": true,
  "decision_id": "dec_…",
  "request_id": "req_…",
  "agent_id": "billing-agent-prod",
  "capability": "payments",
  "operation": "refund",
  "resource": "payment:pi_123"
}
```

- `pending` approvals expire at `expires_at` (organization setting, default 15 minutes). Expired approvals can no longer be approved.
- An approval grant must be consumed before `grant_expires_at` (default 10 minutes after approval).
- `executable` is true only when `status = approved`, not consumed, and the grant has not expired.
- `consume` succeeds once. Afterwards: `409 APPROVAL_ALREADY_CONSUMED`. Other refusals: `APPROVAL_PENDING`, `APPROVAL_DENIED`, `APPROVAL_EXPIRED`, `APPROVAL_GRANT_EXPIRED`.
- The original `review` decision record never changes. Approval actions (approve, deny, expire, consume) are appended as control events with the acting user or API key.

## MCP normalization

MCP tool calls normalize into the same canonical action as direct API calls:

| MCP | Canonical action |
|---|---|
| server name | `capability` (lowercased) and `mcp.server` (exact) |
| tool name | `operation` (lowercased) and `mcp.tool` (exact) |
| tool arguments | `context` |
| calling agent | `agent_id` |
| — | `protocol = "mcp"` |

```http
POST /v1/mcp/evaluate
Authorization: Bearer mai_live_…
Content-Type: application/json
```

```json
{
  "request_id": "mcp_7f3a",
  "agent_id": "sales-agent-prod",
  "server": "salesforce",
  "tool": "contacts.update",
  "arguments": { "id": "003Hs00", "title": "VP Sales" },
  "resource": "contact:003Hs00",
  "destination": "internal",
  "data_class": "confidential"
}
```

The response has the same shape as `/v1/evaluate`. Equivalent `/v1/evaluate` body: `{"protocol":"mcp","mcp":{"server":"salesforce","tool":"contacts.update"},"capability":"salesforce","operation":"contacts.update","context":{…}}`.

**Scope today:** Mother AI is the policy decision point for MCP calls. Your MCP client or server wrapper calls `/v1/mcp/evaluate` before invoking the tool. Mother AI does **not** yet transparently proxy arbitrary MCP servers.

```ts
async function guardedToolCall(server: string, tool: string, args: Record<string, unknown>, invoke: () => Promise<unknown>) {
  const res = await fetch("https://mother-ai.sales-fd3.workers.dev/v1/mcp/evaluate", {
    method: "POST",
    headers: { Authorization: `Bearer ${process.env.MOTHER_AI_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ request_id: crypto.randomUUID(), agent_id: "sales-agent-prod", server, tool, arguments: args }),
  });
  const verdict = await res.json();
  if (verdict.decision !== "allow") throw new Error(`Mother AI: ${verdict.decision} (${verdict.reason_code ?? verdict.error?.code})`);
  return invoke();
}
```

## Error codes

All errors: `{ "decision": "block", "error": { "code": "…", "message": "…", …details } }`.

| HTTP | code | Meaning |
|---|---|---|
| 400 | `INVALID_REQUEST` | Validation failed. `error.fields` maps field → problem. |
| 400 | `INVALID_JSON` | Body is not JSON. |
| 401 | `MISSING_API_KEY` | No `Authorization` header. |
| 401 | `INVALID_API_KEY` | Malformed or unknown key. |
| 401 | `API_KEY_REVOKED` | Key was revoked. |
| 403 | `ORGANIZATION_DISABLED` | Organization suspended or revoked. |
| 403 | `GATEWAY_DISABLED` | Gateway disabled in organization settings. |
| 404 | `APPROVAL_NOT_FOUND` | Unknown approval, or belongs to another organization. |
| 405 | `METHOD_NOT_ALLOWED` | |
| 409 | `IDEMPOTENCY_CONFLICT` | `request_id` reused for a different action. |
| 409 | `APPROVAL_PENDING` / `APPROVAL_DENIED` / `APPROVAL_EXPIRED` / `APPROVAL_GRANT_EXPIRED` / `APPROVAL_ALREADY_CONSUMED` | Consume refused. |
| 413 | `PAYLOAD_TOO_LARGE` | Body > 32 KB. |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | Not `application/json`. |
| 429 | `RATE_LIMITED` | See rate limits. |
| 500 | `INTERNAL_ERROR` | Unexpected error. No internals are returned. |
| 503 | `GATEWAY_UNAVAILABLE` | Policy state could not be loaded. |
| 503 | `AUDIT_WRITE_FAILED` | Decision evidence could not be written. |

## Rate limits

Cloudflare Workers Rate Limiting, counted per Cloudflare location (coarse, eventually consistent):

| Scope | Limit |
|---|---|
| Gateway, per client IP (before key lookup) | 1,200 / minute |
| Gateway, per API key | 600 / minute |
| Public demo, per IP | 30 / minute |
| Founding Access form, per IP | 5 / minute |
| Sign-in endpoints, per IP | 30 / minute |
| Console API, per session | 300 / minute |
| Badge SVG + verification, per IP | 300 / minute |

## API key security

- Format `mai_live_` / `mai_test_` + 40 base62 characters (~238 bits of entropy).
- Only a SHA-256 digest and a display prefix (`mai_live_AbCd1234`) are stored. The raw key is shown once. Because keys are long random secrets (not passwords), a fast digest is appropriate and brute-forcing it is not feasible.
- Revocation takes effect on the next request.
- Mother AI redacts obvious credentials (key names like `password`, `token`, `api_key`, `authorization`; values that look like Mother AI, Stripe, GitHub, Slack, AWS keys, bearer tokens, JWTs and private keys) from stored `context` and `resource`. Do not send secrets in `context` anyway.
- Store keys in your secret manager. Never ship them to browsers or mobile apps.
