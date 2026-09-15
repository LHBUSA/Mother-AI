# Runtime containment (V1)

Mother AI V1 extends deterministic pre-action governance with deterministic runtime containment:

```
IDENTIFY → AUTHORIZE → OBSERVE → CORRELATE → DETECT → CONTAIN → INVESTIGATE
```

The policy engine (`mpe-1.0.0`) is unchanged. The runtime layer is a separate, versioned, deterministic risk engine (`mre-1.0.0`) that can only **preserve or restrict** a policy decision. No model decides anything.

## Release notes

### Mother Runtime Containment V1 — production canary passed

**Status: accepted and frozen (2026-09-15).** V1 does not change `mpe-1.0.0`, `mre-1.0.0`, containment thresholds, clearance rules, lease semantics, grant invalidation or production mode behavior. Follow-up work is tracked in the [V1.1 hardening backlog](#v11-hardening-backlog).

| | |
|---|---|
| Policy engine | `mpe-1.0.0` |
| Runtime engine | `mre-1.0.0` |
| Production canary | **PASS** — organization `proptechusa`, one canary agent, Worker `c9449ae2` (main `bb39cc2`) |
| Human-only passkey clearance | **Proven.** All three canary incidents were cleared by an active human Owner signed in with a passkey, each with a written note; the organization's automation admin (`users.kind = automation`) cannot clear. Every clearance recorded `contained → cleared` with a user actor and a `security.cleared` control event, and preserved the containment epoch. |
| Post-containment authority invalidation | **Proven.** After clearance, the pre-containment grant was refused `APPROVAL_INVALIDATED` and the pre-containment lease `LEASE_REVOKED`; fresh session, decision and lease were all issued after the latest containment epoch. |
| Exact-resource single-use lease | **Proven.** A 60 s, 1-use lease bound to one exact resource was granted once and refused `LEASE_EXHAUSTED` on the second use. |
| Default-deny resource isolation | **Proven.** The same agent and operation on a different resource returned `block` / `DEFAULT_DENY` with no lease and no approval. |
| Replay blocking | **Proven.** Replaying the pre-quarantine ALLOW `request_id` during containment returned BLOCK, left the original decision `allow` unchanged, and appended `runtime.replay_blocked` evidence. |
| Cleanup | **Complete.** Organization returned to `monitor` (alerts off); canary sessions closed through the API; temporary API key revoked; temporary ALLOW/BLOCK policies archived; pre-existing REVIEW policy untouched; canary agent disabled. All incident, decision, runtime-event, signal and audit evidence retained. |
| Active incidents / quarantines | **0 / 0** (all organizations) |
| Unrelated production impact | 0 — other organizations unchanged from the preflight snapshot; 0 risk-evaluation invariant violations |
| Slack | **NOT TESTED** (excluded by owner instruction; no Slack destination configured, 0 security notifications) |

Shipped with the canary:

- **Incident detail 500 on D1** (main `bb39cc2`): the blast-radius query exceeded D1's compound-SELECT term limit, so the console could not render an incident or its clearance control. Each blast-radius category is now its own statement; a regression test caps UNIONs per statement.
- **Stale incident console state** (main `b6e3acc`, UI only): the incident page renders only a response for exactly the incident in the route. Switching incidents clears the previous data and aborts its request; late, out-of-order or mismatched responses are ignored; loading and error states name the requested incident. Verified by unit regression tests and a production browser smoke (cleared A → slow B, A → contained B, A → nonexistent B, A → failing B, rapid A→B→C→A→B with out-of-order responses, and a mismatched response body): no stale status banner in any recorded frame.

## Enforcement boundary

**Mother governs actions that call Mother.** V1 runtime protection covers API, MCP and tool actions routed through trusted integrations that hold a Mother API key.

| Evidence | Source | Shown as |
|---|---|---|
| Evaluations, identity checks, policy, runtime and effective decisions | Mother | observed |
| Sessions, parent sessions, parent decisions | Mother (requested through the API) | observed |
| Approvals, approve/deny, cancellation by quarantine, consume and refused consumes | Mother | observed |
| Capability lease issuance, every use and refusal | Mother | observed |
| Risk signals, transitions, quarantines, clearances, alert deliveries | Mother | observed |
| Execution results (`execution.reported`) and the session principal (`principal.ref`) | the integration | reported by integration |

Mother does **not** see process execution, file access, network connections, shell commands, tool calls that did not ask Mother first, or whether a downstream action actually ran after an `allow` or a consumed grant. Full process/file/network enforcement requires a future trusted runtime proxy, sidecar or sensor. Nothing in the product infers or displays activity Mother did not observe.

## Modes (per organization)

| Mode | Signals and evidence | Gateway decision | Quarantine | Security alerts |
|---|---|---|---|---|
| `off` | none | policy | none | none |
| `monitor` (default) | recorded | always the policy decision | never (manual quarantine refused) | only if the org opts in; never quarantine alerts |
| `enforce` | recorded | restricted by runtime risk | automatic and manual | only if the org opts in |

The mode cannot leave `enforce` while any quarantine is active (database trigger).

## Decisions

Every decision evaluated under runtime protection stores, in `risk_evaluations`:

- `policy_decision` — the policy engine's result (identity and correlation gates count as policy blocks)
- `runtime_risk_decision` — what runtime risk requires (`allow`, `review`, `block`)
- `effective_decision` — the decision actually returned and recorded in `decisions.decision`

**Invariant, enforced by the database:** in `monitor`, `effective = policy`. In `enforce`, `effective` is exactly the most restrictive of `policy` and `runtime`: ALLOW→ALLOW/REVIEW/BLOCK, REVIEW→REVIEW/BLOCK, BLOCK→BLOCK. A `CHECK` constraint rejects any other combination and a trigger rejects a risk evaluation whose effective decision differs from the stored decision row.

## Signals (`mre-1.0.0`)

Behavioral signals accumulate; no single behavioral signal can reach the quarantine threshold. Hard signals are rare deterministic violations that quarantine immediately in `enforce`. A signal fires at most once per subject per evidence key within its window.

| Signal | Type | Points | Window | Rule |
|---|---|---|---|---|
| `AGENT_DISABLED_ATTEMPT` | behavioral | 30 | 60 min | A request named a registered agent that is disabled. |
| `UNKNOWN_AGENT_PROBING` | behavioral (API key) | 30 | 60 min | ≥ 3 requests from one key naming unregistered agents within 10 min. |
| `REPEATED_BLOCK` | behavioral | 20 | 60 min | ≥ 3 blocked requests within 10 min; fires again at 10. |
| `USE_AFTER_EXPIRY_OR_REVOCATION` | behavioral | 40 | 60 min | Use of an approval or lease that expired, was denied, revoked, exhausted, invalidated or consumed. |
| `UNEXPECTED_MCP_TOOL` | behavioral | 25 | 60 min | MCP server/tool with no allowed decision for the agent in 30 days. |
| `CAPABILITY_ESCALATION` | behavioral | 25 | 60 min | Destructive capability·operation with no allowed decision for the agent in 30 days. |
| `UNUSUAL_DESTINATION` | behavioral | 20 | 60 min | Destination outside the agent's allowed baseline (baseline ≥ 20 allowed decisions). |
| `HIGH_VELOCITY` | behavioral (session) | 20 | 30 min | > 60 requests in 60 s, or > 25 distinct resources in 5 min. |
| `SENSITIVE_DATA_ESCALATION` | behavioral (session) | 25 | 60 min | Data class rises above the session maximum into confidential or higher. |
| `CHILD_SESSION_FANOUT` | behavioral | 25 | 60 min | > 10 child sessions in 10 min, or a child at depth ≥ 5. |
| `SESSION_OR_PARENT_INVALID` | behavioral | 50 | 60 min | A session or parent decision id outside this agent, key or lineage. |
| `CONTINUATION_AFTER_QUARANTINE` | recorded | 0 | 60 min | Any attempt to act inside a quarantined scope. |
| `CROSS_TENANT_REFERENCE` | **hard** | 100 | 24 h | A session, decision, approval or lease id that belongs to another organization. |
| `EXECUTED_WITHOUT_AUTHORIZATION` | **hard** | 100 | 24 h | The integration reported executing an action whose effective decision was block, or a review never consumed. |

Score → state: 0–24 normal · 25–49 elevated · 50–79 review_required (`allow → review`) · ≥ 80 quarantined (enforce). API keys are never quarantined (they cap at review_required; revoke a key to contain it).

Every signal row stores the code, points, evidence, engine version, `observed_at`, subject, session and whether it is hard.

## State machine

```
normal ⇄ elevated ⇄ review_required → quarantined → contained → cleared
                                   ↑ hard signal / score ≥ 80 / manual (enforce)
```

- Quarantine is sticky: signals never decay it and only a human clearance leaves it (trigger).
- `contained` means the containment batch was verified: no live lease and no pending approval remains in scope.
- `cleared` requires an **active human** member with role Security, Admin or Owner, a passkey console session and a note of at least 10 characters. The trigger re-checks role, membership, organization and `users.kind = 'human'`. Automation identities (`users.kind = 'automation'`, one-way) can never clear.

## QUARANTINE AGENT/SESSION

One atomic D1 batch:

1. subject → `quarantined`, new `containment_epoch_at`, incident id;
2. transition, incident and members (subject, triggering decision and signals);
3. scope = the agent's live sessions (or the session) and all descendants; child agents recorded;
4. every live capability lease in scope revoked;
5. every pending approval in scope terminated by the **system** — `status = denied`, `acted_by = NULL`, `terminated_reason = quarantine`, control event `approval.cancelled_by_quarantine` (never a human denial);
6. approved-but-unused grants recorded as invalidated;
7. `quarantine.enforced` runtime event, `security.quarantined` control event, alert queue.

While contained, in `enforce`: every evaluation for the scope blocks (any `request_id`), idempotent replays of old decisions block with `runtime.replay_blocked` evidence, leases and consumes are refused, new sessions and child sessions are refused, and approve is refused.

**Grants and leases issued before a containment epoch are permanently invalid, including after clearance.** New authority must be issued.

## Capability leases

Requested with `lease: {ttl_seconds 5–600, max_uses 1–20}` on an allowed evaluation inside a valid session. Bound to organization, agent, API key, session, principal, capability, operation, **exact** resource, destination, data class and policy version. Every `POST /v1/leases/{id}/use` re-checks: same key; not revoked, expired or exhausted; issued after the containment epoch; agent active; session open; risk state (enforce: not review_required or contained); no policy changed since issuance; exact scope match. Every use and refusal is recorded in `lease_uses`.

## API

| Endpoint | Purpose |
|---|---|
| `POST /v1/sessions` | Open a session: `{agent_id, parent_session_id?, principal?: {type, ref?}, purpose?, ttl_seconds?}` |
| `GET /v1/sessions/{id}` · `POST /v1/sessions/{id}/close` | Session state (with effective risk) · close (never clears risk) |
| `POST /v1/evaluate` · `/v1/mcp/evaluate` | Optional `session_id`, `parent_decision_id`, `lease`. The response adds `session_id`, `parent_decision_id`, `risk {mode, engine_version, policy_decision, runtime_risk_decision, effective_decision, state, signals, incident_id}` and `lease` when the org is in `enforce` or the request used correlation. Existing clients see no change. |
| `POST /v1/leases/{id}/use` | `{resource, destination?, data_class?}` → `200 {granted}` or `409 {decision: "block", error}` |
| `POST /v1/events` | `{type: "execution.reported", decision_id, outcome, detail?}` — integration-reported |
| `POST /v1/approvals/{id}/consume` | Adds `APPROVAL_INVALIDATED` and `APPROVAL_QUARANTINED` refusals |
| `GET /api/console/security` · `GET /api/console/security/incidents/{id}` | Overview · incident with observed blast radius |
| `POST /api/console/security/quarantine` · `POST …/incidents/{id}/clear` | `manage_security` (Security role or higher); clear requires a human |

New reason codes: `SESSION_INVALID`, `SESSION_CLOSED`, `SESSION_EXPIRED`, `PARENT_INVALID`, `AGENT_QUARANTINED`, `SESSION_QUARANTINED`, `RISK_REVIEW_REQUIRED`.

## Security alerts

Off by default. When an organization enables them (Settings → Organization → Runtime protection), transitions post to the organization's existing encrypted Slack destination through the existing sender: `risk_elevated`, `review_required`, `quarantined`, `containment_completed`, `cleared`. Separate queue (`security_notifications`) with the same claim, bounded retry and literal statuses as approval alerts. Alert delivery has no write path to risk state, incidents, leases or approvals, so a failed alert can never weaken containment.

## Rollback

- Worker: roll back to the previous version. Migration 0003 is additive, so earlier code runs against it unchanged — but an earlier Worker does not enforce quarantines.
- Without a deploy: an organization can be set to `monitor` or `off` only when no quarantine is active; an active quarantine is cleared by a human.
- No down-migration; evidence is retained.

## V1.1 hardening backlog

Findings from the V1 production canary. They are hardening items, **not V1 defects**: V1 behaved as specified in both cases. Neither item may weaken containment.

### 1. Integration retry hardening

Observed: after a human clearance, two attempts by the same agent to use authority it held before containment (a grant refused `APPROVAL_INVALIDATED`, a lease refused `LEASE_REVOKED`) each scored `USE_AFTER_EXPIRY_OR_REVOCATION` (+40) and re-quarantined the agent at 80. This is correct under `mre-1.0.0`, but an integration that blindly retries dead authority will contain itself again.

- A containment epoch change must cause SDK/integration caches to flush every grant and lease obtained before it.
- `APPROVAL_INVALIDATED`, `LEASE_REVOKED` and `LEASE_EXHAUSTED` must be documented and surfaced as **terminal, non-retryable** authority errors.
- Clients must obtain fresh authority (new session, evaluation, approval or lease) rather than retry dead authority.

### 2. Incident deduplication

Observed: the agent was quarantined at score 95. Its session, already inside the agent's contained scope, carried the same score 95 from the same signals; on the session's next request it crossed the threshold and opened a second, nested incident for the session (recorded as `CONTINUATION_AFTER_QUARANTINE`), which needed its own human clearance.

- Investigate whether a quarantined agent and its contained child sessions should share or correlate into one incident instead of opening a redundant nested incident.
- Preserve all evidence and the full blast radius of both subjects.
- Do not weaken containment to accomplish this: every subject in scope stays contained until a human clears it.
