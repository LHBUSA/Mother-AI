# Mother AI Protected badge

The badge lets an organization show its customers that Mother AI agent access controls are **configured and enabled**. The executable definition is `src/badge/status.ts`; this document must match it.

## Public meaning

> Mother AI Protected indicates that this organization has configured and enabled Mother AI agent access controls. It is not a certification of the organization's entire cybersecurity program or a guarantee against security incidents.

The badge does **not** mean SOC 2, ISO 27001 or any other certification, that the organization is "secure", that incidents cannot happen, or that every agent the organization runs is behind Mother AI.

## Eligibility (all required)

| Criterion | Rule |
|---|---|
| Organization active | `organizations.status = 'active'` |
| Policy enforcement gateway enabled | `organizations.gateway_enabled = 1` |
| Audit logging enabled | `organizations.audit_enabled = 1` |
| Active registered agent | at least one agent with `status = 'active'` |
| Enabled policy | at least one policy with `enabled = 1` and not archived |
| Production API key | at least one `live` API key that is not revoked |

Traffic volume is **not** a criterion. Low-traffic customers keep a valid badge. The verification page shows **Last gateway activity** separately (date only).

## States

| State | When | Rendering |
|---|---|---|
| `setup` | No badge created yet, or created but eligibility has never been met | Grey/amber "Controls not active". Never green. |
| `active` | Badge enabled and every criterion met | Green "MOTHER AI PROTECTED · AI Controls Active" |
| `suspended` | Customer suspended the badge; **or** the organization is suspended; **or** a criterion stopped being met after the badge had been active | Amber "Protection suspended" |
| `revoked` | Token rotated (old token), or the organization is revoked by Mother AI | Red "Badge revoked" |
| invalid | Token does not exist | Grey "Unverified badge", HTTP 404 |

Evaluation order: revoked → suspended → active → (suspended if previously activated, else setup).

## Why a copied badge cannot stay green

- The embed is a **live SVG** rendered by the Worker on every request from current database state. There is no static image file.
- `Cache-Control: no-cache, max-age=0` with a state-based `ETag` makes browsers revalidate every view, so state changes show on the next page load.
- The badge links to `/verify/{token}`, which is rendered with `Cache-Control: no-store`.
- A screenshot of a green badge is not verifiable: the linked verification page shows the real state, and an unknown token shows "Verification not found".
- Third-party caches (for example image proxies used by some Markdown renderers) are outside Mother AI's control; the verification page is authoritative.

## Tokens

- 32 base62 characters (~190 bits), generated with a CSPRNG. Never an internal organization id.
- One live (non-revoked) badge per organization, enforced by a partial unique index.
- **Rotate** permanently revokes the current token (old embeds show "Badge revoked") and issues a new one.

## Endpoints

| Endpoint | Description |
|---|---|
| `GET /badge/{token}.svg` | Dark badge (default). Public, embeddable (`Cross-Origin-Resource-Policy: cross-origin`). |
| `GET /badge/{token}.svg?theme=light` | Light badge. |
| `GET /verify/{token}` | Public verification page: organization display name, status, controls, last verified time, last gateway activity (date), first activation date, engine version, disclaimer. `noindex`. |

Rate limit: 300 requests/minute per IP across badge and verification endpoints.

## Embed snippets

Markdown:

```markdown
[![Mother AI Protected — AI Controls Active](https://mother-ai.sales-fd3.workers.dev/badge/TOKEN.svg)](https://mother-ai.sales-fd3.workers.dev/verify/TOKEN)
```

HTML:

```html
<a href="https://mother-ai.sales-fd3.workers.dev/verify/TOKEN">
  <img src="https://mother-ai.sales-fd3.workers.dev/badge/TOKEN.svg" alt="Mother AI Protected — AI Controls Active" width="236" height="48">
</a>
```

The console (**Badge**) generates these with the organization's real token, in dark and light variants.

## Verification page "Controls" mapping

| Shown control | Derived from |
|---|---|
| Agent identity configured | active registered agent |
| Policy enforcement enabled | gateway enabled + enabled policy + live API key |
| Human approval capability enabled | gateway enabled |
| Audit logging enabled | audit logging enabled |

## Marketing rules

Marketing may say "Mother AI Protected" only for organizations whose badge status is `active`, and must keep the disclaimer attached wherever the badge's meaning is explained.
