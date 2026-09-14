# Mother AI

**Control Plane for AI Agents.**

> Mother AI watches what your AIs are allowed to do.

AI agents now hold real credentials to CRMs, databases, payment systems, internal APIs, email, file systems and MCP servers. Mother AI sits **between the agent and the action**: every protected action is evaluated against deterministic policies before it runs, and Mother returns `allow`, `review` (human approval) or `block`, recording who asked, what they asked for, which policy decided and why.

Zero-trust access control and observability for autonomous agents. No "rogue AI detection", no LLM deciding what production operations are permitted.

Production: **https://mother.proptechusa.ai** (operational fallback for API/badge traffic: `https://mother-ai.sales-fd3.workers.dev`)

---

## What it is

| Component | What it does |
|---|---|
| **Gateway API** | `POST /v1/evaluate`, `POST /v1/mcp/evaluate` — authenticated policy decision point with idempotency and fail-closed behavior. |
| **Policy engine** | Pure deterministic evaluator (`mpe-1.0.0`): block > review > allow > default, three-valued conditions, malformed policies fail closed. |
| **Agent registry** | Stable agent identities per organization with environment and default mode. |
| **Human approval** | Review decisions create expiring approvals; approved grants are single-use and time-limited. |
| **Audit** | Append-oriented decision evidence and control-plane events (trigger-enforced). |
| **Control plane** | Passkey-authenticated console: Overview, Agents, Policies (visual rule builder + simulator), Approvals, Audit, Integrations, Badge, Settings. |
| **Mother AI Protected badge** | Live SVG + public verification page, only green while real controls are configured. |
| **Marketing site** | Public site with a live demo policy workspace and Founding Access capture. |

Docs: [API](docs/API.md) · [Security model](docs/SECURITY_MODEL.md) · [Badge](docs/BADGE.md) · [Operations](docs/OPERATIONS.md)

## Architecture

One Cloudflare Worker. No microservices, no other hosting platform.

```
                     ┌──────────────────────────── Worker: mother-ai ───────────────────────────┐
 agents / SDKs ──►   │ /v1/evaluate, /v1/mcp/evaluate, /v1/approvals/*   (API key)                │
 console (browser) ► │ /api/auth/*  (passkeys)    /api/console/*  (session, RBAC, CSRF)            │ ──► D1 mother-ai-prod
 public ──────────►  │ /api/demo/*  /api/founding-access   /badge/{t}.svg   /verify/{t}  /health   │
                     │ Workers Static Assets: marketing site (/) + console SPA (/app/*)            │
                     └────────────────────────────────────────────────────────────────────────────┘
                        Workers Rate Limiting bindings · cron */10 (approval expiry, session cleanup)
```

- **Cloudflare Workers** — runtime, gateway, API, security headers.
- **Workers Static Assets** — `dist/web` built by Vite (marketing: vanilla TS; console: React).
- **Cloudflare D1** (`mother-ai-prod`, binding `DB`) — canonical data. Schema changes only via committed `migrations/`.
- **KV** — intentionally not used in V1. The gateway loads key, organization, agent, policies and any prior decision in **one** D1 batch; a KV policy cache would add a staleness window to security decisions for little gain at current scale. It can be added later with D1 remaining canonical.
- **GitHub** — source of truth. **No GitHub Actions.** Deploys are direct Wrangler deploys from pushed `main`.

## Directory structure

```
src/
  worker.ts                 entry: routing, security headers, cron
  gateway/                  policy-engine.ts, normalize.ts, evaluate.ts, identity.ts, approvals.ts, audit.ts
  api/                      v1.ts (gateway routes), public.ts (demo, founding access, health), console/* (control plane)
  auth/                     passkeys.ts (WebAuthn + invites), sessions.ts, rbac.ts
  badge/                    status.ts (eligibility), svg.ts, verify-page.ts, routes.ts
  demo/workspace.ts         fixed public demo workspace
  lib/                      crypto, http, redact, db types, security headers, seo
web/
  index.html, src/marketing marketing site
  app/index.html, src/console control plane SPA
  src/styles/tokens.css     design tokens
  public/                   fonts, brand, icons, OG image, 404
migrations/                 D1 schema (committed, applied by deploy)
tests/                      unit (engine) + integration (Worker fetch handler over node:sqlite with real migrations)
scripts/
  deploy.mjs                production deploy from pushed main
  ops/                      create-org, invite (operator bootstrap)
  qa/                       software WebAuthn authenticator, production QA
docs/                       API, SECURITY_MODEL, BADGE, OPERATIONS
config/site.json            canonical origin + SEO metadata (single place for domain cutover)
wrangler.toml
```

## Local development

Requirements: Node ≥ 22 (tests use the built-in `node:sqlite`, Node 24 recommended), npm, Wrangler (dev dependency).

```bash
git checkout main && git pull --ff-only && git status
npm install

# local secrets (never committed)
printf 'ENVIRONMENT="development"\nFORM_SIGNING_KEY="dev-only-signing-key-change-me"\n' > .dev.vars

npm run db:migrate:local
npm run build
npx wrangler dev --port 8787            # http://localhost:8787

# create a local org + owner invite (open the printed URL, register a passkey)
node scripts/ops/create-org.mjs --slug acme-local --name "Acme, Inc." --owner "Local Owner" --local
```

Passkeys work on `http://localhost:8787` because `ENVIRONMENT` is not `production` locally.

## Migrations

```bash
npx wrangler d1 migrations create mother-ai-prod <name>   # add migrations/NNNN_<name>.sql, commit it
npm run db:migrate:local
```

Production migrations are applied by `npm run deploy` from the committed export. Never run ad-hoc schema changes against production.

## Testing

```bash
npm run typecheck     # worker, tests, web
npm test              # vitest: engine unit tests + integration tests
```

Integration tests run the real Worker `fetch` handler against an in-memory SQLite database created from `migrations/`, so triggers and constraints are exercised. Passkey flows use a software WebAuthn authenticator (`scripts/qa/authenticator.mjs`) that produces real ES256 attestations and assertions.

## Deployment

```bash
git checkout main && git pull --ff-only && git status
npm run deploy
```

`scripts/deploy.mjs`:

1. Requires `main` and `HEAD == origin/main` (commit and push first).
2. Exports `git archive HEAD` to `.deploy/<sha>/` — the working tree is never deployed.
3. Typechecks, runs tests, builds.
4. Applies pending committed D1 migrations (`--remote`).
5. `wrangler deploy --var GIT_SHA:<sha>`.
6. Verifies `GET /health` reports that commit.

Production must always correspond to committed, pushed `main`.

## Production verification

```bash
curl -s https://mother.proptechusa.ai/health   # status, version, commit, policy_engine, d1
curl -s https://mother.proptechusa.ai/ready    # d1, schema, form_signing, turnstile
node scripts/qa/verify-prod.mjs                           # gateway/console/badge proof against production
```

See [docs/OPERATIONS.md](docs/OPERATIONS.md) for onboarding, key recovery, badge revocation and custom-domain cutover.

## Security model

Summary (full: [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)):

- Deterministic, auditable policy enforcement; fails closed on invalid keys, disabled orgs, unknown agents, malformed policies, engine errors and evidence-write failures.
- API keys, sessions and invites are high-entropy random tokens stored as SHA-256 digests; raw keys shown once.
- Passkey-only console authentication, `__Host-` SameSite=Strict sessions, Origin + Fetch-Metadata CSRF checks, server-side RBAC.
- Tenant isolation derived only from the authenticated principal; tested.
- Append-oriented evidence (UPDATE/DELETE blocked by triggers). Tamper-resistant — not claimed immutable.
- Credential redaction in stored context; no stack traces to callers; strict CSP and security headers; no CORS.

## Status

Mother AI is in **Founding Access**. The gateway, policy engine, approvals, audit and badge are live. Transparent MCP proxying, SSO/SCIM, SIEM export and signed audit exports are not built yet and are not advertised as available.
