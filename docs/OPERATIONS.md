# Operations

All operator actions run locally from a clean `main` checkout with Wrangler authenticated to the Mother AI Cloudflare account.

```bash
git checkout main && git pull --ff-only && git status
```

## Resources

| Resource | Name / binding | Purpose |
|---|---|---|
| Worker | `mother-ai` | Entire product (gateway, console, APIs, assets, badge) |
| D1 | `mother-ai-prod` → `DB` | Canonical data |
| Static assets | `dist/web` → `ASSETS` | Marketing site + console SPA |
| Rate limiting | `RL_*` (namespaces 4101–4107) | Abuse controls |
| Cron | `*/10 * * * *` | Approval expiry sweep, session/challenge cleanup |
| Secret | `FORM_SIGNING_KEY` | Founding Access form tokens |
| Secrets (optional) | `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_KEY` | Turnstile on Founding Access (enforced only when both are set) |
| Custom domain | `mother.proptechusa.ai` (zone `proptechusa.ai`) | Canonical public host |
| Fallback host | `mother-ai.sales-fd3.workers.dev` | Gateway/API/badge traffic; human pages 308 to canonical |

## Onboard an organization

```bash
node scripts/ops/create-org.mjs --slug acme --name "Acme, Inc." --owner "Jane Doe" --email jane@acme.com --remote
```

Send the printed `invite_url` to the owner over a trusted channel. It is single-use and expires in 72 hours. The owner registers a passkey, then invites teammates from **Settings → Members**.

Use `--kind internal` for Mother AI's own QA/demo organizations so they are distinguishable from customers.

## Recover access (lost passkey)

```bash
node scripts/ops/invite.mjs --slug acme --name "Jane Doe" --role owner --remote
```

Creates a new user identity with the given role. Disable the old membership from the console afterwards.

## Founding Access requests

```bash
npx wrangler d1 execute mother-ai-prod --remote --command "SELECT created_at, name, company, work_email, agent_count, uses_mcp, use_case FROM founding_access_requests ORDER BY created_at DESC LIMIT 50"
```

## Suspend or revoke an organization

Suspension immediately blocks gateway keys (`ORGANIZATION_DISABLED`), blocks console changes and turns the badge `suspended`. Revocation also ends console access and turns the badge `revoked`.

```bash
node scripts/ops/set-org-status.mjs --slug acme --status suspended --reason "Non-payment" --remote
node scripts/ops/set-org-status.mjs --slug acme --status active --reason "Resolved" --remote
node scripts/ops/set-org-status.mjs --slug acme --status revoked --reason "Contract terminated" --remote
```

The change and reason are appended to the organization's control events. Revocation also ends all console sessions.

## Turnstile

The Wrangler OAuth token has no Turnstile (challenge widgets) permission, so the widget is created in the dashboard:

1. Cloudflare dashboard → account `Sales@localhomebuyersusa.com's Account` → **Turnstile** → **Add widget**.
2. Widget name `Mother AI Founding Access`; **Hostname management** → add `mother.proptechusa.ai`; **Widget mode** → **Managed**; pre-clearance **No**. Create.
3. Store both values as Worker secrets (you will be prompted; nothing touches Git):

   ```bash
   npx wrangler secret put TURNSTILE_SITE_KEY
   npx wrangler secret put TURNSTILE_SECRET_KEY
   ```

4. `curl https://mother.proptechusa.ai/ready` reports `"turnstile":"enforced"`. With only one key set it reports `misconfigured` and Founding Access fails closed.

Server-side verification rejects missing, invalid, expired and already-redeemed tokens, and tokens whose `hostname` is not the canonical host. If siteverify is unreachable the submission fails closed (503).

## Custom domain

`mother.proptechusa.ai` is a Workers Custom Domain on the `mother-ai` Worker, declared in `wrangler.toml` (`routes`, `custom_domain = true`); `wrangler deploy` manages its DNS record and certificate.

- `config/site.json` `origin` is the single source for canonical/OG URLs, sitemap/robots, badge and verify URLs, invite URLs and the WebAuthn relying party.
- `fallbackOrigins` (workers.dev) keeps serving `/v1/*`, `/api/*`, `/badge/*.svg`, `/health`; `/`, `/app/*` and `/verify/*` redirect (308) to the canonical host; robots.txt disallows everything there.
- Passkeys are hostname-bound: sign-in works only on the canonical host. Moving hosts again requires new passkeys (issue invites with `scripts/ops/invite.mjs`).
- Deploys verify `/health` on the canonical host and every fallback host.

## Rollback

```bash
npx wrangler deployments list
npx wrangler rollback <version-id>
```

A rollback does not revert D1 migrations. Migrations must stay backward compatible with the previous Worker version for this reason. After any rollback, fix forward on `main` and redeploy so production again matches `main`.
