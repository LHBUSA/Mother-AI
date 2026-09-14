# Operations

All operator actions run locally from a clean `main` checkout with Wrangler authenticated to the Mother AI Cloudflare account.

```bash
git checkout main && git pull --ff-only && git status
```

## Resources

| Resource | Name / binding | Purpose |
|---|---|---|
| Vercel project | `mother` (`prj_X2FC6nkIrBzxyZz1I1C8BKtCv9J9`), Git-linked to `LHBUSA/Mother-AI` | Public UI: marketing, console SPA, `/verify`, robots/sitemap (`vercel.json`, output `dist/web`) |
| Worker | `mother-ai` | Gateway, auth, control-plane API, public browser APIs, badge SVGs, cron |
| API host | `api.mother.proptechusa.ai` (Workers Custom Domain) | Browser and server API traffic |
| D1 | `mother-ai-prod` → `DB` | Canonical data |
| Static assets (Worker) | `dist/web` → `ASSETS` | Serves the UI on `mother.proptechusa.ai` only until the Vercel DNS cutover |
| Rate limiting | `RL_*` (namespaces 4101–4107) | Abuse controls |
| Cron | `*/10 * * * *` | Approval expiry sweep, session/challenge cleanup |
| Secret | `FORM_SIGNING_KEY` | Founding Access form tokens |
| UI host | `mother.proptechusa.ai` | Public UI (Vercel after cutover) and WebAuthn RP ID |
| Fallback host | `mother-ai.sales-fd3.workers.dev` | Operational API fallback; human pages 308 to the UI host |

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

## Hosting topology

- `config/site.json` is the only place hosts live: `origin` (UI, WebAuthn RP), `apiOrigin` (Worker), `fallbackOrigins`.
- UI builds (`npm run build` → `dist/web`) are deployed by Vercel from `main`. The Worker is deployed with `npm run deploy` from pushed `main`. Ship backward-compatible Worker changes before UI changes that depend on them.
- The zone `proptechusa.ai` has wildcard Worker routes for other products (`*proptechusa.ai/sitemap.xml`, `/site-map`, `/news/*`). Mother hosts served by the Worker are pinned with host routes in `wrangler.toml`. The Vercel UI record must be **DNS-only** so zone routes and Web Analytics injection never apply to it.
- No Turnstile or other CAPTCHA is used.

## Rollback

```bash
npx wrangler deployments list
npx wrangler rollback <version-id>
```

A rollback does not revert D1 migrations. Migrations must stay backward compatible with the previous Worker version for this reason. After any rollback, fix forward on `main` and redeploy so production again matches `main`.
