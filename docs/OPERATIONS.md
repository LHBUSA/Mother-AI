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
| Secret (optional) | `TURNSTILE_SECRET_KEY` + var `TURNSTILE_SITE_KEY` | Turnstile on Founding Access |

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

The current Wrangler OAuth token lacks the Turnstile scope, so no widget exists yet. To enable:

1. Cloudflare dashboard → Turnstile → add a widget for the production hostname (managed mode).
2. Put the site key in `wrangler.toml` `[vars] TURNSTILE_SITE_KEY`, commit, push.
3. `npx wrangler secret put TURNSTILE_SECRET_KEY`
4. `npm run deploy`. The form loads the widget automatically and the server enforces it; `/ready` reports `turnstile: true`.

## Custom domain cutover

1. Attach the domain to the `mother-ai` Worker (Custom Domains) in Cloudflare.
2. Change `origin` in `config/site.json` (canonical, OG, sitemap, robots, badge/verify URLs and the WebAuthn relying-party origin all derive from it). Commit, push, `npm run deploy`.
3. Passkeys are bound to a hostname. Existing users must register a new passkey on the new domain: issue invites with `scripts/ops/invite.mjs`.
4. Customers' badge embeds contain the old origin. Keep the workers.dev hostname serving (it does by default) or ask customers to update snippets.

## Rollback

```bash
npx wrangler deployments list
npx wrangler rollback <version-id>
```

A rollback does not revert D1 migrations. Migrations must stay backward compatible with the previous Worker version for this reason. After any rollback, fix forward on `main` and redeploy so production again matches `main`.
