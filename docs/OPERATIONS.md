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
| Rate limiting | `RL_*` (namespaces 4101–4107) | Abuse controls |
| Cron | `*/10 * * * *` | Approval expiry sweep, session/challenge cleanup |
| Secret | `FORM_SIGNING_KEY` | Founding Access form tokens and IP-hash salt |
| Secret | `SLACK_LEADS_WEBHOOK_URL` | Slack Incoming Webhook for `#leads` (new Founding Access leads) |
| UI host | `mother.proptechusa.ai` | Public UI on Vercel (DNS-only CNAME `78326c855bbef250.vercel-dns-016.com`) and WebAuthn RP ID |
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

## Founding Access lead notifications (Slack)

New leads (a new `founding_access_requests` row) post to Slack `#leads` from the Worker in the background. Honeypot, duplicate-within-24h, invalid and rate-limited submissions never notify. If Slack fails, the lead stays saved, the visitor still sees success, and the Worker logs `slack lead notification failed` with the lead id and status (never the webhook URL).

Set or rotate the webhook (paste it only into Wrangler's prompt):

```bash
npx wrangler secret put SLACK_LEADS_WEBHOOK_URL --name mother-ai
```

The booking link shown after submission and in Slack is `bookingUrl` in `config/site.json` (https://calendly.com/proptechusa/new-meeting-1).

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

## UI cutover to Vercel (one-time)

Pre-conditions: Vercel project `mother` has `mother.proptechusa.ai` attached (`verified: true`); `api.mother.proptechusa.ai` is live on the Worker; browser + API QA pass with the Worker still serving the UI.

1. `node scripts/ops/ui-cutover.mjs status` (read-only).
2. `node scripts/ops/ui-cutover.mjs release` — deletes the Worker Custom Domain and host routes for `mother.proptechusa.ai`. Cloudflare removes the Worker-managed DNS record; the UI is offline until step 3.
3. Cloudflare DNS (zone `proptechusa.ai`): `CNAME mother → 78326c855bbef250.vercel-dns-016.com`, **Proxy status: DNS only**, TTL Auto.
4. Remove the `mother.proptechusa.ai` routes from `wrangler.toml`, commit, push, `npm run deploy` (so a later deploy never re-attaches the UI host to the Worker).
5. Production QA on `https://mother.proptechusa.ai` (served by Vercel: `x-vercel-id` header).

Rollback: delete the `mother` CNAME, then `node scripts/ops/ui-cutover.mjs rollback` (re-attaches the Custom Domain and host routes; the Worker still contains the UI build until it is made API-only). Vercel keeps the domain attached harmlessly.

## Rollback

```bash
npx wrangler deployments list
npx wrangler rollback <version-id>
```

A rollback does not revert D1 migrations. Migrations must stay backward compatible with the previous Worker version for this reason. After any rollback, fix forward on `main` and redeploy so production again matches `main`.
