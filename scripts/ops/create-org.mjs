#!/usr/bin/env node
// Provision an organization and a single-use owner invite.
//
//   node scripts/ops/create-org.mjs --slug acme --name "Acme, Inc." --owner "Jane Doe" [--email jane@acme.com] [--kind internal] --local|--remote
//
// Prints the invite URL once. The invite token travels in the URL fragment and
// only its SHA-256 is stored. The owner registers a passkey when they open it.

import { SITE, d1, newId, now, originFor, parseArgs, sha256, sql, token } from "./lib.mjs";

const args = parseArgs(process.argv.slice(2));
const remote = !!args.remote;
if (!remote && !args.local) {
  console.error("Specify --local or --remote.");
  process.exit(2);
}
for (const required of ["slug", "name", "owner"]) {
  if (!args[required] || args[required] === true) {
    console.error(`Missing --${required}`);
    process.exit(2);
  }
}
if (!/^[a-z0-9][a-z0-9-]{1,62}$/.test(args.slug)) {
  console.error("--slug must be lowercase letters, numbers and dashes");
  process.exit(2);
}
const kind = args.kind === "internal" ? "internal" : "customer";
const plan = kind === "internal" ? "internal" : "founding";

const orgId = newId("org");
const inviteId = newId("inv");
const inviteToken = token();
const ts = now();
const expires = new Date(Date.now() + 72 * 3600 * 1000).toISOString();

d1(
  [
    `INSERT INTO organizations (id, slug, display_name, kind, plan, created_at, updated_at) VALUES (${sql(orgId)}, ${sql(args.slug)}, ${sql(args.name)}, ${sql(kind)}, ${sql(plan)}, ${sql(ts)}, ${sql(ts)})`,
    `INSERT INTO invites (id, organization_id, token_hash, role, display_name, email, created_by, created_at, expires_at) VALUES (${sql(inviteId)}, ${sql(orgId)}, ${sql(sha256(inviteToken))}, 'owner', ${sql(args.owner)}, ${sql(args.email && args.email !== true ? args.email : null)}, 'ops', ${sql(ts)}, ${sql(expires)})`,
    `INSERT INTO control_events (id, organization_id, actor_type, actor_label, action, target_type, target_id, detail, created_at) VALUES (${sql(newId("evt"))}, ${sql(orgId)}, 'ops', 'Mother AI operator', 'organization.created', 'organization', ${sql(orgId)}, ${sql(JSON.stringify({ kind, owner_invite: inviteId }))}, ${sql(ts)})`,
  ],
  { remote },
);

console.log(JSON.stringify({ organization_id: orgId, slug: args.slug, kind, invite_id: inviteId, invite_expires_at: expires, invite_url: `${originFor(remote)}/app/accept-invite#token=${inviteToken}`, site: SITE.origin }, null, 2));
