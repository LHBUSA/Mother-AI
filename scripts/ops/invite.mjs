#!/usr/bin/env node
// Issue a new single-use invite for an existing organization (e.g. to recover owner access).
//
//   node scripts/ops/invite.mjs --slug acme --name "Jane Doe" [--role owner] [--email jane@acme.com] --local|--remote

import { d1, newId, now, originFor, parseArgs, query, sha256, sql, token } from "./lib.mjs";

const args = parseArgs(process.argv.slice(2));
const remote = !!args.remote;
if (!remote && !args.local) {
  console.error("Specify --local or --remote.");
  process.exit(2);
}
if (!args.slug || !args.name) {
  console.error("Missing --slug or --name");
  process.exit(2);
}
const role = args.role && args.role !== true ? args.role : "owner";
if (!["owner", "admin", "security", "approver", "viewer"].includes(role)) {
  console.error("Invalid --role");
  process.exit(2);
}
const [org] = query(`SELECT id FROM organizations WHERE slug = ${sql(args.slug)}`, { remote });
if (!org) {
  console.error(`No organization with slug ${args.slug}`);
  process.exit(1);
}
const inviteId = newId("inv");
const inviteToken = token();
const ts = now();
const expires = new Date(Date.now() + 72 * 3600 * 1000).toISOString();
d1(
  [
    `INSERT INTO invites (id, organization_id, token_hash, role, display_name, email, created_by, created_at, expires_at) VALUES (${sql(inviteId)}, ${sql(org.id)}, ${sql(sha256(inviteToken))}, ${sql(role)}, ${sql(args.name)}, ${sql(args.email && args.email !== true ? args.email : null)}, 'ops', ${sql(ts)}, ${sql(expires)})`,
    `INSERT INTO control_events (id, organization_id, actor_type, actor_label, action, target_type, target_id, detail, created_at) VALUES (${sql(newId("evt"))}, ${sql(org.id)}, 'ops', 'Mother AI operator', 'member.invited', 'invite', ${sql(inviteId)}, ${sql(JSON.stringify({ role, display_name: args.name }))}, ${sql(ts)})`,
  ],
  { remote },
);
console.log(JSON.stringify({ invite_id: inviteId, role, expires_at: expires, invite_url: `${originFor(remote)}/app/accept-invite#token=${inviteToken}` }, null, 2));
