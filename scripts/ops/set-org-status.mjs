#!/usr/bin/env node
// Administratively change an organization's status and record it as a control event.
//
//   node scripts/ops/set-org-status.mjs --slug acme --status suspended|active|revoked --reason "..." --local|--remote

import { d1, newId, now, parseArgs, query, sql } from "./lib.mjs";

const args = parseArgs(process.argv.slice(2));
const remote = !!args.remote;
if (!remote && !args.local) {
  console.error("Specify --local or --remote.");
  process.exit(2);
}
if (!args.slug || !["active", "suspended", "revoked"].includes(args.status) || !args.reason || args.reason === true) {
  console.error('Usage: --slug <slug> --status active|suspended|revoked --reason "<why>"');
  process.exit(2);
}
const [org] = query(`SELECT id, status FROM organizations WHERE slug = ${sql(args.slug)}`, { remote });
if (!org) {
  console.error(`No organization with slug ${args.slug}`);
  process.exit(1);
}
const ts = now();
const statements = [
  `UPDATE organizations SET status = ${sql(args.status)}, updated_at = ${sql(ts)} WHERE id = ${sql(org.id)}`,
  `INSERT INTO control_events (id, organization_id, actor_type, actor_label, action, target_type, target_id, detail, created_at) VALUES (${sql(newId("evt"))}, ${sql(org.id)}, 'ops', 'Mother AI operator', 'organization.status_changed', 'organization', ${sql(org.id)}, ${sql(JSON.stringify({ from: org.status, to: args.status, reason: args.reason }))}, ${sql(ts)})`,
];
if (args.status === "revoked") {
  statements.push(`UPDATE sessions SET revoked_at = ${sql(ts)} WHERE organization_id = ${sql(org.id)} AND revoked_at IS NULL`);
}
d1(statements, { remote });
console.log(JSON.stringify({ organization_id: org.id, from: org.status, to: args.status }, null, 2));
