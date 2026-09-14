#!/usr/bin/env node
// Founding Access request administration.
//
//   node scripts/ops/founding-access.mjs list --remote
//   node scripts/ops/founding-access.mjs set-status --id fa_… --status contacted|onboarded|declined|spam --remote
//   node scripts/ops/founding-access.mjs purge-internal-qa --remote
//
// founding_access_requests is lead data, not decision evidence: it has no append-only
// trigger. purge-internal-qa deletes only rows that are unambiguously Mother AI's own QA
// submissions (company ends with "(internal)" AND a qa+ address on the operator domain).

import { d1, parseArgs, query, sql } from "./lib.mjs";

const [command] = process.argv.slice(2);
const args = parseArgs(process.argv.slice(3));
const remote = !!args.remote;
if (!remote && !args.local) {
  console.error("Specify --local or --remote.");
  process.exit(2);
}

const QA_FILTER = `company LIKE '%(internal)' AND work_email LIKE 'qa+%@localhomebuyersusa.com'`;

if (command === "list") {
  console.table(query(`SELECT id, created_at, company, work_email, agent_count, uses_mcp, status FROM founding_access_requests ORDER BY created_at DESC LIMIT 100`, { remote }));
} else if (command === "set-status") {
  if (!/^fa_[0-9A-Za-z]{22}$/.test(args.id ?? "") || !["new", "contacted", "onboarded", "declined", "spam"].includes(args.status)) {
    console.error("Usage: set-status --id fa_… --status new|contacted|onboarded|declined|spam");
    process.exit(2);
  }
  const [res] = d1([`UPDATE founding_access_requests SET status = ${sql(args.status)} WHERE id = ${sql(args.id)}`], { remote });
  console.log(JSON.stringify({ id: args.id, status: args.status, changes: res?.meta?.changes ?? null }));
} else if (command === "purge-internal-qa") {
  const rows = query(`SELECT id, created_at, company, work_email FROM founding_access_requests WHERE ${QA_FILTER}`, { remote });
  if (!rows.length) {
    console.log("No internal QA rows.");
  } else {
    const [res] = d1([`DELETE FROM founding_access_requests WHERE ${QA_FILTER}`], { remote });
    console.log(JSON.stringify({ deleted: res?.meta?.changes ?? rows.length, rows }, null, 2));
  }
} else {
  console.error("usage: founding-access.mjs list|set-status|purge-internal-qa --local|--remote");
  process.exit(2);
}
