// Evidence writers. Decisions and control events are INSERT-only; the schema
// rejects UPDATE/DELETE with triggers.

import { newId } from "../lib/crypto";
import { redactValue } from "../lib/redact";

export type ActorType = "user" | "api_key" | "system" | "ops";

export interface Actor {
  type: ActorType;
  id: string | null;
  label: string | null;
}

export const SYSTEM_ACTOR: Actor = { type: "system", id: null, label: "Mother AI" };

const DETAIL_MAX_BYTES = 8 * 1024;

export function controlEventStatement(
  db: D1Database,
  organizationId: string,
  actor: Actor,
  action: string,
  target: { type: string; id: string } | null,
  detail: Record<string, unknown>,
  now: string,
  opts: { onlyIfChanged?: boolean } = {},
): D1PreparedStatement {
  let serialized = JSON.stringify(redactValue(detail));
  if (serialized.length > DETAIL_MAX_BYTES) serialized = JSON.stringify({ truncated: true });
  const columns =
    "(id, organization_id, actor_type, actor_id, actor_label, action, target_type, target_id, detail, created_at)";
  const values = [newId("evt"), organizationId, actor.type, actor.id, actor.label, action, target?.type ?? null, target?.id ?? null, serialized, now];
  if (opts.onlyIfChanged) {
    // Emits the event only when the immediately preceding statement in the batch changed a row.
    return db
      .prepare(`INSERT INTO control_events ${columns} SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE changes() = 1`)
      .bind(...values);
  }
  return db.prepare(`INSERT INTO control_events ${columns} VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(...values);
}
