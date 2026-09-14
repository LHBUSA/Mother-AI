// Idempotent replay inside a contained scope (enforce mode). The original append-only decision is
// never modified; the replay answers BLOCK and appends runtime.replay_blocked evidence.

import type { Env } from "../env";
import { json } from "../lib/http";
import { iso } from "../lib/time";
import type { DecisionRow } from "../lib/db";
import { RISK_ENGINE_VERSION, isContained } from "./engine";
import { lineageStatement, runtimeEventStatement, subjectKey, subjectsStatement, snapshotFrom, worstSubject, type SessionRow } from "./store";

export async function replayContainment(
  env: Env,
  organizationId: string,
  apiKeyId: string,
  existing: DecisionRow & { session_id: string | null },
  nowMs: number,
): Promise<Response | null> {
  const db = env.DB;
  let chain: SessionRow[] = [];
  if (existing.session_id) {
    const [rows] = await db.batch([lineageStatement(db, existing.session_id, organizationId)]);
    chain = (rows!.results as unknown as SessionRow[]).filter((s) => s.organization_id === organizationId);
  }
  const agentIds = [...new Set([...(existing.agent_id ? [existing.agent_id] : []), ...chain.map((s) => s.agent_id)])];
  const [subjects] = await db.batch([subjectsStatement(db, organizationId, agentIds, chain.map((s) => s.id), null)]);
  const snapshot = snapshotFrom(subjects!.results as never, []);
  const keys = [...agentIds.map((id) => subjectKey("agent", id)), ...chain.map((s) => subjectKey("session", s.id))];
  const worst = worstSubject(snapshot, keys);
  if (!isContained(worst.state)) return null;

  const reasonCode = worst.key?.startsWith("session:") ? "SESSION_QUARANTINED" : "AGENT_QUARANTINED";
  const incidentId = worst.row?.incident_id ?? null;
  const nowIso = iso(nowMs);
  try {
    await db.batch([
      runtimeEventStatement(db, {
        organizationId,
        type: "runtime.replay_blocked",
        source: "mother",
        outcome: "refused",
        reasonCode,
        sessionId: existing.session_id,
        agentId: existing.agent_id,
        apiKeyId,
        decisionId: existing.id,
        requestId: existing.request_id,
        incidentId,
        detail: { original_decision: existing.decision, original_reason_code: existing.reason_code, original_evaluated_at: existing.created_at, subject: worst.key },
        nowIso,
      }),
    ]);
  } catch (err) {
    // Fail closed either way: the replay is refused even if its evidence could not be written.
    console.error("replay_blocked evidence write failed", err instanceof Error ? err.name : "unknown");
  }
  return json(
    {
      decision_id: existing.id,
      request_id: existing.request_id,
      decision: "block",
      reason_code: reasonCode,
      reason: "This request_id was evaluated before its scope was quarantined. A stale decision is not an authorization token; the action is blocked.",
      original_decision: existing.decision,
      policy_id: existing.policy_id,
      policy_version: existing.policy_version,
      agent_id: existing.agent_key,
      engine_version: existing.engine_version,
      evaluated_at: existing.created_at,
      replayed: true,
      session_id: existing.session_id,
      risk: { mode: "enforce", engine_version: RISK_ENGINE_VERSION, state: worst.state, runtime_risk_decision: "block", effective_decision: "block", incident_id: incidentId },
    },
    200,
    { "Idempotent-Replayed": "true" },
  );
}
