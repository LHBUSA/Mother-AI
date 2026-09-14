// QUARANTINE AGENT/SESSION as one atomic D1 batch, containment verification, and human clearance.
//
// The quarantine batch, all or nothing:
//   1. subject -> quarantined, new containment epoch, incident id (only if not already contained)
//   2. transition + incident + members (subject, triggering decision and signals)
//   3. scope sessions (the agent's live sessions, or the session) and all descendants; child agents
//   4. revoke every live capability lease in scope
//   5. cancel every pending approval in scope as the system (never a human denial) + control events
//   6. record approved-but-unused grants in scope as invalidated (the epoch makes them unusable forever)
//   7. runtime event, control event, alert queue
// Every statement after step 1 is guarded by the subject carrying this incident id, so a concurrent
// second quarantine attempt changes nothing.

import { newId } from "../lib/crypto";
import { RISK_ENGINE_VERSION, type RiskState, type SubjectType } from "./engine";
import { EPOCH_START, alertQueueStatement, transitionIfChangedStatement, transitionStatement } from "./store";

export interface QuarantineInput {
  organizationId: string;
  subjectType: "agent" | "session";
  subjectId: string;
  fromState: RiskState;
  score: number;
  cause: "score_quarantine" | "hard_signal_quarantine" | "manual_quarantine";
  actor: { type: "system" | "user"; id: string | null; label: string };
  reason: string;
  decisionId: string | null;
  signalIds: string[];
  nowMs: number;
}

export interface QuarantinePlan {
  incidentId: string;
  transitionId: string;
  statements: D1PreparedStatement[];
}

const SCOPE_CTE = `WITH RECURSIVE scope(id, agent_id, n) AS (
    SELECT id, agent_id, 0 FROM agent_sessions
     WHERE organization_id = ?1
       AND ((?2 = 'agent' AND agent_id = ?3 AND expires_at > ?5) OR (?2 = 'session' AND id = ?3))
    UNION ALL
    SELECT s.id, s.agent_id, scope.n + 1 FROM agent_sessions s JOIN scope ON s.parent_session_id = scope.id
     WHERE s.organization_id = ?1 AND scope.n < 8)`;

/** ?1 org, ?2 subject type, ?3 subject id, ?4 incident id, ?5 now */
const GUARD = `EXISTS (SELECT 1 FROM risk_subjects g WHERE g.organization_id = ?1 AND g.subject_type = ?2 AND g.subject_id = ?3
                         AND g.incident_id = ?4 AND g.state IN ('quarantined', 'contained'))`;

const IN_SCOPE_DECISION = `(d.session_id IN (SELECT id FROM scope) OR (?2 = 'agent' AND d.agent_id = ?3))`;

/** Scope statements that are safe to repeat (verification re-runs them). */
function scopeEnforcementStatements(db: D1Database, orgId: string, type: SubjectType, subjectId: string, incidentId: string, nowIso: string): D1PreparedStatement[] {
  const b = (sql: string) => db.prepare(sql).bind(orgId, type, subjectId, incidentId, nowIso);
  return [
    b(`${SCOPE_CTE}
       INSERT OR IGNORE INTO incident_members (incident_id, organization_id, member_type, member_id, relation, created_at)
       SELECT ?4, ?1, 'session', id, 'scope_session', ?5 FROM scope WHERE ${GUARD}`),
    b(`${SCOPE_CTE}
       INSERT OR IGNORE INTO incident_members (incident_id, organization_id, member_type, member_id, relation, created_at)
       SELECT DISTINCT ?4, ?1, 'agent', agent_id, 'child_agent', ?5 FROM scope
        WHERE agent_id <> CASE WHEN ?2 = 'agent' THEN ?3 ELSE (SELECT agent_id FROM agent_sessions WHERE id = ?3 AND organization_id = ?1) END
          AND ${GUARD}`),
    b(`${SCOPE_CTE}
       INSERT OR IGNORE INTO incident_members (incident_id, organization_id, member_type, member_id, relation, created_at)
       SELECT ?4, ?1, 'lease', l.id, 'revoked_lease', ?5 FROM capability_leases l
        WHERE l.organization_id = ?1 AND l.revoked_at IS NULL AND l.expires_at > ?5
          AND (l.session_id IN (SELECT id FROM scope) OR (?2 = 'agent' AND l.agent_id = ?3)) AND ${GUARD}`),
    b(`${SCOPE_CTE}
       UPDATE capability_leases SET revoked_at = ?5, revoked_reason = 'QUARANTINE ' || ?4
        WHERE organization_id = ?1 AND revoked_at IS NULL AND expires_at > ?5
          AND (session_id IN (SELECT id FROM scope) OR (?2 = 'agent' AND agent_id = ?3)) AND ${GUARD}`),
    b(`${SCOPE_CTE}
       INSERT OR IGNORE INTO incident_members (incident_id, organization_id, member_type, member_id, relation, created_at)
       SELECT ?4, ?1, 'approval', ap.id, 'cancelled_approval', ?5
         FROM approvals ap JOIN decisions d ON d.id = ap.decision_id AND d.organization_id = ap.organization_id
        WHERE ap.organization_id = ?1 AND ap.status = 'pending' AND ${IN_SCOPE_DECISION} AND ${GUARD}`),
    b(`INSERT INTO control_events (id, organization_id, actor_type, actor_id, actor_label, action, target_type, target_id, detail, created_at)
       SELECT 'evt_' || lower(hex(randomblob(11))), ?1, 'system', NULL, 'Mother AI containment', 'approval.cancelled_by_quarantine',
              'approval', ap.id, json_object('incident_id', ?4, 'decision_id', ap.decision_id, 'reason', 'quarantine', 'subject', ?2 || ':' || ?3), ?5
         FROM approvals ap
        WHERE ap.organization_id = ?1 AND ap.status = 'pending'
          AND ap.id IN (SELECT member_id FROM incident_members WHERE incident_id = ?4 AND member_type = 'approval' AND relation = 'cancelled_approval')
          AND ${GUARD}`),
    b(`UPDATE approvals
          SET status = 'denied', acted_at = ?5, acted_by = NULL, acted_by_name = 'Mother AI containment',
              note = 'Cancelled by quarantine (' || ?4 || '). Not a human decision.',
              terminated_reason = 'quarantine', terminated_incident_id = ?4
        WHERE organization_id = ?1 AND status = 'pending'
          AND id IN (SELECT member_id FROM incident_members WHERE incident_id = ?4 AND member_type = 'approval' AND relation = 'cancelled_approval')
          AND ${GUARD}`),
    b(`${SCOPE_CTE}
       INSERT OR IGNORE INTO incident_members (incident_id, organization_id, member_type, member_id, relation, created_at)
       SELECT ?4, ?1, 'approval', ap.id, 'invalidated_grant', ?5
         FROM approvals ap JOIN decisions d ON d.id = ap.decision_id AND d.organization_id = ap.organization_id
        WHERE ap.organization_id = ?1 AND ap.status = 'approved' AND ap.consumed_at IS NULL
          AND ${IN_SCOPE_DECISION} AND ${GUARD}`),
  ];
}

export function quarantineStatements(db: D1Database, q: QuarantineInput): QuarantinePlan {
  const incidentId = newId("inc");
  const transitionId = newId("rtr");
  const nowIso = new Date(q.nowMs).toISOString();
  const severity = q.cause === "hard_signal_quarantine" ? "critical" : "high";
  const g = (sql: string, ...extra: unknown[]) => db.prepare(sql).bind(q.organizationId, q.subjectType, q.subjectId, incidentId, nowIso, ...extra);

  const statements: D1PreparedStatement[] = [
    db
      .prepare(
        `INSERT INTO risk_subjects (organization_id, subject_type, subject_id, state, score, state_since, signals_since,
                                    containment_epoch_at, incident_id, version, updated_at)
         VALUES (?1, ?2, ?3, 'quarantined', ?6, ?5, ?7, ?5, ?4, 1, ?5)
         ON CONFLICT (subject_type, subject_id) DO UPDATE SET
           state = 'quarantined', score = excluded.score, state_since = excluded.state_since,
           containment_epoch_at = excluded.containment_epoch_at, incident_id = excluded.incident_id,
           version = risk_subjects.version + 1, updated_at = excluded.updated_at
         WHERE risk_subjects.organization_id = excluded.organization_id
           AND risk_subjects.state NOT IN ('quarantined', 'contained')`,
      )
      .bind(q.organizationId, q.subjectType, q.subjectId, incidentId, nowIso, q.score, EPOCH_START),
    transitionStatement(
      db,
      {
        id: transitionId,
        organizationId: q.organizationId,
        subjectType: q.subjectType,
        subjectId: q.subjectId,
        from: q.fromState,
        to: "quarantined",
        score: q.score,
        cause: q.cause,
        actor: q.actor,
        incidentId,
        decisionId: q.decisionId,
        note: q.reason.slice(0, 500),
        nowIso,
      },
      { state: "quarantined", incidentId },
    ),
    g(
      `INSERT INTO security_incidents (id, organization_id, subject_type, subject_id, kind, status, severity, cause, opened_by_type, opened_by,
                                       opened_by_name, opened_reason, rule_version, triggering_decision_id, score, opened_at)
       SELECT ?4, ?1, ?2, ?3, 'quarantine', 'open', ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?5 WHERE ${GUARD}`,
      severity,
      q.cause,
      q.actor.type === "user" ? "user" : "risk_engine",
      q.actor.id,
      q.actor.label,
      q.reason.slice(0, 500),
      RISK_ENGINE_VERSION,
      q.decisionId,
      q.score,
    ),
    g(
      `INSERT OR IGNORE INTO incident_members (incident_id, organization_id, member_type, member_id, relation, created_at)
       SELECT ?4, ?1, ?2, ?3, 'subject', ?5 WHERE ${GUARD}`,
    ),
    ...(q.decisionId
      ? [
          g(
            `INSERT OR IGNORE INTO incident_members (incident_id, organization_id, member_type, member_id, relation, created_at)
             SELECT ?4, ?1, 'decision', ?6, 'triggering_decision', ?5 WHERE ${GUARD}`,
            q.decisionId,
          ),
        ]
      : []),
    ...q.signalIds.map((id) =>
      g(
        `INSERT OR IGNORE INTO incident_members (incident_id, organization_id, member_type, member_id, relation, created_at)
         SELECT ?4, ?1, 'signal', ?6, 'triggering_signal', ?5 WHERE ${GUARD}`,
        id,
      ),
    ),
    ...scopeEnforcementStatements(db, q.organizationId, q.subjectType, q.subjectId, incidentId, nowIso),
    g(
      `INSERT INTO runtime_events (id, organization_id, type, source, outcome, reason_code, session_id, agent_id, decision_id, incident_id, detail, created_at)
       SELECT ?6, ?1, 'quarantine.enforced', 'mother', NULL, ?7, CASE WHEN ?2 = 'session' THEN ?3 END, CASE WHEN ?2 = 'agent' THEN ?3 END,
              ?8, ?4, json_object('cause', ?9, 'score', ?10), ?5
        WHERE ${GUARD}`,
      newId("rte"),
      q.subjectType === "agent" ? "AGENT_QUARANTINED" : "SESSION_QUARANTINED",
      q.decisionId,
      q.cause,
      q.score,
    ),
    g(
      `INSERT INTO control_events (id, organization_id, actor_type, actor_id, actor_label, action, target_type, target_id, detail, created_at)
       SELECT ?6, ?1, ?7, ?8, ?9, 'security.quarantined', ?2, ?3, json_object('incident_id', ?4, 'cause', ?10, 'score', ?11, 'reason', ?12), ?5
        WHERE ${GUARD}`,
      newId("evt"),
      q.actor.type,
      q.actor.id,
      q.actor.label,
      q.cause,
      q.score,
      q.reason.slice(0, 500),
    ),
  ];
  const alert = alertQueueStatement(db, q.organizationId, transitionId, "quarantined", incidentId, nowIso);
  if (alert) statements.push(alert);
  return { incidentId, transitionId, statements };
}

export interface IncidentRow {
  id: string;
  organization_id: string;
  subject_type: "agent" | "session";
  subject_id: string;
  status: "open" | "contained" | "cleared";
  severity: string;
  cause: string;
  opened_at: string;
  contained_at: string | null;
  cleared_at: string | null;
}

/**
 * Re-applies scope enforcement (idempotent) and, once no live lease and no pending approval remains
 * in scope, moves the subject and incident to contained. Enforcement never depends on this step.
 */
export async function verifyContainment(db: D1Database, organizationId: string, incidentId: string, nowMs: number): Promise<"contained" | "pending" | "not_applicable"> {
  const nowIso = new Date(nowMs).toISOString();
  const incident = await db.prepare(`SELECT * FROM security_incidents WHERE id = ? AND organization_id = ?`).bind(incidentId, organizationId).first<IncidentRow>();
  if (!incident || incident.status !== "open") return "not_applicable";
  const subject = await db
    .prepare(`SELECT state, score FROM risk_subjects WHERE organization_id = ? AND subject_type = ? AND subject_id = ? AND incident_id = ?`)
    .bind(organizationId, incident.subject_type, incident.subject_id, incidentId)
    .first<{ state: RiskState; score: number }>();
  if (!subject || subject.state !== "quarantined") return "not_applicable";

  await db.batch(scopeEnforcementStatements(db, organizationId, incident.subject_type, incident.subject_id, incidentId, nowIso));
  const remaining = await db
    .prepare(
      `${SCOPE_CTE}
       SELECT (SELECT COUNT(*) FROM capability_leases l WHERE l.organization_id = ?1 AND l.revoked_at IS NULL AND l.expires_at > ?5
                 AND (l.session_id IN (SELECT id FROM scope) OR (?2 = 'agent' AND l.agent_id = ?3))) AS leases,
              (SELECT COUNT(*) FROM approvals ap JOIN decisions d ON d.id = ap.decision_id AND d.organization_id = ap.organization_id
                WHERE ap.organization_id = ?1 AND ap.status = 'pending' AND ${IN_SCOPE_DECISION}) AS pending,
              ?4 AS incident`,
    )
    .bind(organizationId, incident.subject_type, incident.subject_id, incidentId, nowIso)
    .first<{ leases: number; pending: number }>();
  if ((remaining?.leases ?? 1) !== 0 || (remaining?.pending ?? 1) !== 0) return "pending";

  const transitionId = newId("rtr");
  const statements: D1PreparedStatement[] = [
    db
      .prepare(
        `UPDATE risk_subjects SET state = 'contained', version = version + 1, updated_at = ?
          WHERE organization_id = ? AND subject_type = ? AND subject_id = ? AND incident_id = ? AND state = 'quarantined'`,
      )
      .bind(nowIso, organizationId, incident.subject_type, incident.subject_id, incidentId),
    transitionIfChangedStatement(db, {
      id: transitionId,
      organizationId,
      subjectType: incident.subject_type,
      subjectId: incident.subject_id,
      from: "quarantined",
      to: "contained",
      score: subject.score,
      cause: "containment_completed",
      actor: { type: "system", id: null, label: "Mother AI containment" },
      incidentId,
      decisionId: null,
      note: "No live lease and no pending approval remains in scope.",
      nowIso,
    }),
    db
      .prepare(`UPDATE security_incidents SET status = 'contained', contained_at = ? WHERE id = ? AND organization_id = ? AND status = 'open'`)
      .bind(nowIso, incidentId, organizationId),
    db
      .prepare(
        `INSERT INTO control_events (id, organization_id, actor_type, actor_id, actor_label, action, target_type, target_id, detail, created_at)
         SELECT ?, ?, 'system', NULL, 'Mother AI containment', 'security.containment_completed', ?, ?, json_object('incident_id', ?), ?
          WHERE changes() = 1`,
      )
      .bind(newId("evt"), organizationId, incident.subject_type, incident.subject_id, incidentId, nowIso),
  ];
  const alert = alertQueueStatement(db, organizationId, transitionId, "contained", incidentId, nowIso);
  if (alert) statements.push(alert);
  await db.batch(statements);
  return "contained";
}

export class ClearanceError extends Error {
  constructor(
    readonly code: "NOT_FOUND" | "NOT_ACTIVE" | "NOT_AUTHORIZED" | "NOTE_REQUIRED",
    message: string,
  ) {
    super(message);
  }
}

/**
 * Human clearance. The database trigger independently requires an active human security, admin
 * or owner member. Clearing never restores old grants or leases: the containment epoch stays.
 */
export async function clearIncident(
  db: D1Database,
  input: { organizationId: string; incidentId: string; user: { id: string; label: string }; note: string; nowMs: number },
): Promise<{ transitionId: string }> {
  const note = input.note.trim();
  if (note.length < 10) throw new ClearanceError("NOTE_REQUIRED", "A clearance note of at least 10 characters is required.");
  const nowIso = new Date(input.nowMs).toISOString();
  const incident = await db.prepare(`SELECT * FROM security_incidents WHERE id = ? AND organization_id = ?`).bind(input.incidentId, input.organizationId).first<IncidentRow>();
  if (!incident) throw new ClearanceError("NOT_FOUND", "Incident not found.");
  if (incident.status === "cleared") throw new ClearanceError("NOT_ACTIVE", "This incident is already cleared.");
  const subject = await db
    .prepare(`SELECT state, score FROM risk_subjects WHERE organization_id = ? AND subject_type = ? AND subject_id = ? AND incident_id = ?`)
    .bind(input.organizationId, incident.subject_type, incident.subject_id, input.incidentId)
    .first<{ state: RiskState; score: number }>();
  if (!subject || (subject.state !== "quarantined" && subject.state !== "contained")) throw new ClearanceError("NOT_ACTIVE", "The subject is not quarantined.");

  const transitionId = newId("rtr");
  const statements: D1PreparedStatement[] = [
    db
      .prepare(
        `UPDATE risk_subjects
            SET state = 'cleared', score = 0, state_since = ?1, signals_since = ?1, cleared_by = ?2, cleared_at = ?1,
                version = version + 1, updated_at = ?1
          WHERE organization_id = ?3 AND subject_type = ?4 AND subject_id = ?5 AND incident_id = ?6 AND state IN ('quarantined', 'contained')`,
      )
      .bind(nowIso, input.user.id, input.organizationId, incident.subject_type, incident.subject_id, input.incidentId),
    transitionIfChangedStatement(db, {
      id: transitionId,
      organizationId: input.organizationId,
      subjectType: incident.subject_type,
      subjectId: incident.subject_id,
      from: subject.state,
      to: "cleared",
      score: 0,
      cause: "clearance",
      actor: { type: "user", id: input.user.id, label: input.user.label },
      incidentId: input.incidentId,
      decisionId: null,
      note: note.slice(0, 1000),
      nowIso,
    }),
    db
      .prepare(
        `UPDATE security_incidents SET status = 'cleared', cleared_at = ?, cleared_by = ?, cleared_by_name = ?, clearance_note = ?
          WHERE id = ? AND organization_id = ? AND status IN ('open', 'contained')`,
      )
      .bind(nowIso, input.user.id, input.user.label, note.slice(0, 1000), input.incidentId, input.organizationId),
    db
      .prepare(
        `INSERT INTO runtime_events (id, organization_id, type, source, reason_code, session_id, agent_id, incident_id, detail, created_at)
         VALUES (?, ?, 'quarantine.cleared', 'mother', 'CLEARED_BY_HUMAN', ?, ?, ?, json_object('cleared_by', ?), ?)`,
      )
      .bind(
        newId("rte"),
        input.organizationId,
        incident.subject_type === "session" ? incident.subject_id : null,
        incident.subject_type === "agent" ? incident.subject_id : null,
        input.incidentId,
        input.user.id,
        nowIso,
      ),
    db
      .prepare(
        `INSERT INTO control_events (id, organization_id, actor_type, actor_id, actor_label, action, target_type, target_id, detail, created_at)
         VALUES (?, ?, 'user', ?, ?, 'security.cleared', ?, ?, ?, ?)`,
      )
      .bind(
        newId("evt"),
        input.organizationId,
        input.user.id,
        input.user.label,
        incident.subject_type,
        incident.subject_id,
        JSON.stringify({ incident_id: input.incidentId, note: note.slice(0, 1000), grants_and_leases_before_epoch: "remain invalid" }),
        nowIso,
      ),
  ];
  const alert = alertQueueStatement(db, input.organizationId, transitionId, "cleared", input.incidentId, nowIso);
  if (alert) statements.push(alert);
  try {
    const results = await db.batch(statements);
    if ((results[0]!.meta.changes ?? 0) !== 1) throw new ClearanceError("NOT_ACTIVE", "The subject changed state; reload and try again.");
  } catch (err) {
    if (err instanceof ClearanceError) throw err;
    if (err instanceof Error && /invalid risk transition|invalid incident transition/.test(err.message)) {
      throw new ClearanceError("NOT_AUTHORIZED", "Clearing a quarantine requires an active human Security, Admin or Owner member.");
    }
    throw err;
  }
  return { transitionId };
}
