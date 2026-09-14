// Persistence for the runtime risk layer: reading risk context and building the write statements
// (signals, subject state, transitions, alert queue). Every statement is organization-scoped.

import { newId } from "../lib/crypto";
import { redactValue } from "../lib/redact";
import {
  RISK_ENGINE_VERSION,
  SIGNAL_RULES,
  isContained,
  signalExpiry,
  stateSeverity,
  type NewSignal,
  type RiskState,
  type StoredSignal,
  type SubjectAssessment,
  type SubjectRow,
  type SubjectType,
} from "./engine";

export const EPOCH_START = "1970-01-01T00:00:00.000Z";

export interface SessionRow {
  id: string;
  organization_id: string;
  agent_id: string;
  api_key_id: string;
  parent_session_id: string | null;
  root_session_id: string;
  depth: number;
  principal_type: string;
  principal_ref: string | null;
  purpose: string | null;
  opened_at: string;
  expires_at: string;
  closed_at: string | null;
}

export const subjectKey = (type: SubjectType, id: string) => `${type}:${id}`;

/**
 * Session lineage starting at `sessionId` (index 0) and walking up parents within the same
 * organization. The first row is returned even if it belongs to another organization, so the
 * caller can detect cross-tenant references; its ancestors are never followed in that case.
 */
export function lineageStatement(db: D1Database, sessionId: string, organizationId: string): D1PreparedStatement {
  return db
    .prepare(
      `WITH RECURSIVE chain(id, organization_id, agent_id, api_key_id, parent_session_id, root_session_id, depth, principal_type,
                            principal_ref, purpose, opened_at, expires_at, closed_at, n) AS (
         SELECT id, organization_id, agent_id, api_key_id, parent_session_id, root_session_id, depth, principal_type,
                principal_ref, purpose, opened_at, expires_at, closed_at, 0
           FROM agent_sessions WHERE id = ?1
         UNION ALL
         SELECT p.id, p.organization_id, p.agent_id, p.api_key_id, p.parent_session_id, p.root_session_id, p.depth, p.principal_type,
                p.principal_ref, p.purpose, p.opened_at, p.expires_at, p.closed_at, c.n + 1
           FROM agent_sessions p JOIN chain c ON p.id = c.parent_session_id
          WHERE c.organization_id = ?2 AND p.organization_id = ?2 AND c.n < 9)
       SELECT * FROM chain ORDER BY n`,
    )
    .bind(sessionId, organizationId);
}

/** Risk subjects for an agent, API key and a set of session/agent ids from a lineage. */
export function subjectsStatement(db: D1Database, organizationId: string, agentIds: string[], sessionIds: string[], apiKeyId: string | null): D1PreparedStatement {
  const agents = agentIds.length ? agentIds : ["-"];
  const sessions = sessionIds.length ? sessionIds : ["-"];
  return db
    .prepare(
      `SELECT * FROM risk_subjects
        WHERE organization_id = ?
          AND ((subject_type = 'agent' AND subject_id IN (${agents.map(() => "?").join(",")}))
            OR (subject_type = 'session' AND subject_id IN (${sessions.map(() => "?").join(",")}))
            OR (subject_type = 'api_key' AND subject_id = ?))`,
    )
    .bind(organizationId, ...agents, ...sessions, apiKeyId ?? "-");
}

/** Unexpired signals for the subjects that can receive new signals. */
export function signalsStatement(db: D1Database, organizationId: string, subjects: Array<{ type: SubjectType; id: string }>, nowIso: string): D1PreparedStatement {
  const list = subjects.length ? subjects : [{ type: "agent" as SubjectType, id: "-" }];
  return db
    .prepare(
      `SELECT subject_type, subject_id, signal, hard, points, evidence_key, observed_at, expires_at FROM risk_signals
        WHERE organization_id = ? AND expires_at > ?
          AND (${list.map(() => "(subject_type = ? AND subject_id = ?)").join(" OR ")})`,
    )
    .bind(organizationId, nowIso, ...list.flatMap((s) => [s.type, s.id]));
}

export interface RiskSnapshot {
  subjects: Map<string, SubjectRow>;
  signals: StoredSignal[];
}

export function snapshotFrom(subjectRows: SubjectRow[], signalRows: StoredSignal[]): RiskSnapshot {
  return { subjects: new Map(subjectRows.map((r) => [subjectKey(r.subject_type, r.subject_id), r])), signals: signalRows };
}

export async function loadSnapshot(
  db: D1Database,
  organizationId: string,
  scope: { agentIds: string[]; sessionIds: string[]; apiKeyId: string | null; direct: Array<{ type: SubjectType; id: string }> },
  nowIso: string,
): Promise<RiskSnapshot> {
  const [subjects, signals] = await db.batch([
    subjectsStatement(db, organizationId, scope.agentIds, scope.sessionIds, scope.apiKeyId),
    signalsStatement(db, organizationId, scope.direct, nowIso),
  ]);
  return snapshotFrom(subjects!.results as unknown as SubjectRow[], signals!.results as unknown as StoredSignal[]);
}

/** The most severe subject among those given, with its key. */
export function worstSubject(snapshot: RiskSnapshot, keys: string[], overrides: Map<string, RiskState> = new Map()): { key: string | null; state: RiskState; row: SubjectRow | null } {
  let worst: { key: string | null; state: RiskState; row: SubjectRow | null } = { key: null, state: "normal", row: null };
  for (const key of keys) {
    const row = snapshot.subjects.get(key) ?? null;
    const state = overrides.get(key) ?? row?.state ?? "normal";
    if (stateSeverity(state) > stateSeverity(worst.state)) worst = { key, state, row };
  }
  return worst;
}

/** Latest containment epoch across subjects: authority issued before it is permanently invalid. */
export function latestEpoch(snapshot: RiskSnapshot, keys: string[]): string | null {
  let epoch: string | null = null;
  for (const key of keys) {
    const e = snapshot.subjects.get(key)?.containment_epoch_at ?? null;
    if (e && (!epoch || e > epoch)) epoch = e;
  }
  return epoch;
}

export interface SignalWrite {
  id: string;
  signal: NewSignal;
}

export function signalStatements(
  db: D1Database,
  organizationId: string,
  signals: NewSignal[],
  ctx: { mode: "monitor" | "enforce"; sessionId: string | null; decisionId: string | null; nowMs: number },
): { statements: D1PreparedStatement[]; writes: SignalWrite[] } {
  const observedAt = new Date(ctx.nowMs).toISOString();
  const writes = signals.map((signal) => ({ id: newId("rsg"), signal }));
  const statements = writes.map(({ id, signal }) => {
    const rule = SIGNAL_RULES[signal.code];
    return db
      .prepare(
        `INSERT INTO risk_signals (id, organization_id, subject_type, subject_id, signal, hard, points, evidence_key, evidence,
                                   rule_version, session_id, decision_id, mode, observed_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        id,
        organizationId,
        signal.subjectType,
        signal.subjectId,
        signal.code,
        rule.hard ? 1 : 0,
        rule.points,
        signal.evidenceKey.slice(0, 200),
        JSON.stringify(redactValue(signal.evidence)).slice(0, 2000),
        RISK_ENGINE_VERSION,
        ctx.sessionId,
        ctx.decisionId,
        ctx.mode,
        observedAt,
        signalExpiry(signal.code, ctx.nowMs),
      );
  });
  return { statements, writes };
}

export interface TransitionInput {
  id: string;
  organizationId: string;
  subjectType: SubjectType;
  subjectId: string;
  from: RiskState;
  to: RiskState;
  score: number;
  cause: "signals" | "decay" | "score_quarantine" | "hard_signal_quarantine" | "manual_quarantine" | "containment_completed" | "clearance";
  actor: { type: "system" | "user" | "ops"; id: string | null; label: string | null };
  incidentId: string | null;
  decisionId: string | null;
  note: string | null;
  nowIso: string;
}

function transitionColumns(t: TransitionInput): unknown[] {
  return [t.id, t.organizationId, t.subjectType, t.subjectId, t.from, t.to, t.score, t.cause, t.actor.type, t.actor.id, t.actor.label, t.incidentId, t.decisionId, RISK_ENGINE_VERSION, t.note, t.nowIso];
}

const TRANSITION_INSERT = `INSERT INTO risk_transitions (id, organization_id, subject_type, subject_id, from_state, to_state, score, cause,
                             actor_type, actor_id, actor_label, incident_id, decision_id, rule_version, note, created_at)`;

/** Transition row, inserted only when the guarding subject state is present. */
export function transitionStatement(db: D1Database, t: TransitionInput, guard: { state: RiskState; incidentId?: string | null }): D1PreparedStatement {
  return db
    .prepare(
      `${TRANSITION_INSERT}
       SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE EXISTS (SELECT 1 FROM risk_subjects WHERE organization_id = ? AND subject_type = ? AND subject_id = ? AND state = ?
                        AND (? IS NULL OR incident_id = ?))`,
    )
    .bind(...transitionColumns(t), t.organizationId, t.subjectType, t.subjectId, guard.state, guard.incidentId ?? null, guard.incidentId ?? null);
}

/** Transition row, inserted only if the immediately preceding statement in the batch changed a row. */
export function transitionIfChangedStatement(db: D1Database, t: TransitionInput): D1PreparedStatement {
  return db.prepare(`${TRANSITION_INSERT} SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE changes() = 1`).bind(...transitionColumns(t));
}

/**
 * Non-quarantine subject update (score and state). Concurrency-safe: applies only if nobody changed
 * the row since it was read, and never touches a quarantined or contained subject.
 */
export function subjectUpsertStatement(db: D1Database, organizationId: string, a: SubjectAssessment, nowIso: string): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO risk_subjects (organization_id, subject_type, subject_id, state, score, state_since, signals_since, version, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
       ON CONFLICT (subject_type, subject_id) DO UPDATE SET
         state = excluded.state,
         score = excluded.score,
         state_since = CASE WHEN risk_subjects.state = excluded.state THEN risk_subjects.state_since ELSE excluded.state_since END,
         version = risk_subjects.version + 1,
         updated_at = excluded.updated_at
       WHERE risk_subjects.organization_id = excluded.organization_id
         AND risk_subjects.version = ?
         AND risk_subjects.state NOT IN ('quarantined', 'contained')`,
    )
    .bind(organizationId, a.subjectType, a.subjectId, a.nextState, a.score, nowIso, EPOCH_START, nowIso, a.current?.version ?? -1);
}

export const ALERT_EVENT_FOR_STATE: Partial<Record<RiskState, "risk_elevated" | "review_required" | "quarantined" | "containment_completed" | "cleared">> = {
  elevated: "risk_elevated",
  review_required: "review_required",
  quarantined: "quarantined",
  contained: "containment_completed",
  cleared: "cleared",
};

/**
 * Queues a security alert for a transition, only if the organization opted in, has a Slack
 * destination, and the transition row exists. Alerts never write risk state.
 */
export function alertQueueStatement(db: D1Database, organizationId: string, transitionId: string, toState: RiskState, incidentId: string | null, nowIso: string, fromState?: RiskState): D1PreparedStatement | null {
  const event = ALERT_EVENT_FOR_STATE[toState];
  if (!event) return null;
  // Decay back to elevated is not news; only escalations, containment and clearance alert.
  if (fromState && toState !== "cleared" && toState !== "contained" && stateSeverity(toState) <= stateSeverity(fromState)) return null;
  return db
    .prepare(
      `INSERT OR IGNORE INTO security_notifications (id, organization_id, transition_id, incident_id, event, channel, status, max_attempts, queued_at, next_attempt_at)
       SELECT ?, ?, ?, ?, ?, 'slack', 'QUEUED', 3, ?, ?
        WHERE EXISTS (SELECT 1 FROM risk_transitions WHERE id = ? AND organization_id = ?)
          AND EXISTS (SELECT 1 FROM organizations WHERE id = ? AND security_alerts_enabled = 1 AND status = 'active')
          AND EXISTS (SELECT 1 FROM notification_channels WHERE organization_id = ? AND kind = 'slack_webhook')`,
    )
    .bind(newId("snt"), organizationId, transitionId, incidentId, event, nowIso, nowIso, transitionId, organizationId, organizationId, organizationId);
}

export function runtimeEventStatement(
  db: D1Database,
  e: {
    organizationId: string;
    type: string;
    source: "mother" | "integration";
    outcome?: string | null;
    reasonCode?: string | null;
    sessionId?: string | null;
    agentId?: string | null;
    apiKeyId?: string | null;
    decisionId?: string | null;
    requestId?: string | null;
    approvalId?: string | null;
    leaseId?: string | null;
    incidentId?: string | null;
    detail?: Record<string, unknown>;
    nowIso: string;
  },
): D1PreparedStatement {
  let detail = JSON.stringify(redactValue(e.detail ?? {}));
  if (detail.length > 4096) detail = JSON.stringify({ truncated: true });
  return db
    .prepare(
      `INSERT INTO runtime_events (id, organization_id, type, source, outcome, reason_code, session_id, agent_id, api_key_id, decision_id,
                                   request_id, approval_id, lease_id, incident_id, detail, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      newId("rte"),
      e.organizationId,
      e.type,
      e.source,
      e.outcome ?? null,
      e.reasonCode ?? null,
      e.sessionId ?? null,
      e.agentId ?? null,
      e.apiKeyId ?? null,
      e.decisionId ?? null,
      e.requestId ?? null,
      e.approvalId ?? null,
      e.leaseId ?? null,
      e.incidentId ?? null,
      detail,
      e.nowIso,
    );
}

export { isContained };
