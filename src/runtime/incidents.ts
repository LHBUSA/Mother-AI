// Incident blast radius: everything Mother recorded inside the incident's scope — and nothing it did
// not observe. Scope = the quarantined session and its descendants, or for an agent every session of
// that agent live during the incident window plus descendants, and the agent's sessionless decisions.

import type { IncidentRow } from "./containment";

const DAY = 24 * 60 * 60 * 1000;

export async function blastRadius(db: D1Database, incident: IncidentRow & { cleared_at: string | null }, nowIso: string) {
  const windowStart = new Date(Date.parse(incident.opened_at) - DAY).toISOString();
  const windowEnd = incident.cleared_at ?? nowIso;
  const scope = `WITH RECURSIVE scope(id, n) AS (
      SELECT id, 0 FROM agent_sessions
       WHERE organization_id = ?1
         AND ((?2 = 'agent' AND agent_id = ?3 AND opened_at <= ?5 AND expires_at >= ?4) OR (?2 = 'session' AND id = ?3))
      UNION ALL
      SELECT s.id, scope.n + 1 FROM agent_sessions s JOIN scope ON s.parent_session_id = scope.id
       WHERE s.organization_id = ?1 AND scope.n < 8),
    scoped AS (
      SELECT d.* FROM decisions d
       WHERE d.organization_id = ?1
         AND (d.session_id IN (SELECT id FROM scope)
              OR (?2 = 'agent' AND d.agent_id = ?3 AND d.created_at >= ?4 AND d.created_at <= ?5)))`;
  const b = (sql: string) => db.prepare(sql).bind(incident.organization_id, incident.subject_type, incident.subject_id, windowStart, windowEnd);
  // D1 caps the number of terms in a compound SELECT (the recursive scope CTE already uses two), so every
  // "touched" category is its own single-SELECT statement rather than one UNION ALL.
  const touchedKinds: Array<[kind: string, value: string, where: string, group: string]> = [
    ["agent", "agent_key", "1 = 1", "agent_key"],
    ["capability", "capability || '.' || operation", "1 = 1", "capability, operation"],
    ["mcp_tool", "mcp_server || ' / ' || mcp_tool", "mcp_tool IS NOT NULL", "mcp_server, mcp_tool"],
    ["resource", "resource", "resource IS NOT NULL", "resource"],
    ["destination", "destination", "destination IS NOT NULL", "destination"],
    ["data_class", "data_class", "data_class IS NOT NULL", "data_class"],
  ];
  const touchedStatements = touchedKinds.map(([kind, value, where, group]) =>
    b(`${scope}
       SELECT '${kind}' AS kind, ${value} AS value, COUNT(*) AS n, MIN(created_at) AS first_seen, MAX(created_at) AS last_seen,
              SUM(decision = 'allow') AS allowed, SUM(decision = 'review') AS reviewed, SUM(decision = 'block') AS blocked
         FROM scoped WHERE ${where} GROUP BY ${group}`),
  );
  const results = await db.batch([
    b(`${scope}
       SELECT s.id, s.agent_id, a.agent_key, s.parent_session_id, s.root_session_id, s.depth, s.principal_type, s.principal_ref,
              s.opened_at, s.expires_at, s.closed_at
         FROM agent_sessions s JOIN agents a ON a.id = s.agent_id
        WHERE s.organization_id = ?1 AND s.id IN (SELECT id FROM scope)
        ORDER BY s.depth, s.opened_at LIMIT 200`),
    ...touchedStatements,
    b(`${scope}
       SELECT sc.id, sc.request_id, sc.session_id, sc.parent_decision_id, sc.agent_key, sc.protocol, sc.capability, sc.operation, sc.resource,
              sc.destination, sc.data_class, sc.mcp_server, sc.mcp_tool, sc.decision, sc.reason_code, sc.created_at,
              re.policy_decision, re.runtime_risk_decision, re.effective_decision, re.mode
         FROM scoped sc LEFT JOIN risk_evaluations re ON re.decision_id = sc.id
        ORDER BY sc.created_at DESC LIMIT 200`),
    b(`${scope}
       SELECT ap.id, ap.decision_id, ap.status, ap.requested_at, ap.acted_at, ap.acted_by_name, ap.consumed_at, ap.grant_expires_at,
              ap.terminated_reason, ap.terminated_incident_id
         FROM approvals ap WHERE ap.organization_id = ?1 AND ap.decision_id IN (SELECT id FROM scoped)
        ORDER BY ap.requested_at DESC LIMIT 200`),
    b(`${scope}
       SELECT l.id, l.session_id, l.decision_id, l.capability, l.operation, l.resource, l.destination, l.data_class, l.max_uses, l.uses,
              l.issued_at, l.expires_at, l.revoked_at, l.revoked_reason,
              (SELECT COUNT(*) FROM lease_uses u WHERE u.lease_id = l.id AND u.outcome = 'refused') AS refused_uses
         FROM capability_leases l
        WHERE l.organization_id = ?1 AND (l.session_id IN (SELECT id FROM scope) OR (?2 = 'agent' AND l.agent_id = ?3 AND l.issued_at >= ?4))
        ORDER BY l.issued_at DESC LIMIT 200`),
    db
      .prepare(
        `${scope}
       SELECT e.id, e.type, e.source, e.outcome, e.reason_code, e.session_id, e.decision_id, e.request_id, e.approval_id, e.lease_id, e.created_at
         FROM runtime_events e
        WHERE e.organization_id = ?1
          AND (e.session_id IN (SELECT id FROM scope) OR (?2 = 'agent' AND e.agent_id = ?3 AND e.created_at >= ?4 AND e.created_at <= ?5) OR e.incident_id = ?6)
        ORDER BY e.created_at DESC LIMIT 200`,
      )
      .bind(incident.organization_id, incident.subject_type, incident.subject_id, windowStart, windowEnd, incident.id),
  ]);
  const sessions = results[0]!;
  const touchedRows = results.slice(1, 1 + touchedKinds.length).flatMap((r) => r.results as Array<Record<string, unknown>>);
  const [decisions, approvals, leases, events] = results.slice(1 + touchedKinds.length);
  const byKind = (kind: string) => touchedRows.filter((r) => r.kind === kind).map(({ kind: _k, ...rest }) => rest);
  const eventRows = events!.results as Array<{ source: string }>;
  return {
    window: { from: windowStart, to: windowEnd },
    boundary: "Only actions that called Mother are shown. Activity that did not pass through Mother is not visible to Mother and is not inferred.",
    sessions: sessions!.results,
    agents: byKind("agent"),
    capabilities: byKind("capability"),
    mcp_tools: byKind("mcp_tool"),
    resources: byKind("resource"),
    destinations: byKind("destination"),
    data_classes: byKind("data_class"),
    decisions: decisions!.results,
    approvals: approvals!.results,
    leases: leases!.results,
    runtime_events: eventRows.filter((e) => e.source === "mother"),
    execution_reports: eventRows.filter((e) => e.source === "integration"),
  };
}
