// Runtime security console API (/api/console/security*). Reads: any member. Quarantine and clearance:
// manage_security (security, admin, owner). Clearance additionally requires a human identity; the
// database trigger re-checks role, membership and human kind independently.

import { ApiError, json } from "../../lib/http";
import { iso } from "../../lib/time";
import { ELEVATED_SCORE, QUARANTINE_SCORE, REVIEW_SCORE, RISK_ENGINE_VERSION, isContained, ruleTable, type RiskState } from "../../runtime/engine";
import { ClearanceError, clearIncident, quarantineStatements, type IncidentRow } from "../../runtime/containment";
import { afterRuntimeCommit } from "../../runtime/alerts";
import { blastRadius } from "../../runtime/incidents";
import { Validator, assertOrgWritable, type ConsoleContext } from "./context";

const SUBJECT_LABEL = `CASE rs.subject_type
    WHEN 'agent' THEN (SELECT agent_key FROM agents WHERE id = rs.subject_id AND organization_id = rs.organization_id)
    WHEN 'session' THEN (SELECT a.agent_key FROM agent_sessions s JOIN agents a ON a.id = s.agent_id WHERE s.id = rs.subject_id AND s.organization_id = rs.organization_id)
    WHEN 'api_key' THEN (SELECT key_prefix || '…' FROM api_keys WHERE id = rs.subject_id AND organization_id = rs.organization_id) END`;

export async function getSecurityOverview(ctx: ConsoleContext): Promise<Response> {
  const [org, subjects, incidents, signals] = await ctx.db.batch([
    ctx.db.prepare(`SELECT runtime_protection, security_alerts_enabled FROM organizations WHERE id = ?`).bind(ctx.orgId),
    ctx.db
      .prepare(
        `SELECT rs.subject_type, rs.subject_id, rs.state, rs.score, rs.state_since, rs.incident_id, rs.containment_epoch_at, rs.cleared_at, rs.updated_at,
                ${SUBJECT_LABEL} AS label
           FROM risk_subjects rs WHERE rs.organization_id = ? AND rs.state <> 'normal' ORDER BY rs.updated_at DESC LIMIT 100`,
      )
      .bind(ctx.orgId),
    ctx.db.prepare(`SELECT * FROM security_incidents WHERE organization_id = ? ORDER BY opened_at DESC LIMIT 50`).bind(ctx.orgId),
    ctx.db
      .prepare(
        `SELECT id, subject_type, subject_id, signal, hard, points, evidence, rule_version, session_id, decision_id, mode, observed_at, expires_at
           FROM risk_signals WHERE organization_id = ? ORDER BY observed_at DESC LIMIT 50`,
      )
      .bind(ctx.orgId),
  ]);
  const o = org!.results[0] as { runtime_protection: string; security_alerts_enabled: number };
  return json({
    mode: o.runtime_protection,
    alerts_enabled: o.security_alerts_enabled === 1,
    engine_version: RISK_ENGINE_VERSION,
    thresholds: { elevated: ELEVATED_SCORE, review_required: REVIEW_SCORE, quarantine: QUARANTINE_SCORE },
    rules: ruleTable(),
    subjects: subjects!.results,
    incidents: incidents!.results,
    recent_signals: (signals!.results as Array<Record<string, unknown>>).map((s) => ({ ...s, hard: s.hard === 1, evidence: safeJson(s.evidence as string) })),
    boundary: "Mother governs actions that call Mother. Process, file and network activity outside Mother is not visible.",
  });
}

export async function getIncident(ctx: ConsoleContext): Promise<Response> {
  const id = ctx.params[0]!;
  const incident = await ctx.db.prepare(`SELECT * FROM security_incidents WHERE id = ? AND organization_id = ?`).bind(id, ctx.orgId).first<IncidentRow & Record<string, unknown>>();
  if (!incident) throw new ApiError(404, "NOT_FOUND", "Incident not found.");
  const [subject, members, transitions, signals] = await ctx.db.batch([
    ctx.db
      .prepare(`SELECT rs.*, ${SUBJECT_LABEL} AS label FROM risk_subjects rs WHERE rs.organization_id = ? AND rs.subject_type = ? AND rs.subject_id = ?`)
      .bind(ctx.orgId, incident.subject_type, incident.subject_id),
    ctx.db.prepare(`SELECT member_type, member_id, relation, created_at FROM incident_members WHERE incident_id = ? AND organization_id = ? ORDER BY relation, created_at`).bind(id, ctx.orgId),
    ctx.db
      .prepare(`SELECT * FROM risk_transitions WHERE organization_id = ? AND subject_type = ? AND subject_id = ? AND created_at >= ? ORDER BY created_at`)
      .bind(ctx.orgId, incident.subject_type, incident.subject_id, new Date(Date.parse(incident.opened_at) - 24 * 60 * 60 * 1000).toISOString()),
    ctx.db
      .prepare(
        `SELECT s.id, s.subject_type, s.subject_id, s.signal, s.hard, s.points, s.evidence, s.rule_version, s.session_id, s.decision_id, s.mode, s.observed_at
           FROM risk_signals s JOIN incident_members m ON m.member_id = s.id AND m.member_type = 'signal'
          WHERE m.incident_id = ? AND s.organization_id = ? ORDER BY s.observed_at`,
      )
      .bind(id, ctx.orgId),
  ]);
  const subjectRow = subject!.results[0] as { signals_since?: string } | undefined;
  const contributing = await ctx.db
    .prepare(
      `SELECT id, signal, hard, points, evidence, rule_version, session_id, decision_id, mode, observed_at, expires_at FROM risk_signals
        WHERE organization_id = ? AND subject_type = ? AND subject_id = ? AND observed_at <= ? AND observed_at >= ?
        ORDER BY observed_at`,
    )
    .bind(ctx.orgId, incident.subject_type, incident.subject_id, incident.opened_at, subjectRow?.signals_since && subjectRow.signals_since < incident.opened_at ? subjectRow.signals_since : new Date(Date.parse(incident.opened_at) - 24 * 60 * 60 * 1000).toISOString())
    .all();
  return json({
    incident,
    subject: subject!.results[0] ?? null,
    members: members!.results,
    transitions: transitions!.results,
    triggering_signals: (signals!.results as Array<Record<string, unknown>>).map((s) => ({ ...s, hard: s.hard === 1, evidence: safeJson(s.evidence as string) })),
    signals_before_quarantine: (contributing.results as Array<Record<string, unknown>>).map((s) => ({ ...s, hard: s.hard === 1, evidence: safeJson(s.evidence as string) })),
    blast_radius: await blastRadius(ctx.db, incident as IncidentRow & { cleared_at: string | null }, iso(ctx.nowMs)),
  });
}

export async function quarantineSubject(ctx: ConsoleContext): Promise<Response> {
  assertOrgWritable(ctx);
  const v = new Validator(ctx.body);
  const type = v.oneOf("subject_type", ["agent", "session"] as const);
  const subjectId = v.string("subject_id", { min: 1, max: 64, pattern: /^(agt|asn)_[0-9A-Za-z]{22}$/ });
  const note = v.string("note", { min: 10, max: 500 });
  v.assert();
  const org = await ctx.db.prepare(`SELECT runtime_protection FROM organizations WHERE id = ?`).bind(ctx.orgId).first<{ runtime_protection: string }>();
  if (org?.runtime_protection !== "enforce") {
    throw new ApiError(409, "RUNTIME_PROTECTION_NOT_ENFORCING", "Quarantine is only available when runtime protection is set to enforce.");
  }
  const exists =
    type === "agent"
      ? await ctx.db.prepare(`SELECT id FROM agents WHERE id = ? AND organization_id = ?`).bind(subjectId, ctx.orgId).first()
      : await ctx.db.prepare(`SELECT id FROM agent_sessions WHERE id = ? AND organization_id = ?`).bind(subjectId, ctx.orgId).first();
  if (!exists) throw new ApiError(404, "NOT_FOUND", `${type === "agent" ? "Agent" : "Session"} not found.`);
  const current = await ctx.db
    .prepare(`SELECT state, score FROM risk_subjects WHERE organization_id = ? AND subject_type = ? AND subject_id = ?`)
    .bind(ctx.orgId, type, subjectId)
    .first<{ state: RiskState; score: number }>();
  if (current && isContained(current.state)) throw new ApiError(409, "ALREADY_QUARANTINED", "This subject is already quarantined.");

  const plan = quarantineStatements(ctx.db, {
    organizationId: ctx.orgId,
    subjectType: type!,
    subjectId: subjectId!,
    fromState: current?.state ?? "normal",
    score: current?.score ?? 0,
    cause: "manual_quarantine",
    actor: { type: "user", id: ctx.actor.id, label: ctx.actor.label },
    reason: note!,
    decisionId: null,
    signalIds: [],
    nowMs: ctx.nowMs,
  });
  await ctx.db.batch(plan.statements);
  ctx.waitUntil(afterRuntimeCommit(ctx.env, ctx.orgId, plan.incidentId, () => Date.now()));
  return json({ incident_id: plan.incidentId, state: "quarantined" }, 201);
}

export async function clearSecurityIncident(ctx: ConsoleContext): Promise<Response> {
  const v = new Validator(ctx.body);
  const note = v.string("note", { min: 10, max: 1000 });
  v.assert();
  const user = await ctx.db.prepare(`SELECT kind FROM users WHERE id = ?`).bind(ctx.actor.id).first<{ kind: string }>();
  if (user?.kind !== "human") {
    throw new ApiError(403, "HUMAN_REQUIRED", "Clearing a quarantine requires a human member. Automation identities cannot clear containment.");
  }
  try {
    await clearIncident(ctx.db, { organizationId: ctx.orgId, incidentId: ctx.params[0]!, user: { id: ctx.actor.id, label: ctx.actor.label }, note: note!, nowMs: ctx.nowMs });
  } catch (err) {
    if (err instanceof ClearanceError) {
      const status = err.code === "NOT_FOUND" ? 404 : err.code === "NOT_AUTHORIZED" ? 403 : err.code === "NOTE_REQUIRED" ? 400 : 409;
      throw new ApiError(status, err.code === "NOT_AUTHORIZED" ? "CLEARANCE_NOT_AUTHORIZED" : err.code === "NOT_ACTIVE" ? "INCIDENT_NOT_ACTIVE" : err.code, err.message);
    }
    throw err;
  }
  ctx.waitUntil(afterRuntimeCommit(ctx.env, ctx.orgId, null, () => Date.now()));
  return json({ incident_id: ctx.params[0], state: "cleared", note: "Grants and leases issued before the quarantine remain invalid. Issue new authority." });
}

function safeJson(value: string | null): unknown {
  try {
    return value ? JSON.parse(value) : {};
  } catch {
    return {};
  }
}
