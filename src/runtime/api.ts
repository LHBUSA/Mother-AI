// Runtime gateway surfaces (API key auth): agent sessions, capability lease use, integration-reported
// execution results, and the containment checks on approval consumption.

import type { Env } from "../env";
import { newId } from "../lib/crypto";
import { ApiError, json } from "../lib/http";
import { addSeconds, iso } from "../lib/time";
import { AGENT_KEY } from "../gateway/normalize";
import { isContained, type NewSignal, type RiskMode, type RiskState, type SignalCode, type SubjectType } from "./engine";
import { planSubjects, subjectWriteStatements } from "./gateway";
import { afterRuntimeCommit } from "./alerts";
import {
  latestEpoch,
  lineageStatement,
  loadSnapshot,
  runtimeEventStatement,
  subjectKey,
  worstSubject,
  type RiskSnapshot,
  type SessionRow,
} from "./store";

export interface RuntimePrincipal {
  key_id: string;
  key_prefix: string;
  key_environment: "live" | "test";
  org_id: string;
  runtime_protection: RiskMode;
  security_alerts_enabled: number;
}

type WaitUntil = (p: Promise<unknown>) => void;

const SESSION_PATH = /^asn_[0-9A-Za-z]{22}$/;
const PRINTABLE = /^[^\x00-\x1f\x7f]{1,256}$/;
const TOKEN = /^[a-z0-9][a-z0-9._-]{0,63}$/;

function fields(errors: Record<string, string>): void {
  if (Object.keys(errors).length) throw new ApiError(400, "INVALID_REQUEST", "The request failed validation.", { fields: errors });
}

function checkKeys(body: Record<string, unknown>, allowed: string[], errors: Record<string, string>) {
  for (const k of Object.keys(body)) if (!allowed.includes(k)) errors[k] = "unknown field";
}

function optString(body: Record<string, unknown>, key: string, pattern: RegExp, errors: Record<string, string>, lower = false): string | null {
  const v = body[key];
  if (v === undefined || v === null) return null;
  if (typeof v !== "string") {
    errors[key] = "must be a string";
    return null;
  }
  const t = lower ? v.trim().toLowerCase() : v.trim();
  if (!pattern.test(t)) {
    errors[key] = "has an invalid format";
    return null;
  }
  return t;
}

interface ScopeState {
  chain: SessionRow[];
  snapshot: RiskSnapshot;
  keys: string[];
  worst: { key: string | null; state: RiskState; incidentId: string | null };
  epoch: string | null;
}

/** Risk state for an agent, a session lineage and a key. */
export async function scopeState(db: D1Database, organizationId: string, agentId: string | null, sessionId: string | null, apiKeyId: string, nowIso: string): Promise<ScopeState> {
  let chain: SessionRow[] = [];
  if (sessionId) {
    const [rows] = await db.batch([lineageStatement(db, sessionId, organizationId)]);
    chain = (rows!.results as unknown as SessionRow[]).filter((s) => s.organization_id === organizationId);
  }
  const agentIds = [...new Set([...(agentId ? [agentId] : []), ...chain.map((s) => s.agent_id)])];
  const direct: Array<{ type: SubjectType; id: string }> = [{ type: "api_key", id: apiKeyId }];
  if (agentId) direct.push({ type: "agent", id: agentId });
  if (sessionId && chain.length) direct.push({ type: "session", id: sessionId });
  const snapshot = await loadSnapshot(db, organizationId, { agentIds, sessionIds: chain.map((s) => s.id), apiKeyId, direct }, nowIso);
  const keys = [...agentIds.map((id) => subjectKey("agent", id)), ...chain.map((s) => subjectKey("session", s.id)), subjectKey("api_key", apiKeyId)];
  const w = worstSubject(snapshot, keys);
  return { chain, snapshot, keys, worst: { key: w.key, state: w.state, incidentId: w.row?.incident_id ?? null }, epoch: latestEpoch(snapshot, keys) };
}

/**
 * Applies runtime signals outside /v1/evaluate, atomically with `extra` evidence statements.
 * In monitor mode signals are recorded and nothing is enforced. Returns the post-write effective state.
 */
export async function applyRuntimeSignals(
  env: Env,
  principal: RuntimePrincipal,
  scope: { agentId: string | null; sessionId: string | null },
  signals: Array<{ code: SignalCode; evidenceKey: string; evidence: Record<string, unknown>; subjects?: Array<{ type: SubjectType; id: string }> }>,
  extra: D1PreparedStatement[],
  nowMs: number,
  waitUntil: WaitUntil,
  ref: { decisionId?: string | null } = {},
): Promise<{ state: RiskState; incidentId: string | null; quarantined: boolean }> {
  const db = env.DB;
  const mode = principal.runtime_protection;
  const nowIso = iso(nowMs);
  if (mode === "off") {
    if (extra.length) await db.batch(extra);
    return { state: "normal", incidentId: null, quarantined: false };
  }
  const s = await scopeState(db, principal.org_id, scope.agentId, scope.sessionId, principal.key_id, nowIso);
  const validSession = scope.sessionId && s.chain.length ? scope.sessionId : null;
  const direct: Array<{ type: SubjectType; id: string }> = [{ type: "api_key", id: principal.key_id }];
  if (scope.agentId) direct.push({ type: "agent", id: scope.agentId });
  if (validSession) direct.push({ type: "session", id: validSession });

  const detected: NewSignal[] = [];
  for (const sig of signals) {
    const targets = sig.subjects ?? direct.filter((d) => d.type !== "api_key" || (!scope.agentId && !validSession));
    for (const t of targets) detected.push({ subjectType: t.type, subjectId: t.id, code: sig.code, evidenceKey: sig.evidenceKey, evidence: sig.evidence });
  }
  const plan = planSubjects(mode, s.snapshot, direct, detected, nowIso);
  const writes = subjectWriteStatements(db, { organizationId: principal.org_id, mode, alertsEnabled: principal.security_alerts_enabled === 1, nowMs, nowIso }, plan, {
    decisionId: ref.decisionId ?? null,
    sessionId: validSession,
  });
  await db.batch([...extra, ...writes.statements]);
  if (writes.incidentId || writes.alertsQueued) waitUntil(afterRuntimeCommit(env, principal.org_id, writes.incidentId, () => Date.now()));

  const overrides = new Map<string, RiskState>();
  for (const a of plan.assessments) overrides.set(subjectKey(a.subjectType, a.subjectId), a.nextState);
  if (plan.quarantine) overrides.set(subjectKey(plan.quarantine.subjectType, plan.quarantine.subjectId), "quarantined");
  const after = worstSubject(s.snapshot, [...new Set([...s.keys, ...direct.map((d) => subjectKey(d.type, d.id))])], overrides);
  return { state: after.state, incidentId: writes.incidentId ?? (isContained(after.state) ? (after.row?.incident_id ?? null) : null), quarantined: !!plan.quarantine };
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

const PRINCIPAL_TYPES = ["user", "service", "schedule", "agent", "unknown"] as const;

export async function openSession(env: Env, principal: RuntimePrincipal, body: Record<string, unknown>, nowMs: number, waitUntil: WaitUntil): Promise<Response> {
  const db = env.DB;
  const errors: Record<string, string> = {};
  checkKeys(body, ["agent_id", "parent_session_id", "principal", "purpose", "ttl_seconds"], errors);
  const agentKey = typeof body.agent_id === "string" ? body.agent_id.trim().toLowerCase() : "";
  if (!AGENT_KEY.test(agentKey)) errors.agent_id = body.agent_id === undefined ? "is required" : "has an invalid format";
  const parentId = optString(body, "parent_session_id", SESSION_PATH, errors);
  let principalType: (typeof PRINCIPAL_TYPES)[number] = "unknown";
  let principalRef: string | null = null;
  if (body.principal !== undefined && body.principal !== null) {
    if (typeof body.principal !== "object" || Array.isArray(body.principal)) errors.principal = "must be an object";
    else {
      const p = body.principal as Record<string, unknown>;
      const pe: Record<string, string> = {};
      checkKeys(p, ["type", "ref"], pe);
      if (typeof p.type !== "string" || !(PRINCIPAL_TYPES as readonly string[]).includes(p.type)) pe.type = `must be one of ${PRINCIPAL_TYPES.join(", ")}`;
      else principalType = p.type as (typeof PRINCIPAL_TYPES)[number];
      principalRef = optString(p, "ref", PRINTABLE, pe);
      for (const [k, v] of Object.entries(pe)) errors[`principal.${k}`] = v;
    }
  }
  const purpose = optString(body, "purpose", PRINTABLE, errors);
  let ttl = 3600;
  if (body.ttl_seconds !== undefined && body.ttl_seconds !== null) {
    if (typeof body.ttl_seconds !== "number" || !Number.isInteger(body.ttl_seconds) || body.ttl_seconds < 60 || body.ttl_seconds > 86400) errors.ttl_seconds = "must be an integer between 60 and 86400";
    else ttl = body.ttl_seconds;
  }
  fields(errors);

  const agent = await db
    .prepare(`SELECT id, status, environment FROM agents WHERE organization_id = ? AND agent_key = ?`)
    .bind(principal.org_id, agentKey)
    .first<{ id: string; status: string; environment: string }>();
  if (!agent) throw new ApiError(404, "AGENT_UNKNOWN", `Agent "${agentKey}" is not registered in this organization.`);
  if (agent.status !== "active") throw new ApiError(409, "AGENT_DISABLED", `Agent "${agentKey}" is disabled.`);
  if (principal.key_environment === "test" && agent.environment === "production") {
    throw new ApiError(403, "API_KEY_ENVIRONMENT_MISMATCH", "Test API keys cannot open sessions for production agents.");
  }

  const nowIso = iso(nowMs);
  let parent: SessionRow | null = null;
  const signals: Parameters<typeof applyRuntimeSignals>[3] = [];
  if (parentId) {
    const [rows] = await db.batch([lineageStatement(db, parentId, principal.org_id)]);
    const first = (rows!.results as unknown as SessionRow[])[0];
    if (!first || first.organization_id !== principal.org_id) {
      const code: SignalCode = first ? "CROSS_TENANT_REFERENCE" : "SESSION_OR_PARENT_INVALID";
      await applyRuntimeSignals(env, principal, { agentId: agent.id, sessionId: null }, [{ code, evidenceKey: parentId, evidence: { claimed_parent_session_id: parentId } }], [
        runtimeEventStatement(db, { organizationId: principal.org_id, type: "session.refused", source: "mother", outcome: "refused", reasonCode: "PARENT_SESSION_INVALID", agentId: agent.id, apiKeyId: principal.key_id, detail: { claimed_parent_session_id: parentId }, nowIso }),
      ], nowMs, waitUntil);
      throw new ApiError(404, "PARENT_SESSION_INVALID", "The parent session was not found in this organization.");
    }
    if (first.closed_at) throw new ApiError(409, "SESSION_CLOSED", "The parent session is closed.");
    if (first.expires_at <= nowIso) throw new ApiError(409, "SESSION_EXPIRED", "The parent session has expired.");
    if (first.depth + 1 > 8) throw new ApiError(409, "SESSION_DEPTH_EXCEEDED", "Sessions can be nested at most 8 levels deep.");
    parent = first;
    const children = await db
      .prepare(`SELECT COUNT(*) AS n FROM agent_sessions WHERE organization_id = ? AND parent_session_id = ? AND opened_at > ?`)
      .bind(principal.org_id, parent.id, iso(nowMs - 10 * 60_000))
      .first<{ n: number }>();
    const parentSubjects: Array<{ type: SubjectType; id: string }> = [
      { type: "session", id: parent.id },
      { type: "agent", id: parent.agent_id },
    ];
    if ((children?.n ?? 0) + 1 > 10) signals.push({ code: "CHILD_SESSION_FANOUT", evidenceKey: "fanout", evidence: { children_10m: (children?.n ?? 0) + 1, threshold: 10 }, subjects: parentSubjects });
    if (parent.depth + 1 >= 5) signals.push({ code: "CHILD_SESSION_FANOUT", evidenceKey: "depth", evidence: { depth: parent.depth + 1, threshold: 5 }, subjects: parentSubjects });
  }

  // Containment: no new sessions for a quarantined agent or inside a quarantined lineage.
  const scope = await scopeState(db, principal.org_id, agent.id, parent?.id ?? null, principal.key_id, nowIso);
  const refuse = principal.runtime_protection === "enforce" && isContained(scope.worst.state);
  if (refuse) {
    await applyRuntimeSignals(env, principal, { agentId: agent.id, sessionId: parent?.id ?? null }, [{ code: "CONTINUATION_AFTER_QUARANTINE", evidenceKey: "session.open", evidence: { parent_session_id: parent?.id ?? null } }], [
      runtimeEventStatement(db, { organizationId: principal.org_id, type: "session.refused", source: "mother", outcome: "refused", reasonCode: scope.worst.key?.startsWith("session:") ? "SESSION_QUARANTINED" : "AGENT_QUARANTINED", sessionId: parent?.id ?? null, agentId: agent.id, apiKeyId: principal.key_id, incidentId: scope.worst.incidentId, nowIso }),
    ], nowMs, waitUntil);
    throw new ApiError(409, "SESSION_REFUSED", "This agent or session lineage is quarantined. New sessions are refused until an authorized human clears it.", { incident_id: scope.worst.incidentId });
  }

  const sessionId = newId("asn");
  const expiresAt = addSeconds(nowIso, ttl);
  const insert = [
    db
      .prepare(
        `INSERT INTO agent_sessions (id, organization_id, agent_id, api_key_id, parent_session_id, root_session_id, depth, principal_type, principal_ref, purpose, opened_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(sessionId, principal.org_id, agent.id, principal.key_id, parent?.id ?? null, parent?.root_session_id ?? sessionId, parent ? parent.depth + 1 : 0, principalType, principalRef, purpose, nowIso, expiresAt),
    runtimeEventStatement(db, {
      organizationId: principal.org_id,
      type: "session.opened",
      source: "mother",
      outcome: "granted",
      sessionId,
      agentId: agent.id,
      apiKeyId: principal.key_id,
      detail: { parent_session_id: parent?.id ?? null, depth: parent ? parent.depth + 1 : 0, principal_type: principalType, principal_asserted_by: "integration" },
      nowIso,
    }),
  ];
  const result = signals.length
    ? await applyRuntimeSignals(env, principal, { agentId: parent?.agent_id ?? agent.id, sessionId: parent?.id ?? null }, signals, insert, nowMs, waitUntil)
    : (await db.batch(insert), { state: scope.worst.state, incidentId: null, quarantined: false });
  if (result.quarantined && principal.runtime_protection === "enforce") {
    // The fan-out itself quarantined the parent scope; the child exists as evidence but is inside the contained lineage.
    throw new ApiError(409, "SESSION_REFUSED", "Opening this child session quarantined the parent scope.", { incident_id: result.incidentId, session_id: sessionId });
  }
  return json(
    {
      session_id: sessionId,
      root_session_id: parent?.root_session_id ?? sessionId,
      parent_session_id: parent?.id ?? null,
      depth: parent ? parent.depth + 1 : 0,
      agent_id: agentKey,
      principal: { type: principalType, ref: principalRef, asserted_by: "integration" },
      opened_at: nowIso,
      expires_at: expiresAt,
      risk_state: result.state,
    },
    201,
  );
}

export async function closeSession(env: Env, principal: RuntimePrincipal, sessionId: string, nowMs: number): Promise<Response> {
  const db = env.DB;
  const nowIso = iso(nowMs);
  const results = await db.batch([
    db.prepare(`UPDATE agent_sessions SET closed_at = ? WHERE id = ? AND organization_id = ? AND closed_at IS NULL`).bind(nowIso, sessionId, principal.org_id),
    db
      .prepare(
        `INSERT INTO runtime_events (id, organization_id, type, source, outcome, session_id, api_key_id, detail, created_at)
         SELECT ?, ?, 'session.closed', 'mother', 'succeeded', ?, ?, '{}', ? WHERE changes() = 1`,
      )
      .bind(newId("rte"), principal.org_id, sessionId, principal.key_id, nowIso),
  ]);
  if ((results[0]!.meta.changes ?? 0) !== 1) throw new ApiError(404, "SESSION_NOT_FOUND", "Open session not found.");
  return json({ session_id: sessionId, closed_at: nowIso, note: "Closing a session never clears its runtime risk state." });
}

export async function getSession(env: Env, principal: RuntimePrincipal, sessionId: string, nowMs: number): Promise<Response> {
  const db = env.DB;
  const session = await db.prepare(`SELECT * FROM agent_sessions WHERE id = ? AND organization_id = ?`).bind(sessionId, principal.org_id).first<SessionRow>();
  if (!session) throw new ApiError(404, "SESSION_NOT_FOUND", "Session not found.");
  const scope = await scopeState(db, principal.org_id, session.agent_id, session.id, principal.key_id, iso(nowMs));
  return json({
    session_id: session.id,
    root_session_id: session.root_session_id,
    parent_session_id: session.parent_session_id,
    depth: session.depth,
    opened_at: session.opened_at,
    expires_at: session.expires_at,
    closed_at: session.closed_at,
    risk: { mode: principal.runtime_protection, state: scope.worst.state, incident_id: isContained(scope.worst.state) ? scope.worst.incidentId : null },
  });
}

// ---------------------------------------------------------------------------
// Capability lease use
// ---------------------------------------------------------------------------

interface LeaseRow {
  id: string;
  organization_id: string;
  agent_id: string;
  session_id: string;
  api_key_id: string;
  decision_id: string;
  capability: string;
  operation: string;
  resource: string | null;
  destination: string | null;
  data_class: string | null;
  max_uses: number;
  uses: number;
  issued_at: string;
  expires_at: string;
  revoked_at: string | null;
  revoked_reason: string | null;
}

const LEASE_SIGNAL: Partial<Record<string, SignalCode>> = {
  LEASE_REVOKED: "USE_AFTER_EXPIRY_OR_REVOCATION",
  LEASE_EXPIRED: "USE_AFTER_EXPIRY_OR_REVOCATION",
  LEASE_EXHAUSTED: "USE_AFTER_EXPIRY_OR_REVOCATION",
  LEASE_INVALIDATED: "USE_AFTER_EXPIRY_OR_REVOCATION",
  LEASE_QUARANTINED: "CONTINUATION_AFTER_QUARANTINE",
};

const LEASE_MESSAGE: Record<string, string> = {
  LEASE_KEY_MISMATCH: "This lease was issued to a different API key.",
  LEASE_REVOKED: "This lease was revoked.",
  LEASE_EXPIRED: "This lease has expired.",
  LEASE_EXHAUSTED: "This lease has no uses remaining.",
  LEASE_INVALIDATED: "This lease was issued before its scope was contained. It can never be used; request new authority.",
  LEASE_AGENT_INACTIVE: "The agent is no longer active.",
  LEASE_SESSION_CLOSED: "The lease's session is closed.",
  LEASE_SESSION_EXPIRED: "The lease's session has expired.",
  LEASE_QUARANTINED: "This agent or session is quarantined.",
  LEASE_RISK_REVIEW: "Runtime risk for this scope requires human review; leases cannot be used.",
  LEASE_POLICY_CHANGED: "A policy changed after this lease was issued; evaluate the action again.",
  LEASE_SCOPE_MISMATCH: "The lease does not cover this exact resource, destination and data class.",
};

export async function useLease(env: Env, principal: RuntimePrincipal, leaseId: string, body: Record<string, unknown>, nowMs: number, waitUntil: WaitUntil): Promise<Response> {
  const db = env.DB;
  const errors: Record<string, string> = {};
  checkKeys(body, ["resource", "destination", "data_class"], errors);
  const resource = optString(body, "resource", /^[^\x00-\x1f\x7f]{1,512}$/, errors);
  const destination = optString(body, "destination", TOKEN, errors, true);
  const dataClass = optString(body, "data_class", TOKEN, errors, true);
  fields(errors);

  const nowIso = iso(nowMs);
  const lease = await db.prepare(`SELECT * FROM capability_leases WHERE id = ?`).bind(leaseId).first<LeaseRow>();
  if (!lease || lease.organization_id !== principal.org_id) {
    if (lease) {
      await applyRuntimeSignals(env, principal, { agentId: null, sessionId: null }, [{ code: "CROSS_TENANT_REFERENCE", evidenceKey: leaseId, evidence: { claimed_lease_id: leaseId } }], [], nowMs, waitUntil);
    }
    throw new ApiError(404, "LEASE_NOT_FOUND", "Lease not found.");
  }

  const [agentRows, sessionRows, policyRows] = await db.batch([
    db.prepare(`SELECT status FROM agents WHERE id = ? AND organization_id = ?`).bind(lease.agent_id, principal.org_id),
    db.prepare(`SELECT closed_at, expires_at FROM agent_sessions WHERE id = ? AND organization_id = ?`).bind(lease.session_id, principal.org_id),
    db.prepare(`SELECT COUNT(*) AS n FROM policies WHERE organization_id = ? AND updated_at > ?`).bind(principal.org_id, lease.issued_at),
  ]);
  const agent = agentRows!.results[0] as { status: string } | undefined;
  const session = sessionRows!.results[0] as { closed_at: string | null; expires_at: string } | undefined;
  const policyChanges = (policyRows!.results[0] as { n: number }).n;
  const scope = await scopeState(db, principal.org_id, lease.agent_id, lease.session_id, principal.key_id, nowIso);
  const enforce = principal.runtime_protection === "enforce";

  let refusal: string | null = null;
  if (lease.api_key_id !== principal.key_id) refusal = "LEASE_KEY_MISMATCH";
  else if (lease.revoked_at) refusal = "LEASE_REVOKED";
  else if (lease.expires_at <= nowIso) refusal = "LEASE_EXPIRED";
  else if (lease.uses >= lease.max_uses) refusal = "LEASE_EXHAUSTED";
  else if (scope.epoch && lease.issued_at < scope.epoch) refusal = "LEASE_INVALIDATED";
  else if (!agent || agent.status !== "active") refusal = "LEASE_AGENT_INACTIVE";
  else if (!session || session.closed_at) refusal = "LEASE_SESSION_CLOSED";
  else if (session.expires_at <= nowIso) refusal = "LEASE_SESSION_EXPIRED";
  else if (enforce && isContained(scope.worst.state)) refusal = "LEASE_QUARANTINED";
  else if (enforce && scope.worst.state === "review_required") refusal = "LEASE_RISK_REVIEW";
  else if (policyChanges > 0) refusal = "LEASE_POLICY_CHANGED";
  else if (resource !== lease.resource || destination !== lease.destination || dataClass !== lease.data_class) refusal = "LEASE_SCOPE_MISMATCH";

  const useRow = (outcome: "granted" | "refused", code: string | null, state: RiskState) =>
    db
      .prepare(
        `INSERT INTO lease_uses (id, organization_id, lease_id, api_key_id, outcome, refusal_code, resource, destination, data_class, effective_state, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(newId("lsu"), principal.org_id, lease.id, principal.key_id, outcome, code, resource, destination, dataClass, state, nowIso);

  if (!refusal) {
    const claim = await db
      .prepare(
        `UPDATE capability_leases SET uses = uses + 1
          WHERE id = ? AND organization_id = ? AND api_key_id = ? AND revoked_at IS NULL AND expires_at > ? AND uses < max_uses`,
      )
      .bind(lease.id, principal.org_id, principal.key_id, nowIso)
      .run();
    if ((claim.meta.changes ?? 0) === 1) {
      await db.batch([
        useRow("granted", null, scope.worst.state),
        runtimeEventStatement(db, { organizationId: principal.org_id, type: "lease.used", source: "mother", outcome: "granted", sessionId: lease.session_id, agentId: lease.agent_id, apiKeyId: principal.key_id, decisionId: lease.decision_id, leaseId: lease.id, detail: { use: lease.uses + 1, max_uses: lease.max_uses }, nowIso }),
      ]);
      return json({ granted: true, lease_id: lease.id, uses: lease.uses + 1, uses_remaining: lease.max_uses - lease.uses - 1, expires_at: lease.expires_at, capability: lease.capability, operation: lease.operation });
    }
    refusal = "LEASE_EXHAUSTED";
  }

  const signal = LEASE_SIGNAL[refusal];
  const extra = [
    useRow("refused", refusal, scope.worst.state),
    runtimeEventStatement(db, { organizationId: principal.org_id, type: "lease.refused", source: "mother", outcome: "refused", reasonCode: refusal, sessionId: lease.session_id, agentId: lease.agent_id, apiKeyId: principal.key_id, decisionId: lease.decision_id, leaseId: lease.id, incidentId: scope.worst.incidentId, nowIso }),
  ];
  if (signal) {
    await applyRuntimeSignals(env, principal, { agentId: lease.agent_id, sessionId: lease.session_id }, [{ code: signal, evidenceKey: `${refusal}:${lease.id}`, evidence: { lease_id: lease.id, refusal } }], extra, nowMs, waitUntil);
  } else {
    await db.batch(extra);
  }
  return json({ decision: "block", granted: false, error: { code: refusal, message: LEASE_MESSAGE[refusal] ?? "Lease use refused." } }, 409);
}

// ---------------------------------------------------------------------------
// Integration-reported execution results
// ---------------------------------------------------------------------------

const OUTCOMES = ["succeeded", "failed", "skipped"] as const;

export async function reportEvent(env: Env, principal: RuntimePrincipal, body: Record<string, unknown>, nowMs: number, waitUntil: WaitUntil): Promise<Response> {
  const db = env.DB;
  const errors: Record<string, string> = {};
  checkKeys(body, ["type", "decision_id", "outcome", "detail"], errors);
  if (body.type !== "execution.reported") errors.type = 'must be "execution.reported"';
  const decisionId = optString(body, "decision_id", /^dec_[0-9A-Za-z]{22}$/, errors);
  if (!decisionId && !errors.decision_id) errors.decision_id = "is required";
  const outcome = typeof body.outcome === "string" && (OUTCOMES as readonly string[]).includes(body.outcome) ? (body.outcome as (typeof OUTCOMES)[number]) : null;
  if (!outcome) errors.outcome = `must be one of ${OUTCOMES.join(", ")}`;
  let detail: Record<string, unknown> = {};
  if (body.detail !== undefined && body.detail !== null) {
    if (typeof body.detail !== "object" || Array.isArray(body.detail) || JSON.stringify(body.detail).length > 2048) errors.detail = "must be a JSON object of at most 2 KB";
    else detail = body.detail as Record<string, unknown>;
  }
  fields(errors);

  const nowIso = iso(nowMs);
  const decision = await db
    .prepare(
      `SELECT d.id, d.organization_id, d.agent_id, d.session_id, d.request_id, d.decision, ap.id AS approval_id, ap.consumed_at
         FROM decisions d LEFT JOIN approvals ap ON ap.decision_id = d.id AND ap.organization_id = d.organization_id
        WHERE d.id = ?`,
    )
    .bind(decisionId)
    .first<{ id: string; organization_id: string; agent_id: string | null; session_id: string | null; request_id: string; decision: string; approval_id: string | null; consumed_at: string | null }>();
  if (!decision || decision.organization_id !== principal.org_id) {
    if (decision) {
      await applyRuntimeSignals(env, principal, { agentId: null, sessionId: null }, [{ code: "CROSS_TENANT_REFERENCE", evidenceKey: decisionId!, evidence: { claimed_decision_id: decisionId } }], [], nowMs, waitUntil);
    }
    throw new ApiError(404, "DECISION_NOT_FOUND", "Decision not found.");
  }

  const unauthorized = outcome === "succeeded" && (decision.decision === "block" || (decision.decision === "review" && !decision.consumed_at));
  const eventId = newId("rte");
  const event = db
    .prepare(
      `INSERT INTO runtime_events (id, organization_id, type, source, outcome, reason_code, session_id, agent_id, api_key_id, decision_id, request_id, approval_id, detail, created_at)
       VALUES (?, ?, 'execution.reported', 'integration', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      eventId,
      principal.org_id,
      outcome,
      unauthorized ? "EXECUTED_WITHOUT_AUTHORIZATION" : null,
      decision.session_id,
      decision.agent_id,
      principal.key_id,
      decision.id,
      decision.request_id,
      decision.approval_id,
      JSON.stringify({ reported_by: "integration", detail }).slice(0, 4096),
      nowIso,
    );
  const result = await applyRuntimeSignals(
    env,
    principal,
    { agentId: decision.agent_id, sessionId: decision.session_id },
    unauthorized ? [{ code: "EXECUTED_WITHOUT_AUTHORIZATION", evidenceKey: decision.id, evidence: { decision_id: decision.id, effective_decision: decision.decision, approval_consumed: !!decision.consumed_at } }] : [],
    [event],
    nowMs,
    waitUntil,
    { decisionId: decision.id },
  );
  return json({ event_id: eventId, recorded: true, source: "integration", violation: unauthorized ? "EXECUTED_WITHOUT_AUTHORIZATION" : null, risk: { mode: principal.runtime_protection, state: result.state, incident_id: result.incidentId } }, 201);
}

// ---------------------------------------------------------------------------
// Approval consumption under containment
// ---------------------------------------------------------------------------

/**
 * Refuses consumption of a grant issued before the scope's containment epoch (forever, including after
 * clearance), or while the scope is quarantined in enforce mode. Returns null when consumption may proceed.
 */
export async function approvalContainmentRefusal(env: Env, principal: RuntimePrincipal, approvalId: string, nowMs: number, waitUntil: WaitUntil): Promise<ApiError | null> {
  const db = env.DB;
  const row = await db
    .prepare(
      `SELECT ap.id, ap.requested_at, ap.status, d.id AS decision_id, d.agent_id, d.session_id, d.request_id
         FROM approvals ap JOIN decisions d ON d.id = ap.decision_id AND d.organization_id = ap.organization_id
        WHERE ap.id = ? AND ap.organization_id = ?`,
    )
    .bind(approvalId, principal.org_id)
    .first<{ id: string; requested_at: string; status: string; decision_id: string; agent_id: string | null; session_id: string | null; request_id: string }>();
  if (!row) return null;
  const nowIso = iso(nowMs);
  const scope = await scopeState(db, principal.org_id, row.agent_id, row.session_id, principal.key_id, nowIso);
  let code: "APPROVAL_INVALIDATED" | "APPROVAL_QUARANTINED" | null = null;
  if (scope.epoch && row.requested_at < scope.epoch) code = "APPROVAL_INVALIDATED";
  else if (principal.runtime_protection === "enforce" && isContained(scope.worst.state)) code = "APPROVAL_QUARANTINED";
  if (!code) return null;
  await applyRuntimeSignals(
    env,
    principal,
    { agentId: row.agent_id, sessionId: row.session_id },
    [{ code: code === "APPROVAL_INVALIDATED" ? "USE_AFTER_EXPIRY_OR_REVOCATION" : "CONTINUATION_AFTER_QUARANTINE", evidenceKey: `${code}:${row.id}`, evidence: { approval_id: row.id, refusal: code } }],
    [runtimeEventStatement(db, { organizationId: principal.org_id, type: "approval.consume_refused", source: "mother", outcome: "refused", reasonCode: code, sessionId: row.session_id, agentId: row.agent_id, apiKeyId: principal.key_id, decisionId: row.decision_id, requestId: row.request_id, approvalId: row.id, incidentId: scope.worst.incidentId, nowIso })],
    nowMs,
    waitUntil,
  );
  return code === "APPROVAL_INVALIDATED"
    ? new ApiError(409, code, "This approval was issued before its scope was contained. It can never be used; request new authority.", { status: row.status })
    : new ApiError(409, code, "This agent or session is quarantined. Approved grants cannot be consumed until an authorized human clears it, and grants issued before the quarantine never become usable.", { status: row.status, incident_id: scope.worst.incidentId });
}

/** Records a refused consume (expired, denied, consumed, grant expired) as runtime evidence. Never throws. */
export async function recordConsumeRefusal(env: Env, principal: RuntimePrincipal, approvalId: string, code: string, nowMs: number, waitUntil: WaitUntil): Promise<void> {
  try {
    if (principal.runtime_protection === "off") return;
    const db = env.DB;
    const row = await db
      .prepare(`SELECT d.id AS decision_id, d.agent_id, d.session_id, d.request_id FROM approvals ap JOIN decisions d ON d.id = ap.decision_id AND d.organization_id = ap.organization_id WHERE ap.id = ? AND ap.organization_id = ?`)
      .bind(approvalId, principal.org_id)
      .first<{ decision_id: string; agent_id: string | null; session_id: string | null; request_id: string }>();
    if (!row) return;
    await applyRuntimeSignals(
      env,
      principal,
      { agentId: row.agent_id, sessionId: row.session_id },
      [{ code: "USE_AFTER_EXPIRY_OR_REVOCATION", evidenceKey: `${code}:${approvalId}`, evidence: { approval_id: approvalId, refusal: code } }],
      [runtimeEventStatement(db, { organizationId: principal.org_id, type: "approval.consume_refused", source: "mother", outcome: "refused", reasonCode: code, sessionId: row.session_id, agentId: row.agent_id, apiKeyId: principal.key_id, decisionId: row.decision_id, requestId: row.request_id, approvalId, nowIso: iso(nowMs) })],
      nowMs,
      waitUntil,
    );
  } catch (err) {
    console.error("consume refusal evidence failed", err instanceof Error ? err.name : "unknown");
  }
}
