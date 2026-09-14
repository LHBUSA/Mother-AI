// Runtime layer for /v1/evaluate: correlation validation, risk assessment and the write statements
// that ride in the same atomic batch as the decision.
//
// Order (see handleEvaluate): identity gates -> correlation gate -> policy engine -> runtime risk
// -> effective decision = restrict(policy, runtime) in enforce mode, = policy in monitor mode.

import { newId } from "../lib/crypto";
import { addSeconds } from "../lib/time";
import type { CorrelationInput } from "../gateway/normalize";
import {
  RISK_ENGINE_VERSION,
  SIGNAL_RULES,
  assessSubject,
  countingSignals,
  dataClassRank,
  dedupeSignals,
  detectEvaluationSignals,
  effectiveDecision,
  isContained,
  stateSeverity,
  verdictForState,
  type NewSignal,
  type RiskMode,
  type RiskState,
  type SubjectAssessment,
  type SubjectType,
  type Verdict,
} from "./engine";
import { quarantineStatements } from "./containment";
import {
  alertQueueStatement,
  lineageStatement,
  runtimeEventStatement,
  signalStatements,
  signalsStatement,
  snapshotFrom,
  subjectKey,
  subjectUpsertStatement,
  subjectsStatement,
  transitionIfChangedStatement,
  worstSubject,
  type RiskSnapshot,
  type SessionRow,
  type SignalWrite,
} from "./store";

export type CorrelationStatus = "none" | "valid" | "missing" | "cross_tenant" | "mismatch" | "closed" | "expired";

export interface RuntimeContext {
  mode: RiskMode;
  alertsEnabled: boolean;
  organizationId: string;
  apiKeyId: string;
  agentId: string | null;
  nowMs: number;
  nowIso: string;
  chain: SessionRow[];
  session: CorrelationStatus;
  parent: "none" | "valid" | "missing" | "cross_tenant" | "outside_lineage";
  snapshot: RiskSnapshot;
  counts: { blocks10m: number; unknown10m: number; session60s: number; sessionResources5m: number; sessionMaxDataRank: number };
  baseline: { capabilityOperationAllowed: boolean; mcpToolAllowed: boolean; destinationAllowed: boolean; destinationBaselineSize: number };
}

interface ActionFacts {
  capability: string;
  operation: string;
  protocol: "api" | "mcp";
  destination: string | null;
  dataClass: string | null;
  mcpTool: string | null;
}

const EMPTY_SNAPSHOT: RiskSnapshot = { subjects: new Map(), signals: [] };

/** Everything the runtime layer needs, in at most two read batches. */
export async function loadRuntimeContext(
  db: D1Database,
  p: {
    mode: RiskMode;
    alertsEnabled: boolean;
    organizationId: string;
    apiKeyId: string;
    agentId: string | null;
    agentKnownAsUnknown: boolean;
    correlation: CorrelationInput | null;
    action: ActionFacts;
    nowMs: number;
  },
): Promise<RuntimeContext> {
  const nowIso = new Date(p.nowMs).toISOString();
  const sessionId = p.correlation?.sessionId ?? null;
  const parentId = p.correlation?.parentDecisionId ?? null;

  // Batch 1: correlation (only if the request carries it).
  let chain: SessionRow[] = [];
  let session: CorrelationStatus = "none";
  let parent: RuntimeContext["parent"] = "none";
  if (sessionId || parentId) {
    const statements: D1PreparedStatement[] = [];
    if (sessionId) statements.push(lineageStatement(db, sessionId, p.organizationId));
    if (parentId) statements.push(db.prepare(`SELECT id, organization_id, session_id, agent_id FROM decisions WHERE id = ?`).bind(parentId));
    const results = await db.batch(statements);
    let i = 0;
    if (sessionId) {
      const rows = results[i++]!.results as unknown as SessionRow[];
      const first = rows[0];
      if (!first) session = "missing";
      else if (first.organization_id !== p.organizationId) session = "cross_tenant";
      else if (!p.agentId || first.agent_id !== p.agentId || first.api_key_id !== p.apiKeyId) session = "mismatch";
      else if (first.closed_at) session = "closed";
      else if (first.expires_at <= nowIso) session = "expired";
      else session = "valid";
      if (first && first.organization_id === p.organizationId) chain = rows;
    }
    if (parentId) {
      const row = results[i]!.results[0] as { id: string; organization_id: string; session_id: string | null; agent_id: string | null } | undefined;
      if (!row) parent = "missing";
      else if (row.organization_id !== p.organizationId) parent = "cross_tenant";
      else if (sessionId ? !(session === "valid" && row.session_id && chain.some((s) => s.id === row.session_id)) : row.session_id !== null || row.agent_id !== p.agentId) parent = "outside_lineage";
      else parent = "valid";
    }
  }

  const empty: RuntimeContext = {
    mode: p.mode,
    alertsEnabled: p.alertsEnabled,
    organizationId: p.organizationId,
    apiKeyId: p.apiKeyId,
    agentId: p.agentId,
    nowMs: p.nowMs,
    nowIso,
    chain,
    session,
    parent,
    snapshot: EMPTY_SNAPSHOT,
    counts: { blocks10m: 0, unknown10m: 0, session60s: 0, sessionResources5m: 0, sessionMaxDataRank: 0 },
    baseline: { capabilityOperationAllowed: true, mcpToolAllowed: true, destinationAllowed: true, destinationBaselineSize: 0 },
  };
  if (p.mode === "off") return empty;

  // Batch 2: risk state, windows and baselines.
  const validSession = session === "valid" ? sessionId : null;
  const lineageSessions = chain.map((s) => s.id);
  const lineageAgents = [...new Set([...(p.agentId ? [p.agentId] : []), ...chain.map((s) => s.agent_id)])];
  const direct: Array<{ type: SubjectType; id: string }> = [{ type: "api_key", id: p.apiKeyId }];
  if (p.agentId) direct.push({ type: "agent", id: p.agentId });
  if (validSession) direct.push({ type: "session", id: validSession });
  const t = (ms: number) => new Date(p.nowMs - ms).toISOString();

  const blockScope = validSession ? "session_id = ?" : "agent_id = ?";
  const statements: D1PreparedStatement[] = [
    subjectsStatement(db, p.organizationId, lineageAgents, lineageSessions, p.apiKeyId),
    signalsStatement(db, p.organizationId, direct, nowIso),
    db
      .prepare(
        `SELECT
           (SELECT COUNT(*) FROM decisions WHERE organization_id = ?1 AND ${blockScope.replace("?", "?2")} AND decision = 'block' AND created_at > ?3) AS blocks_10m,
           (CASE WHEN ?4 = 1 THEN (SELECT COUNT(*) FROM decisions WHERE organization_id = ?1 AND api_key_id = ?5 AND reason_code = 'AGENT_UNKNOWN' AND created_at > ?3) ELSE 0 END) AS unknown_10m,
           (SELECT COUNT(*) FROM decisions WHERE organization_id = ?1 AND session_id = ?6 AND created_at > ?7) AS session_60s,
           (SELECT COUNT(DISTINCT resource) FROM decisions WHERE organization_id = ?1 AND session_id = ?6 AND created_at > ?8) AS session_resources_5m,
           (SELECT GROUP_CONCAT(DISTINCT data_class) FROM decisions WHERE organization_id = ?1 AND session_id = ?6 AND data_class IS NOT NULL) AS session_data_classes`,
      )
      .bind(p.organizationId, validSession ?? p.agentId ?? "-", t(10 * 60_000), p.agentKnownAsUnknown ? 1 : 0, p.apiKeyId, validSession ?? "-", t(60_000), t(5 * 60_000)),
  ];
  if (p.agentId) {
    const since = t(30 * 24 * 60 * 60_000);
    statements.push(
      db
        .prepare(
          `SELECT kind, value FROM agent_baselines
            WHERE agent_id = ?1 AND organization_id = ?2 AND last_allowed_at > ?3
              AND ((kind = 'capability_operation' AND value = ?4) OR (kind = 'mcp_tool' AND value = ?5) OR (kind = 'destination' AND value = ?6))`,
        )
        .bind(p.agentId, p.organizationId, since, `${p.action.capability}.${p.action.operation}`, p.action.mcpTool ?? "-", p.action.destination ?? "-"),
      db
        .prepare(`SELECT COALESCE(SUM(allow_count), 0) AS n FROM agent_baselines WHERE agent_id = ? AND organization_id = ? AND kind = 'destination' AND last_allowed_at > ?`)
        .bind(p.agentId, p.organizationId, since),
    );
  }
  const results = await db.batch(statements);
  const counts = results[2]!.results[0] as { blocks_10m: number; unknown_10m: number; session_60s: number; session_resources_5m: number; session_data_classes: string | null };
  const baselineRows = p.agentId ? (results[3]!.results as Array<{ kind: string; value: string }>) : [];
  const has = (kind: string) => baselineRows.some((r) => r.kind === kind);
  return {
    ...empty,
    snapshot: snapshotFrom(results[0]!.results as never, results[1]!.results as never),
    counts: {
      blocks10m: counts.blocks_10m,
      unknown10m: counts.unknown_10m,
      session60s: counts.session_60s,
      sessionResources5m: counts.session_resources_5m,
      sessionMaxDataRank: Math.max(0, ...(counts.session_data_classes ?? "").split(",").filter(Boolean).map(dataClassRank)),
    },
    baseline: {
      capabilityOperationAllowed: has("capability_operation"),
      mcpToolAllowed: has("mcp_tool"),
      destinationAllowed: has("destination"),
      destinationBaselineSize: p.agentId ? ((results[4]!.results[0] as { n: number }).n ?? 0) : 0,
    },
  };
}

export interface CorrelationGate {
  reasonCode: "SESSION_INVALID" | "SESSION_CLOSED" | "SESSION_EXPIRED" | "PARENT_INVALID";
  reason: string;
  signal: { kind: "cross_tenant" | "invalid"; claimed: string } | null;
}

/** Request-integrity gate for correlation fields. Applies in every mode; existing clients never send them. */
export function correlationGate(ctx: RuntimeContext | null, correlation: CorrelationInput | null): CorrelationGate | null {
  if (!ctx || !correlation) return null;
  if (correlation.sessionId && ctx.session !== "valid") {
    const claimed = correlation.sessionId;
    switch (ctx.session) {
      case "closed":
        return { reasonCode: "SESSION_CLOSED", reason: "The session is closed. Open a new session.", signal: null };
      case "expired":
        return { reasonCode: "SESSION_EXPIRED", reason: "The session has expired. Open a new session.", signal: null };
      case "cross_tenant":
        return { reasonCode: "SESSION_INVALID", reason: "The session does not belong to this agent and API key.", signal: { kind: "cross_tenant", claimed } };
      default:
        return { reasonCode: "SESSION_INVALID", reason: "The session does not belong to this agent and API key.", signal: { kind: "invalid", claimed } };
    }
  }
  if (correlation.parentDecisionId && ctx.parent !== "valid") {
    const claimed = correlation.parentDecisionId;
    return {
      reasonCode: "PARENT_INVALID",
      reason: "The parent decision is not part of this session lineage.",
      signal: { kind: ctx.parent === "cross_tenant" ? "cross_tenant" : "invalid", claimed },
    };
  }
  return null;
}

export interface RuntimeAssessment {
  mode: "monitor" | "enforce";
  policyDecision: Verdict;
  runtimeDecision: Verdict;
  effective: Verdict;
  riskReasonCode: string | null;
  riskReason: string | null;
  effectiveState: RiskState;
  ceilingSubject: string | null;
  score: number;
  signals: NewSignal[];
  assessments: SubjectAssessment[];
  quarantine: { subjectType: "agent" | "session"; subjectId: string; fromState: RiskState; score: number; cause: "score_quarantine" | "hard_signal_quarantine" } | null;
  existingIncidentId: string | null;
}

const REASON_FOR_SUBJECT = (key: string | null) => (key?.startsWith("session:") ? "SESSION_QUARANTINED" : "AGENT_QUARANTINED");

export function assessEvaluation(
  ctx: RuntimeContext,
  input: {
    policyDecision: Verdict;
    gateReason: string | null;
    correlationSignal: CorrelationGate["signal"];
    action: ActionFacts;
    validSessionId: string | null;
  },
): RuntimeAssessment | null {
  if (ctx.mode === "off") return null;
  const mode = ctx.mode;
  const agentKey = ctx.agentId ? subjectKey("agent", ctx.agentId) : null;
  const sessionKey = input.validSessionId ? subjectKey("session", input.validSessionId) : null;
  const keyKey = subjectKey("api_key", ctx.apiKeyId);
  const lineageKeys = [
    ...ctx.chain.map((s) => subjectKey("session", s.id)),
    ...new Set(ctx.chain.map((s) => subjectKey("agent", s.agent_id))),
  ];
  const scopeKeys = [...new Set([...(agentKey ? [agentKey] : []), ...(input.validSessionId ? lineageKeys : []), keyKey])];
  const before = worstSubject(ctx.snapshot, scopeKeys);
  const inQuarantinedScope = mode === "enforce" && isContained(before.state);

  const detected = detectEvaluationSignals({
    agentId: ctx.agentId,
    sessionId: input.validSessionId,
    apiKeyId: ctx.apiKeyId,
    gateReason: input.gateReason,
    policyDecision: input.policyDecision,
    protocol: input.action.protocol,
    capability: input.action.capability,
    operation: input.action.operation,
    destination: input.action.destination,
    dataClass: input.action.dataClass,
    mcpTool: input.action.mcpTool,
    recentBlocks: ctx.counts.blocks10m + (input.policyDecision === "block" ? 1 : 0),
    unknownAgentAttempts10m: ctx.counts.unknown10m + (input.gateReason === "AGENT_UNKNOWN" ? 1 : 0),
    sessionRequests60s: ctx.counts.session60s + 1,
    sessionDistinctResources5m: ctx.counts.sessionResources5m,
    sessionMaxDataRank: ctx.counts.sessionMaxDataRank,
    baseline: ctx.baseline,
    correlation: input.correlationSignal,
    inQuarantinedScope,
  });

  const direct: Array<{ type: SubjectType; id: string }> = [{ type: "api_key", id: ctx.apiKeyId }];
  if (ctx.agentId) direct.push({ type: "agent", id: ctx.agentId });
  if (input.validSessionId) direct.push({ type: "session", id: input.validSessionId });
  const { signals, assessments, quarantine } = planSubjects(mode, ctx.snapshot, direct, detected, ctx.nowIso);

  const overrides = new Map<string, RiskState>();
  for (const a of assessments) overrides.set(subjectKey(a.subjectType, a.subjectId), mode === "monitor" ? a.wouldState : a.nextState);
  const after = worstSubject(ctx.snapshot, scopeKeys, overrides);
  const runtimeDecision = verdictForState(after.state);
  const effective = effectiveDecision(mode, input.policyDecision, runtimeDecision);
  const riskReasonCode = runtimeDecision === "block" ? REASON_FOR_SUBJECT(after.key) : runtimeDecision === "review" ? "RISK_REVIEW_REQUIRED" : null;
  const riskReason =
    runtimeDecision === "block"
      ? `Runtime containment: ${after.key?.startsWith("session:") ? "this session" : "this agent"} is quarantined. Every action in scope is blocked until an authorized human clears it.`
      : runtimeDecision === "review"
        ? "Runtime risk requires human review for this scope before the action may proceed."
        : null;

  return {
    mode,
    policyDecision: input.policyDecision,
    runtimeDecision,
    effective,
    riskReasonCode,
    riskReason,
    effectiveState: after.state,
    ceilingSubject: stateSeverity(after.state) > 0 ? after.key : null,
    score: Math.max(0, ...assessments.map((a) => a.score)),
    signals,
    assessments,
    quarantine,
    existingIncidentId: isContained(before.state) ? (before.row?.incident_id ?? null) : null,
  };
}

export interface RuntimeWrites {
  statements: D1PreparedStatement[];
  signalWrites: SignalWrite[];
  incidentId: string | null;
  alertsQueued: boolean;
  leaseId: string | null;
  leaseExpiresAt: string | null;
}

/** Statements that must follow the decision INSERT in the same batch. */
export function runtimeWriteStatements(
  db: D1Database,
  ctx: RuntimeContext,
  a: RuntimeAssessment | null,
  d: {
    decisionId: string;
    requestId: string;
    agent: { id: string } | null;
    validSessionId: string | null;
    claimedSessionId: string | null;
    claimedParentId: string | null;
    action: ActionFacts & { resource: string | null };
    policy: { id: string | null; version: number | null };
    lease: CorrelationInput["lease"];
    effective: Verdict;
  },
): RuntimeWrites {
  const statements: D1PreparedStatement[] = [];
  const out: RuntimeWrites = { statements, signalWrites: [], incidentId: null, alertsQueued: false, leaseId: null, leaseExpiresAt: null };

  if (a) {
    const w = subjectWriteStatements(db, { organizationId: ctx.organizationId, mode: a.mode, alertsEnabled: ctx.alertsEnabled, nowMs: ctx.nowMs, nowIso: ctx.nowIso }, a, {
      decisionId: d.decisionId,
      sessionId: d.validSessionId,
    });
    statements.push(...w.statements);
    out.signalWrites = w.signalWrites;
    out.incidentId = w.incidentId;
    out.alertsQueued = w.alertsQueued;

    statements.push(
      db
        .prepare(
          `INSERT INTO risk_evaluations (decision_id, organization_id, engine_version, mode, policy_decision, runtime_risk_decision, effective_decision,
                                        risk_reason_code, effective_state, ceiling_subject, score, signal_ids, claimed_session_id, claimed_parent_id, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          d.decisionId,
          ctx.organizationId,
          RISK_ENGINE_VERSION,
          a.mode,
          a.policyDecision,
          a.runtimeDecision,
          d.effective,
          a.riskReasonCode,
          a.effectiveState,
          a.ceilingSubject,
          a.score,
          JSON.stringify(out.signalWrites.map((w) => w.id)),
          d.claimedSessionId,
          d.claimedParentId,
          ctx.nowIso,
        ),
    );
  }

  // Behavioral baseline: only allowed decisions extend what is "normal" for an agent.
  if (d.effective === "allow" && d.agent && ctx.mode !== "off") {
    const upsert = (kind: string, value: string) =>
      db
        .prepare(
          `INSERT INTO agent_baselines (organization_id, agent_id, kind, value, first_allowed_at, last_allowed_at, allow_count)
           VALUES (?, ?, ?, ?, ?, ?, 1)
           ON CONFLICT (agent_id, kind, value) DO UPDATE SET last_allowed_at = excluded.last_allowed_at, allow_count = agent_baselines.allow_count + 1`,
        )
        .bind(ctx.organizationId, d.agent!.id, kind, value.slice(0, 256), ctx.nowIso, ctx.nowIso);
    statements.push(upsert("capability_operation", `${d.action.capability}.${d.action.operation}`));
    if (d.action.protocol === "mcp" && d.action.mcpTool) statements.push(upsert("mcp_tool", d.action.mcpTool));
    if (d.action.destination) statements.push(upsert("destination", d.action.destination));
  }

  // Capability lease: only for an allowed action in a valid session that asked for one.
  if (d.lease && d.effective === "allow" && d.validSessionId && d.agent) {
    const session = ctx.chain[0]!;
    const leaseId = newId("lse");
    const expiresAt = addSeconds(ctx.nowIso, d.lease.ttlSeconds);
    statements.push(
      db
        .prepare(
          `INSERT INTO capability_leases (id, organization_id, agent_id, session_id, api_key_id, decision_id, principal_type, principal_ref,
                                          capability, operation, resource, destination, data_class, policy_id, policy_version, max_uses, uses,
                                          issued_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
        )
        .bind(
          leaseId,
          ctx.organizationId,
          d.agent.id,
          d.validSessionId,
          ctx.apiKeyId,
          d.decisionId,
          session.principal_type,
          session.principal_ref,
          d.action.capability,
          d.action.operation,
          d.action.resource,
          d.action.destination,
          d.action.dataClass,
          d.policy.id,
          d.policy.version,
          d.lease.maxUses,
          ctx.nowIso,
          expiresAt,
        ),
      runtimeEventStatement(db, {
        organizationId: ctx.organizationId,
        type: "lease.issued",
        source: "mother",
        outcome: "granted",
        sessionId: d.validSessionId,
        agentId: d.agent.id,
        apiKeyId: ctx.apiKeyId,
        decisionId: d.decisionId,
        requestId: d.requestId,
        leaseId,
        detail: { ttl_seconds: d.lease.ttlSeconds, max_uses: d.lease.maxUses },
        nowIso: ctx.nowIso,
      }),
    );
    out.leaseId = leaseId;
    out.leaseExpiresAt = expiresAt;
  }
  return out;
}

/** Signal rule summary for API responses. */
export function signalSummary(a: RuntimeAssessment | null) {
  return a ? [...new Set(a.signals.map((s) => s.code))].map((code) => ({ code, points: SIGNAL_RULES[code].points, hard: SIGNAL_RULES[code].hard })) : [];
}

export interface SubjectPlan {
  signals: NewSignal[];
  assessments: SubjectAssessment[];
  quarantine: RuntimeAssessment["quarantine"];
}

/** Deduplicates signals, assesses each direct subject and picks at most one quarantine target (the agent covers its sessions). */
export function planSubjects(mode: "monitor" | "enforce", snapshot: RiskSnapshot, direct: Array<{ type: SubjectType; id: string }>, detected: NewSignal[], nowIso: string): SubjectPlan {
  const countingBySubject = new Map<string, ReturnType<typeof countingSignals>>();
  for (const d of direct) {
    const key = subjectKey(d.type, d.id);
    const row = snapshot.subjects.get(key) ?? null;
    countingBySubject.set(key, countingSignals(row, snapshot.signals.filter((s) => s.subject_type === d.type && s.subject_id === d.id), nowIso));
  }
  const signals = dedupeSignals(detected, [...countingBySubject.values()].flat());
  const assessments = direct.map((d) => {
    const key = subjectKey(d.type, d.id);
    return assessSubject(mode, d.type, d.id, snapshot.subjects.get(key) ?? null, countingBySubject.get(key)!, signals);
  });

  let quarantine: RuntimeAssessment["quarantine"] = null;
  if (mode === "enforce") {
    const candidates = assessments.filter((a) => a.nextState === "quarantined" && a.changed && a.subjectType !== "api_key");
    const chosen = candidates.find((a) => a.subjectType === "agent") ?? candidates[0];
    if (chosen) {
      quarantine = {
        subjectType: chosen.subjectType as "agent" | "session",
        subjectId: chosen.subjectId,
        fromState: chosen.current?.state ?? "normal",
        score: chosen.score,
        cause: chosen.hardSignal ? "hard_signal_quarantine" : "score_quarantine",
      };
      for (const a of candidates) {
        if (a === chosen) continue;
        a.nextState = "review_required";
        a.changed = a.nextState !== (a.current?.state ?? "normal");
        a.cause = a.changed ? "signals" : null;
      }
    }
  }
  return { signals, assessments, quarantine };
}

/** Signal rows, subject state/transition rows, alert queue rows and the quarantine batch for a plan. */
export function subjectWriteStatements(
  db: D1Database,
  ctx: { organizationId: string; mode: "monitor" | "enforce"; alertsEnabled: boolean; nowMs: number; nowIso: string },
  plan: SubjectPlan,
  ref: { decisionId: string | null; sessionId: string | null },
): { statements: D1PreparedStatement[]; signalWrites: SignalWrite[]; incidentId: string | null; alertsQueued: boolean } {
  const statements: D1PreparedStatement[] = [];
  let alertsQueued = false;
  let incidentId: string | null = null;
  const sig = signalStatements(db, ctx.organizationId, plan.signals, { mode: ctx.mode, sessionId: ref.sessionId, decisionId: ref.decisionId, nowMs: ctx.nowMs });
  statements.push(...sig.statements);

  for (const s of plan.assessments) {
    const isTarget = plan.quarantine && plan.quarantine.subjectType === s.subjectType && plan.quarantine.subjectId === s.subjectId;
    if (isTarget || (!s.changed && !s.newSignals.length)) continue;
    statements.push(subjectUpsertStatement(db, ctx.organizationId, s, ctx.nowIso));
    if (s.changed) {
      const transitionId = newId("rtr");
      statements.push(
        transitionIfChangedStatement(db, {
          id: transitionId,
          organizationId: ctx.organizationId,
          subjectType: s.subjectType,
          subjectId: s.subjectId,
          from: s.current?.state ?? "normal",
          to: s.nextState,
          score: s.score,
          cause: s.cause ?? "signals",
          actor: { type: "system", id: null, label: "Mother Risk Engine" },
          incidentId: null,
          decisionId: ref.decisionId,
          note: s.newSignals.map((x) => x.code).join(",") || null,
          nowIso: ctx.nowIso,
        }),
      );
      const alert = ctx.alertsEnabled ? alertQueueStatement(db, ctx.organizationId, transitionId, s.nextState, null, ctx.nowIso, s.current?.state ?? "normal") : null;
      if (alert) {
        statements.push(alert);
        alertsQueued = true;
      }
    }
  }

  if (plan.quarantine) {
    const q = plan.quarantine;
    const codes = [...new Set(plan.signals.filter((s) => s.subjectType === q.subjectType && s.subjectId === q.subjectId).map((s) => s.code))];
    const qp = quarantineStatements(db, {
      organizationId: ctx.organizationId,
      subjectType: q.subjectType,
      subjectId: q.subjectId,
      fromState: q.fromState,
      score: q.score,
      cause: q.cause,
      actor: { type: "system", id: null, label: "Mother Risk Engine" },
      reason: `${q.cause === "hard_signal_quarantine" ? "Hard signal" : `Score ${q.score} >= 80`}: ${codes.join(", ") || "accumulated signals"}`,
      decisionId: ref.decisionId,
      signalIds: sig.writes.filter((w) => w.signal.subjectType === q.subjectType && w.signal.subjectId === q.subjectId).map((w) => w.id),
      nowMs: ctx.nowMs,
    });
    statements.push(...qp.statements);
    incidentId = qp.incidentId;
    alertsQueued = alertsQueued || ctx.alertsEnabled;
  }
  return { statements, signalWrites: sig.writes, incidentId, alertsQueued };
}
