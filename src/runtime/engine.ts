// Mother Risk Engine (mre-1.0.0): deterministic runtime risk, separate from the policy engine.
//
// Pure functions only. Given the same evidence and the same clock they return the same signals,
// scores, states and runtime decisions. No model, no probabilities, no free-text classification.
//
//   * Behavioral signals accumulate toward the score thresholds. No behavioral signal alone can
//     reach the quarantine threshold (every behavioral rule is below QUARANTINE_SCORE).
//   * Hard signals are rare deterministic violations. In enforce mode they quarantine immediately.
//   * The runtime layer can only preserve or restrict the policy decision (restrict()).
//   * monitor mode computes and records everything but never changes the effective decision and
//     never quarantines.

export const RISK_ENGINE_VERSION = "mre-1.0.0";

export type RiskMode = "off" | "monitor" | "enforce";
export type SubjectType = "agent" | "session" | "api_key";
export type RiskState = "normal" | "elevated" | "review_required" | "quarantined" | "contained" | "cleared";
export type Verdict = "allow" | "review" | "block";

export const ELEVATED_SCORE = 25;
export const REVIEW_SCORE = 50;
export const QUARANTINE_SCORE = 80;

const MIN = 60_000;

export type SignalCode =
  | "AGENT_DISABLED_ATTEMPT"
  | "UNKNOWN_AGENT_PROBING"
  | "REPEATED_BLOCK"
  | "USE_AFTER_EXPIRY_OR_REVOCATION"
  | "UNEXPECTED_MCP_TOOL"
  | "CAPABILITY_ESCALATION"
  | "UNUSUAL_DESTINATION"
  | "HIGH_VELOCITY"
  | "SENSITIVE_DATA_ESCALATION"
  | "CHILD_SESSION_FANOUT"
  | "SESSION_OR_PARENT_INVALID"
  | "CONTINUATION_AFTER_QUARANTINE"
  | "CROSS_TENANT_REFERENCE"
  | "EXECUTED_WITHOUT_AUTHORIZATION";

export interface SignalRule {
  code: SignalCode;
  hard: boolean;
  points: number;
  windowMs: number;
  rule: string;
}

export const SIGNAL_RULES: Record<SignalCode, SignalRule> = {
  AGENT_DISABLED_ATTEMPT: { code: "AGENT_DISABLED_ATTEMPT", hard: false, points: 30, windowMs: 60 * MIN, rule: "A request named a registered agent that is disabled." },
  UNKNOWN_AGENT_PROBING: { code: "UNKNOWN_AGENT_PROBING", hard: false, points: 30, windowMs: 60 * MIN, rule: "At least 3 requests from one API key named unregistered agents within 10 minutes." },
  REPEATED_BLOCK: { code: "REPEATED_BLOCK", hard: false, points: 20, windowMs: 60 * MIN, rule: "At least 3 blocked requests within 10 minutes (fires again at 10)." },
  USE_AFTER_EXPIRY_OR_REVOCATION: { code: "USE_AFTER_EXPIRY_OR_REVOCATION", hard: false, points: 40, windowMs: 60 * MIN, rule: "Tried to use an approval or lease that had expired, been denied, revoked, exhausted, invalidated or already consumed." },
  UNEXPECTED_MCP_TOOL: { code: "UNEXPECTED_MCP_TOOL", hard: false, points: 25, windowMs: 60 * MIN, rule: "Called an MCP server/tool this agent has no allowed decision for in 30 days." },
  CAPABILITY_ESCALATION: { code: "CAPABILITY_ESCALATION", hard: false, points: 25, windowMs: 60 * MIN, rule: "Attempted a destructive capability·operation this agent has no allowed decision for in 30 days." },
  UNUSUAL_DESTINATION: { code: "UNUSUAL_DESTINATION", hard: false, points: 20, windowMs: 60 * MIN, rule: "Used a destination outside this agent's allowed baseline (baseline of at least 20 allowed decisions)." },
  HIGH_VELOCITY: { code: "HIGH_VELOCITY", hard: false, points: 20, windowMs: 30 * MIN, rule: "More than 60 requests in 60 seconds, or more than 25 distinct resources in 5 minutes, in one session." },
  SENSITIVE_DATA_ESCALATION: { code: "SENSITIVE_DATA_ESCALATION", hard: false, points: 25, windowMs: 60 * MIN, rule: "Data class rose above the session's previous maximum into confidential or higher." },
  CHILD_SESSION_FANOUT: { code: "CHILD_SESSION_FANOUT", hard: false, points: 25, windowMs: 60 * MIN, rule: "More than 10 child sessions opened within 10 minutes, or a child session at depth 5 or more." },
  SESSION_OR_PARENT_INVALID: { code: "SESSION_OR_PARENT_INVALID", hard: false, points: 50, windowMs: 60 * MIN, rule: "A session or parent decision id did not belong to this agent, key or session lineage." },
  CONTINUATION_AFTER_QUARANTINE: { code: "CONTINUATION_AFTER_QUARANTINE", hard: false, points: 0, windowMs: 60 * MIN, rule: "Attempted to act inside a quarantined scope (recorded; quarantine is already in force)." },
  CROSS_TENANT_REFERENCE: { code: "CROSS_TENANT_REFERENCE", hard: true, points: 100, windowMs: 24 * 60 * MIN, rule: "Referenced a session, decision, approval or lease that belongs to a different organization." },
  EXECUTED_WITHOUT_AUTHORIZATION: { code: "EXECUTED_WITHOUT_AUTHORIZATION", hard: true, points: 100, windowMs: 24 * 60 * MIN, rule: "The integration reported executing an action whose effective decision was block, or a review that was never consumed." },
};

export interface NewSignal {
  subjectType: SubjectType;
  subjectId: string;
  code: SignalCode;
  evidenceKey: string;
  evidence: Record<string, unknown>;
}

export interface StoredSignal {
  subject_type: SubjectType;
  subject_id: string;
  signal: string;
  hard: number;
  points: number;
  evidence_key: string;
  observed_at: string;
  expires_at: string;
}

export interface SubjectRow {
  organization_id: string;
  subject_type: SubjectType;
  subject_id: string;
  state: RiskState;
  score: number;
  state_since: string;
  signals_since: string;
  containment_epoch_at: string | null;
  incident_id: string | null;
  version: number;
}

const RANK: Record<Verdict, number> = { allow: 0, review: 1, block: 2 };
const BY_RANK: Verdict[] = ["allow", "review", "block"];

/** The only way the runtime layer combines with policy: the most restrictive of the two. */
export function restrict(policy: Verdict, runtime: Verdict): Verdict {
  return BY_RANK[Math.max(RANK[policy], RANK[runtime])]!;
}

/** Effective decision. monitor never changes the policy decision; enforce restricts. */
export function effectiveDecision(mode: "monitor" | "enforce", policy: Verdict, runtime: Verdict): Verdict {
  return mode === "monitor" ? policy : restrict(policy, runtime);
}

export const isContained = (s: RiskState | null | undefined): boolean => s === "quarantined" || s === "contained";

const STATE_SEVERITY: Record<RiskState, number> = { normal: 0, cleared: 0, elevated: 1, review_required: 2, quarantined: 3, contained: 3 };

export function stateSeverity(state: RiskState): number {
  return STATE_SEVERITY[state];
}

export function verdictForState(state: RiskState): Verdict {
  return isContained(state) ? "block" : state === "review_required" ? "review" : "allow";
}

export function stateForScore(score: number): RiskState {
  if (score >= QUARANTINE_SCORE) return "quarantined";
  if (score >= REVIEW_SCORE) return "review_required";
  if (score >= ELEVATED_SCORE) return "elevated";
  return "normal";
}

/** Signals that still count for a subject: unexpired and observed after signals_since. */
export function countingSignals(subject: SubjectRow | null, stored: StoredSignal[], nowIso: string): StoredSignal[] {
  return stored.filter((s) => s.expires_at > nowIso && (!subject || s.observed_at >= subject.signals_since));
}

/** Drops new signals that already fired for the same subject + code + evidence key within the window. */
export function dedupeSignals(newSignals: NewSignal[], counting: StoredSignal[]): NewSignal[] {
  const seen = new Set(counting.map((s) => `${s.subject_type}:${s.subject_id}:${s.signal}:${s.evidence_key}`));
  const out: NewSignal[] = [];
  for (const s of newSignals) {
    const key = `${s.subjectType}:${s.subjectId}:${s.code}:${s.evidenceKey}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(s);
  }
  return out;
}

export type TransitionCause = "signals" | "decay" | "score_quarantine" | "hard_signal_quarantine";

export interface SubjectAssessment {
  subjectType: SubjectType;
  subjectId: string;
  current: SubjectRow | null;
  score: number;
  /** State stored after this assessment. */
  nextState: RiskState;
  /** What enforce mode would do (monitor records it but never applies it). */
  wouldState: RiskState;
  changed: boolean;
  cause: TransitionCause | null;
  hardSignal: SignalCode | null;
  newSignals: NewSignal[];
}

/**
 * Assesses one subject after this request's signals. Quarantine is sticky and is never produced
 * for an api_key subject (a key is contained by revoking it, which is a human action).
 */
export function assessSubject(
  mode: "monitor" | "enforce",
  subjectType: SubjectType,
  subjectId: string,
  current: SubjectRow | null,
  counting: StoredSignal[],
  newSignals: NewSignal[],
): SubjectAssessment {
  const mine = newSignals.filter((s) => s.subjectType === subjectType && s.subjectId === subjectId);
  const currentState: RiskState = current?.state ?? "normal";
  const score = counting.reduce((sum, s) => sum + s.points, 0) + mine.reduce((sum, s) => sum + SIGNAL_RULES[s.code].points, 0);
  const hard = mine.find((s) => SIGNAL_RULES[s.code].hard)?.code ?? null;

  if (isContained(currentState)) {
    return { subjectType, subjectId, current, score, nextState: currentState, wouldState: currentState, changed: false, cause: null, hardSignal: hard, newSignals: mine };
  }

  const quarantinable = subjectType !== "api_key";
  let wouldState = stateForScore(score);
  let wouldCause: TransitionCause = "signals";
  if (quarantinable && hard) {
    wouldState = "quarantined";
    wouldCause = "hard_signal_quarantine";
  } else if (wouldState === "quarantined") {
    wouldCause = quarantinable ? "score_quarantine" : "signals";
    if (!quarantinable) wouldState = "review_required";
  }

  let nextState = wouldState;
  let cause: TransitionCause = wouldCause;
  if (wouldState === "quarantined" && mode === "monitor") {
    nextState = "review_required";
    cause = "signals";
  }
  // A cleared subject stays "cleared" until new signals raise it again.
  if (currentState === "cleared" && nextState === "normal") nextState = "cleared";
  if (nextState !== "quarantined" && stateSeverity(nextState) < stateSeverity(currentState)) cause = "decay";

  return {
    subjectType,
    subjectId,
    current,
    score,
    nextState,
    wouldState,
    changed: nextState !== currentState,
    cause: nextState !== currentState ? cause : null,
    hardSignal: hard,
    newSignals: mine,
  };
}

// ---------------------------------------------------------------------------
// Evaluation signal detection
// ---------------------------------------------------------------------------

export const DESTRUCTIVE_OPERATIONS = new Set(["delete", "modify", "update", "write", "transfer", "export", "refund", "grant", "revoke", "execute", "deploy"]);

export function isDestructive(operation: string): boolean {
  const last = operation.split(/[._:/-]/).filter(Boolean).pop() ?? operation;
  return DESTRUCTIVE_OPERATIONS.has(operation) || DESTRUCTIVE_OPERATIONS.has(last);
}

export const DATA_CLASS_RANK: Record<string, number> = { public: 0, internal: 1, confidential: 2, pii: 3, financial: 3, restricted: 4 };

export function dataClassRank(value: string | null | undefined): number {
  return value ? (DATA_CLASS_RANK[value] ?? 0) : 0;
}

export interface EvaluationFacts {
  agentId: string | null;
  sessionId: string | null;
  apiKeyId: string;
  /** Reason code when an identity or correlation gate blocked before policy. */
  gateReason: string | null;
  policyDecision: Verdict;
  protocol: "api" | "mcp";
  capability: string;
  operation: string;
  destination: string | null;
  dataClass: string | null;
  mcpTool: string | null;
  /** Blocks in the last 10 minutes for the session (or agent without a session), including this one if blocked. */
  recentBlocks: number;
  unknownAgentAttempts10m: number;
  sessionRequests60s: number;
  sessionDistinctResources5m: number;
  sessionMaxDataRank: number;
  baseline: {
    capabilityOperationAllowed: boolean;
    mcpToolAllowed: boolean;
    destinationAllowed: boolean;
    destinationBaselineSize: number;
  };
  correlation: { kind: "cross_tenant" | "invalid"; claimed: string } | null;
  inQuarantinedScope: boolean;
}

/** Deterministic signals raised by one evaluation. Behavioral signals go to the session and the agent. */
export function detectEvaluationSignals(f: EvaluationFacts): NewSignal[] {
  const out: NewSignal[] = [];
  const behavioral = (code: SignalCode, evidenceKey: string, evidence: Record<string, unknown>, sessionOnly = false) => {
    if (f.sessionId) out.push({ subjectType: "session", subjectId: f.sessionId, code, evidenceKey, evidence });
    if (f.agentId && !sessionOnly) out.push({ subjectType: "agent", subjectId: f.agentId, code, evidenceKey, evidence });
  };

  if (f.correlation) {
    const code: SignalCode = f.correlation.kind === "cross_tenant" ? "CROSS_TENANT_REFERENCE" : "SESSION_OR_PARENT_INVALID";
    const evidence = { claimed: f.correlation.claimed };
    if (f.agentId) out.push({ subjectType: "agent", subjectId: f.agentId, code, evidenceKey: f.correlation.claimed, evidence });
    else out.push({ subjectType: "api_key", subjectId: f.apiKeyId, code, evidenceKey: f.correlation.claimed, evidence });
  }
  if (f.gateReason === "AGENT_DISABLED" && f.agentId) {
    out.push({ subjectType: "agent", subjectId: f.agentId, code: "AGENT_DISABLED_ATTEMPT", evidenceKey: "disabled", evidence: {} });
  }
  if (f.gateReason === "AGENT_UNKNOWN" && f.unknownAgentAttempts10m >= 3) {
    out.push({ subjectType: "api_key", subjectId: f.apiKeyId, code: "UNKNOWN_AGENT_PROBING", evidenceKey: "probing", evidence: { attempts_10m: f.unknownAgentAttempts10m } });
  }
  if (f.inQuarantinedScope) {
    behavioral("CONTINUATION_AFTER_QUARANTINE", `${f.capability}.${f.operation}`, { capability: f.capability, operation: f.operation });
  }
  if (f.recentBlocks >= 3) behavioral("REPEATED_BLOCK", "3", { blocks_10m: f.recentBlocks, threshold: 3 });
  if (f.recentBlocks >= 10) behavioral("REPEATED_BLOCK", "10", { blocks_10m: f.recentBlocks, threshold: 10 });

  if (f.agentId && !f.gateReason) {
    const capOp = `${f.capability}.${f.operation}`;
    if (f.protocol === "mcp" && f.mcpTool && !f.baseline.mcpToolAllowed) {
      behavioral("UNEXPECTED_MCP_TOOL", f.mcpTool, { mcp_tool: f.mcpTool, baseline_days: 30 });
    }
    if (isDestructive(f.operation) && !f.baseline.capabilityOperationAllowed) {
      behavioral("CAPABILITY_ESCALATION", capOp, { capability_operation: capOp, baseline_days: 30 });
    }
    if (f.destination && !f.baseline.destinationAllowed && f.baseline.destinationBaselineSize >= 20) {
      behavioral("UNUSUAL_DESTINATION", f.destination, { destination: f.destination, baseline_allowed_decisions: f.baseline.destinationBaselineSize });
    }
  }
  if (f.sessionId) {
    if (f.sessionRequests60s > 60) behavioral("HIGH_VELOCITY", "requests", { requests_60s: f.sessionRequests60s, threshold: 60 }, true);
    if (f.sessionDistinctResources5m > 25) behavioral("HIGH_VELOCITY", "resources", { distinct_resources_5m: f.sessionDistinctResources5m, threshold: 25 }, true);
    const rank = dataClassRank(f.dataClass);
    if (rank >= 2 && rank > f.sessionMaxDataRank) {
      behavioral("SENSITIVE_DATA_ESCALATION", f.dataClass!, { data_class: f.dataClass, previous_max_rank: f.sessionMaxDataRank, rank });
    }
  }
  return out;
}

export function signalExpiry(code: SignalCode, observedAtMs: number): string {
  return new Date(observedAtMs + SIGNAL_RULES[code].windowMs).toISOString();
}

/** Human-readable table of the rule set (console and docs). */
export function ruleTable() {
  return Object.values(SIGNAL_RULES).map((r) => ({ code: r.code, hard: r.hard, points: r.points, window_minutes: r.windowMs / MIN, rule: r.rule }));
}
