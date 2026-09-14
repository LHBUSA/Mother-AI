import { describe, expect, it } from "vitest";
import {
  QUARANTINE_SCORE,
  RISK_ENGINE_VERSION,
  SIGNAL_RULES,
  assessSubject,
  detectEvaluationSignals,
  effectiveDecision,
  isDestructive,
  restrict,
  ruleTable,
  type EvaluationFacts,
  type StoredSignal,
  type SubjectRow,
  type Verdict,
} from "../../src/runtime/engine";

const NOW = "2026-09-14T20:00:00.000Z";

const facts = (over: Partial<EvaluationFacts> = {}): EvaluationFacts => ({
  agentId: "agt_A",
  sessionId: "asn_S",
  apiKeyId: "key_K",
  gateReason: null,
  policyDecision: "allow",
  protocol: "api",
  capability: "records",
  operation: "read",
  destination: null,
  dataClass: null,
  mcpTool: null,
  recentBlocks: 0,
  unknownAgentAttempts10m: 0,
  sessionRequests60s: 1,
  sessionDistinctResources5m: 1,
  sessionMaxDataRank: 0,
  baseline: { capabilityOperationAllowed: true, mcpToolAllowed: true, destinationAllowed: true, destinationBaselineSize: 0 },
  correlation: null,
  inQuarantinedScope: false,
  ...over,
});

describe("mre-1.0.0 rule set", () => {
  it("is the approved, versioned table", () => {
    expect(RISK_ENGINE_VERSION).toBe("mre-1.0.0");
    expect(ruleTable().map((r) => [r.code, r.hard, r.points, r.window_minutes])).toEqual([
      ["AGENT_DISABLED_ATTEMPT", false, 30, 60],
      ["UNKNOWN_AGENT_PROBING", false, 30, 60],
      ["REPEATED_BLOCK", false, 20, 60],
      ["USE_AFTER_EXPIRY_OR_REVOCATION", false, 40, 60],
      ["UNEXPECTED_MCP_TOOL", false, 25, 60],
      ["CAPABILITY_ESCALATION", false, 25, 60],
      ["UNUSUAL_DESTINATION", false, 20, 60],
      ["HIGH_VELOCITY", false, 20, 30],
      ["SENSITIVE_DATA_ESCALATION", false, 25, 60],
      ["CHILD_SESSION_FANOUT", false, 25, 60],
      ["SESSION_OR_PARENT_INVALID", false, 50, 60],
      ["CONTINUATION_AFTER_QUARANTINE", false, 0, 60],
      ["CROSS_TENANT_REFERENCE", true, 100, 1440],
      ["EXECUTED_WITHOUT_AUTHORIZATION", true, 100, 1440],
    ]);
  });

  it("no single behavioral signal can reach the quarantine threshold; hard signals are exactly the two violations", () => {
    for (const rule of Object.values(SIGNAL_RULES)) {
      if (!rule.hard) expect(rule.points).toBeLessThan(QUARANTINE_SCORE);
    }
    expect(Object.values(SIGNAL_RULES).filter((r) => r.hard).map((r) => r.code)).toEqual(["CROSS_TENANT_REFERENCE", "EXECUTED_WITHOUT_AUTHORIZATION"]);
  });
});

describe("restrict-only combination", () => {
  it("never relaxes policy: ALLOW→ALLOW/REVIEW/BLOCK, REVIEW→REVIEW/BLOCK, BLOCK→BLOCK; monitor always returns policy", () => {
    const v: Verdict[] = ["allow", "review", "block"];
    const table = v.map((p) => v.map((r) => restrict(p, r)));
    expect(table).toEqual([
      ["allow", "review", "block"],
      ["review", "review", "block"],
      ["block", "block", "block"],
    ]);
    for (const p of v) for (const r of v) expect(effectiveDecision("monitor", p, r)).toBe(p);
  });
});

describe("subject assessment", () => {
  const signal = (points: number, hard = 0): StoredSignal => ({ subject_type: "agent", subject_id: "agt_A", signal: "X", hard, points, evidence_key: String(Math.random()), observed_at: NOW, expires_at: "2999-01-01T00:00:00.000Z" });
  const row = (state: SubjectRow["state"]): SubjectRow => ({ organization_id: "org", subject_type: "agent", subject_id: "agt_A", state, score: 0, state_since: NOW, signals_since: "1970-01-01T00:00:00.000Z", containment_epoch_at: null, incident_id: null, version: 1 });

  it("accumulates behavioral points through elevated and review to quarantine only in enforce mode", () => {
    const hit = [{ subjectType: "agent" as const, subjectId: "agt_A", code: "CAPABILITY_ESCALATION" as const, evidenceKey: "k", evidence: {} }];
    expect(assessSubject("enforce", "agent", "agt_A", null, [], hit).nextState).toBe("elevated");
    expect(assessSubject("enforce", "agent", "agt_A", row("elevated"), [signal(30)], hit).nextState).toBe("review_required");
    const q = assessSubject("enforce", "agent", "agt_A", row("review_required"), [signal(30), signal(25)], hit);
    expect([q.nextState, q.cause]).toEqual(["quarantined", "score_quarantine"]);
    const m = assessSubject("monitor", "agent", "agt_A", row("review_required"), [signal(30), signal(25)], hit);
    expect([m.nextState, m.wouldState]).toEqual(["review_required", "quarantined"]);
  });

  it("a hard signal quarantines immediately in enforce, is only recorded in monitor, and never quarantines an API key", () => {
    const hard = (subjectType: "agent" | "api_key") => [{ subjectType, subjectId: "x", code: "EXECUTED_WITHOUT_AUTHORIZATION" as const, evidenceKey: "d", evidence: {} }];
    expect(assessSubject("enforce", "agent", "x", null, [], hard("agent"))).toMatchObject({ nextState: "quarantined", cause: "hard_signal_quarantine" });
    expect(assessSubject("monitor", "agent", "x", null, [], hard("agent"))).toMatchObject({ nextState: "review_required", wouldState: "quarantined" });
    expect(assessSubject("enforce", "api_key", "x", null, [], hard("api_key")).nextState).toBe("review_required");
  });

  it("quarantine is sticky: no score, decay or signal can leave it", () => {
    for (const state of ["quarantined", "contained"] as const) {
      const a = assessSubject("enforce", "agent", "agt_A", row(state), [], []);
      expect([a.nextState, a.changed]).toEqual([state, false]);
    }
  });

  it("detects the canary signals deterministically", () => {
    expect(detectEvaluationSignals(facts({ operation: "delete", policyDecision: "block", baseline: { ...facts().baseline, capabilityOperationAllowed: false } })).map((s) => `${s.subjectType}:${s.code}`)).toEqual([
      "session:CAPABILITY_ESCALATION",
      "agent:CAPABILITY_ESCALATION",
    ]);
    expect(detectEvaluationSignals(facts({ recentBlocks: 3 })).map((s) => s.code)).toEqual(["REPEATED_BLOCK", "REPEATED_BLOCK"]);
    expect(detectEvaluationSignals(facts({ protocol: "mcp", mcpTool: "exec", baseline: { ...facts().baseline, mcpToolAllowed: false } })).map((s) => s.code)).toContain("UNEXPECTED_MCP_TOOL");
    expect(detectEvaluationSignals(facts({ dataClass: "restricted", sessionMaxDataRank: 1 })).map((s) => s.code)).toContain("SENSITIVE_DATA_ESCALATION");
    expect(detectEvaluationSignals(facts({ dataClass: "internal" }))).toEqual([]);
    expect(detectEvaluationSignals(facts({ correlation: { kind: "cross_tenant", claimed: "asn_X" } }))[0]).toMatchObject({ code: "CROSS_TENANT_REFERENCE", subjectType: "agent" });
    expect(isDestructive("contacts.delete")).toBe(true);
    expect(isDestructive("read")).toBe(false);
  });
});
