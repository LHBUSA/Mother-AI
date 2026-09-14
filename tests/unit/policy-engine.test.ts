import { describe, expect, it } from "vitest";
import {
  evaluate,
  evaluateSafely,
  globMatch,
  validateConditionGroup,
  type NormalizedAction,
  type PolicyRecord,
} from "../../src/gateway/policy-engine";

const AGENT = "agt_research";

function action(overrides: Partial<NormalizedAction> = {}): NormalizedAction {
  return {
    agent: "research-agent-prod",
    environment: "production",
    protocol: "api",
    capability: "records",
    operation: "read",
    resource: "customer:1",
    destination: "internal",
    data_class: "internal",
    mcp_server: null,
    mcp_tool: null,
    context: {},
    ...overrides,
  };
}

let seq = 0;
function policy(p: Partial<PolicyRecord> & Pick<PolicyRecord, "effect" | "conditions">): PolicyRecord {
  seq++;
  return {
    id: `pol_${String(seq).padStart(4, "0")}`,
    name: `policy ${seq}`,
    priority: 100,
    enabled: true,
    scope: "organization",
    agent_ids: [],
    version: 1,
    created_at: `2026-09-01T00:00:${String(seq % 60).padStart(2, "0")}.000Z`,
    ...p,
  };
}

const researchPolicies = () => [
  policy({
    name: "research reads",
    effect: "allow",
    scope: "agents",
    agent_ids: [AGENT],
    conditions: { match: "all", conditions: [{ field: "capability", operator: "in", value: ["knowledge", "records"] }, { field: "operation", operator: "equals", value: "read" }] },
  }),
  policy({
    name: "research no writes",
    effect: "block",
    priority: 10,
    scope: "agents",
    agent_ids: [AGENT],
    reason_code: "OPERATION_NOT_ALLOWED",
    conditions: {
      match: "any",
      conditions: [
        { field: "operation", operator: "in", value: ["modify", "update", "delete"] },
        { field: "capability", operator: "starts_with", value: "finance" },
      ],
    },
  }),
  policy({
    name: "restricted egress",
    effect: "block",
    priority: 1,
    reason_code: "RESTRICTED_DATA_EGRESS",
    conditions: { match: "all", conditions: [{ field: "data_class", operator: "equals", value: "restricted" }, { field: "destination", operator: "equals", value: "external" }] },
  }),
];

const financePolicies = () => [
  policy({ name: "refunds allowed", effect: "allow", conditions: { match: "all", conditions: [{ field: "capability", operator: "equals", value: "payments" }, { field: "operation", operator: "equals", value: "refund" }] } }),
  policy({
    name: "high value review",
    effect: "review",
    priority: 20,
    conditions: {
      match: "all",
      conditions: [
        { field: "capability", operator: "equals", value: "payments" },
        { field: "operation", operator: "equals", value: "refund" },
        { field: "context.amount", operator: "greater_than", value: 1000 },
      ],
    },
  }),
];

describe("policy engine — required cases", () => {
  it("1. allows an explicitly allowed read", () => {
    const r = evaluate({ action: action(), agentId: AGENT, policies: researchPolicies(), defaultDecision: "block" });
    expect(r.decision).toBe("allow");
    expect(r.reason_code).toBe("POLICY_ALLOW");
    expect(r.policy?.name).toBe("research reads");
  });

  it("2. blocks an unauthorized modify", () => {
    const r = evaluate({ action: action({ operation: "modify" }), agentId: AGENT, policies: researchPolicies(), defaultDecision: "block" });
    expect(r.decision).toBe("block");
    expect(r.reason_code).toBe("OPERATION_NOT_ALLOWED");
    expect(r.policy?.name).toBe("research no writes");
  });

  it("2b. blocks finance.* capabilities for the research agent even though no allow matches", () => {
    const r = evaluate({ action: action({ capability: "finance.ledger", operation: "read" }), agentId: AGENT, policies: researchPolicies(), defaultDecision: "block" });
    expect(r.decision).toBe("block");
    expect(r.policy?.name).toBe("research no writes");
  });

  it("3. blocks restricted data egress to external destinations, even when an allow matches", () => {
    const r = evaluate({
      action: action({ capability: "records", operation: "read", data_class: "restricted", destination: "external" }),
      agentId: AGENT,
      policies: researchPolicies(),
      defaultDecision: "block",
    });
    expect(r.decision).toBe("block");
    expect(r.reason_code).toBe("RESTRICTED_DATA_EGRESS");
    expect(r.matched.map((m) => m.effect)).toEqual(["block", "allow"]);
  });

  it("4. requires human approval above the threshold and allows below it", () => {
    const base = { capability: "payments", operation: "refund" };
    const below = evaluate({ action: action({ ...base, context: { amount: 420 } }), agentId: null, policies: financePolicies(), defaultDecision: "block" });
    const above = evaluate({ action: action({ ...base, context: { amount: 4200 } }), agentId: null, policies: financePolicies(), defaultDecision: "block" });
    const exactly = evaluate({ action: action({ ...base, context: { amount: 1000 } }), agentId: null, policies: financePolicies(), defaultDecision: "block" });
    expect(below.decision).toBe("allow");
    expect(above.decision).toBe("review");
    expect(above.reason_code).toBe("HUMAN_APPROVAL_REQUIRED");
    expect(exactly.decision).toBe("allow");
  });

  it("5. unknown/unbound agent falls to default deny (agent-scoped allows do not apply)", () => {
    const r = evaluate({ action: action(), agentId: "agt_someone_else", policies: researchPolicies(), defaultDecision: "block" });
    expect(r.decision).toBe("block");
    expect(r.reason_code).toBe("DEFAULT_DENY");
    expect(r.policy).toBeNull();
  });

  it("6. ignores disabled policies", () => {
    const policies = [policy({ effect: "allow", enabled: false, conditions: { match: "all", conditions: [] } })];
    const r = evaluate({ action: action(), agentId: AGENT, policies, defaultDecision: "block" });
    expect(r.decision).toBe("block");
    expect(r.evaluated_policies).toBe(0);
  });

  it("7. conflicting policies: block > review > allow regardless of priority numbers", () => {
    const all = { match: "all", conditions: [] };
    const policies = [
      policy({ name: "allow first", effect: "allow", priority: 0, conditions: all }),
      policy({ name: "review", effect: "review", priority: 1, conditions: all }),
      policy({ name: "block last", effect: "block", priority: 9999, conditions: all }),
    ];
    expect(evaluate({ action: action(), agentId: AGENT, policies, defaultDecision: "allow" }).decision).toBe("block");
    expect(evaluate({ action: action(), agentId: AGENT, policies: policies.slice(0, 2), defaultDecision: "block" }).decision).toBe("review");
  });

  it("7b. within one effect the reported policy is lowest priority, then oldest, then id", () => {
    const all = { match: "all", conditions: [] };
    const a = policy({ name: "b-late", effect: "block", priority: 5, created_at: "2026-09-02T00:00:00.000Z", conditions: all });
    const b = policy({ name: "b-early", effect: "block", priority: 5, created_at: "2026-09-01T00:00:00.000Z", conditions: all });
    const c = policy({ name: "b-high", effect: "block", priority: 50, created_at: "2026-08-01T00:00:00.000Z", conditions: all });
    for (const order of [[a, b, c], [c, b, a], [b, c, a]]) {
      expect(evaluate({ action: action(), agentId: AGENT, policies: order, defaultDecision: "block" }).policy?.name).toBe("b-early");
    }
  });

  it("8. malformed policy fails the whole evaluation closed", () => {
    const policies = [
      policy({ effect: "allow", conditions: { match: "all", conditions: [] } }),
      policy({ name: "broken", effect: "allow", conditions: { match: "all", conditions: [{ field: "context.amount", operator: "roughly", value: 3 }] } }),
    ];
    const r = evaluate({ action: action(), agentId: AGENT, policies, defaultDecision: "allow" });
    expect(r.decision).toBe("block");
    expect(r.reason_code).toBe("POLICY_INVALID");
    expect(r.policy?.name).toBe("broken");
  });

  it("8b. corrupt stored JSON and unknown effect also fail closed", () => {
    const corrupt = [policy({ effect: "allow", conditions: { __invalid__: true } })];
    expect(evaluate({ action: action(), agentId: AGENT, policies: corrupt, defaultDecision: "allow" }).reason_code).toBe("POLICY_INVALID");
    const badEffect = [policy({ effect: "permit" as never, conditions: { match: "all", conditions: [] } })];
    expect(evaluate({ action: action(), agentId: AGENT, policies: badEffect, defaultDecision: "allow" }).decision).toBe("block");
  });
});

describe("policy engine — semantics", () => {
  it("numeric comparisons on missing or non-numeric values are indeterminate: block/review apply, allow does not", () => {
    const review = financePolicies();
    const missing = evaluate({ action: action({ capability: "payments", operation: "refund", context: {} }), agentId: null, policies: review, defaultDecision: "block" });
    expect(missing.decision).toBe("review");
    expect(missing.reason_code).toBe("POLICY_CONDITION_INDETERMINATE");
    const stringy = evaluate({ action: action({ capability: "payments", operation: "refund", context: { amount: "4200" } }), agentId: null, policies: review, defaultDecision: "block" });
    expect(stringy.decision).toBe("review");

    const allowOnly = [policy({ effect: "allow", conditions: { match: "all", conditions: [{ field: "context.amount", operator: "less_than", value: 100 }] } })];
    expect(evaluate({ action: action({ context: {} }), agentId: null, policies: allowOnly, defaultDecision: "block" }).decision).toBe("block");
  });

  it("a definite false short-circuits indeterminate in an all-group", () => {
    const r = evaluate({ action: action({ capability: "email", operation: "send", context: {} }), agentId: null, policies: financePolicies(), defaultDecision: "block" });
    expect(r.reason_code).toBe("DEFAULT_DENY");
    expect(r.matched).toHaveLength(0);
  });

  it("missing string fields: equals/in/starts_with are false, not_equals/not_in are true", () => {
    const p = (operator: string, value: unknown) => [policy({ effect: "block", conditions: { match: "all", conditions: [{ field: "destination", operator, value }] } })];
    const act = action({ destination: null });
    expect(evaluate({ action: act, agentId: null, policies: p("equals", "external"), defaultDecision: "allow" }).decision).toBe("allow");
    expect(evaluate({ action: act, agentId: null, policies: p("in", ["external"]), defaultDecision: "allow" }).decision).toBe("allow");
    expect(evaluate({ action: act, agentId: null, policies: p("not_equals", "internal"), defaultDecision: "allow" }).decision).toBe("block");
    expect(evaluate({ action: act, agentId: null, policies: p("not_in", ["internal"]), defaultDecision: "allow" }).decision).toBe("block");
  });

  it("exists / not_exists", () => {
    const p = (operator: string) => [policy({ effect: "block", conditions: { match: "all", conditions: [{ field: "context.approval_ticket", operator }] } })];
    expect(evaluate({ action: action(), agentId: null, policies: p("not_exists"), defaultDecision: "allow" }).decision).toBe("block");
    expect(evaluate({ action: action({ context: { approval_ticket: "T-1" } }), agentId: null, policies: p("not_exists"), defaultDecision: "allow" }).decision).toBe("allow");
    expect(evaluate({ action: action({ context: { approval_ticket: "T-1" } }), agentId: null, policies: p("exists"), defaultDecision: "allow" }).decision).toBe("block");
  });

  it("any-group matches when one condition matches", () => {
    const policies = [policy({ effect: "block", conditions: { match: "any", conditions: [{ field: "operation", operator: "equals", value: "delete" }, { field: "operation", operator: "equals", value: "drop" }] } })];
    expect(evaluate({ action: action({ operation: "drop" }), agentId: null, policies, defaultDecision: "allow" }).decision).toBe("block");
    expect(evaluate({ action: action({ operation: "read" }), agentId: null, policies, defaultDecision: "allow" }).decision).toBe("allow");
  });

  it("nested context paths never read the prototype chain", () => {
    const policies = [policy({ effect: "allow", conditions: { match: "all", conditions: [{ field: "context.constructor", operator: "exists" }] } })];
    expect(evaluate({ action: action({ context: {} }), agentId: null, policies, defaultDecision: "block" }).decision).toBe("block");
    const nested = [policy({ effect: "review", conditions: { match: "all", conditions: [{ field: "context.payment.amount", operator: "greater_than_or_equal", value: 50 }] } })];
    expect(evaluate({ action: action({ context: { payment: { amount: 50 } } }), agentId: null, policies: nested, defaultDecision: "allow" }).decision).toBe("review");
  });

  it("MCP fields are addressable", () => {
    const policies = [
      policy({ effect: "allow", conditions: { match: "all", conditions: [{ field: "protocol", operator: "equals", value: "mcp" }, { field: "mcp.tool", operator: "in", value: ["contacts.read"] }] } }),
    ];
    const mcp = action({ protocol: "mcp", capability: "salesforce", operation: "contacts.read", mcp_server: "salesforce", mcp_tool: "contacts.read" });
    expect(evaluate({ action: mcp, agentId: null, policies, defaultDecision: "block" }).decision).toBe("allow");
    expect(evaluate({ action: { ...mcp, mcp_tool: "contacts.delete" }, agentId: null, policies, defaultDecision: "block" }).decision).toBe("block");
  });

  it("default decisions: review and allow", () => {
    expect(evaluate({ action: action(), agentId: null, policies: [], defaultDecision: "review" }).reason_code).toBe("DEFAULT_REVIEW");
    expect(evaluate({ action: action(), agentId: null, policies: [], defaultDecision: "allow" }).reason_code).toBe("DEFAULT_ALLOW");
  });

  it("is deterministic: identical inputs give identical outputs", () => {
    const input = { action: action({ capability: "payments", operation: "refund", context: { amount: 5000 } }), agentId: null, policies: financePolicies(), defaultDecision: "block" as const };
    const first = JSON.stringify(evaluate(input));
    for (let i = 0; i < 50; i++) expect(JSON.stringify(evaluate(input))).toBe(first);
  });

  it("evaluateSafely converts an engine exception into a block", () => {
    const hostile = { get conditions() { throw new Error("boom"); } } as unknown as PolicyRecord;
    const r = evaluateSafely({ action: action(), agentId: null, policies: [Object.assign(hostile, { enabled: true, scope: "organization", effect: "allow" })], defaultDecision: "allow" });
    expect(r.decision).toBe("block");
    expect(r.reason_code).toBe("POLICY_ENGINE_ERROR");
  });
});

describe("policy validation", () => {
  it("lowercases case-insensitive fields and keeps exact fields", () => {
    const v = validateConditionGroup({ match: "all", conditions: [{ field: "capability", operator: "equals", value: "Payments" }, { field: "mcp.tool", operator: "equals", value: "Contacts.Read" }] });
    expect(v.ok).toBe(true);
    if (v.ok) {
      expect(v.value.conditions[0]!.value).toBe("payments");
      expect(v.value.conditions[1]!.value).toBe("Contacts.Read");
    }
  });

  it("rejects numeric operators on non-context fields, unknown fields, unknown keys and empty any-groups", () => {
    expect(validateConditionGroup({ match: "all", conditions: [{ field: "capability", operator: "greater_than", value: 1 }] }).ok).toBe(false);
    expect(validateConditionGroup({ match: "all", conditions: [{ field: "whatever", operator: "equals", value: "x" }] }).ok).toBe(false);
    expect(validateConditionGroup({ match: "all", conditions: [{ field: "capability", operator: "equals", value: "x", extra: 1 }] }).ok).toBe(false);
    expect(validateConditionGroup({ match: "any", conditions: [] }).ok).toBe(false);
    expect(validateConditionGroup({ match: "all", conditions: [{ field: "context.a", operator: "in", value: [] }] }).ok).toBe(false);
    expect(validateConditionGroup({ match: "all", conditions: [{ field: "context.a", operator: "exists", value: 1 }] }).ok).toBe(false);
    expect(validateConditionGroup(null).ok).toBe(false);
    expect(validateConditionGroup({ match: "all", conditions: Array.from({ length: 51 }, () => ({ field: "agent", operator: "exists" })) }).ok).toBe(false);
  });

  it("glob matching is linear and anchored", () => {
    expect(globMatch("*.delete", "contacts.delete")).toBe(true);
    expect(globMatch("*.delete", "contacts.delete.all")).toBe(false);
    expect(globMatch("finance*", "finance.ledger")).toBe(true);
    expect(globMatch("a*b*c", "axxbyyc")).toBe(true);
    expect(globMatch("a*b*c", "axxbyy")).toBe(false);
    const started = Date.now();
    expect(globMatch("*a*a*a*a*a*a*a*a*b", "a".repeat(500))).toBe(false);
    expect(Date.now() - started).toBeLessThan(200);
  });
});

describe("engine performance (Node, CPU only)", () => {
  it("evaluates 200 policies well under a millisecond on average", () => {
    const policies = Array.from({ length: 200 }, (_, i) =>
      policy({
        effect: i % 3 === 0 ? "block" : i % 3 === 1 ? "review" : "allow",
        conditions: { match: "all", conditions: [{ field: "capability", operator: "equals", value: `cap${i}` }, { field: "context.amount", operator: "greater_than", value: i }] },
      }),
    );
    const act = action({ capability: "cap199", context: { amount: 5000 } });
    const runs = 500;
    const t0 = performance.now();
    for (let i = 0; i < runs; i++) evaluate({ action: act, agentId: null, policies, defaultDecision: "block" });
    const avg = (performance.now() - t0) / runs;
    console.log(`[bench] 200 policies: ${avg.toFixed(4)} ms/evaluation`);
    expect(avg).toBeLessThan(5);
  });
});
