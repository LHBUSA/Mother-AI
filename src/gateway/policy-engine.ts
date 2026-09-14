// Mother Policy Engine (MPE).
//
// A pure, deterministic function from (normalized action, policies, default) to
// a decision. No I/O, no clocks, no randomness, no LLMs. The same inputs always
// produce the same output, which is what makes decisions auditable.
//
// Precedence (documented in docs/API.md#policy-precedence):
//   1. Any matching BLOCK policy  -> block
//   2. Any matching REVIEW policy -> review (human approval)
//   3. Any matching ALLOW policy  -> allow
//   4. Nothing matched            -> agent default_mode, else organization default
// Within one effect, the reported policy is the lowest `priority` number, then
// the oldest `created_at`, then the lexicographically smallest id.
//
// Conditions are three-valued: true, false, or indeterminate (e.g. a numeric
// comparison on a context value that is missing or not a number). Indeterminate
// BLOCK/REVIEW policies apply (fail closed); indeterminate ALLOW policies do not.
// Any malformed in-scope policy fails the whole evaluation closed.

export const ENGINE_VERSION = "mpe-1.0.0";

export type Effect = "allow" | "review" | "block";
export type DefaultDecision = "block" | "review" | "allow";
export type Scalar = string | number | boolean;

export const OPERATORS = [
  "equals",
  "not_equals",
  "in",
  "not_in",
  "starts_with",
  "glob",
  "greater_than",
  "greater_than_or_equal",
  "less_than",
  "less_than_or_equal",
  "exists",
  "not_exists",
] as const;
export type Operator = (typeof OPERATORS)[number];

const NUMERIC_OPERATORS = new Set<Operator>(["greater_than", "greater_than_or_equal", "less_than", "less_than_or_equal"]);
const NO_VALUE_OPERATORS = new Set<Operator>(["exists", "not_exists"]);
const LIST_OPERATORS = new Set<Operator>(["in", "not_in"]);

export const STRING_FIELDS = [
  "agent",
  "environment",
  "protocol",
  "capability",
  "operation",
  "resource",
  "destination",
  "data_class",
  "mcp.server",
  "mcp.tool",
] as const;
export type StringField = (typeof STRING_FIELDS)[number];

/** Fields whose request values and policy values are compared case-insensitively (lowercased). */
export const LOWERCASE_FIELDS = new Set<string>(["agent", "environment", "protocol", "capability", "operation", "destination", "data_class"]);

const CONTEXT_PATH = /^context(\.[A-Za-z0-9_-]{1,64}){1,6}$/;

export const LIMITS = {
  conditionsPerPolicy: 50,
  listValues: 100,
  stringValue: 512,
  reasonCode: 64,
  reason: 500,
} as const;

export interface Condition {
  field: string;
  operator: Operator;
  value?: Scalar | Scalar[];
}

export interface ConditionGroup {
  match: "all" | "any";
  conditions: Condition[];
}

export interface PolicyRecord {
  id: string;
  name: string;
  priority: number;
  enabled: boolean;
  effect: Effect;
  scope: "organization" | "agents";
  agent_ids: string[];
  /** Raw stored value — validated at evaluation time, never trusted. */
  conditions: unknown;
  reason_code?: string | null;
  reason?: string | null;
  version: number;
  created_at: string;
}

/** Canonical Mother AI action. Both direct API calls and MCP tool calls normalize to this. */
export interface NormalizedAction {
  agent: string;
  environment: string | null;
  protocol: "api" | "mcp";
  capability: string;
  operation: string;
  resource: string | null;
  destination: string | null;
  data_class: string | null;
  mcp_server: string | null;
  mcp_tool: string | null;
  context: Record<string, unknown>;
}

export interface EvaluationInput {
  action: NormalizedAction;
  /** Internal agent id, used for agent-scoped policies. Null when the agent is unregistered. */
  agentId: string | null;
  policies: PolicyRecord[];
  defaultDecision: DefaultDecision;
}

export interface MatchedPolicy {
  policy_id: string;
  name: string;
  effect: Effect;
  priority: number;
  version: number;
  indeterminate: boolean;
  indeterminate_fields: string[];
}

export interface EvaluationResult {
  decision: Effect;
  reason_code: string;
  reason: string;
  policy: { id: string; name: string; effect: Effect; priority: number; version: number } | null;
  matched: MatchedPolicy[];
  evaluated_policies: number;
  engine_version: string;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

export type ValidationResult<T> = { ok: true; value: T } | { ok: false; errors: string[] };

function isScalar(v: unknown): v is Scalar {
  return (typeof v === "string" && v.length <= LIMITS.stringValue) || (typeof v === "number" && Number.isFinite(v)) || typeof v === "boolean";
}

export function isKnownField(field: string): boolean {
  return (STRING_FIELDS as readonly string[]).includes(field) || CONTEXT_PATH.test(field);
}

/**
 * Validates and canonicalizes a condition group. Lowercases policy values for
 * case-insensitive fields so evaluation is a plain comparison.
 */
export function validateConditionGroup(raw: unknown): ValidationResult<ConditionGroup> {
  const errors: string[] = [];
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, errors: ["conditions must be an object with `match` and `conditions`"] };
  }
  const group = raw as Record<string, unknown>;
  const extra = Object.keys(group).filter((k) => k !== "match" && k !== "conditions");
  if (extra.length) errors.push(`unknown keys in condition group: ${extra.join(", ")}`);
  if (group.match !== "all" && group.match !== "any") errors.push("`match` must be \"all\" or \"any\"");
  if (!Array.isArray(group.conditions)) {
    errors.push("`conditions` must be an array");
    return { ok: false, errors };
  }
  if (group.conditions.length > LIMITS.conditionsPerPolicy) errors.push(`at most ${LIMITS.conditionsPerPolicy} conditions per policy`);
  if (group.match === "any" && group.conditions.length === 0) errors.push("a policy with match \"any\" needs at least one condition");

  const out: Condition[] = [];
  group.conditions.forEach((c, i) => {
    const at = `conditions[${i}]`;
    if (!c || typeof c !== "object" || Array.isArray(c)) {
      errors.push(`${at} must be an object`);
      return;
    }
    const cond = c as Record<string, unknown>;
    const unknownKeys = Object.keys(cond).filter((k) => k !== "field" && k !== "operator" && k !== "value");
    if (unknownKeys.length) errors.push(`${at} has unknown keys: ${unknownKeys.join(", ")}`);
    const field = cond.field;
    const operator = cond.operator;
    if (typeof field !== "string" || !isKnownField(field)) {
      errors.push(`${at}.field "${String(field)}" is not a supported field`);
      return;
    }
    if (typeof operator !== "string" || !(OPERATORS as readonly string[]).includes(operator)) {
      errors.push(`${at}.operator "${String(operator)}" is not supported`);
      return;
    }
    const op = operator as Operator;
    const isContext = field.startsWith("context.");
    let value = cond.value as Scalar | Scalar[] | undefined;

    if (NO_VALUE_OPERATORS.has(op)) {
      if (value !== undefined) errors.push(`${at}: operator ${op} takes no value`);
      out.push({ field, operator: op });
      return;
    }
    if (NUMERIC_OPERATORS.has(op)) {
      if (!isContext) errors.push(`${at}: numeric operator ${op} can only be used on context.* fields`);
      if (typeof value !== "number" || !Number.isFinite(value)) errors.push(`${at}: ${op} requires a finite number value`);
      out.push({ field, operator: op, value });
      return;
    }
    if (LIST_OPERATORS.has(op)) {
      if (!Array.isArray(value) || value.length === 0 || value.length > LIMITS.listValues || !value.every(isScalar)) {
        errors.push(`${at}: ${op} requires a non-empty array of at most ${LIMITS.listValues} strings/numbers/booleans`);
        return;
      }
      if (!isContext && !value.every((v) => typeof v === "string")) errors.push(`${at}: ${field} values must be strings`);
      if (LOWERCASE_FIELDS.has(field)) value = value.map((v) => (typeof v === "string" ? v.toLowerCase() : v));
      out.push({ field, operator: op, value });
      return;
    }
    if (op === "starts_with" || op === "glob") {
      if (typeof value !== "string" || value.length === 0 || value.length > LIMITS.stringValue) {
        errors.push(`${at}: ${op} requires a non-empty string value`);
        return;
      }
      if (LOWERCASE_FIELDS.has(field)) value = value.toLowerCase();
      out.push({ field, operator: op, value });
      return;
    }
    // equals / not_equals
    if (!isScalar(value)) {
      errors.push(`${at}: ${op} requires a string, number or boolean value`);
      return;
    }
    if (!isContext && typeof value !== "string") errors.push(`${at}: ${field} values must be strings`);
    if (LOWERCASE_FIELDS.has(field) && typeof value === "string") value = value.toLowerCase();
    out.push({ field, operator: op, value });
  });

  if (errors.length) return { ok: false, errors };
  return { ok: true, value: { match: group.match as "all" | "any", conditions: out } };
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

type Tri = true | false | "indeterminate";

const MISSING = Symbol("missing");

function readField(action: NormalizedAction, field: string): unknown {
  switch (field) {
    case "agent":
      return action.agent;
    case "environment":
      return action.environment ?? MISSING;
    case "protocol":
      return action.protocol;
    case "capability":
      return action.capability;
    case "operation":
      return action.operation;
    case "resource":
      return action.resource ?? MISSING;
    case "destination":
      return action.destination ?? MISSING;
    case "data_class":
      return action.data_class ?? MISSING;
    case "mcp.server":
      return action.mcp_server ?? MISSING;
    case "mcp.tool":
      return action.mcp_tool ?? MISSING;
  }
  // context.a.b.c — own properties only, never the prototype chain.
  let cursor: unknown = action.context;
  for (const segment of field.split(".").slice(1)) {
    if (cursor === null || typeof cursor !== "object" || Array.isArray(cursor)) return MISSING;
    if (!Object.prototype.hasOwnProperty.call(cursor, segment)) return MISSING;
    cursor = (cursor as Record<string, unknown>)[segment];
  }
  return cursor === null || cursor === undefined ? MISSING : cursor;
}

/** Wildcard match supporting only `*`. Iterative, no regex, no backtracking blowup. */
export function globMatch(pattern: string, value: string): boolean {
  let p = 0;
  let v = 0;
  let star = -1;
  let mark = 0;
  while (v < value.length) {
    if (p < pattern.length && pattern[p] !== "*" && pattern[p] === value[v]) {
      p++;
      v++;
    } else if (p < pattern.length && pattern[p] === "*") {
      star = p++;
      mark = v;
    } else if (star !== -1) {
      p = star + 1;
      v = ++mark;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === "*") p++;
  return p === pattern.length;
}

function evaluateCondition(action: NormalizedAction, cond: Condition): Tri {
  const actual = readField(action, cond.field);
  const missing = actual === MISSING;

  switch (cond.operator) {
    case "exists":
      return !missing;
    case "not_exists":
      return missing;
    case "equals":
      return !missing && actual === cond.value;
    case "not_equals":
      return missing || actual !== cond.value;
    case "in":
      return !missing && isScalar(actual) && (cond.value as Scalar[]).includes(actual);
    case "not_in":
      return missing || !isScalar(actual) || !(cond.value as Scalar[]).includes(actual);
    case "starts_with":
      return !missing && typeof actual === "string" && actual.startsWith(cond.value as string);
    case "glob":
      return !missing && typeof actual === "string" && globMatch(cond.value as string, actual);
    case "greater_than":
    case "greater_than_or_equal":
    case "less_than":
    case "less_than_or_equal": {
      if (missing || typeof actual !== "number" || !Number.isFinite(actual)) return "indeterminate";
      const target = cond.value as number;
      if (cond.operator === "greater_than") return actual > target;
      if (cond.operator === "greater_than_or_equal") return actual >= target;
      if (cond.operator === "less_than") return actual < target;
      return actual <= target;
    }
  }
}

function evaluateGroup(action: NormalizedAction, group: ConditionGroup): { result: Tri; indeterminateFields: string[] } {
  const results = group.conditions.map((c) => ({ c, r: evaluateCondition(action, c) }));
  const indeterminateFields = results.filter((x) => x.r === "indeterminate").map((x) => x.c.field);
  if (group.match === "all") {
    if (results.some((x) => x.r === false)) return { result: false, indeterminateFields: [] };
    return { result: indeterminateFields.length ? "indeterminate" : true, indeterminateFields };
  }
  if (results.some((x) => x.r === true)) return { result: true, indeterminateFields: [] };
  return { result: indeterminateFields.length ? "indeterminate" : false, indeterminateFields };
}

const EFFECT_RANK: Record<Effect, number> = { block: 0, review: 1, allow: 2 };

function comparePolicies(a: MatchedPolicy & { created_at: string }, b: MatchedPolicy & { created_at: string }): number {
  return (
    EFFECT_RANK[a.effect] - EFFECT_RANK[b.effect] ||
    a.priority - b.priority ||
    (a.created_at < b.created_at ? -1 : a.created_at > b.created_at ? 1 : 0) ||
    (a.policy_id < b.policy_id ? -1 : a.policy_id > b.policy_id ? 1 : 0)
  );
}

export class PolicyEvaluationError extends Error {
  constructor(
    readonly policyId: string,
    readonly errors: string[],
  ) {
    super(`policy ${policyId} is malformed`);
  }
}

export function evaluate(input: EvaluationInput): EvaluationResult {
  const { action, agentId, policies, defaultDecision } = input;

  const inScope = policies.filter(
    (p) => p.enabled && (p.scope === "organization" || (agentId !== null && p.agent_ids.includes(agentId))),
  );

  const matched: Array<MatchedPolicy & { created_at: string }> = [];
  for (const policy of inScope) {
    const effectOk = policy.effect === "allow" || policy.effect === "review" || policy.effect === "block";
    const validated = validateConditionGroup(policy.conditions);
    if (!effectOk || !validated.ok) {
      return failClosed(
        "POLICY_INVALID",
        `Policy "${policy.name}" is malformed and cannot be evaluated; failing closed.`,
        policy,
        inScope.length,
      );
    }
    const { result, indeterminateFields } = evaluateGroup(action, validated.value);
    const applies = result === true || (result === "indeterminate" && policy.effect !== "allow");
    if (!applies) continue;
    matched.push({
      policy_id: policy.id,
      name: policy.name,
      effect: policy.effect,
      priority: policy.priority,
      version: policy.version,
      indeterminate: result === "indeterminate",
      indeterminate_fields: indeterminateFields,
      created_at: policy.created_at,
    });
  }

  matched.sort(comparePolicies);
  const publicMatched: MatchedPolicy[] = matched.map(({ created_at: _created, ...m }) => m);
  const winner = matched[0];

  if (!winner) {
    const decision = defaultDecision;
    const codes = {
      block: ["DEFAULT_DENY", "No enabled policy allows this action. Default decision is block."],
      review: ["DEFAULT_REVIEW", "No enabled policy matched. Default decision requires human approval."],
      allow: ["DEFAULT_ALLOW", "No enabled policy matched. This non-production agent defaults to allow."],
    } as const;
    return {
      decision,
      reason_code: codes[decision][0],
      reason: codes[decision][1],
      policy: null,
      matched: [],
      evaluated_policies: inScope.length,
      engine_version: ENGINE_VERSION,
    };
  }

  const policy = policies.find((p) => p.id === winner.policy_id)!;
  let reasonCode: string;
  let reason: string;
  if (winner.indeterminate) {
    reasonCode = "POLICY_CONDITION_INDETERMINATE";
    reason = `Policy "${winner.name}" could not be fully evaluated (${winner.indeterminate_fields.join(", ")} missing or not a number); failing closed to ${winner.effect}.`;
  } else {
    const defaults: Record<Effect, [string, string]> = {
      block: ["POLICY_BLOCK", `Blocked by policy "${winner.name}".`],
      review: ["HUMAN_APPROVAL_REQUIRED", `Policy "${winner.name}" requires human approval.`],
      allow: ["POLICY_ALLOW", `Allowed by policy "${winner.name}".`],
    };
    reasonCode = policy.reason_code || defaults[winner.effect][0];
    reason = policy.reason || defaults[winner.effect][1];
  }

  return {
    decision: winner.effect,
    reason_code: reasonCode,
    reason,
    policy: { id: winner.policy_id, name: winner.name, effect: winner.effect, priority: winner.priority, version: winner.version },
    matched: publicMatched,
    evaluated_policies: inScope.length,
    engine_version: ENGINE_VERSION,
  };
}

function failClosed(code: string, reason: string, policy: PolicyRecord | null, evaluated: number): EvaluationResult {
  return {
    decision: "block",
    reason_code: code,
    reason,
    policy: policy
      ? { id: policy.id, name: policy.name, effect: policy.effect, priority: policy.priority, version: policy.version }
      : null,
    matched: [],
    evaluated_policies: evaluated,
    engine_version: ENGINE_VERSION,
  };
}

/** Wraps evaluate() so an unexpected exception can never become an allow. */
export function evaluateSafely(input: EvaluationInput): EvaluationResult {
  try {
    return evaluate(input);
  } catch {
    return failClosed("POLICY_ENGINE_ERROR", "The policy engine failed while evaluating this action; failing closed.", null, 0);
  }
}
