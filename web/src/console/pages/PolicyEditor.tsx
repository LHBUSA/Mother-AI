import { useEffect, useMemo, useRef, useState } from "react";
import { api, ApiFailure, errorMessage, type Agent, type Condition, type ConditionGroup, type Decision, type Operator, type Policy, type Scalar } from "../lib/api";
import { useApi, useDocumentTitle } from "../lib/hooks";
import { Link, useRouter } from "../lib/router";
import { dateTime, relativeTime } from "../lib/format";
import { useSession } from "../lib/session";
import { IconArrowLeft, IconClose, IconPlus, IconTrash } from "../components/icons";
import { Alert, Button, Card, ConfirmDialog, DecisionPill, ErrorState, Field, Input, JsonView, Mono, PageHeader, Select, Skeleton, Tag, Textarea, Toggle, cx, toast } from "../components/ui";
import { describeCondition } from "./Policies";

// ---------------------------------------------------------------------------
// Builder model
// ---------------------------------------------------------------------------

const STRING_FIELDS = ["agent", "environment", "protocol", "capability", "operation", "resource", "destination", "data_class", "mcp.server", "mcp.tool"] as const;
const FIELD_LABEL: Record<string, string> = {
  agent: "agent",
  environment: "environment",
  protocol: "protocol",
  capability: "capability",
  operation: "operation",
  resource: "resource",
  destination: "destination",
  data_class: "data_class",
  "mcp.server": "mcp.server",
  "mcp.tool": "mcp.tool",
  context: "context field…",
};
const STRING_OPERATORS: Operator[] = ["equals", "not_equals", "in", "not_in", "starts_with", "glob", "exists", "not_exists"];
const CONTEXT_OPERATORS: Operator[] = ["equals", "not_equals", "greater_than", "greater_than_or_equal", "less_than", "less_than_or_equal", "in", "not_in", "starts_with", "glob", "exists", "not_exists"];
const OP_LABEL: Record<Operator, string> = {
  equals: "equals",
  not_equals: "does not equal",
  in: "is one of",
  not_in: "is not one of",
  starts_with: "starts with",
  glob: "matches pattern",
  greater_than: "greater than",
  greater_than_or_equal: "at least",
  less_than: "less than",
  less_than_or_equal: "at most",
  exists: "is present",
  not_exists: "is missing",
};
const NUMERIC: Operator[] = ["greater_than", "greater_than_or_equal", "less_than", "less_than_or_equal"];
const LIST: Operator[] = ["in", "not_in"];
const NO_VALUE: Operator[] = ["exists", "not_exists"];
const SUGGESTIONS: Record<string, string[]> = {
  environment: ["production", "staging", "development"],
  protocol: ["api", "mcp"],
  destination: ["internal", "external"],
  data_class: ["public", "internal", "confidential", "financial", "restricted"],
};
const CONTEXT_PATH = /^[A-Za-z0-9_-]{1,64}(\.[A-Za-z0-9_-]{1,64}){0,5}$/;

type ValueType = "text" | "number" | "boolean";
interface Row {
  key: number;
  field: string; // one of STRING_FIELDS or "context"
  path: string; // for context
  operator: Operator;
  valueType: ValueType;
  value: string;
  list: string[];
}

let rowSeq = 0;
function newRow(partial: Partial<Row> = {}): Row {
  return { key: ++rowSeq, field: "capability", path: "", operator: "equals", valueType: "text", value: "", list: [], ...partial };
}

function rowFromCondition(c: Condition): Row {
  const isContext = c.field.startsWith("context.");
  const values = Array.isArray(c.value) ? c.value : c.value === undefined ? [] : [c.value];
  const first = values[0];
  const valueType: ValueType = typeof first === "number" ? "number" : typeof first === "boolean" ? "boolean" : "text";
  return newRow({
    field: isContext ? "context" : c.field,
    path: isContext ? c.field.slice("context.".length) : "",
    operator: c.operator,
    valueType: isContext ? valueType : "text",
    value: Array.isArray(c.value) || c.value === undefined ? "" : String(c.value),
    list: Array.isArray(c.value) ? c.value.map(String) : [],
  });
}

function coerce(raw: string, type: ValueType): Scalar | null {
  if (type === "number") {
    if (raw.trim() === "") return null;
    const n = Number(raw);
    return Number.isFinite(n) ? n : null;
  }
  if (type === "boolean") return raw === "true" ? true : raw === "false" ? false : null;
  return raw;
}

function rowToCondition(r: Row): { condition?: Condition; error?: string } {
  const field = r.field === "context" ? `context.${r.path.trim()}` : r.field;
  if (r.field === "context" && !CONTEXT_PATH.test(r.path.trim())) return { error: "Context path must be segments of letters, numbers, _ or -, separated by dots (max 6)." };
  if (NO_VALUE.includes(r.operator)) return { condition: { field, operator: r.operator } };
  const isContext = r.field === "context";
  if (NUMERIC.includes(r.operator)) {
    const n = Number(r.value);
    if (r.value.trim() === "" || !Number.isFinite(n)) return { error: `${OP_LABEL[r.operator]} needs a number.` };
    return { condition: { field, operator: r.operator, value: n } };
  }
  if (LIST.includes(r.operator)) {
    if (!r.list.length) return { error: "Add at least one value." };
    const type = isContext ? r.valueType : "text";
    const values = r.list.map((v) => coerce(v, type));
    if (values.some((v) => v === null)) return { error: `Every value must be a valid ${type}.` };
    return { condition: { field, operator: r.operator, value: values as Scalar[] } };
  }
  const type = isContext && r.operator !== "starts_with" && r.operator !== "glob" ? r.valueType : "text";
  const v = coerce(r.value, type);
  if (v === null || (typeof v === "string" && v.trim() === "")) return { error: "Enter a value." };
  return { condition: { field, operator: r.operator, value: typeof v === "string" ? v.trim() : v } };
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

const TEMPLATES: Array<{ id: string; title: string; text: string; policy: { name: string; description: string; effect: Decision; priority: number; reason_code: string; reason: string; conditions: ConditionGroup } }> = [
  {
    id: "read-only",
    title: "Read-only research agent",
    text: "Allow reads on knowledge and records. Everything else falls to default deny. Scope it to your research agent.",
    policy: {
      name: "Research agent may read knowledge and records",
      description: "Read access only. Writes, finance and anything unmatched fall to the default decision.",
      effect: "allow",
      priority: 100,
      reason_code: "",
      reason: "",
      conditions: { match: "all", conditions: [{ field: "capability", operator: "in", value: ["knowledge", "records"] }, { field: "operation", operator: "equals", value: "read" }] },
    },
  },
  {
    id: "refunds",
    title: "High-value refunds need approval",
    text: "Route refunds over $1,000 to a human approver. A missing amount fails closed to review.",
    policy: {
      name: "Refunds over $1,000 need human approval",
      description: "High-value refunds wait for an approver before execution.",
      effect: "review",
      priority: 20,
      reason_code: "",
      reason: "Refunds over $1,000 require human approval.",
      conditions: {
        match: "all",
        conditions: [
          { field: "capability", operator: "equals", value: "payments" },
          { field: "operation", operator: "equals", value: "refund" },
          { field: "context.amount", operator: "greater_than", value: 1000 },
        ],
      },
    },
  },
  {
    id: "egress",
    title: "Restricted data never leaves",
    text: "Block any agent sending restricted data to an external destination.",
    policy: {
      name: "Restricted data never leaves the company",
      description: "Blocks restricted data from reaching external destinations.",
      effect: "block",
      priority: 1,
      reason_code: "RESTRICTED_DATA_EGRESS",
      reason: "Restricted data cannot be sent to external destinations.",
      conditions: { match: "all", conditions: [{ field: "data_class", operator: "equals", value: "restricted" }, { field: "destination", operator: "equals", value: "external" }] },
    },
  },
];

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

function ChipInput({ values, onChange, placeholder, disabled, id, mono }: { values: string[]; onChange: (v: string[]) => void; placeholder?: string; disabled?: boolean; id?: string; mono?: boolean }) {
  const [draft, setDraft] = useState("");
  const commit = () => {
    const parts = draft.split(",").map((s) => s.trim()).filter(Boolean);
    if (parts.length) onChange([...values, ...parts.filter((p) => !values.includes(p))]);
    setDraft("");
  };
  return (
    <div className={cx("chips", disabled && "is-disabled")}>
      {values.map((v) => (
        <span key={v} className="chip">
          <span className={cx(mono && "mono")}>{v}</span>
          {!disabled && (
            <button type="button" aria-label={`Remove ${v}`} onClick={() => onChange(values.filter((x) => x !== v))}>
              <IconClose width={12} height={12} />
            </button>
          )}
        </span>
      ))}
      <input
        id={id}
        className={cx("chips-input", mono && "mono")}
        value={draft}
        disabled={disabled}
        placeholder={values.length ? "" : placeholder}
        onChange={(e) => {
          if (e.target.value.includes(",")) {
            setDraft(e.target.value);
            const parts = e.target.value.split(",");
            const last = parts.pop() ?? "";
            const add = parts.map((s) => s.trim()).filter(Boolean).filter((p) => !values.includes(p));
            if (add.length) onChange([...values, ...add]);
            setDraft(last);
          } else setDraft(e.target.value);
        }}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            commit();
          } else if (e.key === "Backspace" && !draft && values.length) onChange(values.slice(0, -1));
        }}
        onBlur={commit}
      />
    </div>
  );
}

function ConditionRow({ row, index, match, onChange, onRemove, error, disabled, canRemove }: { row: Row; index: number; match: "all" | "any"; onChange: (r: Row) => void; onRemove: () => void; error?: string; disabled: boolean; canRemove: boolean }) {
  const isContext = row.field === "context";
  const operators = isContext ? CONTEXT_OPERATORS : STRING_OPERATORS;
  const listId = `sugg-${row.key}`;
  const suggestions = SUGGESTIONS[row.field];
  const set = (patch: Partial<Row>) => onChange({ ...row, ...patch });
  const showTypeSelect = isContext && !NUMERIC.includes(row.operator) && !NO_VALUE.includes(row.operator) && row.operator !== "starts_with" && row.operator !== "glob";

  return (
    <div className={cx("cond", error && "has-error")}>
      <div className="cond-joiner mono" aria-hidden="true">
        {index === 0 ? "IF" : match === "all" ? "AND" : "OR"}
      </div>
      <div className="cond-fields">
        <div className="cond-field">
          <Select
            aria-label={`Condition ${index + 1} field`}
            value={row.field}
            disabled={disabled}
            onChange={(e) => {
              const field = e.target.value;
              const ops = field === "context" ? CONTEXT_OPERATORS : STRING_OPERATORS;
              set({ field, operator: ops.includes(row.operator) ? row.operator : "equals", valueType: field === "context" ? row.valueType : "text" });
            }}
            className="mono"
          >
            {STRING_FIELDS.map((f) => (
              <option key={f} value={f}>
                {FIELD_LABEL[f]}
              </option>
            ))}
            <option value="context">{FIELD_LABEL.context}</option>
          </Select>
          {isContext && (
            <div className="ctx-path">
              <span className="ctx-prefix mono">context.</span>
              <Input aria-label={`Condition ${index + 1} context path`} className="mono" value={row.path} disabled={disabled} placeholder="amount" onChange={(e) => set({ path: e.target.value })} spellCheck={false} />
            </div>
          )}
        </div>
        <Select
          aria-label={`Condition ${index + 1} operator`}
          value={row.operator}
          disabled={disabled}
          onChange={(e) => {
            const operator = e.target.value as Operator;
            set({ operator, valueType: NUMERIC.includes(operator) ? "number" : row.valueType, list: LIST.includes(operator) ? (row.list.length ? row.list : row.value ? [row.value] : []) : row.list });
          }}
          className="cond-op"
        >
          {operators.map((o) => (
            <option key={o} value={o}>
              {OP_LABEL[o]}
            </option>
          ))}
        </Select>
        <div className="cond-value">
          {NO_VALUE.includes(row.operator) ? (
            <span className="cond-novalue muted small">no value needed</span>
          ) : LIST.includes(row.operator) ? (
            <ChipInput values={row.list} onChange={(list) => set({ list })} placeholder="Type a value, press Enter" disabled={disabled} mono />
          ) : row.valueType === "boolean" && showTypeSelect ? (
            <Select aria-label={`Condition ${index + 1} value`} value={row.value} disabled={disabled} onChange={(e) => set({ value: e.target.value })}>
              <option value="">choose…</option>
              <option value="true">true</option>
              <option value="false">false</option>
            </Select>
          ) : (
            <>
              <Input
                aria-label={`Condition ${index + 1} value`}
                className="mono"
                inputMode={NUMERIC.includes(row.operator) || row.valueType === "number" ? "decimal" : undefined}
                type="text"
                value={row.value}
                disabled={disabled}
                placeholder={NUMERIC.includes(row.operator) || row.valueType === "number" ? "1000" : row.operator === "glob" ? "*.delete" : "value"}
                list={suggestions ? listId : undefined}
                onChange={(e) => set({ value: e.target.value })}
                spellCheck={false}
              />
              {suggestions && (
                <datalist id={listId}>
                  {suggestions.map((s) => (
                    <option key={s} value={s} />
                  ))}
                </datalist>
              )}
            </>
          )}
          {showTypeSelect && (
            <Select aria-label={`Condition ${index + 1} value type`} className="cond-type" value={row.valueType} disabled={disabled} onChange={(e) => set({ valueType: e.target.value as ValueType })}>
              <option value="text">text</option>
              <option value="number">number</option>
              <option value="boolean">true/false</option>
            </Select>
          )}
        </div>
        {canRemove && !disabled && (
          <button type="button" className="icon-btn cond-remove" aria-label={`Remove condition ${index + 1}`} onClick={onRemove}>
            <IconTrash />
          </button>
        )}
      </div>
      {error && <p className="field-error cond-error">{error}</p>}
    </div>
  );
}

interface SimResult {
  decision: Decision;
  reason_code: string;
  reason: string;
  policy: { id: string; name: string; effect: Decision; priority: number; version: number } | null;
  matched: Array<{ policy_id: string; name: string; effect: Decision; indeterminate: boolean; indeterminate_fields?: string[] }>;
  evaluated_policies?: number;
}

function Simulator({ agents, draft, draftError }: { agents: Agent[]; draft: Record<string, unknown> | null; draftError: string | null }) {
  const [req, setReq] = useState({ agent_id: agents[0]?.agent_key ?? "", capability: "payments", operation: "refund", resource: "", destination: "internal", data_class: "", protocol: "api", mcp_server: "", mcp_tool: "", context: '{\n  "amount": 4200,\n  "currency": "USD"\n}' });
  const [result, setResult] = useState<SimResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!req.agent_id && agents[0]) setReq((r) => ({ ...r, agent_id: agents[0]!.agent_key }));
  }, [agents, req.agent_id]);

  const run = async () => {
    setError(null);
    let context: unknown = undefined;
    if (req.context.trim()) {
      try {
        context = JSON.parse(req.context);
      } catch {
        setError("Context must be valid JSON.");
        return;
      }
    }
    const request: Record<string, unknown> = { agent_id: req.agent_id, capability: req.capability, operation: req.operation, protocol: req.protocol };
    for (const k of ["resource", "destination", "data_class"] as const) if (req[k].trim()) request[k] = req[k].trim();
    if (req.protocol === "mcp") request.mcp = { server: req.mcp_server, tool: req.mcp_tool };
    if (context !== undefined) request.context = context;
    setBusy(true);
    try {
      setResult(await api<SimResult>("/api/console/policies/simulate", { body: { request, ...(draft ? { draft } : {}) } }));
    } catch (err) {
      setResult(null);
      if (err instanceof ApiFailure && Object.keys(err.fields).length) setError(Object.entries(err.fields).map(([k, v]) => `${k}: ${v}`).join(" · "));
      else setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const set = (k: keyof typeof req, v: string) => setReq((r) => ({ ...r, [k]: v }));

  return (
    <Card title="Test this policy" className="sim">
      <p className="muted small mb-12">Dry-run a sample action against your enabled policies with this draft applied. Nothing is recorded.</p>
      {draftError && <Alert tone="warn">Fix the rule builder first: {draftError}</Alert>}
      <div className="sim-grid">
        <Field label="Agent" htmlFor="sim-agent">
          {agents.length ? (
            <Select id="sim-agent" className="mono" value={req.agent_id} onChange={(e) => set("agent_id", e.target.value)}>
              {agents.map((a) => (
                <option key={a.id} value={a.agent_key}>
                  {a.agent_key}
                </option>
              ))}
            </Select>
          ) : (
            <Input id="sim-agent" className="mono" value={req.agent_id} onChange={(e) => set("agent_id", e.target.value)} placeholder="agent id" />
          )}
        </Field>
        <Field label="Protocol" htmlFor="sim-proto">
          <Select id="sim-proto" value={req.protocol} onChange={(e) => set("protocol", e.target.value)}>
            <option value="api">api</option>
            <option value="mcp">mcp</option>
          </Select>
        </Field>
        <Field label="Capability" htmlFor="sim-cap">
          <Input id="sim-cap" className="mono" value={req.capability} onChange={(e) => set("capability", e.target.value)} />
        </Field>
        <Field label="Operation" htmlFor="sim-op">
          <Input id="sim-op" className="mono" value={req.operation} onChange={(e) => set("operation", e.target.value)} />
        </Field>
        {req.protocol === "mcp" && (
          <>
            <Field label="MCP server" htmlFor="sim-srv">
              <Input id="sim-srv" className="mono" value={req.mcp_server} onChange={(e) => set("mcp_server", e.target.value)} placeholder="salesforce" />
            </Field>
            <Field label="MCP tool" htmlFor="sim-tool">
              <Input id="sim-tool" className="mono" value={req.mcp_tool} onChange={(e) => set("mcp_tool", e.target.value)} placeholder="contacts.update" />
            </Field>
          </>
        )}
        <Field label="Resource" htmlFor="sim-res" optional>
          <Input id="sim-res" className="mono" value={req.resource} onChange={(e) => set("resource", e.target.value)} placeholder="payment:pi_123" />
        </Field>
        <Field label="Destination" htmlFor="sim-dest" optional>
          <Input id="sim-dest" className="mono" value={req.destination} onChange={(e) => set("destination", e.target.value)} list="sim-dest-list" />
          <datalist id="sim-dest-list"><option value="internal" /><option value="external" /></datalist>
        </Field>
        <Field label="Data class" htmlFor="sim-dc" optional>
          <Input id="sim-dc" className="mono" value={req.data_class} onChange={(e) => set("data_class", e.target.value)} list="sim-dc-list" />
          <datalist id="sim-dc-list">{SUGGESTIONS.data_class!.map((s) => <option key={s} value={s} />)}</datalist>
        </Field>
        <Field label="Context (JSON)" htmlFor="sim-ctx" optional>
          <Textarea id="sim-ctx" className="mono" rows={4} value={req.context} onChange={(e) => set("context", e.target.value)} spellCheck={false} />
        </Field>
      </div>
      <div className="form-actions">
        <Button variant="secondary" onClick={() => void run()} loading={busy} disabled={!!draftError}>
          Run simulation
        </Button>
      </div>
      {error && <Alert tone="bad">{error}</Alert>}
      {result && (
        <div className={cx("sim-result", `sim-${result.decision}`)} aria-live="polite">
          <div className="sim-result-head">
            <DecisionPill decision={result.decision} />
            <Mono>{result.reason_code}</Mono>
          </div>
          <p className="sim-reason">{result.reason}</p>
          {result.policy ? (
            <p className="muted small">
              Winning policy: <strong className="text-strong">{result.policy.name}</strong> · priority {result.policy.priority}
              {result.policy.version === 0 && <Tag tone="warn">draft</Tag>}
            </p>
          ) : (
            <p className="muted small">No policy matched — default decision applied.</p>
          )}
          {result.matched.length > 0 && (
            <ul className="sim-matched">
              {result.matched.map((m) => (
                <li key={m.policy_id}>
                  <DecisionPill decision={m.effect} size="sm" />
                  <span>{m.name}</span>
                  {m.indeterminate && <Tag tone="warn">indeterminate · fail closed{m.indeterminate_fields?.length ? ` (${m.indeterminate_fields.join(", ")})` : ""}</Tag>}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

interface FormState {
  name: string;
  description: string;
  priority: string;
  enabled: boolean;
  effect: Decision;
  scope: "organization" | "agents";
  agentIds: string[];
  match: "all" | "any";
  rows: Row[];
  reason_code: string;
  reason: string;
}

function emptyForm(): FormState {
  return { name: "", description: "", priority: "100", enabled: true, effect: "block", scope: "organization", agentIds: [], match: "all", rows: [newRow()], reason_code: "", reason: "" };
}

function formFromPolicy(p: Policy): FormState {
  const group = p.conditions ?? { match: "all", conditions: [] };
  return {
    name: p.name,
    description: p.description,
    priority: String(p.priority),
    enabled: p.enabled,
    effect: p.effect,
    scope: p.scope,
    agentIds: p.agents.map((a) => a.id),
    match: group.match,
    rows: group.conditions.map(rowFromCondition),
    reason_code: p.reason_code ?? "",
    reason: p.reason ?? "",
  };
}

const EFFECT_OPTIONS: Array<{ id: Decision; label: string; text: string }> = [
  { id: "allow", label: "ALLOW", text: "Permit the action" },
  { id: "review", label: "REQUIRE HUMAN APPROVAL", text: "Pause for an approver" },
  { id: "block", label: "BLOCK", text: "Refuse the action" },
];

export function PolicyEditorPage({ id }: { id: string | null }) {
  const { can } = useSession();
  const { navigate } = useRouter();
  const editable = can("manage_policies");
  const existing = useApi<{ policy: Policy; versions: Array<{ version: number; changed_by: string | null; created_at: string; snapshot: unknown }> }>(id ? `/api/console/policies/${id}` : null);
  const agentsRes = useApi<{ agents: Agent[] }>("/api/console/agents");
  const agents = agentsRes.data?.agents ?? [];
  const [form, setForm] = useState<FormState>(emptyForm);
  const [loadedVersion, setLoadedVersion] = useState<number | null>(null);
  const [fields, setFields] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);
  const [saving, setSaving] = useState(false);
  const [showJson, setShowJson] = useState(false);
  const [jsonMode, setJsonMode] = useState(false);
  const [jsonText, setJsonText] = useState("");
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [archiveOpen, setArchiveOpen] = useState(false);
  const [archiveBusy, setArchiveBusy] = useState(false);
  const [archiveError, setArchiveError] = useState<string | null>(null);
  const [agentFilter, setAgentFilter] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const initialized = useRef(false);

  const policy = existing.data?.policy ?? null;
  useDocumentTitle(id ? (policy?.name ?? "Policy") : "New policy");

  useEffect(() => {
    if (policy && !initialized.current) {
      initialized.current = true;
      setForm(formFromPolicy(policy));
      setLoadedVersion(policy.version);
    }
  }, [policy]);

  const readOnly = !editable || !!policy?.archived_at;

  const built = useMemo(() => {
    const errors: Record<number, string> = {};
    const conditions: Condition[] = [];
    form.rows.forEach((r) => {
      const { condition, error: e } = rowToCondition(r);
      if (e) errors[r.key] = e;
      else if (condition) conditions.push(condition);
    });
    const group: ConditionGroup = { match: form.match, conditions };
    let groupError: string | null = null;
    if (form.match === "any" && form.rows.length === 0) groupError = "An OR group needs at least one condition.";
    return { errors, group, hasErrors: Object.keys(errors).length > 0 || !!groupError, groupError };
  }, [form.rows, form.match]);

  const payload = useMemo(
    () => ({
      name: form.name.trim(),
      description: form.description.trim(),
      priority: Number(form.priority),
      enabled: form.enabled,
      effect: form.effect,
      scope: form.scope,
      agent_ids: form.scope === "agents" ? form.agentIds : [],
      conditions: built.group,
      reason_code: form.reason_code.trim() || null,
      reason: form.reason.trim() || null,
    }),
    [form, built.group],
  );

  const draftForSim = built.hasErrors ? null : { id: id ?? "pol_draft", name: payload.name || "Draft policy", effect: payload.effect, priority: Number.isFinite(payload.priority) ? payload.priority : 100, scope: payload.scope, agent_ids: payload.agent_ids, conditions: payload.conditions };
  const firstRowError = Object.values(built.errors)[0] ?? built.groupError;

  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => setForm((f) => ({ ...f, [k]: v }));
  const updateRow = (key: number, r: Row) => setForm((f) => ({ ...f, rows: f.rows.map((x) => (x.key === key ? r : x)) }));

  const clientErrors = (): Record<string, string> => {
    const e: Record<string, string> = {};
    if (!payload.name) e.name = "Give the policy a name.";
    if (!Number.isInteger(payload.priority) || payload.priority < 0 || payload.priority > 10000) e.priority = "Whole number from 0 to 10000.";
    if (payload.scope === "agents" && payload.agent_ids.length === 0) e.agent_ids = "Choose at least one agent.";
    if (payload.reason_code && !/^[A-Z][A-Z0-9_]{2,63}$/.test(payload.reason_code)) e.reason_code = "UPPER_SNAKE_CASE, 3–64 characters.";
    return e;
  };

  const save = async () => {
    setSubmitted(true);
    setError(null);
    setConflict(false);
    const ce = clientErrors();
    setFields(ce);
    if (Object.keys(ce).length || built.hasErrors) {
      setError("Fix the highlighted fields before saving.");
      return;
    }
    setSaving(true);
    try {
      if (id) {
        const res = await api<{ policy: Policy }>(`/api/console/policies/${id}`, { method: "PUT", body: { ...payload, expected_version: loadedVersion } });
        setForm(formFromPolicy(res.policy));
        setLoadedVersion(res.policy.version);
        toast(`Saved version ${res.policy.version}`);
        void existing.reload();
      } else {
        const res = await api<{ policy: Policy }>("/api/console/policies", { body: payload });
        toast("Policy created");
        navigate(`/app/policies/${res.policy.id}`, { replace: true });
      }
      setSubmitted(false);
    } catch (err) {
      if (err instanceof ApiFailure && err.code === "VERSION_CONFLICT") setConflict(true);
      else if (err instanceof ApiFailure && Object.keys(err.fields).length) {
        setFields(err.fields);
        setError(err.fields.conditions ? `Conditions rejected: ${err.fields.conditions}` : "The server rejected some fields.");
      } else setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  const reloadLatest = async () => {
    initialized.current = false;
    setConflict(false);
    await existing.reload();
  };

  const applyTemplate = (t: (typeof TEMPLATES)[number]) => {
    setForm((f) => ({
      ...f,
      name: t.policy.name,
      description: t.policy.description,
      effect: t.policy.effect,
      priority: String(t.policy.priority),
      match: t.policy.conditions.match,
      rows: t.policy.conditions.conditions.map(rowFromCondition),
      reason_code: t.policy.reason_code,
      reason: t.policy.reason,
    }));
    toast(`Loaded “${t.title}” — review scope before saving`);
  };

  const openJsonMode = () => {
    setJsonText(JSON.stringify(built.group, null, 2));
    setJsonError(null);
    setJsonMode(true);
  };
  const applyJson = () => {
    try {
      const parsed = JSON.parse(jsonText) as ConditionGroup;
      if (!parsed || (parsed.match !== "all" && parsed.match !== "any") || !Array.isArray(parsed.conditions)) throw new Error("Expected { \"match\": \"all\" | \"any\", \"conditions\": [...] }");
      const rows = parsed.conditions.map((c) => {
        if (!c || typeof c.field !== "string" || typeof c.operator !== "string") throw new Error("Each condition needs field and operator.");
        const known = (STRING_FIELDS as readonly string[]).includes(c.field) || c.field.startsWith("context.");
        if (!known) throw new Error(`Unsupported field "${c.field}".`);
        if (!(c.field.startsWith("context.") ? CONTEXT_OPERATORS : STRING_OPERATORS).includes(c.operator)) throw new Error(`Operator "${c.operator}" isn't valid for ${c.field}.`);
        return rowFromCondition(c);
      });
      setForm((f) => ({ ...f, match: parsed.match, rows }));
      setJsonMode(false);
    } catch (err) {
      setJsonError(err instanceof Error ? err.message : "Invalid JSON.");
    }
  };

  const archive = async () => {
    setArchiveBusy(true);
    setArchiveError(null);
    try {
      await api(`/api/console/policies/${id}/archive`, { body: {} });
      toast("Policy archived");
      navigate("/app/policies");
    } catch (err) {
      setArchiveError(errorMessage(err));
    } finally {
      setArchiveBusy(false);
    }
  };

  if (id && existing.error && !existing.data) return <ErrorState error={existing.error} onRetry={() => void existing.reload()} />;
  if (id && !existing.data) return <Skeleton lines={10} />;

  const filteredAgents = agents.filter((a) => !agentFilter || `${a.agent_key} ${a.display_name}`.toLowerCase().includes(agentFilter.toLowerCase()));

  return (
    <>
      <Link to="/app/policies" className="back-link">
        <IconArrowLeft /> Policies
      </Link>
      <PageHeader
        title={id ? form.name || "Policy" : "New policy"}
        eyebrow={id && policy ? <span className="mono">{policy.id} · v{loadedVersion}</span> : "Deterministic rule"}
        actions={
          !readOnly && (
            <>
              {id && (
                <Button variant="ghost" onClick={() => setArchiveOpen(true)}>
                  Archive
                </Button>
              )}
              <Button variant="primary" onClick={() => void save()} loading={saving}>
                {id ? "Save new version" : "Create policy"}
              </Button>
            </>
          )
        }
      />
      {policy?.archived_at && <Alert tone="warn" title="Archived">This policy was archived {relativeTime(policy.archived_at)} and is no longer evaluated. Archived policies are read-only.</Alert>}
      {!editable && !policy?.archived_at && <Alert tone="info">Your role can view policies but not change them.</Alert>}
      {conflict && (
        <Alert tone="warn" title="Someone else changed this policy">
          A newer version was saved since you opened it. Your edits weren't saved.{" "}
          <Button size="sm" variant="secondary" onClick={() => void reloadLatest()}>
            Load latest version
          </Button>
        </Alert>
      )}

      {!id && !readOnly && (
        <div className="templates">
          <div className="templates-title">Start from an example</div>
          <div className="templates-grid">
            {TEMPLATES.map((t) => (
              <button key={t.id} type="button" className="template" onClick={() => applyTemplate(t)}>
                <DecisionPill decision={t.policy.effect} size="sm" />
                <span className="template-name">{t.title}</span>
                <span className="template-text">{t.text}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="grid-editor">
        <div className="stack">
          <Card title="Rule">
            <div className="builder">
              <div className="builder-match">
                <span className="muted small">Match</span>
                <div className="seg" role="radiogroup" aria-label="Condition matching">
                  <button type="button" role="radio" aria-checked={form.match === "all"} className={cx("seg-btn", form.match === "all" && "is-on")} disabled={readOnly} onClick={() => set("match", "all")}>
                    ALL <span className="muted">(AND)</span>
                  </button>
                  <button type="button" role="radio" aria-checked={form.match === "any"} className={cx("seg-btn", form.match === "any" && "is-on")} disabled={readOnly} onClick={() => set("match", "any")}>
                    ANY <span className="muted">(OR)</span>
                  </button>
                </div>
                {!readOnly && !jsonMode && (
                  <button type="button" className="link-sm builder-json-link" onClick={openJsonMode}>
                    Edit as JSON
                  </button>
                )}
              </div>

              {jsonMode ? (
                <div className="json-editor">
                  <Textarea className="mono" rows={12} value={jsonText} onChange={(e) => setJsonText(e.target.value)} spellCheck={false} aria-label="Conditions JSON" />
                  {jsonError && <p className="field-error">{jsonError}</p>}
                  <div className="form-actions">
                    <Button variant="ghost" size="sm" onClick={() => setJsonMode(false)}>Cancel</Button>
                    <Button variant="secondary" size="sm" onClick={applyJson}>Apply to builder</Button>
                  </div>
                </div>
              ) : (
                <>
                  {form.rows.length === 0 && (
                    <div className="cond cond-empty">
                      <div className="cond-joiner mono">IF</div>
                      <p className="muted small">No conditions — this policy {form.match === "all" ? "matches every action in scope" : "can't match anything"}.</p>
                    </div>
                  )}
                  {form.rows.map((r, i) => (
                    <ConditionRow
                      key={r.key}
                      row={r}
                      index={i}
                      match={form.match}
                      onChange={(nr) => updateRow(r.key, nr)}
                      onRemove={() => set("rows", form.rows.filter((x) => x.key !== r.key))}
                      error={submitted || r.value || r.list.length || r.path ? built.errors[r.key] : undefined}
                      disabled={readOnly}
                      canRemove={true}
                    />
                  ))}
                  {!readOnly && (
                    <button type="button" className="add-cond" onClick={() => set("rows", [...form.rows, newRow()])}>
                      <IconPlus /> Add condition
                    </button>
                  )}
                  {built.groupError && submitted && <p className="field-error">{built.groupError}</p>}
                </>
              )}

              <div className="then">
                <div className="cond-joiner mono">THEN</div>
                <div className="effect-options" role="radiogroup" aria-label="Effect">
                  {EFFECT_OPTIONS.map((o) => (
                    <button key={o.id} type="button" role="radio" aria-checked={form.effect === o.id} disabled={readOnly} className={cx("effect-opt", `effect-${o.id}`, form.effect === o.id && "is-on")} onClick={() => set("effect", o.id)}>
                      <span className="effect-opt-label mono">{o.label}</span>
                      <span className="effect-opt-text">{o.text}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
            {fields.conditions && <Alert tone="bad">{fields.conditions}</Alert>}
          </Card>

          <Card title="Scope">
            <div className="scope-choice" role="radiogroup" aria-label="Scope">
              <label className={cx("radio-card", form.scope === "organization" && "is-on")}>
                <input type="radio" name="scope" checked={form.scope === "organization"} disabled={readOnly} onChange={() => set("scope", "organization")} />
                <span>
                  <strong>All agents</strong>
                  <span className="muted small">Evaluated for every agent in the organization.</span>
                </span>
              </label>
              <label className={cx("radio-card", form.scope === "agents" && "is-on")}>
                <input type="radio" name="scope" checked={form.scope === "agents"} disabled={readOnly} onChange={() => set("scope", "agents")} />
                <span>
                  <strong>Selected agents</strong>
                  <span className="muted small">Only evaluated for the agents you bind.</span>
                </span>
              </label>
            </div>
            {form.scope === "agents" && (
              <div className="agent-picker">
                {agents.length > 6 && <Input placeholder="Filter agents" value={agentFilter} onChange={(e) => setAgentFilter(e.target.value)} aria-label="Filter agents" />}
                {agentsRes.loading && !agentsRes.data ? (
                  <Skeleton lines={3} />
                ) : agents.length === 0 ? (
                  <p className="muted small">No agents registered yet. <Link to="/app/agents">Register an agent</Link> first.</p>
                ) : (
                  <ul className="agent-checks">
                    {filteredAgents.map((a) => (
                      <li key={a.id}>
                        <label className={cx("agent-check", form.agentIds.includes(a.id) && "is-on")}>
                          <input
                            type="checkbox"
                            checked={form.agentIds.includes(a.id)}
                            disabled={readOnly}
                            onChange={(e) => set("agentIds", e.target.checked ? [...form.agentIds, a.id] : form.agentIds.filter((x) => x !== a.id))}
                          />
                          <span className="mono">{a.agent_key}</span>
                          <span className="muted small">{a.environment}</span>
                          {a.status !== "active" && <Tag tone="muted">disabled</Tag>}
                        </label>
                      </li>
                    ))}
                  </ul>
                )}
                {fields.agent_ids && <p className="field-error">{fields.agent_ids}</p>}
              </div>
            )}
          </Card>

          <Card
            title="What will be saved"
            actions={
              <button type="button" className="link-sm" onClick={() => setShowJson((s) => !s)} aria-expanded={showJson}>
                {showJson ? "Hide JSON" : "Show JSON"}
              </button>
            }
          >
            <p className="policy-sentence">
              <DecisionPill decision={form.effect} size="sm" /> {form.scope === "organization" ? "any agent" : `${form.agentIds.length} selected agent${form.agentIds.length === 1 ? "" : "s"}`} when{" "}
              {built.group.conditions.length === 0 ? <em>always</em> : built.group.conditions.map((c, i) => (
                <span key={i}>
                  {i > 0 && <b className="mono">{form.match === "all" ? " AND " : " OR "}</b>}
                  <code className="mono-inline">{describeCondition(c)}</code>
                </span>
              ))}
            </p>
            {showJson && <JsonView value={payload} />}
          </Card>
        </div>

        <div className="stack">
          <Card title="Details">
            <div className="form-grid">
              <Field label="Name" htmlFor="p-name" error={fields.name}>
                <Input id="p-name" value={form.name} disabled={readOnly} onChange={(e) => set("name", e.target.value)} placeholder="Refunds over $1,000 need approval" maxLength={120} />
              </Field>
              <Field label="Description" htmlFor="p-desc" optional error={fields.description}>
                <Textarea id="p-desc" rows={2} value={form.description} disabled={readOnly} onChange={(e) => set("description", e.target.value)} maxLength={500} />
              </Field>
              <div className="form-row">
                <Field label="Priority" htmlFor="p-pri" error={fields.priority} hint="Lower reports first within an effect.">
                  <Input id="p-pri" className="mono" inputMode="numeric" value={form.priority} disabled={readOnly} onChange={(e) => set("priority", e.target.value.replace(/[^0-9]/g, ""))} />
                </Field>
                <Field label="Enabled" htmlFor="p-enabled" hint={form.enabled ? "Evaluated on every request" : "Ignored by the engine"}>
                  <div className="toggle-row">
                    <Toggle id="p-enabled" checked={form.enabled} onChange={(v) => set("enabled", v)} label="Policy enabled" disabled={readOnly} />
                    <span className="small">{form.enabled ? "On" : "Off"}</span>
                  </div>
                </Field>
              </div>
              <Field label="Reason code" htmlFor="p-code" optional error={fields.reason_code} hint="Returned to the agent. Defaults to POLICY_ALLOW / HUMAN_APPROVAL_REQUIRED / POLICY_BLOCK.">
                <Input id="p-code" className="mono" value={form.reason_code} disabled={readOnly} onChange={(e) => set("reason_code", e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, ""))} placeholder="OPERATION_NOT_ALLOWED" maxLength={64} />
              </Field>
              <Field label="Reason" htmlFor="p-reason" optional error={fields.reason} hint="Human-readable explanation stored with each decision.">
                <Textarea id="p-reason" rows={2} value={form.reason} disabled={readOnly} onChange={(e) => set("reason", e.target.value)} maxLength={500} />
              </Field>
            </div>
            {error && <Alert tone="bad">{error}</Alert>}
            {!readOnly && (
              <div className="form-actions">
                <Button variant="primary" onClick={() => void save()} loading={saving}>
                  {id ? "Save new version" : "Create policy"}
                </Button>
              </div>
            )}
          </Card>

          <Simulator agents={agents} draft={draftForSim} draftError={built.hasErrors && (submitted || form.rows.some((r) => r.value || r.list.length)) ? firstRowError ?? null : null} />

          {id && existing.data && (
            <Card title="Version history">
              <ol className="versions">
                {existing.data.versions.map((v) => (
                  <li key={v.version} className={cx(v.version === loadedVersion && "is-current")}>
                    <span className="mono">v{v.version}</span>
                    <span className="muted small">{dateTime(v.created_at)}</span>
                    {v.version === loadedVersion && <Tag tone="ok">current</Tag>}
                  </li>
                ))}
              </ol>
              <p className="muted small mt-12">Every decision records the policy version that produced it. Versions are append-only.</p>
            </Card>
          )}
        </div>
      </div>

      <ConfirmDialog open={archiveOpen} onClose={() => setArchiveOpen(false)} onConfirm={() => void archive()} title="Archive this policy?" confirmLabel="Archive policy" busy={archiveBusy} error={archiveError}>
        <p>The policy stops being evaluated immediately. Past decisions keep referencing it, and its version history is preserved. This is recorded as a control event.</p>
      </ConfirmDialog>
    </>
  );
}
