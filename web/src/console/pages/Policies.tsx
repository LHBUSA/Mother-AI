import { Fragment, useState, type ReactNode } from "react";
import type { Condition, Policy, Scalar } from "../lib/api";
import { useApi, useDocumentTitle } from "../lib/hooks";
import { Link, useRouter } from "../lib/router";
import { dateTime, relativeTime } from "../lib/format";
import { useSession } from "../lib/session";
import { IconChevron, IconPolicies, IconPlus } from "../components/icons";
import { Button, DecisionPill, Empty, ErrorState, JsonView, PageHeader, Skeleton, Tag, cx } from "../components/ui";

export function describeCondition(c: Condition): string {
  const op = c.operator.replace(/_/g, " ");
  if (c.operator === "exists" || c.operator === "not_exists") return `${c.field} ${op}`;
  const value = Array.isArray(c.value) ? `[${c.value.map((v) => JSON.stringify(v)).join(", ")}]` : JSON.stringify(c.value);
  return `${c.field} ${op} ${value}`;
}

const OPERATOR_WORDS: Record<Condition["operator"], string> = {
  equals: "is",
  not_equals: "is not",
  in: "is one of",
  not_in: "is not one of",
  starts_with: "starts with",
  glob: "matches",
  greater_than: "is greater than",
  greater_than_or_equal: "is at least",
  less_than: "is less than",
  less_than_or_equal: "is at most",
  exists: "is present",
  not_exists: "is missing",
};

function scalar(v: Scalar): string {
  return typeof v === "string" ? v : String(v);
}

/** Readable form of one condition: the field and values stay exact, the operator reads as words. */
export function HumanCondition({ c }: { c: Condition }) {
  const values = c.value === undefined ? [] : Array.isArray(c.value) ? c.value : [c.value];
  return (
    <span className="hc">
      <code className="hc-field">{c.field}</code> <span className="hc-op">{OPERATOR_WORDS[c.operator] ?? c.operator.replace(/_/g, " ")}</span>
      {values.length > 0 && " "}
      {values.map((v, i) => (
        <Fragment key={i}>
          {i > 0 && <span className="hc-op">{c.operator === "in" || c.operator === "not_in" || i < values.length - 1 ? ", " : " or "}</span>}
          <code className="hc-value">{scalar(v)}</code>
        </Fragment>
      ))}
    </span>
  );
}

const MAX_CONDITIONS = 6;

function PolicySentence({ p }: { p: Policy }) {
  const conds = p.conditions?.conditions ?? [];
  const joiner = p.conditions?.match === "any" ? "OR" : "AND";
  let clauses: ReactNode;
  if (conds.length === 0) {
    clauses = <span className="hc">any action in scope</span>;
  } else {
    clauses = (
      <>
        {conds.slice(0, MAX_CONDITIONS).map((c, i) => (
          <span key={i} className="ps-clause">
            {i > 0 && <span className="ps-kw">{joiner}</span>}
            <HumanCondition c={c} />
          </span>
        ))}
        {conds.length > MAX_CONDITIONS && <span className="ps-more">+{conds.length - MAX_CONDITIONS} more conditions</span>}
      </>
    );
  }
  return (
    <p className="ps">
      <span className="ps-kw">IF</span>
      {clauses}
      <span className="ps-then">
        <span className="ps-kw">THEN</span>
        <DecisionPill decision={p.effect} size="sm" />
      </span>
    </p>
  );
}

function PolicyCard({ p, canEdit }: { p: Policy; canEdit: boolean }) {
  const inactive = !p.enabled || !!p.archived_at;
  const technical = {
    id: p.id,
    version: p.version,
    effect: p.effect,
    priority: p.priority,
    enabled: p.enabled,
    scope: p.scope,
    agents: p.agents.map((a) => a.agent_key),
    conditions: p.conditions,
    reason_code: p.reason_code,
    reason: p.reason,
  };
  return (
    <article className={cx("pcard", `pcard-${p.effect}`, inactive && "is-muted")} aria-labelledby={`pol-${p.id}`}>
      <header className="pcard-head">
        <DecisionPill decision={p.effect} />
        <h2 className="pcard-name" id={`pol-${p.id}`}>
          <Link to={`/app/policies/${p.id}`} className="pcard-link">
            {p.name}
          </Link>
        </h2>
        <span className="pcard-state">
          {p.archived_at ? <Tag tone="muted">Archived</Tag> : p.enabled ? <Tag tone="ok">Enabled</Tag> : <Tag tone="warn">Disabled</Tag>}
        </span>
      </header>
      {p.description && <p className="pcard-desc">{p.description}</p>}
      <PolicySentence p={p} />
      <dl className="pcard-facts">
        <div>
          <dt>Applies to</dt>
          <dd>
            {p.scope === "organization" ? (
              "All agents"
            ) : p.agents.length === 0 ? (
              <span className="muted">No agents bound</span>
            ) : (
              <span className="scope-agents">
                {p.agents.slice(0, 3).map((a) => (
                  <Tag key={a.id}>{a.agent_key}</Tag>
                ))}
                {p.agents.length > 3 && <Tag tone="muted">+{p.agents.length - 3}</Tag>}
              </span>
            )}
          </dd>
        </div>
        <div>
          <dt>Priority</dt>
          <dd className="mono">{p.priority}</dd>
        </div>
        <div>
          <dt>Version</dt>
          <dd className="mono">v{p.version}</dd>
        </div>
        <div>
          <dt>Decisions · 7d</dt>
          <dd className="mono">{p.decisions_7d === undefined ? "—" : p.decisions_7d}</dd>
        </div>
        <div>
          <dt>Updated</dt>
          <dd>
            <time dateTime={p.updated_at} title={dateTime(p.updated_at)}>
              {relativeTime(p.updated_at)}
            </time>
          </dd>
        </div>
      </dl>
      <footer className="pcard-foot">
        <details className="pcard-json">
          <summary>Technical definition</summary>
          <JsonView value={technical} />
        </details>
        <Link to={`/app/policies/${p.id}`} className="btn btn-ghost btn-sm pcard-open" aria-label={`${canEdit && !p.archived_at ? "Edit" : "View"} policy: ${p.name}`}>
          {canEdit && !p.archived_at ? "Edit" : "View"} <IconChevron />
        </Link>
      </footer>
    </article>
  );
}

export function PoliciesPage() {
  useDocumentTitle("Policies");
  const { can } = useSession();
  const { navigate } = useRouter();
  const [archived, setArchived] = useState(false);
  const { data, error, loading, reload } = useApi<{ policies: Policy[] }>(`/api/console/policies${archived ? "?archived=1" : ""}`, [archived]);
  const canEdit = can("manage_policies");
  const enabled = data ? data.policies.filter((p) => p.enabled && !p.archived_at) : [];
  const enabledWith = (effect: Policy["effect"]) => enabled.filter((p) => p.effect === effect).length;

  return (
    <>
      <PageHeader
        title="Policies"
        description="Deterministic rules evaluated on every protected action. No model decides; the same request always gets the same answer."
        actions={
          canEdit && (
            <Button variant="primary" onClick={() => navigate("/app/policies/new")}>
              <IconPlus /> New policy
            </Button>
          )
        }
      />

      <div className="precedence">
        <div className="precedence-title">Precedence</div>
        <ol className="precedence-steps">
          <li><DecisionPill decision="block" size="sm" /> any matching block wins</li>
          <li><DecisionPill decision="review" size="sm" /> then any matching review</li>
          <li><DecisionPill decision="allow" size="sm" /> then any matching allow</li>
          <li><span className="pill pill-neutral pill-sm">DEFAULT</span> nothing matched → agent or org default</li>
        </ol>
        <p className="precedence-note">Priority (lowest number first) only picks which policy is reported within the winning effect. Missing numeric context fails closed for block and review rules.</p>
      </div>

      <div className="toolbar-inline policies-toolbar">
        {data && data.policies.length > 0 && (
          <p className="muted small">
            {enabled.length} enabled: {enabledWith("block")} block · {enabledWith("review")} review · {enabledWith("allow")} allow
          </p>
        )}
        <label className="check">
          <input type="checkbox" checked={archived} onChange={(e) => setArchived(e.target.checked)} /> Show archived
        </label>
      </div>

      {error && !data ? (
        <ErrorState error={error} onRetry={() => void reload()} />
      ) : loading && !data ? (
        <div className="card card-body"><Skeleton lines={6} /></div>
      ) : data && data.policies.length === 0 ? (
        <div className="card">
          <Empty
            icon={<IconPolicies width={22} height={22} />}
            title={archived ? "No policies, including archived" : "No policies yet"}
            action={canEdit && <Button variant="primary" onClick={() => navigate("/app/policies/new")}><IconPlus /> Create a policy</Button>}
          >
            Without policies every registered agent falls to the default decision — block, unless you changed it.
            {!canEdit && " Ask a security, admin or owner member to create one."}
          </Empty>
        </div>
      ) : (
        data && (
          <div className="pcard-list">
            {data.policies.map((p) => (
              <PolicyCard key={p.id} p={p} canEdit={canEdit} />
            ))}
          </div>
        )
      )}
    </>
  );
}
