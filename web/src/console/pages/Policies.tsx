import { useState } from "react";
import type { Condition, Policy } from "../lib/api";
import { useApi, useDocumentTitle } from "../lib/hooks";
import { Link, useRouter } from "../lib/router";
import { relativeTime } from "../lib/format";
import { useSession } from "../lib/session";
import { IconPlus, IconPolicies } from "../components/icons";
import { Button, DecisionPill, Empty, ErrorState, PageHeader, Skeleton, Tag, cx } from "../components/ui";

export function describeCondition(c: Condition): string {
  const op = c.operator.replace(/_/g, " ");
  if (c.operator === "exists" || c.operator === "not_exists") return `${c.field} ${op}`;
  const value = Array.isArray(c.value) ? `[${c.value.map((v) => JSON.stringify(v)).join(", ")}]` : JSON.stringify(c.value);
  return `${c.field} ${op} ${value}`;
}

export function PoliciesPage() {
  useDocumentTitle("Policies");
  const { can } = useSession();
  const { navigate } = useRouter();
  const [archived, setArchived] = useState(false);
  const { data, error, loading, reload } = useApi<{ policies: Policy[] }>(`/api/console/policies${archived ? "?archived=1" : ""}`, [archived]);

  return (
    <>
      <PageHeader
        title="Policies"
        description="Deterministic rules evaluated on every protected action. No model decides; the same request always gets the same answer."
        actions={
          can("manage_policies") && (
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

      <div className="toolbar-inline">
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
            title="No policies yet"
            action={can("manage_policies") && <Button variant="primary" onClick={() => navigate("/app/policies/new")}><IconPlus /> Create a policy</Button>}
          >
            Without policies every registered agent falls to the default decision — block, unless you changed it.
          </Empty>
        </div>
      ) : (
        data && (
          <div className="policy-list">
            {data.policies.map((p) => (
              <Link key={p.id} to={`/app/policies/${p.id}`} className={cx("policy-row", (!p.enabled || p.archived_at) && "is-muted")}>
                <div className="policy-effect">
                  <DecisionPill decision={p.effect} />
                </div>
                <div className="policy-main">
                  <div className="policy-name">
                    {p.name}
                    {p.archived_at ? <Tag tone="muted">archived</Tag> : !p.enabled && <Tag tone="warn">disabled</Tag>}
                  </div>
                  <div className="policy-conds mono">
                    {p.conditions && p.conditions.conditions.length > 0 ? (
                      p.conditions.conditions.slice(0, 3).map((c, i) => (
                        <span key={i} className="cond-chip">
                          {i > 0 && <b>{p.conditions!.match === "all" ? "AND" : "OR"}</b>}
                          {describeCondition(c)}
                        </span>
                      ))
                    ) : (
                      <span className="cond-chip">matches every action in scope</span>
                    )}
                    {p.conditions && p.conditions.conditions.length > 3 && <span className="cond-more">+{p.conditions.conditions.length - 3} more</span>}
                  </div>
                </div>
                <div className="policy-scope">
                  {p.scope === "organization" ? (
                    <Tag>all agents</Tag>
                  ) : (
                    <span className="scope-agents">
                      {p.agents.slice(0, 2).map((a) => (
                        <Tag key={a.id}>{a.agent_key}</Tag>
                      ))}
                      {p.agents.length > 2 && <Tag tone="muted">+{p.agents.length - 2}</Tag>}
                    </span>
                  )}
                </div>
                <div className="policy-meta mono">
                  <span title="Priority">p{p.priority}</span>
                  <span title="Version">v{p.version}</span>
                  <span title="Decisions attributed in 7 days">{p.decisions_7d ?? 0} · 7d</span>
                </div>
                <div className="policy-updated muted small">{relativeTime(p.updated_at)}</div>
              </Link>
            ))}
          </div>
        )
      )}
    </>
  );
}
