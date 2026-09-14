import { API_ORIGIN } from "../../shared/site";
import { useEffect, useState } from "react";
import type { BadgeStatus, Decision, DecisionSummary } from "../lib/api";
import { useApi, useDocumentTitle, useNow, useVisibleInterval } from "../lib/hooks";
import { Link } from "../lib/router";
import { dateTime, number, relativeTime } from "../lib/format";
import { useSession } from "../lib/session";
import { DecisionLine } from "../components/decisions";
import { IconAudit, IconChevron, IconRefresh } from "../components/icons";
import { Button, Card, CodeBlock, DecisionGlyph, Empty, ErrorState, PageHeader, Skeleton, StaleNotice, StatusDot, cx } from "../components/ui";

interface Hour {
  hour: string;
  allow: number;
  review: number;
  block: number;
}

interface OverviewData {
  gateway: { enabled: boolean; status: "operational" | "disabled" | "suspended" };
  audit_enabled: boolean;
  decisions_24h: { total: number; allow: number; review: number; block: number };
  hourly: Hour[];
  active_agents: number;
  active_policies: number;
  pending_approvals: number;
  active_keys: number;
  recent: DecisionSummary[];
  last_gateway_activity: string | null;
  badge: { status: BadgeStatus; exists: boolean };
  server_time: string;
}

function HourlyChart({ hourly }: { hourly: Hour[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const max = Math.max(1, ...hourly.map((h) => h.allow + h.review + h.block));
  const W = 720;
  const H = 142;
  const pad = { top: 8, bottom: 4, left: 0, right: 0 };
  const innerH = H - pad.top - pad.bottom;
  const slot = W / hourly.length;
  const barW = Math.max(4, slot - 6);
  const ticks = [0, Math.round(max / 2), max];
  const hovered = hover !== null ? hourly[hover] : null;
  const totals = hourly.reduce((a, h) => ({ allow: a.allow + h.allow, review: a.review + h.review, block: a.block + h.block }), { allow: 0, review: 0, block: 0 });
  return (
    <div className="chart">
      <div className="chart-legend">
        <span><i className="lg lg-allow" /> ALLOW</span>
        <span><i className="lg lg-review" /> REVIEW</span>
        <span><i className="lg lg-block" /> BLOCK</span>
        <span className="chart-hover mono" aria-live="polite">
          {hovered ? `${hovered.hour.slice(11, 13)}:00 UTC — ${hovered.allow} allow · ${hovered.review} review · ${hovered.block} block` : "Hourly, last 24h (UTC)"}
        </span>
      </div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="chart-svg"
        role="img"
        aria-label={`Decisions per hour over the last 24 hours: ${totals.allow} allow, ${totals.review} review, ${totals.block} block. Busiest hour had ${max}.`}
        preserveAspectRatio="none"
      >
        {ticks.map((t) => {
          const y = pad.top + innerH - (t / max) * innerH;
          return <line key={t} x1={0} x2={W} y1={y} y2={y} className="chart-grid" />;
        })}
        {hourly.map((h, i) => {
          const x = i * slot + (slot - barW) / 2;
          let y = pad.top + innerH;
          const segs: Array<[number, string]> = [
            [h.allow, "bar-allow"],
            [h.review, "bar-review"],
            [h.block, "bar-block"],
          ];
          return (
            <g key={h.hour} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
              <rect x={i * slot} y={0} width={slot} height={H} fill="transparent" />
              {segs.map(([v, cls]) => {
                if (!v) return null;
                const hgt = (v / max) * innerH;
                y -= hgt;
                return <rect key={cls} x={x} y={y} width={barW} height={Math.max(1, hgt - 1)} rx={1.5} className={cls} opacity={hover === null || hover === i ? 1 : 0.45} />;
              })}
            </g>
          );
        })}
      </svg>
      <div className="chart-axis" aria-hidden="true">
        {hourly.map((h, i) =>
          i % 6 === 0 ? (
            <span key={h.hour} style={{ left: `${((i + 0.5) / hourly.length) * 100}%` }}>
              {h.hour.slice(11, 13)}:00
            </span>
          ) : null,
        )}
      </div>
    </div>
  );
}

const BADGE_COPY: Record<BadgeStatus, { label: string; tone: "ok" | "warn" | "bad" | "muted"; text: string }> = {
  active: { label: "Active", tone: "ok", text: "Your Mother AI Protected badge is live and verifiable." },
  setup: { label: "Not active", tone: "muted", text: "Complete the eligibility checklist to activate your badge." },
  suspended: { label: "Suspended", tone: "warn", text: "Your badge currently shows as suspended to anyone who views it." },
  revoked: { label: "Revoked", tone: "bad", text: "This badge has been revoked." },
};

const GATEWAY_COPY = {
  operational: { label: "Operational", tone: "ok", text: "Evaluating agent requests" },
  disabled: { label: "Disabled", tone: "warn", text: "Gateway is turned off in settings" },
  suspended: { label: "Suspended", tone: "bad", text: "Organization is not active" },
} as const;

const DECISION_TILES: Array<{ id: Decision; label: string; text: string }> = [
  { id: "allow", label: "ALLOW", text: "Agent may proceed" },
  { id: "review", label: "REVIEW", text: "Held for a human" },
  { id: "block", label: "BLOCK", text: "Refused" },
];

function share(n: number, total: number): string {
  if (!total) return "";
  const pct = (n / total) * 100;
  return pct > 0 && pct < 1 ? "<1%" : `${Math.round(pct)}%`;
}

const NBSP = " ";

export function OverviewPage() {
  useDocumentTitle("Overview");
  const { session, setPendingApprovals, can } = useSession();
  const now = useNow(30_000);
  const { data, error, loading, updatedAt, reload } = useApi<OverviewData>("/api/console/overview");
  useVisibleInterval(() => void reload(), 60_000);

  useEffect(() => {
    if (data) setPendingApprovals(data.pending_approvals);
  }, [data, setPendingApprovals]);

  const origin = API_ORIGIN;
  const curl = `curl -X POST ${origin}/v1/evaluate \\
  -H "Authorization: Bearer $MOTHER_AI_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "request_id": "req_$(date +%s)",
    "agent_id": "billing-agent-prod",
    "capability": "payments",
    "operation": "refund",
    "resource": "payment:pi_123",
    "context": { "amount": 4200, "currency": "USD" }
  }'`;

  const refreshing = loading && !!data;
  const header = (
    <PageHeader
      eyebrow={session.organization.display_name}
      title="Overview"
      description="What your agents asked to do, what Mother AI decided, and what is waiting on a human. Every figure is read from recorded gateway decisions."
      actions={
        data ? (
          <div className="ov-refresh">
            {updatedAt && (
              <span className="muted small">
                Updated <time dateTime={new Date(updatedAt).toISOString()}>{relativeTime(new Date(updatedAt).toISOString(), now)}</time>
              </span>
            )}
            <Button size="sm" variant="ghost" onClick={() => void reload()} loading={refreshing}>
              {!refreshing && <IconRefresh />} Refresh
            </Button>
          </div>
        ) : undefined
      }
    />
  );

  if (error && !data) {
    return (
      <>
        {header}
        <ErrorState error={error} onRetry={() => void reload()} />
      </>
    );
  }

  const gw = data ? GATEWAY_COPY[data.gateway.status] : null;
  const totals = data?.decisions_24h;

  return (
    <>
      {header}
      {error && data ? <StaleNotice error={error} onRetry={() => void reload()} updatedAt={updatedAt} now={now} /> : null}

      <section className="ov-status" aria-label="Control plane status">
        <div className={cx("ov-status-cell", gw && `ov-${gw.tone}`)}>
          <span className="ov-k">Gateway</span>
          {gw ? (
            <span className="ov-v">
              <StatusDot tone={gw.tone} />
              {gw.label}
            </span>
          ) : (
            <Skeleton lines={1} height={18} />
          )}
          <span className="ov-s">{gw?.text ?? NBSP}</span>
        </div>
        <div className={cx("ov-status-cell", data && !data.audit_enabled && "ov-warn")}>
          <span className="ov-k">Audit capture</span>
          {data ? (
            <span className="ov-v">
              <StatusDot tone={data.audit_enabled ? "ok" : "warn"} />
              {data.audit_enabled ? "On" : "Off"}
            </span>
          ) : (
            <Skeleton lines={1} height={18} />
          )}
          <span className="ov-s">{data ? (data.audit_enabled ? "Request context stored, redacted" : "Decisions recorded without context") : NBSP}</span>
        </div>
        <div className="ov-status-cell">
          <span className="ov-k">Last gateway activity</span>
          {data ? (
            data.last_gateway_activity ? (
              <time className="ov-v" dateTime={data.last_gateway_activity} title={dateTime(data.last_gateway_activity)}>
                {relativeTime(data.last_gateway_activity, now)}
              </time>
            ) : (
              <span className="ov-v">None recorded</span>
            )
          ) : (
            <Skeleton lines={1} height={18} />
          )}
          <span className="ov-s">{data ? (data.last_gateway_activity ? dateTime(data.last_gateway_activity) : "No agent has called the gateway yet") : NBSP}</span>
        </div>
        <div className="ov-status-cell">
          <span className="ov-k">Active API keys</span>
          {data ? <span className="ov-v">{number(data.active_keys)}</span> : <Skeleton lines={1} height={18} />}
          <span className="ov-s">
            {!data ? (
              NBSP
            ) : can("manage_keys") ? (
              <Link to="/app/settings?tab=keys" className="link-sm">
                Manage keys <IconChevron />
              </Link>
            ) : (
              "Integrations authenticate with keys"
            )}
          </span>
        </div>
      </section>

      <section className="ov-decisions" aria-labelledby="ov-24h">
        <div className="ov-section-head">
          <h2 id="ov-24h" className="ov-section-title">
            Decisions · last 24 hours
          </h2>
          {totals && (
            <span className="muted small">
              {number(totals.total)} evaluation{totals.total === 1 ? "" : "s"}
            </span>
          )}
        </div>
        <div className="ov-tiles">
          {DECISION_TILES.map((t) => (
            <Link key={t.id} to={`/app/audit?decision=${t.id}`} className={cx("ov-tile", `ov-tile-${t.id}`)}>
              <span className="ov-tile-label">
                <DecisionGlyph decision={t.id} />
                {t.label}
              </span>
              {totals ? <span className="ov-tile-value">{number(totals[t.id])}</span> : <Skeleton lines={1} height={30} />}
              <span className="ov-tile-sub">
                <span>{t.text}</span>
                {totals && totals.total > 0 && <span className="ov-share">{share(totals[t.id], totals.total)}</span>}
              </span>
              <span className="ov-bar" aria-hidden="true">
                {totals && totals.total > 0 && <span style={{ width: `${(totals[t.id] / totals.total) * 100}%` }} />}
              </span>
            </Link>
          ))}
          <Link to="/app/approvals" className={cx("ov-tile ov-tile-pending", data && data.pending_approvals > 0 && "has-pending")}>
            <span className="ov-tile-label">Pending approvals</span>
            {data ? <span className="ov-tile-value">{number(data.pending_approvals)}</span> : <Skeleton lines={1} height={30} />}
            <span className="ov-tile-sub">
              <span>{data ? (data.pending_approvals > 0 ? "Waiting on an approver" : "Queue clear") : NBSP}</span>
              {data && data.pending_approvals > 0 && <span className="ov-share">Open queue →</span>}
            </span>
            <span className="ov-bar ov-bar-none" aria-hidden="true" />
          </Link>
        </div>
      </section>

      <div className="grid-main">
        <Card
          className="span-2 ov-stream"
          title="Recent decisions"
          pad={false}
          actions={
            <Link to="/app/audit" className="link-sm">
              Open audit <IconChevron />
            </Link>
          }
        >
          {!data ? (
            <div className="card-body">
              <Skeleton lines={6} />
            </div>
          ) : data.recent.length === 0 ? (
            <div className="card-body">
              <Empty
                title="No decisions recorded yet"
                action={
                  <Link to="/app/integrations" className="btn btn-secondary btn-sm">
                    Connect an agent <IconChevron />
                  </Link>
                }
              >
                Decisions appear here the moment an agent calls <code className="mono-inline">POST /v1/evaluate</code> or <code className="mono-inline">POST /v1/mcp/evaluate</code>.
              </Empty>
            </div>
          ) : (
            <>
              <div className="decision-list">
                {data.recent.map((d) => (
                  <DecisionLine key={d.id} d={d} now={now} />
                ))}
              </div>
              <p className="ov-stream-foot muted small">Latest {data.recent.length} decisions. Select one to open its evidence in the audit log.</p>
            </>
          )}
        </Card>

        <div className="stack">
          <Card title="Coverage">
            {!data ? (
              <Skeleton lines={3} />
            ) : (
              <ul className="ov-coverage">
                <li>
                  <Link to="/app/agents" className="ov-cov-link">
                    <span className="ov-cov-value">{number(data.active_agents)}</span>
                    <span className="ov-cov-label">Active agent{data.active_agents === 1 ? "" : "s"}</span>
                    <IconChevron />
                  </Link>
                </li>
                <li>
                  <Link to="/app/policies" className="ov-cov-link">
                    <span className="ov-cov-value">{number(data.active_policies)}</span>
                    <span className="ov-cov-label">Enabled polic{data.active_policies === 1 ? "y" : "ies"}</span>
                    <IconChevron />
                  </Link>
                </li>
                <li>
                  <Link to="/app/audit?tab=events" className="ov-cov-link">
                    <span className="ov-cov-value ov-cov-icon" aria-hidden="true">
                      <IconAudit />
                    </span>
                    <span className="ov-cov-label">Control events: policy, key, approval and member changes</span>
                    <IconChevron />
                  </Link>
                </li>
              </ul>
            )}
          </Card>

          <Card title="Mother AI Protected" actions={<Link to="/app/badge" className="link-sm">Manage <IconChevron /></Link>}>
            {!data ? (
              <Skeleton lines={3} />
            ) : (
              <div className="badge-mini">
                <div className="badge-mini-status">
                  <StatusDot tone={data.badge.exists ? BADGE_COPY[data.badge.status].tone : "muted"} />
                  <strong>{data.badge.exists ? BADGE_COPY[data.badge.status].label : "Not created"}</strong>
                </div>
                <p className="muted small">{data.badge.exists ? BADGE_COPY[data.badge.status].text : "Create a live, verifiable badge once your controls are configured."}</p>
              </div>
            )}
          </Card>
        </div>

        <Card className="span-2" title="Hourly decisions" actions={<span className="muted small">Last 24h · UTC</span>}>
          {!data ? (
            <Skeleton lines={4} />
          ) : data.decisions_24h.total > 0 ? (
            <HourlyChart hourly={data.hourly} />
          ) : (
            <Empty
              title="No gateway evaluations in the last 24 hours"
              action={
                <Link to="/app/integrations" className="btn btn-secondary btn-sm">
                  Integrate an agent <IconChevron />
                </Link>
              }
            >
              The chart appears once agents call the gateway. Zero here is a real zero from the decision log.
            </Empty>
          )}
        </Card>

        <Card title="Quick integration" actions={<Link to="/app/integrations" className="link-sm">All snippets <IconChevron /></Link>}>
          <p className="muted small mb-12">
            Ask Mother before an agent acts. Anything other than <code className="mono-inline">"allow"</code> means do not execute.
          </p>
          <CodeBlock code={curl} language="bash" />
          {data && <p className="muted small mt-12">Server time {dateTime(data.server_time)}</p>}
        </Card>
      </div>
    </>
  );
}
