import { useEffect, useState } from "react";
import type { BadgeStatus, DecisionSummary } from "../lib/api";
import { useApi, useDocumentTitle, useNow, useVisibleInterval } from "../lib/hooks";
import { Link } from "../lib/router";
import { dateTime, number, relativeTime } from "../lib/format";
import { useSession } from "../lib/session";
import { DecisionLine } from "../components/decisions";
import { IconChevron } from "../components/icons";
import { Card, CodeBlock, Empty, ErrorState, PageHeader, Skeleton, Stat, StatusDot, cx } from "../components/ui";

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
  return (
    <div className="chart">
      <div className="chart-legend">
        <span><i className="lg lg-allow" /> Allow</span>
        <span><i className="lg lg-review" /> Review</span>
        <span><i className="lg lg-block" /> Block</span>
        <span className="chart-hover mono" aria-live="polite">
          {hovered ? `${hovered.hour.slice(11, 13)}:00 UTC — ${hovered.allow} allow · ${hovered.review} review · ${hovered.block} block` : "Hourly, last 24h (UTC)"}
        </span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="chart-svg" role="img" aria-label="Decisions per hour over the last 24 hours" preserveAspectRatio="none">
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

export function OverviewPage() {
  useDocumentTitle("Overview");
  const { session, setPendingApprovals } = useSession();
  const now = useNow(30_000);
  const { data, error, loading, reload } = useApi<OverviewData>("/api/console/overview");
  useVisibleInterval(() => void reload(), 60_000);

  useEffect(() => {
    if (data) setPendingApprovals(data.pending_approvals);
  }, [data, setPendingApprovals]);

  const origin = window.location.origin;
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

  if (error && !data) return <ErrorState error={error} onRetry={() => void reload()} />;

  const gatewayTone = data?.gateway.status === "operational" ? "ok" : data?.gateway.status === "disabled" ? "warn" : "bad";
  const gatewayLabel = data ? { operational: "Operational", disabled: "Disabled", suspended: "Suspended" }[data.gateway.status] : "—";

  return (
    <>
      <PageHeader
        eyebrow={session.organization.display_name}
        title="Overview"
        description="Live state of agent access control for your organization. Every number here comes from recorded gateway decisions."
      />

      <div className="kpi-row">
        <div className={cx("kpi", "kpi-gateway", data && `kpi-${gatewayTone}`)}>
          <div className="kpi-label">Gateway</div>
          {loading && !data ? (
            <Skeleton lines={1} height={26} />
          ) : (
            <div className="kpi-value kpi-status">
              <StatusDot tone={gatewayTone} />
              {gatewayLabel}
            </div>
          )}
          <div className="kpi-sub">{data ? `Audit logging ${data.audit_enabled ? "on" : "off"} · ${data.active_keys} active key${data.active_keys === 1 ? "" : "s"}` : " "}</div>
        </div>
        <Link to="/app/agents" className="kpi kpi-link">
          <div className="kpi-label">Active agents</div>
          <div className="kpi-value">{data ? number(data.active_agents) : "—"}</div>
          <div className="kpi-sub">Registered identities</div>
        </Link>
        <Link to="/app/policies" className="kpi kpi-link">
          <div className="kpi-label">Active policies</div>
          <div className="kpi-value">{data ? number(data.active_policies) : "—"}</div>
          <div className="kpi-sub">Enabled rules</div>
        </Link>
        <Link to="/app/approvals" className={cx("kpi kpi-link", data && data.pending_approvals > 0 && "kpi-attention")}>
          <div className="kpi-label">Pending approvals</div>
          <div className="kpi-value">{data ? number(data.pending_approvals) : "—"}</div>
          <div className="kpi-sub">{data && data.pending_approvals > 0 ? "Waiting on a human" : "Queue clear"}</div>
        </Link>
      </div>

      <div className="grid-main">
        <Card
          className="span-2"
          title="Decisions · last 24 hours"
          actions={data && <span className="muted small">Last gateway activity: {data.last_gateway_activity ? relativeTime(data.last_gateway_activity, now) : "none yet"}</span>}
        >
          {!data ? (
            <Skeleton lines={4} />
          ) : (
            <>
              <div className="stat-row">
                <Stat label="Evaluations" value={number(data.decisions_24h.total)} />
                <Stat label="Allowed" value={number(data.decisions_24h.allow)} tone="allow" />
                <Stat label="Review required" value={number(data.decisions_24h.review)} tone="review" />
                <Stat label="Blocked" value={number(data.decisions_24h.block)} tone="block" />
              </div>
              {data.decisions_24h.total > 0 ? (
                <HourlyChart hourly={data.hourly} />
              ) : (
                <Empty title="No gateway evaluations in the last 24 hours" action={<Link to="/app/integrations" className="btn btn-secondary btn-sm">Integrate an agent <IconChevron /></Link>}>
                  Charts appear once your agents call <code className="mono-inline">POST /v1/evaluate</code>. Zero is shown as zero.
                </Empty>
              )}
            </>
          )}
        </Card>

        <Card title="Mother AI Protected" actions={<Link to="/app/badge" className="link-sm">Manage <IconChevron /></Link>}>
          {!data ? (
            <Skeleton lines={3} />
          ) : (
            <div className="badge-mini">
              <div className="badge-mini-status">
                <StatusDot tone={BADGE_COPY[data.badge.status].tone} />
                <strong>{data.badge.exists ? BADGE_COPY[data.badge.status].label : "Not created"}</strong>
              </div>
              <p className="muted small">{data.badge.exists ? BADGE_COPY[data.badge.status].text : "Create a live, verifiable badge once your controls are configured."}</p>
            </div>
          )}
        </Card>

        <Card
          className="span-2"
          title="Recent activity"
          pad={false}
          actions={<Link to="/app/audit" className="link-sm">Open audit <IconChevron /></Link>}
        >
          {!data ? (
            <div className="card-body"><Skeleton lines={5} /></div>
          ) : data.recent.length === 0 ? (
            <div className="card-body">
              <Empty title="No decisions recorded yet">Evaluations appear here the moment the gateway records them.</Empty>
            </div>
          ) : (
            <div className="decision-list">
              {data.recent.map((d) => (
                <DecisionLine key={d.id} d={d} now={now} />
              ))}
            </div>
          )}
        </Card>

        <Card title="Quick integration" actions={<Link to="/app/integrations" className="link-sm">All snippets <IconChevron /></Link>}>
          <p className="muted small mb-12">Ask Mother before an agent acts. Anything other than <code className="mono-inline">"allow"</code> means do not execute.</p>
          <CodeBlock code={curl} language="bash" />
          {data && <p className="muted small mt-12">Server time {dateTime(data.server_time)}</p>}
        </Card>
      </div>
    </>
  );
}
