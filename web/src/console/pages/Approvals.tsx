import { useEffect, useState } from "react";
import { api, ApiFailure, errorMessage, type DecisionSummary } from "../lib/api";
import { useApi, useDocumentTitle, useNow, useVisibleInterval } from "../lib/hooks";
import { Link } from "../lib/router";
import { countdown, dateTime, relativeTime } from "../lib/format";
import { useSession } from "../lib/session";
import { IconApprovals, IconChevron } from "../components/icons";
import { Alert, Button, DecisionPill, Dialog, Empty, EnvTag, ErrorState, Field, Mono, PageHeader, Skeleton, StaleNotice, Tabs, Tag, Textarea, cx, toast } from "../components/ui";

type Status = "pending" | "approved" | "denied" | "expired";

interface ApprovalItem {
  approval_id: string;
  status: Status;
  requested_at: string;
  expires_at: string;
  grant_expires_at: string | null;
  consumed_at: string | null;
  executable: boolean;
  acted_at: string | null;
  acted_by_name: string | null;
  note: string | null;
  decision: DecisionSummary & { context: Record<string, unknown> | null };
  policy: { id: string; name: string | null; effect: string | null; version: number | null } | null;
  agent: { display_name: string | null; environment: string | null };
}

interface ApprovalsResponse {
  approvals: ApprovalItem[];
  counts: Partial<Record<Status, number>>;
  server_time: string;
}

function formatValue(v: unknown): { text: string; redacted: boolean } {
  if (v === "[REDACTED]") return { text: "[REDACTED]", redacted: true };
  if (typeof v === "string") return { text: v, redacted: false };
  return { text: JSON.stringify(v), redacted: false };
}

function ContextList({ context }: { context: Record<string, unknown> | null }) {
  if (context === null) return <p className="muted small">Request context was not captured (audit capture disabled).</p>;
  const entries = Object.entries(context);
  if (!entries.length) return <p className="muted small">No context supplied.</p>;
  return (
    <dl className="ctx-list">
      {entries.slice(0, 8).map(([k, v]) => {
        const f = formatValue(v);
        return (
          <div key={k} className="ctx-item">
            <dt className="mono">{k}</dt>
            <dd className={cx("mono", f.redacted && "redacted")}>{f.text.length > 120 ? `${f.text.slice(0, 117)}…` : f.text}</dd>
          </div>
        );
      })}
      {entries.length > 8 && <div className="ctx-more muted small">+{entries.length - 8} more fields in the audit record</div>}
    </dl>
  );
}

const STATUS_LABEL: Record<Status, string> = { pending: "Pending", approved: "Approved", denied: "Denied", expired: "Expired" };

function ApprovalCard({ a, skewMs, onAct, canApprove }: { a: ApprovalItem; skewMs: number; onAct: (a: ApprovalItem, verb: "approve" | "deny") => void; canApprove: boolean }) {
  const now = useNow(1000) + skewMs;
  const remaining = Date.parse(a.expires_at) - now;
  const status: Status = a.status === "pending" && remaining <= 0 ? "expired" : a.status;
  const d = a.decision;
  const total = Date.parse(a.expires_at) - Date.parse(a.requested_at);
  const pct = Math.max(0, Math.min(100, (remaining / Math.max(1, total)) * 100));
  return (
    <article className={cx("approval", `approval-${status}`)} aria-label={`Approval for ${d.agent_key}`}>
      <header className="approval-head">
        <div className="approval-who">
          <span className="approval-avatar" aria-hidden="true">
            {(a.agent.display_name ?? d.agent_key).slice(0, 1).toUpperCase()}
          </span>
          <div>
            <div className="approval-agent">{a.agent.display_name ?? d.agent_key}</div>
            <div className="approval-agent-sub">
              <Mono>{d.agent_key}</Mono>
              <EnvTag env={a.agent.environment ?? d.environment} />
            </div>
          </div>
        </div>
        <div className="approval-timer">
          {status === "pending" ? (
            <>
              <span className={cx("timer", remaining < 60_000 && "timer-urgent")} aria-label={`Expires in ${countdown(remaining)}`}>
                {countdown(remaining)}
              </span>
              <span className="timer-bar" aria-hidden="true">
                <span style={{ width: `${pct}%` }} />
              </span>
              <span className="muted small">until expiry</span>
            </>
          ) : (
            <span className={cx("status-chip", `status-${status}`)}>{STATUS_LABEL[status]}</span>
          )}
        </div>
      </header>

      <div className="approval-grid">
        <section className="approval-block">
          <h3 className="approval-label">Wants to</h3>
          <p className="approval-action">
            <span className="mono">{d.capability}</span>
            <span className="dl-sep">·</span>
            <span className="mono">{d.operation}</span>
            {d.protocol === "mcp" && <span className="tag tag-mcp">MCP</span>}
          </p>
          <dl className="approval-facts">
            {d.resource && (
              <div>
                <dt>Resource</dt>
                <dd className="mono">{d.resource}</dd>
              </div>
            )}
            {d.protocol === "mcp" && (
              <div>
                <dt>MCP tool</dt>
                <dd className="mono">
                  {d.mcp_server} / {d.mcp_tool}
                </dd>
              </div>
            )}
            <div>
              <dt>Destination</dt>
              <dd className="mono">{d.destination ?? "—"}</dd>
            </div>
            <div>
              <dt>Data class</dt>
              <dd className="mono">{d.data_class ?? "—"}</dd>
            </div>
          </dl>
          <h3 className="approval-label mt-12">Context</h3>
          <ContextList context={d.context} />
        </section>

        <section className="approval-block approval-why">
          <h3 className="approval-label">Why Mother stopped it</h3>
          <p className="approval-reason">{d.reason}</p>
          <span className="approval-verdict">
            <DecisionPill decision={d.decision} size="sm" />
            <Mono className="approval-code">{d.reason_code}</Mono>
          </span>
          <h3 className="approval-label mt-16">Policy</h3>
          {a.policy ? (
            <Link to={`/app/policies/${a.policy.id}`} className="approval-policy">
              <span>{a.policy.name ?? a.policy.id}</span>
              <span className="mono muted">v{a.policy.version}</span>
              <IconChevron />
            </Link>
          ) : (
            <p className="muted small">Default decision (no policy matched)</p>
          )}
          <dl className="approval-facts mt-12">
            <div>
              <dt>Requested</dt>
              <dd title={dateTime(a.requested_at)}>{relativeTime(a.requested_at, now)}</dd>
            </div>
            <div>
              <dt>Expires</dt>
              <dd>{dateTime(a.expires_at)}</dd>
            </div>
            <div>
              <dt>Request id</dt>
              <dd className="mono truncate" title={d.request_id}>{d.request_id}</dd>
            </div>
          </dl>
        </section>
      </div>

      {status === "pending" ? (
        <footer className="approval-foot">
          <Link to={`/app/audit?q=${encodeURIComponent(d.id)}&open=${encodeURIComponent(d.id)}`} className="link-sm">
            View decision evidence
          </Link>
          {canApprove ? (
            <div className="approval-actions">
              <Button variant="danger" onClick={() => onAct(a, "deny")}>
                Deny
              </Button>
              <Button variant="approve" onClick={() => onAct(a, "approve")}>
                Approve
              </Button>
            </div>
          ) : (
            <span className="muted small">Approving or denying requires the Approver role or higher.</span>
          )}
        </footer>
      ) : (
        <footer className="approval-foot approval-foot-resolved">
          <span className="small">
            {status === "expired" ? (
              <>Expired without a decision {relativeTime(a.acted_at ?? a.expires_at, now)}.</>
            ) : (
              <>
                {STATUS_LABEL[status]} by <strong>{a.acted_by_name ?? "unknown"}</strong> {relativeTime(a.acted_at, now)}
                {a.note && <> — “{a.note}”</>}
              </>
            )}
          </span>
          {status === "approved" && (
            <span className="small">
              {a.consumed_at ? (
                <Tag tone="ok">executed {relativeTime(a.consumed_at, now)}</Tag>
              ) : a.grant_expires_at && Date.parse(a.grant_expires_at) > now ? (
                <Tag tone="warn">grant valid {countdown(Date.parse(a.grant_expires_at) - now)}</Tag>
              ) : (
                <Tag tone="muted">grant expired unused</Tag>
              )}
            </span>
          )}
        </footer>
      )}
    </article>
  );
}

export function ApprovalsPage() {
  useDocumentTitle("Approvals");
  const { can, setPendingApprovals } = useSession();
  const [tab, setTab] = useState<"pending" | "resolved" | "all">("pending");
  const { data, error, loading, updatedAt, reload } = useApi<ApprovalsResponse>(`/api/console/approvals?status=${tab}`, [tab]);
  const pageNow = useNow(30_000);
  const [skewMs, setSkewMs] = useState(0);
  const [acting, setActing] = useState<{ a: ApprovalItem; verb: "approve" | "deny" } | null>(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [actError, setActError] = useState<string | null>(null);

  useVisibleInterval(() => void reload(), 15_000);
  useEffect(() => {
    if (!data) return;
    setSkewMs(Date.parse(data.server_time) - Date.now());
    setPendingApprovals(data.counts.pending ?? 0);
  }, [data, setPendingApprovals]);

  // Counts only render once the API answered; a failed load never shows as zero.
  const counts = data?.counts;
  const resolvedCount = counts ? (counts.approved ?? 0) + (counts.denied ?? 0) + (counts.expired ?? 0) : undefined;

  const act = async () => {
    if (!acting) return;
    setBusy(true);
    setActError(null);
    try {
      await api(`/api/console/approvals/${acting.a.approval_id}/${acting.verb}`, { body: note.trim() ? { note: note.trim() } : {} });
      toast(acting.verb === "approve" ? "Approved — the agent may now execute once" : "Denied — the agent cannot execute");
      setActing(null);
      setNote("");
      void reload();
    } catch (err) {
      if (err instanceof ApiFailure && (err.code === "APPROVAL_EXPIRED" || err.code === "APPROVAL_NOT_PENDING")) {
        toast(err.message, "bad");
        setActing(null);
        void reload();
      } else setActError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader title="Approvals" description="Actions that a policy routed to a human. Nothing executes until an approver says yes — and an approval can be used exactly once before its grant expires." />
      <details className="how-review">
        <summary>How review works</summary>
        <ol className="how-review-steps">
          <li>
            <DecisionPill decision="review" size="sm" />
            <span>A matching review policy answers the agent with <code className="mono-inline">decision: "review"</code> and an <code className="mono-inline">approval_id</code>. The agent must not act yet.</span>
          </li>
          <li>
            <span className="how-n" aria-hidden="true">2</span>
            <span>The request waits in this queue. An Approver, Security, Admin or Owner approves or denies it with an optional note. Unanswered requests expire after the approval window set in Settings.</span>
          </li>
          <li>
            <span className="how-n" aria-hidden="true">3</span>
            <span>The integration polls <code className="mono-inline">GET /v1/approvals/{"{id}"}</code>. If approved, it redeems the grant once with <code className="mono-inline">POST /v1/approvals/{"{id}"}/consume</code> before the grant expires.</span>
          </li>
        </ol>
        <p className="muted small">Mother AI does not send Slack or email notifications for approvals. This queue refreshes every 15 seconds while it is open.</p>
      </details>
      <Tabs
        label="Approval status"
        value={tab}
        onChange={setTab}
        tabs={[
          { id: "pending", label: "Pending", count: counts ? counts.pending ?? 0 : undefined },
          { id: "resolved", label: "Resolved", count: resolvedCount },
          { id: "all", label: "All" },
        ]}
      />
      {error && data ? <StaleNotice error={error} onRetry={() => void reload()} updatedAt={updatedAt} now={pageNow} /> : null}
      {error && !data ? (
        <ErrorState error={error} onRetry={() => void reload()} />
      ) : loading && !data ? (
        <div className="card card-body"><Skeleton lines={6} /></div>
      ) : data && data.approvals.length === 0 ? (
        <div className="card">
          <Empty
            icon={<IconApprovals width={22} height={22} />}
            title={tab === "pending" ? "No actions are waiting for approval" : "No approvals here yet"}
            action={
              tab === "pending" && (
                <Link to="/app/policies" className="btn btn-secondary btn-sm">
                  Review policies <IconChevron />
                </Link>
              )
            }
          >
            {tab === "pending" ? "When a review policy matches, the request appears here with who is asking, what it wants and why Mother stopped it." : "Approved, denied and expired requests are kept as evidence."}
          </Empty>
        </div>
      ) : (
        data && (
          <div className="approval-list">
            {data.approvals.map((a) => (
              <ApprovalCard key={a.approval_id} a={a} skewMs={skewMs} canApprove={can("approve")} onAct={(item, verb) => { setActError(null); setNote(""); setActing({ a: item, verb }); }} />
            ))}
          </div>
        )
      )}

      <Dialog
        open={!!acting}
        onClose={() => !busy && setActing(null)}
        size="sm"
        title={acting?.verb === "approve" ? "Approve this action?" : "Deny this action?"}
        description={acting ? `${acting.a.decision.agent_key} → ${acting.a.decision.capability} · ${acting.a.decision.operation}${acting.a.decision.resource ? ` on ${acting.a.decision.resource}` : ""}` : undefined}
        footer={
          <>
            <Button variant="ghost" onClick={() => setActing(null)} disabled={busy}>Cancel</Button>
            <Button variant={acting?.verb === "approve" ? "approve" : "danger"} onClick={() => void act()} loading={busy}>
              {acting?.verb === "approve" ? "Approve" : "Deny"}
            </Button>
          </>
        }
      >
        <p className="small mb-12">
          {acting?.verb === "approve"
            ? "The agent receives a single-use grant. Your name, the time and your note are appended to the audit trail. The original decision is never modified."
            : "The integration sees this request as denied and cannot execute it. Your name, the time and your note are appended to the audit trail."}
        </p>
        <Field label="Note" htmlFor="ap-note" optional hint="Visible in the audit trail.">
          <Textarea id="ap-note" data-autofocus rows={3} maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} placeholder={acting?.verb === "approve" ? "Verified with the customer on ticket #4821" : "Amount exceeds the customer's order total"} />
        </Field>
        {actError && <Alert tone="bad">{actError}</Alert>}
      </Dialog>
    </>
  );
}
