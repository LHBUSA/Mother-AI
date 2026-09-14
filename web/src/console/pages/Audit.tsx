import { useCallback, useEffect, useState } from "react";
import { api, errorMessage, type Decision, type DecisionSummary } from "../lib/api";
import { useDocumentTitle, useNow } from "../lib/hooks";
import { Link, useQuery, useRouter } from "../lib/router";
import { dateTime, relativeTime } from "../lib/format";
import { ApprovalChip, DecisionLine } from "../components/decisions";
import { IconAudit, IconChevron, IconClose } from "../components/icons";
import { Alert, Button, CopyButton, DecisionPill, DefinitionList, Empty, ErrorState, Input, JsonView, Mono, PageHeader, Select, Skeleton, Tabs, Tag, cx } from "../components/ui";

type Row = DecisionSummary & { policy_name: string | null; approval_status: string | null };

interface DecisionDetail {
  decision: DecisionSummary & {
    matched_policies: Array<{ policy_id: string; name: string; effect: Decision; priority: number; version: number; indeterminate: boolean; indeterminate_fields?: string[] }>;
    context: Record<string, unknown> | null;
    context_captured: boolean;
    eval_ms: number | null;
    gateway_ms: number | null;
    engine_version: string;
    request_fingerprint: string;
    api_key: { key_prefix: string; environment: string } | null;
  };
  policy_snapshot: Record<string, unknown> | null;
  approval: { approval_id: string; status: string; requested_at: string; expires_at: string; grant_expires_at: string | null; consumed_at: string | null; executable: boolean; acted_at: string | null; acted_by_name: string | null; note: string | null } | null;
  approval_events: Array<{ action: string; actor_type: string; actor_label: string | null; created_at: string; detail: Record<string, unknown> }>;
}

interface ControlEvent {
  id: string;
  actor_type: string;
  actor_label: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  detail: Record<string, unknown>;
  created_at: string;
}

const FILTER_KEYS = ["agent", "decision", "capability", "environment", "from", "to", "q"] as const;

function DecisionDetailPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const [data, setData] = useState<DecisionDetail | null>(null);
  const [error, setError] = useState<unknown>(null);
  const load = useCallback(() => {
    setError(null);
    api<DecisionDetail>(`/api/console/decisions/${id}`).then(setData).catch(setError);
  }, [id]);
  useEffect(() => {
    setData(null);
    load();
  }, [load]);

  return (
    <div className="detail-panel" role="region" aria-label="Decision detail">
      <div className="detail-head">
        <div className="detail-id">
          <div className="page-eyebrow">Decision evidence</div>
          <span className="detail-id-row">
            <Mono>{id}</Mono>
            <CopyButton text={id} label="Copy ID" />
          </span>
        </div>
        <button type="button" className="icon-btn" onClick={onClose} aria-label="Close detail">
          <IconClose />
        </button>
      </div>
      {error ? (
        <ErrorState error={error} onRetry={load} compact />
      ) : !data ? (
        <Skeleton lines={10} />
      ) : (
        <div className="detail-body">
          <div className={cx("detail-verdict", `verdict-${data.decision.decision}`)}>
            <DecisionPill decision={data.decision.decision} />
            <Mono>{data.decision.reason_code}</Mono>
            <p>{data.decision.reason}</p>
          </div>

          <h3 className="subhead">Who asked</h3>
          <DefinitionList
            items={[
              ["Agent", <Mono key="a">{data.decision.agent_key}</Mono>],
              ["Integration (API key)", data.decision.api_key ? <span key="k"><Mono>{data.decision.api_key.key_prefix}…</Mono> <Tag>{data.decision.api_key.environment}</Tag></span> : "—"],
            ]}
          />
          <p className="muted small detail-note">Mother AI records the calling agent and the API key it used. Any end-user identity exists only if the integration sent it in context.</p>

          <h3 className="subhead">Request</h3>
          <DefinitionList
            items={[
              ["Protocol", data.decision.protocol.toUpperCase()],
              ["Action", <Mono key="c">{`${data.decision.capability} · ${data.decision.operation}`}</Mono>],
              ...(data.decision.protocol === "mcp" ? ([["MCP", <Mono key="m">{`${data.decision.mcp_server} / ${data.decision.mcp_tool}`}</Mono>]] as Array<[string, React.ReactNode]>) : []),
              ["Resource", data.decision.resource ? <Mono key="r">{data.decision.resource}</Mono> : "—"],
              ["Destination", data.decision.destination ?? "—"],
              ["Data class", data.decision.data_class ?? "—"],
              ["Environment", data.decision.environment ?? "—"],
              ["Request id", <Mono key="q">{data.decision.request_id}</Mono>],
              ["Recorded", dateTime(data.decision.created_at)],
            ]}
          />

          <h3 className="subhead">Matched policies</h3>
          {data.decision.matched_policies.length === 0 ? (
            <p className="muted small">No policy matched{data.decision.policy_id ? "" : " — the identity gate or default decision applied"}.</p>
          ) : (
            <ul className="sim-matched">
              {data.decision.matched_policies.map((m) => (
                <li key={m.policy_id}>
                  <DecisionPill decision={m.effect} size="sm" />
                  <Link to={`/app/policies/${m.policy_id}`}>{m.name}</Link>
                  <span className="mono muted small">p{m.priority} · v{m.version}</span>
                  {m.indeterminate && <Tag tone="warn">indeterminate</Tag>}
                </li>
              ))}
            </ul>
          )}

          <h3 className="subhead">Context</h3>
          {data.decision.context_captured ? (
            <JsonView value={data.decision.context} />
          ) : (
            <Alert tone="info">Context was not captured for this decision because audit capture was disabled at the time.</Alert>
          )}

          {data.policy_snapshot && (
            <details className="detail-disclosure">
              <summary>Policy definition at version {String(data.policy_snapshot.version ?? data.decision.policy_version)}</summary>
              <JsonView value={data.policy_snapshot} />
            </details>
          )}

          {data.approval && (
            <>
              <h3 className="subhead">Approval</h3>
              <div className="detail-approval">
                <ApprovalChip status={data.approval.status} />
                {data.approval.status === "approved" && (
                  <span className="muted small">
                    {data.approval.consumed_at
                      ? `Grant consumed by the integration ${dateTime(data.approval.consumed_at)}`
                      : data.approval.executable && data.approval.grant_expires_at
                        ? `Grant usable once until ${dateTime(data.approval.grant_expires_at)}`
                        : "Grant expired without being consumed"}
                  </span>
                )}
              </div>
              <ol className="timeline">
                <li>
                  <span className="tl-dot tl-review" />
                  <div>
                    <strong>Approval requested</strong>
                    <span className="muted small">{dateTime(data.approval.requested_at)} · expires {dateTime(data.approval.expires_at)}</span>
                  </div>
                </li>
                {data.approval_events.map((e, i) => (
                  <li key={i}>
                    <span className={cx("tl-dot", e.action.endsWith("approved") || e.action.endsWith("consumed") ? "tl-allow" : e.action.endsWith("denied") ? "tl-block" : "tl-muted")} />
                    <div>
                      <strong>{e.action.replace("approval.", "").replace(/^./, (c) => c.toUpperCase())}</strong>
                      <span className="muted small">
                        {e.actor_label ?? e.actor_type} · {dateTime(e.created_at)}
                        {typeof e.detail.note === "string" && e.detail.note ? ` · “${e.detail.note}”` : ""}
                      </span>
                    </div>
                  </li>
                ))}
                {data.approval.status === "pending" && (
                  <li>
                    <span className="tl-dot tl-muted" />
                    <div>
                      <strong>Waiting for an approver</strong>
                      <Link to="/app/approvals" className="small">Open approvals</Link>
                    </div>
                  </li>
                )}
              </ol>
            </>
          )}

          <h3 className="subhead">Integrity</h3>
          <DefinitionList
            items={[
              ["Engine", <Mono key="e">{data.decision.engine_version}</Mono>],
              ["Policy evaluation", data.decision.eval_ms === null ? "—" : `${data.decision.eval_ms < 1 ? "<1" : data.decision.eval_ms} ms (server-measured)`],
              ["Gateway (pre-write)", data.decision.gateway_ms === null ? "—" : `${data.decision.gateway_ms} ms (server-measured)`],
              ["Request fingerprint", <span key="f" className="detail-fp"><Mono className="break">{data.decision.request_fingerprint}</Mono><CopyButton text={data.decision.request_fingerprint} label="Copy" /></span>],
            ]}
          />
          <p className="muted small">Decision records are append-only. Approval actions are appended as separate events; this record is never rewritten.</p>
        </div>
      )}
    </div>
  );
}

function ControlEvents() {
  const now = useNow(30_000);
  const [events, setEvents] = useState<ControlEvent[] | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(async (after: string | null) => {
    setBusy(true);
    try {
      const r = await api<{ events: ControlEvent[]; next_cursor: string | null }>(`/api/console/events${after ? `?cursor=${encodeURIComponent(after)}` : ""}`);
      setEvents((cur) => (after && cur ? [...cur, ...r.events] : r.events));
      setCursor(r.next_cursor);
      setError(null);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }, []);
  useEffect(() => {
    void load(null);
  }, [load]);

  if (error && !events) return <ErrorState error={error} onRetry={() => void load(null)} />;
  if (!events) return <div className="card card-body"><Skeleton lines={6} /></div>;
  if (!events.length) return <div className="card"><Empty title="No control events yet">Policy edits, key lifecycle, approvals, badge and membership changes are recorded here.</Empty></div>;
  return (
    <div className="card">
      <ol className="event-list">
        {events.map((e) => (
          <li key={e.id} className="event">
            <span className={cx("tl-dot", e.action.includes("revoked") || e.action.includes("denied") || e.action.includes("disabled") || e.action.includes("suspended") ? "tl-block" : e.action.includes("approved") || e.action.includes("created") ? "tl-allow" : "tl-muted")} />
            <div className="event-main">
              <div className="event-title">
                <Mono>{e.action}</Mono>
                {e.target_type && <span className="muted small">{e.target_type}{e.target_id ? ` ${e.target_id}` : ""}</span>}
              </div>
              <div className="muted small">
                {e.actor_label ?? e.actor_type} <Tag tone="muted">{e.actor_type}</Tag>
              </div>
              {Object.keys(e.detail).length > 0 && (
                <details className="event-detail">
                  <summary>Details</summary>
                  <JsonView value={e.detail} />
                </details>
              )}
            </div>
            <time className="dl-time" title={dateTime(e.created_at)} dateTime={e.created_at}>
              {relativeTime(e.created_at, now)}
            </time>
          </li>
        ))}
      </ol>
      {cursor && (
        <div className="load-more">
          <Button onClick={() => void load(cursor)} loading={busy}>Load more</Button>
        </div>
      )}
    </div>
  );
}

export function AuditPage() {
  useDocumentTitle("Audit");
  const query = useQuery();
  const { navigate, location } = useRouter();
  const now = useNow(30_000);
  const tab = query.get("tab") === "events" ? "events" : "decisions";
  const openId = query.get("open");
  const [draft, setDraft] = useState<Record<string, string>>(() => Object.fromEntries(FILTER_KEYS.map((k) => [k, query.get(k) ?? ""])));
  const [rows, setRows] = useState<Row[] | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  const filterString = FILTER_KEYS.map((k) => `${k}=${query.get(k) ?? ""}`).join("&");

  const buildApiQuery = useCallback(
    (after: string | null) => {
      const p = new URLSearchParams();
      for (const k of FILTER_KEYS) {
        const v = query.get(k);
        if (!v) continue;
        if (k === "from" || k === "to") {
          const d = new Date(k === "to" ? `${v}T23:59:59.999` : `${v}T00:00:00`);
          if (!Number.isNaN(d.getTime())) p.set(k, d.toISOString());
        } else p.set(k, v);
      }
      if (after) p.set("cursor", after);
      return `/api/console/decisions?${p.toString()}`;
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [filterString],
  );

  useEffect(() => {
    if (tab !== "decisions") return;
    let cancelled = false;
    setRows(null);
    setError(null);
    api<{ decisions: Row[]; next_cursor: string | null }>(buildApiQuery(null))
      .then((r) => {
        if (cancelled) return;
        setRows(r.decisions);
        setCursor(r.next_cursor);
      })
      .catch((err) => !cancelled && setError(err));
    return () => {
      cancelled = true;
    };
  }, [buildApiQuery, tab, attempt]);

  const setParams = (patch: Record<string, string | null>) => {
    const p = new URLSearchParams(location.search);
    for (const [k, v] of Object.entries(patch)) {
      if (v) p.set(k, v);
      else p.delete(k);
    }
    const qs = p.toString();
    navigate(`/app/audit${qs ? `?${qs}` : ""}`, { replace: true });
  };

  const applyFilters = (e?: React.FormEvent) => {
    e?.preventDefault();
    setParams({ ...Object.fromEntries(FILTER_KEYS.map((k) => [k, draft[k]?.trim() || null])), open: null });
  };
  const clearFilters = () => {
    setDraft(Object.fromEntries(FILTER_KEYS.map((k) => [k, ""])));
    setParams({ ...Object.fromEntries(FILTER_KEYS.map((k) => [k, null])), open: null });
  };
  const activeFilters = FILTER_KEYS.filter((k) => query.get(k)).length;

  const loadMore = async () => {
    if (!cursor) return;
    setLoadingMore(true);
    setMoreError(null);
    try {
      const r = await api<{ decisions: Row[]; next_cursor: string | null }>(buildApiQuery(cursor));
      setRows((cur) => [...(cur ?? []), ...r.decisions]);
      setCursor(r.next_cursor);
    } catch (err) {
      setMoreError(errorMessage(err));
    } finally {
      setLoadingMore(false);
    }
  };

  return (
    <>
      <PageHeader title="Audit" description="Tamper-resistant, append-oriented record of every gateway decision and every control-plane change." />
      <Tabs
        label="Audit view"
        value={tab}
        onChange={(v) => setParams({ tab: v === "events" ? "events" : null, open: null })}
        tabs={[
          { id: "decisions", label: "Decisions" },
          { id: "events", label: "Control events" },
        ]}
      />

      {tab === "events" ? (
        <ControlEvents />
      ) : (
        <>
          <form className="filters" onSubmit={applyFilters}>
            <Input className="filter-q mono" placeholder="Request id, decision id, resource or reason code" value={draft.q} onChange={(e) => setDraft({ ...draft, q: e.target.value })} aria-label="Search" />
            <Input className="mono" placeholder="agent id" value={draft.agent} onChange={(e) => setDraft({ ...draft, agent: e.target.value.toLowerCase() })} aria-label="Agent" />
            <Select value={draft.decision} onChange={(e) => setDraft({ ...draft, decision: e.target.value })} aria-label="Decision">
              <option value="">Any decision</option>
              <option value="allow">Allow</option>
              <option value="review">Review</option>
              <option value="block">Block</option>
            </Select>
            <Input className="mono" placeholder="capability" value={draft.capability} onChange={(e) => setDraft({ ...draft, capability: e.target.value.toLowerCase() })} aria-label="Capability" />
            <Select value={draft.environment} onChange={(e) => setDraft({ ...draft, environment: e.target.value })} aria-label="Environment">
              <option value="">Any environment</option>
              <option value="production">production</option>
              <option value="staging">staging</option>
              <option value="development">development</option>
            </Select>
            <label className="date-field">
              <span>From</span>
              <Input type="date" value={draft.from} onChange={(e) => setDraft({ ...draft, from: e.target.value })} aria-label="From date" />
            </label>
            <label className="date-field">
              <span>To</span>
              <Input type="date" value={draft.to} onChange={(e) => setDraft({ ...draft, to: e.target.value })} aria-label="To date" />
            </label>
            <div className="filters-actions">
              <Button type="submit" variant="secondary">Apply</Button>
              {activeFilters > 0 && (
                <Button type="button" variant="ghost" onClick={clearFilters}>
                  Clear ({activeFilters})
                </Button>
              )}
            </div>
          </form>

          <div className={cx("audit-layout", openId && "has-detail")}>
            <div className="card audit-list">
              {error && !rows ? (
                <ErrorState error={error} onRetry={() => setAttempt((n) => n + 1)} />
              ) : !rows ? (
                <div className="card-body"><Skeleton lines={8} /></div>
              ) : rows.length === 0 ? (
                <Empty
                  icon={<IconAudit width={22} height={22} />}
                  title={activeFilters ? "No decisions match these filters" : "No decisions recorded yet"}
                  action={
                    activeFilters ? (
                      <Button size="sm" variant="secondary" onClick={clearFilters}>Clear filters</Button>
                    ) : (
                      <Link to="/app/integrations" className="btn btn-secondary btn-sm">Connect an agent <IconChevron /></Link>
                    )
                  }
                >
                  {activeFilters ? "Try widening the date range or clearing a filter." : "Every gateway evaluation — allow, review or block — is recorded here before the agent receives its answer."}
                </Empty>
              ) : (
                <>
                  <div className="decision-list">
                    {rows.map((d) => (
                      <DecisionLine key={d.id} d={d} now={now} active={openId === d.id} onOpen={() => setParams({ open: openId === d.id ? null : d.id })} />
                    ))}
                  </div>
                  {(cursor || moreError) && (
                    <div className="load-more">
                      {moreError && <p className="small load-more-error" role="alert">Couldn't load more: {moreError}</p>}
                      {cursor && <Button onClick={() => void loadMore()} loading={loadingMore}>{moreError ? "Retry" : "Load more"}</Button>}
                    </div>
                  )}
                </>
              )}
            </div>
            {openId && /^dec_[0-9A-Za-z]{22}$/.test(openId) && (
              <aside className="audit-detail card">
                <DecisionDetailPanel id={openId} onClose={() => setParams({ open: null })} />
              </aside>
            )}
          </div>
        </>
      )}
    </>
  );
}
