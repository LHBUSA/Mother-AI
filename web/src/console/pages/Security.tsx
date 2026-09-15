import { useEffect, useState } from "react";
import { api, errorMessage, type Decision } from "../lib/api";
import { useApi, useDocumentTitle, useKeyedApi, useNow } from "../lib/hooks";
import { incidentView } from "./incident-view";
import { Link, useRouter } from "../lib/router";
import { dateTime, relativeTime } from "../lib/format";
import { useSession } from "../lib/session";
import { Alert, Button, Card, DecisionPill, Dialog, Empty, ErrorState, Field, Mono, PageHeader, Skeleton, Tag, Textarea, cx, toast } from "../components/ui";

type RiskState = "normal" | "elevated" | "review_required" | "quarantined" | "contained" | "cleared";

interface Subject {
  subject_type: "agent" | "session" | "api_key";
  subject_id: string;
  label: string | null;
  state: RiskState;
  score: number;
  state_since: string;
  incident_id: string | null;
  updated_at: string;
}

interface Incident {
  id: string;
  subject_type: "agent" | "session";
  subject_id: string;
  status: "open" | "contained" | "cleared";
  severity: "high" | "critical";
  cause: "score_quarantine" | "hard_signal_quarantine" | "manual_quarantine";
  opened_by_name: string | null;
  opened_reason: string;
  score: number;
  opened_at: string;
  contained_at: string | null;
  cleared_at: string | null;
  cleared_by_name: string | null;
  clearance_note: string | null;
}

interface Rule {
  code: string;
  hard: boolean;
  points: number;
  window_minutes: number;
  rule: string;
}

interface Overview {
  mode: "off" | "monitor" | "enforce";
  alerts_enabled: boolean;
  engine_version: string;
  thresholds: { elevated: number; review_required: number; quarantine: number };
  rules: Rule[];
  subjects: Subject[];
  incidents: Incident[];
  boundary: string;
}

const STATE_LABEL: Record<RiskState, string> = {
  normal: "Normal",
  elevated: "Elevated",
  review_required: "Review required",
  quarantined: "Quarantined",
  contained: "Contained",
  cleared: "Cleared",
};
const STATE_TONE: Record<RiskState, "ok" | "warn" | "bad" | "muted"> = {
  normal: "muted",
  elevated: "warn",
  review_required: "warn",
  quarantined: "bad",
  contained: "bad",
  cleared: "ok",
};
const CAUSE_LABEL: Record<Incident["cause"], string> = {
  score_quarantine: "Risk score reached 80",
  hard_signal_quarantine: "Hard deterministic violation",
  manual_quarantine: "Quarantined by a person",
};
const MODE_COPY: Record<Overview["mode"], { label: string; text: string; tone: "ok" | "warn" | "muted" }> = {
  off: { label: "Off", text: "Runtime risk is not evaluated.", tone: "muted" },
  monitor: { label: "Monitor", text: "Signals and risk are recorded. Decisions are never changed and nothing is quarantined.", tone: "warn" },
  enforce: { label: "Enforce", text: "Runtime risk can require review or quarantine. Quarantine blocks every action in scope until a human clears it.", tone: "ok" },
};

export function StatePill({ state }: { state: RiskState }) {
  return <Tag tone={STATE_TONE[state]}>{STATE_LABEL[state]}</Tag>;
}

function QuarantineDialog({ subject, onClose, onDone }: { subject: Subject | null; onClose: () => void; onDone: (incident: string) => void }) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <Dialog
      open={!!subject}
      onClose={() => !busy && onClose()}
      size="sm"
      title={`Quarantine this ${subject?.subject_type ?? "subject"}?`}
      description={subject ? `${subject.label ?? subject.subject_id} · ${subject.subject_id}` : undefined}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button
            variant="danger"
            loading={busy}
            disabled={note.trim().length < 10}
            onClick={async () => {
              setBusy(true);
              setErr(null);
              try {
                const r = await api<{ incident_id: string }>("/api/console/security/quarantine", { body: { subject_type: subject!.subject_type, subject_id: subject!.subject_id, note: note.trim() } });
                setNote("");
                onDone(r.incident_id);
              } catch (e) {
                setErr(errorMessage(e));
              } finally {
                setBusy(false);
              }
            }}
          >
            Quarantine
          </Button>
        </>
      }
    >
      <p className="small mb-12">Every new action in scope is blocked immediately, live leases are revoked, pending approvals are cancelled by the system and older grants can never be used again. Only a human with the Security, Admin or Owner role can clear it.</p>
      <Field label="Reason" htmlFor="q-note" hint="At least 10 characters. Recorded in the incident and audit trail.">
        <Textarea id="q-note" rows={3} maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} data-autofocus />
      </Field>
      {err && <Alert tone="bad">{err}</Alert>}
    </Dialog>
  );
}

export function SecurityPage() {
  useDocumentTitle("Security");
  const { can } = useSession();
  const now = useNow(30_000);
  const { navigate } = useRouter();
  const { data, error, loading, reload } = useApi<Overview>("/api/console/security");
  const [quarantining, setQuarantining] = useState<Subject | null>(null);

  if (error && !data) return <ErrorState error={error} onRetry={() => void reload()} />;
  if (loading && !data) return <div className="card card-body"><Skeleton lines={8} /></div>;
  if (!data) return null;
  const mode = MODE_COPY[data.mode];
  const open = data.incidents.filter((i) => i.status !== "cleared");

  return (
    <>
      <PageHeader title="Security" description="Deterministic runtime risk and containment for actions that are routed through Mother." />
      <div className="sec-strip">
        <div className="sec-strip-item">
          <span className="field-label">Runtime protection</span>
          <span><Tag tone={mode.tone}>{mode.label}</Tag> <span className="muted small">{mode.text}</span></span>
        </div>
        <div className="sec-strip-item">
          <span className="field-label">Security alerts</span>
          <span className="small">{data.alerts_enabled ? "Slack alerts on" : "Off"}</span>
        </div>
        <div className="sec-strip-item">
          <span className="field-label">Engine</span>
          <Mono>{data.engine_version}</Mono>
        </div>
        {can("manage_org") && <Link to="/app/settings" className="link-sm">Change in Settings</Link>}
      </div>
      <p className="muted small sec-boundary">{data.boundary}</p>

      <Card title={`Incidents${open.length ? ` · ${open.length} active` : ""}`} pad={false}>
        {data.incidents.length === 0 ? (
          <Empty title="No security incidents">When a scope is quarantined, its incident appears here with everything Mother observed it touch.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table table-notify">
              <thead><tr><th>Status</th><th>Subject</th><th>Cause</th><th>Opened</th><th>Cleared</th></tr></thead>
              <tbody>
                {data.incidents.map((i) => (
                  <tr key={i.id} className="is-link" onClick={() => navigate(`/app/security/incidents/${i.id}`)}>
                    <td data-label="Status"><Tag tone={i.status === "cleared" ? "ok" : "bad"}>{i.status}</Tag></td>
                    <td data-label="Subject" className="cell-title"><Link to={`/app/security/incidents/${i.id}`}>{i.subject_type} <Mono>{i.subject_id}</Mono></Link></td>
                    <td data-label="Cause">{CAUSE_LABEL[i.cause]}</td>
                    <td data-label="Opened" className="muted" title={dateTime(i.opened_at)}>{relativeTime(i.opened_at, now)}</td>
                    <td data-label="Cleared" className="muted">{i.cleared_at ? `${relativeTime(i.cleared_at, now)} by ${i.cleared_by_name ?? "—"}` : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="Subjects with runtime risk" pad={false}>
        {data.subjects.length === 0 ? (
          <Empty title="Every agent, session and key is at normal risk" />
        ) : (
          <div className="table-wrap">
            <table className="table table-notify">
              <thead><tr><th>Subject</th><th>State</th><th>Score</th><th>Since</th><th><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {data.subjects.map((s) => (
                  <tr key={`${s.subject_type}:${s.subject_id}`}>
                    <td data-label="Subject" className="cell-title">{s.subject_type} · {s.label ?? "—"} <Mono className="muted">{s.subject_id}</Mono></td>
                    <td data-label="State"><StatePill state={s.state} /></td>
                    <td data-label="Score" className="num">{s.score}</td>
                    <td data-label="Since" className="muted" title={dateTime(s.state_since)}>{relativeTime(s.state_since, now)}</td>
                    <td className="actions-cell">
                      {s.incident_id && (s.state === "quarantined" || s.state === "contained") ? (
                        <Link to={`/app/security/incidents/${s.incident_id}`} className="link-sm">Incident</Link>
                      ) : data.mode === "enforce" && can("manage_security") && s.subject_type !== "api_key" ? (
                        <Button size="sm" variant="ghost" onClick={() => setQuarantining(s)}>Quarantine</Button>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title={`Rules · ${data.engine_version}`} pad={false}>
        <p className="muted small sec-card-note">Behavioral signals add points: {data.thresholds.elevated} elevated, {data.thresholds.review_required} review required, {data.thresholds.quarantine} quarantine (enforce only). No single behavioral signal can quarantine. Hard signals quarantine immediately in enforce mode.</p>
        <div className="table-wrap">
          <table className="table table-notify">
            <thead><tr><th>Signal</th><th>Type</th><th>Points</th><th>Window</th><th>Rule</th></tr></thead>
            <tbody>
              {data.rules.map((r) => (
                <tr key={r.code}>
                  <td data-label="Signal"><Mono>{r.code}</Mono></td>
                  <td data-label="Type">{r.hard ? <Tag tone="bad">hard</Tag> : <Tag tone="muted">behavioral</Tag>}</td>
                  <td data-label="Points" className="num">{r.points}</td>
                  <td data-label="Window" className="muted">{r.window_minutes >= 60 ? `${r.window_minutes / 60} h` : `${r.window_minutes} min`}</td>
                  <td data-label="Rule" className="small">{r.rule}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <QuarantineDialog
        subject={quarantining}
        onClose={() => setQuarantining(null)}
        onDone={(incident) => {
          setQuarantining(null);
          toast("Quarantined — every action in scope is now blocked");
          navigate(`/app/security/incidents/${incident}`);
        }}
      />
    </>
  );
}

// ---------------------------------------------------------------------------
// Incident detail
// ---------------------------------------------------------------------------

interface Touched {
  value: string;
  n: number;
  first_seen: string;
  last_seen: string;
  allowed: number;
  reviewed: number;
  blocked: number;
}

interface IncidentDetail {
  incident: Incident;
  subject: (Subject & { containment_epoch_at: string | null }) | null;
  members: Array<{ member_type: string; member_id: string; relation: string }>;
  transitions: Array<{ id: string; from_state: RiskState; to_state: RiskState; score: number; cause: string; actor_type: string; actor_label: string | null; note: string | null; created_at: string }>;
  triggering_signals: Array<{ id: string; signal: string; hard: boolean; points: number; evidence: Record<string, unknown>; observed_at: string; subject_type: string }>;
  signals_before_quarantine: Array<{ id: string; signal: string; hard: boolean; points: number; evidence: Record<string, unknown>; observed_at: string; mode: string }>;
  blast_radius: {
    window: { from: string; to: string };
    boundary: string;
    sessions: Array<{ id: string; agent_key: string; parent_session_id: string | null; depth: number; principal_type: string; principal_ref: string | null; opened_at: string; closed_at: string | null }>;
    agents: Touched[];
    capabilities: Touched[];
    mcp_tools: Touched[];
    resources: Touched[];
    destinations: Touched[];
    data_classes: Touched[];
    decisions: Array<{ id: string; agent_key: string; capability: string; operation: string; resource: string | null; decision: Decision; reason_code: string; created_at: string; policy_decision: Decision | null; runtime_risk_decision: Decision | null; effective_decision: Decision | null }>;
    approvals: Array<{ id: string; status: string; requested_at: string; acted_by_name: string | null; consumed_at: string | null; terminated_reason: string | null }>;
    leases: Array<{ id: string; capability: string; operation: string; resource: string | null; uses: number; max_uses: number; issued_at: string; expires_at: string; revoked_at: string | null; refused_uses: number }>;
    execution_reports: Array<{ id: string; outcome: string; reason_code: string | null; decision_id: string; created_at: string }>;
  };
}

function TouchedList({ title, rows }: { title: string; rows: Touched[] }) {
  if (!rows.length) return null;
  return (
    <div className="br-group">
      <h3 className="approval-label">{title}</h3>
      <ul className="br-list">
        {rows.map((r) => (
          <li key={r.value}>
            <Mono>{r.value}</Mono>
            <span className="muted small">{r.n} request{r.n === 1 ? "" : "s"} · {r.allowed} allowed · {r.reviewed} review · {r.blocked} blocked</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

const fetchIncident = (id: string, signal: AbortSignal) => api<IncidentDetail>(`/api/console/security/incidents/${id}`, { signal });

export function IncidentPage({ id }: { id: string }) {
  useDocumentTitle("Incident");
  const { can } = useSession();
  const now = useNow(30_000);
  const { state, reload } = useKeyedApi<IncidentDetail>(id, fetchIncident, (key, d) => d.incident?.id === key);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // A clearance note or error typed for one incident never carries over to another.
  useEffect(() => {
    setNote("");
    setErr(null);
  }, [id]);

  // Only a response for exactly this route's incident is ever rendered; while it loads or if it fails, the page
  // names the requested incident and shows nothing from any other incident.
  const view = incidentView(state, id);
  const eyebrow = <Link to="/app/security" className="link-sm">Security</Link>;
  if (view.phase === "loading") {
    return (
      <>
        <PageHeader eyebrow={eyebrow} title={view.heading} description="Loading this incident…" />
        <div className="card card-body" aria-busy="true"><Skeleton lines={10} /></div>
      </>
    );
  }
  if (view.phase === "error" || state.status !== "ready") {
    return (
      <>
        <PageHeader eyebrow={eyebrow} title={view.heading} description="This incident could not be loaded." />
        <ErrorState error={state.status === "error" ? state.error : null} onRetry={() => void reload()} />
      </>
    );
  }
  const data = state.data;
  const { incident, blast_radius: br } = data;
  const active = incident.status !== "cleared";
  const count = (relation: string) => data.members.filter((m) => m.relation === relation).length;

  const clear = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api(`/api/console/security/incidents/${incident.id}/clear`, { body: { note: note.trim() } });
      toast("Cleared — issue new authority; older grants and leases stay invalid");
      setNote("");
      void reload();
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader
        eyebrow={eyebrow}
        title={view.heading}
        description={`${CAUSE_LABEL[incident.cause]} · ${incident.subject_type} ${data.subject?.label ?? ""}`}
      />
      <div className={cx("sec-banner", active ? "sec-banner-bad" : "sec-banner-ok")} role="status">
        <strong>{view.banner}</strong>
        <span>
          {active
            ? "Every new action in scope is blocked. Grants and leases issued before the quarantine can never be used."
            : `Cleared ${relativeTime(incident.cleared_at, now)} by ${incident.cleared_by_name ?? "—"}: “${incident.clearance_note ?? ""}”`}
        </span>
      </div>

      <div className="settings-grid">
        <Card title="What happened">
          <dl className="approval-facts">
            <div><dt>Subject</dt><dd>{incident.subject_type} <Mono>{incident.subject_id}</Mono></dd></div>
            <div><dt>Reason</dt><dd>{incident.opened_reason}</dd></div>
            <div><dt>Severity</dt><dd><Tag tone="bad">{incident.severity}</Tag></dd></div>
            <div><dt>Opened</dt><dd>{dateTime(incident.opened_at)}{incident.opened_by_name ? ` · ${incident.opened_by_name}` : ""}</dd></div>
            <div><dt>Contained</dt><dd>{incident.contained_at ? dateTime(incident.contained_at) : "—"}</dd></div>
            <div><dt>Containment</dt><dd>{count("revoked_lease")} leases revoked · {count("cancelled_approval")} approvals cancelled · {count("invalidated_grant")} grants invalidated</dd></div>
          </dl>
          {data.signals_before_quarantine.length > 0 && (
            <>
              <h3 className="approval-label mt-16">Signals</h3>
              <ul className="br-list">
                {data.signals_before_quarantine.map((s) => (
                  <li key={s.id}>
                    <span><Mono>{s.signal}</Mono> {s.hard ? <Tag tone="bad">hard</Tag> : <Tag tone="muted">+{s.points}</Tag>}</span>
                    <span className="muted small">{dateTime(s.observed_at)} · {Object.entries(s.evidence).map(([k, v]) => `${k}: ${String(v)}`).join(" · ")}</span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </Card>

        <Card title="Timeline">
          <ol className="sec-timeline">
            {data.transitions.map((t) => (
              <li key={t.id}>
                <span className="muted small">{dateTime(t.created_at)}</span>
                <span><StatePill state={t.from_state} /> → <StatePill state={t.to_state} /> <span className="small">score {t.score} · {t.cause.replace(/_/g, " ")} · {t.actor_label ?? t.actor_type}</span></span>
              </li>
            ))}
          </ol>
        </Card>

        <Card title="Blast radius">
          <p className="muted small">{br.boundary} Window {dateTime(br.window.from)} – {dateTime(br.window.to)}.</p>
          {br.sessions.length > 0 && (
            <div className="br-group">
              <h3 className="approval-label">Sessions</h3>
              <ul className="br-list">
                {br.sessions.map((s) => (
                  <li key={s.id} style={{ paddingLeft: `${s.depth * 16}px` }}>
                    <span><Mono>{s.id}</Mono> · {s.agent_key}</span>
                    <span className="muted small">depth {s.depth} · principal {s.principal_type}{s.principal_ref ? ` “${s.principal_ref}” (reported by integration)` : ""} · opened {dateTime(s.opened_at)}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <TouchedList title="Agents" rows={br.agents} />
          <TouchedList title="Capabilities" rows={br.capabilities} />
          <TouchedList title="MCP servers / tools" rows={br.mcp_tools} />
          <TouchedList title="Resources" rows={br.resources} />
          <TouchedList title="Destinations" rows={br.destinations} />
          <TouchedList title="Data classes" rows={br.data_classes} />
          {br.approvals.length > 0 && (
            <div className="br-group">
              <h3 className="approval-label">Approvals</h3>
              <ul className="br-list">
                {br.approvals.map((a) => (
                  <li key={a.id}>
                    <Mono>{a.id}</Mono>
                    <span className="small">{a.terminated_reason === "quarantine" ? <Tag tone="muted">cancelled by quarantine</Tag> : <Tag tone={a.status === "approved" ? "ok" : "muted"}>{a.status}</Tag>} {a.consumed_at ? "· grant consumed" : ""} {a.acted_by_name && a.terminated_reason !== "quarantine" ? `· by ${a.acted_by_name}` : ""}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {br.leases.length > 0 && (
            <div className="br-group">
              <h3 className="approval-label">Capability leases</h3>
              <ul className="br-list">
                {br.leases.map((l) => (
                  <li key={l.id}>
                    <span><Mono>{l.id}</Mono> · {l.capability}.{l.operation} {l.resource && <Mono>{l.resource}</Mono>}</span>
                    <span className="muted small">{l.uses}/{l.max_uses} uses · {l.refused_uses} refused · {l.revoked_at ? "revoked" : Date.parse(l.expires_at) < now ? "expired" : "live"}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {br.decisions.length > 0 && (
            <div className="br-group">
              <h3 className="approval-label">Decisions (latest {br.decisions.length})</h3>
              <ul className="br-list">
                {br.decisions.map((d) => (
                  <li key={d.id}>
                    <span><DecisionPill decision={d.decision} size="sm" /> <Mono>{d.capability}.{d.operation}</Mono> {d.resource && <Mono className="muted">{d.resource}</Mono>}</span>
                    <span className="muted small">
                      {d.policy_decision ? `policy ${d.policy_decision} · runtime ${d.runtime_risk_decision} · effective ${d.effective_decision}` : "no runtime evaluation"} · {d.reason_code} · {relativeTime(d.created_at, now)}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {br.execution_reports.length > 0 && (
            <div className="br-group">
              <h3 className="approval-label">Execution results · reported by integration</h3>
              <ul className="br-list">
                {br.execution_reports.map((e) => (
                  <li key={e.id}>
                    <span><Tag tone={e.reason_code ? "bad" : "muted"}>{e.outcome}</Tag> <Mono>{e.decision_id}</Mono></span>
                    <span className="muted small">{e.reason_code ?? "consistent with the decision"} · {dateTime(e.created_at)}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Card>

        {active && (
          <Card title="Clear this incident">
            {can("manage_security") ? (
              <>
                <p className="small">Clearing ends the block for this scope. It never restores grants or leases issued before the quarantine; new authority must be issued. Only a human Security, Admin or Owner member can clear, with a written note.</p>
                <Field label="Clearance note" htmlFor="clear-note" hint="At least 10 characters. Recorded in the incident, audit trail and Slack alert.">
                  <Textarea id="clear-note" rows={3} maxLength={1000} value={note} onChange={(e) => setNote(e.target.value)} />
                </Field>
                {err && <Alert tone="bad">{err}</Alert>}
                <div className="form-actions">
                  <Button variant="primary" loading={busy} disabled={note.trim().length < 10} onClick={() => void clear()}>Clear quarantine</Button>
                </div>
              </>
            ) : (
              <Alert tone="info">Clearing a quarantine requires the Security role or higher.</Alert>
            )}
          </Card>
        )}
      </div>
    </>
  );
}
