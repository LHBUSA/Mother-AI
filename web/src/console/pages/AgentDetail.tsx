import { useEffect, useState } from "react";
import { api, errorMessage, type Agent, type Decision, type DecisionSummary } from "../lib/api";
import { useApi, useDocumentTitle, useNow } from "../lib/hooks";
import { Link } from "../lib/router";
import { dateTime } from "../lib/format";
import { useSession } from "../lib/session";
import { DecisionLine } from "../components/decisions";
import { IconArrowLeft, IconChevron } from "../components/icons";
import { Alert, Button, Card, CodeBlock, ConfirmDialog, DecisionPill, DefinitionList, Empty, EnvTag, ErrorState, Field, Input, Mono, PageHeader, Select, Skeleton, Stat, StatusDot, Textarea, Tag, toast } from "../components/ui";

interface AgentDetail {
  agent: Agent;
  policies: Array<{ id: string; name: string; effect: Decision; priority: number; enabled: number; scope: "organization" | "agents"; version: number; bound: number }>;
  recent_decisions: DecisionSummary[];
  stats_7d: Record<Decision, number>;
}

export function AgentDetailPage({ id }: { id: string }) {
  const { can } = useSession();
  const now = useNow(30_000);
  const { data, error, loading, reload, setData } = useApi<AgentDetail>(`/api/console/agents/${id}`);
  useDocumentTitle(data ? data.agent.display_name : "Agent");
  const [edit, setEdit] = useState({ display_name: "", description: "", default_mode: "inherit" as Agent["default_mode"] });
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [confirmDisable, setConfirmDisable] = useState(false);

  useEffect(() => {
    if (data) setEdit({ display_name: data.agent.display_name, description: data.agent.description, default_mode: data.agent.default_mode });
  }, [data]);

  if (error && !data) return <ErrorState error={error} onRetry={() => void reload()} />;
  if (loading && !data) return <Skeleton lines={8} />;
  if (!data) return null;
  const { agent } = data;
  const canEdit = can("manage_agents");
  const dirty = edit.display_name !== agent.display_name || edit.description !== agent.description || edit.default_mode !== agent.default_mode;

  const patch = async (body: Record<string, unknown>, success: string) => {
    setBusy(true);
    setSaveError(null);
    try {
      const res = await api<{ agent: Agent }>(`/api/console/agents/${id}`, { method: "PATCH", body });
      setData({ ...data, agent: res.agent });
      toast(success);
      return true;
    } catch (err) {
      setSaveError(errorMessage(err));
      return false;
    } finally {
      setBusy(false);
    }
  };

  const origin = window.location.origin;
  const curl = `curl -X POST ${origin}/v1/evaluate \\
  -H "Authorization: Bearer $MOTHER_AI_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "request_id": "<unique id per action>",
    "agent_id": "${agent.agent_key}",
    "capability": "<capability>",
    "operation": "<operation>",
    "resource": "<resource id>"
  }'`;

  const orgWide = data.policies.filter((p) => p.scope === "organization");
  const bound = data.policies.filter((p) => p.scope === "agents");
  const total7 = data.stats_7d.allow + data.stats_7d.review + data.stats_7d.block;

  const PolicyRows = ({ items }: { items: AgentDetail["policies"] }) => (
    <ul className="plist">
      {items.map((p) => (
        <li key={p.id}>
          <Link to={`/app/policies/${p.id}`} className="plist-item">
            <DecisionPill decision={p.effect} size="sm" />
            <span className="plist-name">{p.name}</span>
            <span className="plist-meta mono">p{p.priority} · v{p.version}</span>
            {!p.enabled && <Tag tone="muted">disabled</Tag>}
            <IconChevron className="plist-chev" />
          </Link>
        </li>
      ))}
    </ul>
  );

  return (
    <>
      <Link to="/app/agents" className="back-link">
        <IconArrowLeft /> Agents
      </Link>
      <PageHeader
        title={agent.display_name}
        eyebrow={<Mono>{agent.agent_key}</Mono>}
        description={agent.description || undefined}
        actions={
          canEdit && (
            agent.status === "active" ? (
              <Button variant="danger" onClick={() => setConfirmDisable(true)}>Disable agent</Button>
            ) : (
              <Button variant="primary" loading={busy} onClick={() => void patch({ status: "active" }, "Agent enabled")}>Enable agent</Button>
            )
          )
        }
      />
      {agent.status === "disabled" && (
        <Alert tone="warn" title="Agent disabled">
          Every gateway request from <Mono>{agent.agent_key}</Mono> is blocked with <Mono>AGENT_DISABLED</Mono> until it is re-enabled.
        </Alert>
      )}

      <div className="grid-detail">
        <div className="stack">
          <Card title="Identity">
            <DefinitionList
              items={[
                ["Agent id", <Mono key="k">{agent.agent_key}</Mono>],
                ["Environment", <EnvTag key="e" env={agent.environment} />],
                ["Status", <span key="s" className="status-inline"><StatusDot tone={agent.status === "active" ? "ok" : "muted"} />{agent.status === "active" ? "Active" : "Disabled"}</span>],
                ["Internal id", <Mono key="i">{agent.id}</Mono>],
                ["Registered", dateTime(agent.created_at)],
                ["Updated", dateTime(agent.updated_at)],
              ]}
            />
          </Card>

          <Card title="Decisions · last 7 days">
            <div className="stat-row stat-row-3">
              <Stat label="Allowed" value={data.stats_7d.allow} tone="allow" />
              <Stat label="Review" value={data.stats_7d.review} tone="review" />
              <Stat label="Blocked" value={data.stats_7d.block} tone="block" />
            </div>
            {total7 === 0 && <p className="muted small mt-12">No gateway decisions for this agent in the last 7 days.</p>}
          </Card>

          <Card title="Recent decisions" pad={false} actions={<Link to={`/app/audit?agent=${encodeURIComponent(agent.agent_key)}`} className="link-sm">Full audit <IconChevron /></Link>}>
            {data.recent_decisions.length === 0 ? (
              <div className="card-body"><Empty title="No decisions yet">Decisions appear once this agent calls the gateway.</Empty></div>
            ) : (
              <div className="decision-list">
                {data.recent_decisions.map((d) => <DecisionLine key={d.id} d={d} now={now} />)}
              </div>
            )}
          </Card>
        </div>

        <div className="stack">
          <Card title="Applicable policies">
            {data.policies.length === 0 ? (
              <Empty title="No policies apply">
                With no matching policy this agent falls to its default decision. <Link to="/app/policies/new">Create a policy</Link>.
              </Empty>
            ) : (
              <>
                {bound.length > 0 && (
                  <>
                    <h3 className="subhead">Bound to this agent</h3>
                    <PolicyRows items={bound} />
                  </>
                )}
                {orgWide.length > 0 && (
                  <>
                    <h3 className="subhead">Organization-wide</h3>
                    <PolicyRows items={orgWide} />
                  </>
                )}
              </>
            )}
          </Card>

          <Card title="Behaviour & profile">
            <form
              className="form-grid"
              onSubmit={(e) => {
                e.preventDefault();
                void patch({ display_name: edit.display_name, description: edit.description, default_mode: edit.default_mode }, "Agent updated");
              }}
            >
              <Field label="Display name" htmlFor="a-name">
                <Input id="a-name" value={edit.display_name} disabled={!canEdit} onChange={(e) => setEdit({ ...edit, display_name: e.target.value })} />
              </Field>
              <Field label="Description" htmlFor="a-desc" optional>
                <Textarea id="a-desc" rows={2} value={edit.description} disabled={!canEdit} onChange={(e) => setEdit({ ...edit, description: e.target.value })} />
              </Field>
              <Field
                label="When no policy matches"
                htmlFor="a-mode"
                hint={agent.environment === "production" ? "Production agents can't default to allow: an unmatched production action is always blocked or sent for review." : "Non-production agents may default to allow for testing."}
              >
                <Select id="a-mode" value={edit.default_mode} disabled={!canEdit} onChange={(e) => setEdit({ ...edit, default_mode: e.target.value as Agent["default_mode"] })}>
                  <option value="inherit">Organization default</option>
                  <option value="block">Block</option>
                  <option value="review">Require approval</option>
                  <option value="allow" disabled={agent.environment === "production"}>Allow{agent.environment === "production" ? " (not for production)" : ""}</option>
                </Select>
              </Field>
              {saveError && <Alert tone="bad">{saveError}</Alert>}
              {canEdit && (
                <div className="form-actions">
                  <Button variant="primary" type="submit" disabled={!dirty} loading={busy}>Save changes</Button>
                </div>
              )}
            </form>
          </Card>

          <Card title="Integration">
            <p className="muted small mb-12">
              Send exactly <Mono>{agent.agent_key}</Mono> as <Mono>agent_id</Mono>. Environment is taken from the registry{agent.environment ? ` (${agent.environment})` : ""}; a request declaring a different environment is blocked.
            </p>
            <CodeBlock code={curl} language="bash" />
          </Card>
        </div>
      </div>

      <ConfirmDialog
        open={confirmDisable}
        onClose={() => setConfirmDisable(false)}
        onConfirm={async () => {
          if (await patch({ status: "disabled" }, "Agent disabled")) setConfirmDisable(false);
        }}
        title="Disable this agent?"
        confirmLabel="Disable agent"
        busy={busy}
        error={saveError}
      >
        <p>
          Every gateway evaluation for <Mono>{agent.agent_key}</Mono> will be blocked immediately with <Mono>AGENT_DISABLED</Mono>. This is recorded in the control event log and can be reversed.
        </p>
      </ConfirmDialog>
    </>
  );
}
