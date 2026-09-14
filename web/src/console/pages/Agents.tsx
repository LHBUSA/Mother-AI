import { useState } from "react";
import { api, ApiFailure, errorMessage, type Agent } from "../lib/api";
import { useApi, useDocumentTitle, useNow } from "../lib/hooks";
import { Link, useRouter } from "../lib/router";
import { relativeTime } from "../lib/format";
import { useSession } from "../lib/session";
import { MiniBars } from "../components/decisions";
import { IconAgents, IconPlus } from "../components/icons";
import { Alert, Button, Dialog, Empty, EnvTag, ErrorState, Field, Input, PageHeader, Select, Skeleton, StatusDot, Textarea, toast } from "../components/ui";

interface AgentListItem extends Agent {
  bound_policies: number;
  last_activity: string | null;
  allow_7d: number;
  review_7d: number;
  block_7d: number;
}

export const DEFAULT_MODE_LABEL: Record<Agent["default_mode"], string> = {
  inherit: "Organization default",
  block: "Block",
  review: "Require approval",
  allow: "Allow",
};

export function RegisterAgentDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (a: Agent) => void }) {
  const [form, setForm] = useState({ agent_id: "", display_name: "", description: "", environment: "production", default_mode: "inherit" });
  const [fields, setFields] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof form, v: string) => setForm((f) => ({ ...f, [k]: v }));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setFields({});
    setError(null);
    try {
      const res = await api<{ agent: Agent }>("/api/console/agents", { body: { ...form, description: form.description || undefined } });
      toast(`Registered ${res.agent.agent_key}`);
      onCreated(res.agent);
      setForm({ agent_id: "", display_name: "", description: "", environment: "production", default_mode: "inherit" });
    } catch (err) {
      if (err instanceof ApiFailure && Object.keys(err.fields).length) setFields(err.fields);
      else setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Register agent"
      description="An agent identity is stable: its id and environment can't change after registration."
      footer={
        <>
          <Button variant="ghost" onClick={onClose} type="button">
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="register-agent" loading={busy}>
            Register agent
          </Button>
        </>
      }
    >
      <form id="register-agent" className="form-grid" onSubmit={submit}>
        <Field label="Agent id" htmlFor="agent_id" error={fields.agent_id} hint="Sent as agent_id on every gateway call. Lowercase letters, numbers, dots, dashes, underscores.">
          <Input id="agent_id" data-autofocus className="mono" value={form.agent_id} onChange={(e) => set("agent_id", e.target.value.toLowerCase())} placeholder="billing-agent-prod" autoComplete="off" spellCheck={false} required />
        </Field>
        <Field label="Display name" htmlFor="display_name" error={fields.display_name}>
          <Input id="display_name" value={form.display_name} onChange={(e) => set("display_name", e.target.value)} placeholder="Billing agent" required />
        </Field>
        <Field label="Description" htmlFor="description" optional error={fields.description}>
          <Textarea id="description" rows={2} value={form.description} onChange={(e) => set("description", e.target.value)} placeholder="What this agent does and which systems it touches." />
        </Field>
        <div className="form-row">
          <Field label="Environment" htmlFor="environment" error={fields.environment}>
            <Select id="environment" value={form.environment} onChange={(e) => { set("environment", e.target.value); if (e.target.value === "production" && form.default_mode === "allow") set("default_mode", "inherit"); }}>
              <option value="production">production</option>
              <option value="staging">staging</option>
              <option value="development">development</option>
            </Select>
          </Field>
          <Field label="When no policy matches" htmlFor="default_mode" error={fields.default_mode}>
            <Select id="default_mode" value={form.default_mode} onChange={(e) => set("default_mode", e.target.value)}>
              <option value="inherit">Organization default</option>
              <option value="block">Block</option>
              <option value="review">Require approval</option>
              <option value="allow" disabled={form.environment === "production"}>
                Allow{form.environment === "production" ? " (not for production)" : ""}
              </option>
            </Select>
          </Field>
        </div>
        {form.environment === "production" && <p className="field-hint">Production agents can never default to allow — an unmatched production action must be blocked or reviewed.</p>}
        {error && <Alert tone="bad">{error}</Alert>}
      </form>
    </Dialog>
  );
}

export function AgentsPage() {
  useDocumentTitle("Agents");
  const { can } = useSession();
  const { navigate } = useRouter();
  const now = useNow(30_000);
  const { data, error, loading, reload } = useApi<{ agents: AgentListItem[]; organization_policies: number }>("/api/console/agents");
  const [registering, setRegistering] = useState(false);
  const [filter, setFilter] = useState("");

  const agents = (data?.agents ?? []).filter((a) => !filter || `${a.agent_key} ${a.display_name}`.toLowerCase().includes(filter.toLowerCase()));

  return (
    <>
      <PageHeader
        title="Agents"
        description="Registered agent identities. The gateway blocks any agent id it doesn't recognise."
        actions={
          can("manage_agents") && (
            <Button variant="primary" onClick={() => setRegistering(true)}>
              <IconPlus /> Register agent
            </Button>
          )
        }
      />
      {error && !data ? (
        <ErrorState error={error} onRetry={() => void reload()} />
      ) : loading && !data ? (
        <div className="card card-body"><Skeleton lines={6} /></div>
      ) : data && data.agents.length === 0 ? (
        <div className="card">
          <Empty
            icon={<IconAgents width={22} height={22} />}
            title="No agents registered"
            action={can("manage_agents") && <Button variant="primary" onClick={() => setRegistering(true)}><IconPlus /> Register your first agent</Button>}
          >
            Register each autonomous agent with a stable id. Requests from unregistered ids fail closed with <code className="mono-inline">AGENT_UNKNOWN</code>.
          </Empty>
        </div>
      ) : (
        data && (
          <div className="card">
            <div className="table-toolbar">
              <Input className="toolbar-search" placeholder="Filter agents" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter agents" />
              <span className="muted small">
                {data.agents.length} agent{data.agents.length === 1 ? "" : "s"} · {data.organization_policies} organization-wide polic{data.organization_policies === 1 ? "y applies" : "ies apply"} to all
              </span>
            </div>
            <div className="table-wrap">
              <table className="table table-agents">
                <thead>
                  <tr>
                    <th>Agent</th>
                    <th>Environment</th>
                    <th>Status</th>
                    <th className="num">Bound policies</th>
                    <th>Last activity</th>
                    <th>Decisions · 7d</th>
                  </tr>
                </thead>
                <tbody>
                  {agents.map((a) => (
                    <tr key={a.id} className="row-link" onClick={() => navigate(`/app/agents/${a.id}`)}>
                      <td data-label="Agent">
                        <Link to={`/app/agents/${a.id}`} className="cell-primary" onClick={(e) => e.stopPropagation()}>
                          <span className="cell-title">{a.display_name}</span>
                          <span className="cell-sub mono">{a.agent_key}</span>
                        </Link>
                      </td>
                      <td data-label="Environment"><EnvTag env={a.environment} /></td>
                      <td data-label="Status">
                        <span className="status-inline">
                          <StatusDot tone={a.status === "active" ? "ok" : "muted"} />
                          {a.status === "active" ? "Active" : "Disabled"}
                        </span>
                      </td>
                      <td data-label="Bound policies" className="num mono">{a.bound_policies}</td>
                      <td data-label="Last activity" className="muted">{relativeTime(a.last_activity, now)}</td>
                      <td data-label="Decisions · 7d"><MiniBars allow={a.allow_7d} review={a.review_7d} block={a.block_7d} /></td>
                    </tr>
                  ))}
                  {agents.length === 0 && (
                    <tr>
                      <td colSpan={6} className="muted center">No agents match “{filter}”.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )
      )}
      <RegisterAgentDialog
        open={registering}
        onClose={() => setRegistering(false)}
        onCreated={(a) => {
          setRegistering(false);
          void reload();
          navigate(`/app/agents/${a.id}`);
        }}
      />
    </>
  );
}
