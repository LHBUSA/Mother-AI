import { useEffect, useState } from "react";
import { api, ApiFailure, errorMessage, type Role } from "../lib/api";
import { useApi, useDocumentTitle, useNow } from "../lib/hooks";
import { useQuery, useRouter } from "../lib/router";
import { dateTime, duration, relativeTime, ROLE_LABEL } from "../lib/format";
import { useSession } from "../lib/session";
import { describeNotificationError, EVENT_LABEL, STATUS_LABEL, STATUS_TONE, type NotificationSettings } from "../lib/notifications";
import { IconKey, IconPlus } from "../components/icons";
import { Alert, Button, Card, ConfirmDialog, CopyButton, Dialog, Empty, ErrorState, Field, Input, Mono, PageHeader, PermissionNotice, Select, Skeleton, Tabs, Tag, Toggle, cx, toast } from "../components/ui";

type TabId = "organization" | "notifications" | "keys" | "members" | "security";

// ---------------------------------------------------------------------------
// Organization
// ---------------------------------------------------------------------------

interface OrgSettings {
  id: string;
  slug: string;
  display_name: string;
  kind: string;
  status: string;
  plan: string;
  gateway_enabled: boolean;
  audit_enabled: boolean;
  require_registered_agents: boolean;
  default_decision: "block" | "review";
  approval_ttl_seconds: number;
  approval_grant_ttl_seconds: number;
  created_at: string;
}

const TTL_OPTIONS = [60, 300, 600, 900, 1800, 3600, 4 * 3600, 24 * 3600];
const GRANT_OPTIONS = [30, 60, 300, 600, 1800, 3600];

function OrganizationTab() {
  const { can, reloadSession } = useSession();
  const { data, error, loading, reload, setData } = useApi<{ organization: OrgSettings }>("/api/console/settings");
  const [form, setForm] = useState<OrgSettings | null>(null);
  const [busy, setBusy] = useState(false);
  const [fields, setFields] = useState<Record<string, string>>({});
  const [err, setErr] = useState<string | null>(null);
  const editable = can("manage_org");

  useEffect(() => {
    if (data) setForm(data.organization);
  }, [data]);

  if (error && !data) return <ErrorState error={error} onRetry={() => void reload()} />;
  if ((loading && !data) || !form || !data) return <div className="card card-body"><Skeleton lines={8} /></div>;
  const org = data.organization;
  const dirty = JSON.stringify(form) !== JSON.stringify(org);
  const set = <K extends keyof OrgSettings>(k: K, v: OrgSettings[K]) => setForm({ ...form, [k]: v });

  const save = async () => {
    setBusy(true);
    setErr(null);
    setFields({});
    try {
      const res = await api<{ organization: OrgSettings }>("/api/console/settings", {
        method: "PATCH",
        body: {
          display_name: form.display_name,
          gateway_enabled: form.gateway_enabled,
          audit_enabled: form.audit_enabled,
          require_registered_agents: form.require_registered_agents,
          default_decision: form.default_decision,
          approval_ttl_seconds: form.approval_ttl_seconds,
          approval_grant_ttl_seconds: form.approval_grant_ttl_seconds,
        },
      });
      setData(res);
      toast("Settings saved");
      void reloadSession();
    } catch (e) {
      if (e instanceof ApiFailure && Object.keys(e.fields).length) setFields(e.fields);
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const badgeRisk = (org.gateway_enabled && !form.gateway_enabled) || (org.audit_enabled && !form.audit_enabled);

  return (
    <div className="settings-grid">
      <Card title="Organization">
        <div className="form-grid">
          <Field label="Display name" htmlFor="o-name" error={fields.display_name} hint="Shown on your public badge verification page.">
            <Input id="o-name" value={form.display_name} disabled={!editable} onChange={(e) => set("display_name", e.target.value)} maxLength={120} />
          </Field>
          <div className="kv-grid">
            <div><span className="field-label">Slug</span><Mono>{org.slug}</Mono></div>
            <div><span className="field-label">Plan</span><span>{org.plan}</span></div>
            <div><span className="field-label">Status</span><span>{org.status}</span></div>
            <div><span className="field-label">Created</span><span>{dateTime(org.created_at)}</span></div>
          </div>
        </div>
      </Card>

      <Card title="Enforcement">
        <ul className="setting-list">
          <li className="setting">
            <div>
              <div className="setting-title">Policy enforcement gateway</div>
              <p className="muted small">When off, every <Mono>/v1/evaluate</Mono> call is rejected with <Mono>GATEWAY_DISABLED</Mono> and a block decision. Agents that follow the fail-closed contract stop acting.</p>
            </div>
            <Toggle checked={form.gateway_enabled} onChange={(v) => set("gateway_enabled", v)} label="Gateway enabled" disabled={!editable} />
          </li>
          <li className="setting">
            <div>
              <div className="setting-title">Audit context capture</div>
              <p className="muted small">When off, decisions are still recorded but the request context is not stored.</p>
            </div>
            <Toggle checked={form.audit_enabled} onChange={(v) => set("audit_enabled", v)} label="Audit logging enabled" disabled={!editable} />
          </li>
          <li className="setting">
            <div>
              <div className="setting-title">Require registered agents</div>
              <p className="muted small">Block requests from agent ids that aren't in the registry (<Mono>AGENT_UNKNOWN</Mono>). Strongly recommended.</p>
            </div>
            <Toggle checked={form.require_registered_agents} onChange={(v) => set("require_registered_agents", v)} label="Require registered agents" disabled={!editable} />
          </li>
          <li className="setting">
            <div>
              <div className="setting-title">Default decision</div>
              <p className="muted small">Applied when no enabled policy matches and the agent inherits the organization default.</p>
            </div>
            <Select value={form.default_decision} disabled={!editable} onChange={(e) => set("default_decision", e.target.value as "block" | "review")} aria-label="Default decision" className="setting-select">
              <option value="block">Block</option>
              <option value="review">Require approval</option>
            </Select>
          </li>
        </ul>
        {badgeRisk && (
          <Alert tone="warn" title="This suspends your badge">
            Disabling the gateway or audit logging fails a Mother AI Protected eligibility check. Your public badge will immediately show as suspended.
          </Alert>
        )}
        {!form.require_registered_agents && org.require_registered_agents && <Alert tone="warn">Unregistered agent ids will be evaluated against organization-wide policies instead of being blocked outright.</Alert>}
      </Card>

      <Card title="Human approval">
        <div className="form-row">
          <Field label="Approval request expires after" htmlFor="o-ttl" error={fields.approval_ttl_seconds} hint="Pending requests expire and can no longer be approved.">
            <Select id="o-ttl" value={form.approval_ttl_seconds} disabled={!editable} onChange={(e) => set("approval_ttl_seconds", Number(e.target.value))}>
              {[...new Set([...TTL_OPTIONS, org.approval_ttl_seconds])].sort((a, b) => a - b).map((s) => (
                <option key={s} value={s}>{duration(s)}</option>
              ))}
            </Select>
          </Field>
          <Field label="Approved grant valid for" htmlFor="o-grant" error={fields.approval_grant_ttl_seconds} hint="How long the agent has to execute (once) after approval.">
            <Select id="o-grant" value={form.approval_grant_ttl_seconds} disabled={!editable} onChange={(e) => set("approval_grant_ttl_seconds", Number(e.target.value))}>
              {[...new Set([...GRANT_OPTIONS, org.approval_grant_ttl_seconds])].sort((a, b) => a - b).map((s) => (
                <option key={s} value={s}>{duration(s)}</option>
              ))}
            </Select>
          </Field>
        </div>
      </Card>

      {err && <Alert tone="bad">{err}</Alert>}
      {editable ? (
        <div className="sticky-save">
          <span className="muted small">{dirty ? "You have unsaved changes." : "All changes saved."}</span>
          <div className="form-actions">
            <Button variant="ghost" disabled={!dirty || busy} onClick={() => setForm(org)}>Discard</Button>
            <Button variant="primary" disabled={!dirty} loading={busy} onClick={() => void save()}>Save settings</Button>
          </div>
        </div>
      ) : (
        <Alert tone="info">Your role can view organization settings but not change them.</Alert>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

interface KeyItem {
  id: string;
  name: string;
  key_prefix: string;
  environment: "live" | "test";
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  status: "active" | "revoked";
}

function CreateKeyDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const [environment, setEnvironment] = useState<"live" | "test">("live");
  const [name, setName] = useState("");
  const [secret, setSecret] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);

  const close = () => {
    // The secret only ever lives in this component's state and is dropped on close.
    setSecret(null);
    setName("");
    setErr(null);
    setAcknowledged(false);
    setEnvironment("live");
    onClose();
  };

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const res = await api<{ secret: string }>("/api/console/keys", { body: { name: name.trim() || (environment === "live" ? "Production gateway key" : "Test gateway key"), environment } });
      setSecret(res.secret);
      onCreated();
    } catch (e2) {
      setErr(errorMessage(e2));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={close}
      dismissable={!secret}
      title={secret ? "Copy your key now" : environment === "live" ? "Production Gateway Key" : "Test Gateway Key"}
      description={secret ? undefined : "Keys authenticate your integration to POST /v1/evaluate. Use one key per service so you can revoke precisely."}
      footer={
        secret ? (
          <Button variant="primary" onClick={close} disabled={!acknowledged}>
            Done
          </Button>
        ) : (
          <>
            <Button variant="ghost" onClick={close}>Cancel</Button>
            <Button variant="primary" type="submit" form="create-key" loading={busy}>Create key</Button>
          </>
        )
      }
    >
      {secret ? (
        <div className="secret-reveal">
          <Alert tone="warn" title="Store this securely. Mother AI cannot show this key again.">
            Only a one-way hash is stored. If you lose it, revoke it and create a new one.
          </Alert>
          <div className="secret-box">
            <code className="secret-value" data-autofocus tabIndex={0}>{secret}</code>
            <CopyButton text={secret} label="Copy key" size="md" />
          </div>
          <label className="check">
            <input type="checkbox" checked={acknowledged} onChange={(e) => setAcknowledged(e.target.checked)} /> I've stored this key in a secret manager
          </label>
        </div>
      ) : (
        <form id="create-key" className="form-grid" onSubmit={create}>
          <Field label="Environment" htmlFor="k-env" hint={environment === "live" ? "Live keys can evaluate production agents and count toward badge eligibility." : "Test keys cannot evaluate production agents."}>
            <div className="seg seg-wide" role="radiogroup" aria-label="Key environment">
              <button type="button" role="radio" aria-checked={environment === "live"} className={cx("seg-btn", environment === "live" && "is-on")} onClick={() => setEnvironment("live")}>live</button>
              <button type="button" role="radio" aria-checked={environment === "test"} className={cx("seg-btn", environment === "test" && "is-on")} onClick={() => setEnvironment("test")}>test</button>
            </div>
          </Field>
          <Field label="Name" htmlFor="k-name" optional hint="Where this key is used, e.g. “billing-worker (us-east)”.">
            <Input id="k-name" data-autofocus value={name} maxLength={80} onChange={(e) => setName(e.target.value)} placeholder={environment === "live" ? "Production gateway key" : "Test gateway key"} />
          </Field>
          {err && <Alert tone="bad">{err}</Alert>}
        </form>
      )}
    </Dialog>
  );
}

function KeysTab() {
  const { can, session } = useSession();
  const now = useNow(30_000);
  const allowed = can("manage_keys");
  const { data, error, loading, reload } = useApi<{ keys: KeyItem[] }>(allowed ? "/api/console/keys" : null);
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<KeyItem | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (!allowed) return <PermissionNotice what="Gateway API keys" requires="Admin" role={ROLE_LABEL[session.role]} />;
  if (error && !data) return <ErrorState error={error} onRetry={() => void reload()} requires="Admin" />;

  const revoke = async () => {
    if (!revoking) return;
    setBusy(true);
    setErr(null);
    try {
      await api(`/api/console/keys/${revoking.id}/revoke`, { body: {} });
      toast(`Revoked ${revoking.key_prefix}…`);
      setRevoking(null);
      void reload();
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const keys = data?.keys ?? [];
  return (
    <>
      <Card
        title="Gateway API keys"
        pad={false}
        actions={
          <Button variant="primary" size="sm" onClick={() => setCreating(true)}>
            <IconPlus /> Create key
          </Button>
        }
      >
        {loading && !data ? (
          <div className="card-body"><Skeleton lines={4} /></div>
        ) : keys.length === 0 ? (
          <div className="card-body">
            <Empty icon={<IconKey width={22} height={22} />} title="No API keys yet" action={<Button variant="primary" onClick={() => setCreating(true)}><IconPlus /> Create a production gateway key</Button>}>
              Your integration needs a key to call the gateway. The badge also requires an active live key.
            </Empty>
          </div>
        ) : (
          <div className="table-wrap">
            <table className="table table-keys">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Key</th>
                  <th>Environment</th>
                  <th>Created</th>
                  <th>Last used</th>
                  <th>Status</th>
                  <th><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {keys.map((k) => (
                  <tr key={k.id} className={cx(k.status === "revoked" && "is-muted")}>
                    <td data-label="Name" className="cell-title">{k.name}</td>
                    <td data-label="Key"><Mono>{k.key_prefix}…</Mono></td>
                    <td data-label="Environment"><Tag tone={k.environment === "live" ? "prod" : undefined}>{k.environment}</Tag></td>
                    <td data-label="Created" className="muted">{relativeTime(k.created_at, now)}</td>
                    <td data-label="Last used" className="muted">{k.last_used_at ? relativeTime(k.last_used_at, now) : "Never"}</td>
                    <td data-label="Status">{k.status === "active" ? <Tag tone="ok">active</Tag> : <Tag tone="bad">revoked {relativeTime(k.revoked_at, now)}</Tag>}</td>
                    <td className="actions-cell">
                      {k.status === "active" && (
                        <Button size="sm" variant="ghost" onClick={() => { setErr(null); setRevoking(k); }}>
                          Revoke
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <p className="muted small mt-12">Mother AI stores only a SHA-256 hash of each key. Last-used time updates at most once a minute. Keys are sent only in the <Mono>Authorization</Mono> header — never in URLs.</p>
      <CreateKeyDialog open={creating} onClose={() => setCreating(false)} onCreated={() => void reload()} />
      <ConfirmDialog open={!!revoking} onClose={() => setRevoking(null)} onConfirm={() => void revoke()} title="Revoke this key?" confirmLabel="Revoke key" busy={busy} error={err}>
        <p>
          <Mono>{revoking?.key_prefix}…</Mono> ({revoking?.name}) stops working immediately. Integrations using it receive <Mono>API_KEY_REVOKED</Mono>. This can't be undone.
        </p>
      </ConfirmDialog>
    </>
  );
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

interface Member {
  id: string;
  role: Role;
  status: "active" | "disabled";
  created_at: string;
  user_id: string;
  display_name: string;
  email: string | null;
  passkeys: number;
}
interface Invite {
  id: string;
  role: Role;
  display_name: string;
  email: string | null;
  created_at: string;
  expires_at: string;
}

const ROLE_RANK: Record<Role, number> = { viewer: 0, approver: 1, security: 2, admin: 3, owner: 4 };
const ROLE_HELP: Record<Role, string> = {
  owner: "Everything, including granting owner.",
  admin: "Keys, badge, settings and members.",
  security: "Agents and policies.",
  approver: "Approve or deny actions.",
  viewer: "Read-only access.",
};

function MembersTab() {
  const { session, can } = useSession();
  const { data, error, loading, reload } = useApi<{ members: Member[]; invites: Invite[]; me: string }>("/api/console/members");
  const manage = can("manage_members");
  const [inviting, setInviting] = useState(false);
  const [form, setForm] = useState({ display_name: "", email: "", role: "viewer" as Role });
  const [inviteUrl, setInviteUrl] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [fields, setFields] = useState<Record<string, string>>({});
  const [err, setErr] = useState<string | null>(null);
  const [revokeInvite, setRevokeInvite] = useState<Invite | null>(null);

  const grantable = (Object.keys(ROLE_RANK) as Role[]).filter((r) => ROLE_RANK[r] <= ROLE_RANK[session.role]).sort((a, b) => ROLE_RANK[b] - ROLE_RANK[a]);

  const closeInvite = () => {
    setInviting(false);
    setInviteUrl(null);
    setForm({ display_name: "", email: "", role: "viewer" });
    setFields({});
    setErr(null);
  };

  const createInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    setFields({});
    try {
      const res = await api<{ invite_url: string }>("/api/console/members/invites", { body: { display_name: form.display_name, email: form.email.trim() || undefined, role: form.role } });
      setInviteUrl(res.invite_url);
      void reload();
    } catch (e2) {
      if (e2 instanceof ApiFailure && Object.keys(e2.fields).length) setFields(e2.fields);
      else setErr(errorMessage(e2));
    } finally {
      setBusy(false);
    }
  };

  const updateMember = async (m: Member, patch: Partial<Pick<Member, "role" | "status">>) => {
    try {
      await api(`/api/console/members/${m.id}`, { method: "PATCH", body: patch });
      toast(`Updated ${m.display_name}`);
      void reload();
    } catch (e) {
      toast(errorMessage(e), "bad");
    }
  };

  const doRevokeInvite = async () => {
    if (!revokeInvite) return;
    setBusy(true);
    try {
      await api(`/api/console/members/invites/${revokeInvite.id}/revoke`, { body: {} });
      toast("Invite revoked");
      setRevokeInvite(null);
      void reload();
    } catch (e) {
      toast(errorMessage(e), "bad");
    } finally {
      setBusy(false);
    }
  };

  if (error && !data) return <ErrorState error={error} onRetry={() => void reload()} />;
  if (loading && !data) return <div className="card card-body"><Skeleton lines={5} /></div>;
  if (!data) return null;

  return (
    <>
      <Card title="Members" pad={false} actions={manage && <Button variant="primary" size="sm" onClick={() => setInviting(true)}><IconPlus /> Invite member</Button>}>
        <ul className="member-list">
          {data.members.map((m) => {
            const isMe = m.user_id === data.me;
            const canManageThis = manage && !isMe && ROLE_RANK[m.role] <= ROLE_RANK[session.role];
            return (
              <li key={m.id} className={cx("member", m.status === "disabled" && "is-muted")}>
                <span className="avatar" aria-hidden="true">{m.display_name.split(/\s+/).slice(0, 2).map((s) => s[0]?.toUpperCase()).join("")}</span>
                <div className="member-main">
                  <div className="member-name">
                    {m.display_name} {isMe && <Tag tone="muted">you</Tag>} {m.status === "disabled" && <Tag tone="bad">disabled</Tag>}
                  </div>
                  <div className="muted small">
                    {m.email ?? "no email"} · {m.passkeys} passkey{m.passkeys === 1 ? "" : "s"} · joined {dateTime(m.created_at)}
                  </div>
                </div>
                <div className="member-controls">
                  {canManageThis ? (
                    <>
                      <Select aria-label={`Role for ${m.display_name}`} value={m.role} onChange={(e) => void updateMember(m, { role: e.target.value as Role })}>
                        {grantable.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
                      </Select>
                      <Button size="sm" variant="ghost" onClick={() => void updateMember(m, { status: m.status === "active" ? "disabled" : "active" })}>
                        {m.status === "active" ? "Disable" : "Enable"}
                      </Button>
                    </>
                  ) : (
                    <Tag>{ROLE_LABEL[m.role]}</Tag>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      </Card>

      <Card title="Pending invites" pad={false}>
        {data.invites.length === 0 ? (
          <div className="card-body"><p className="muted small">No pending invites.</p></div>
        ) : (
          <ul className="member-list">
            {data.invites.map((i) => (
              <li key={i.id} className="member">
                <span className="avatar avatar-pending" aria-hidden="true">…</span>
                <div className="member-main">
                  <div className="member-name">{i.display_name} <Tag>{ROLE_LABEL[i.role]}</Tag></div>
                  <div className="muted small">{i.email ?? "no email"} · expires {dateTime(i.expires_at)}</div>
                </div>
                {manage && (
                  <div className="member-controls">
                    <Button size="sm" variant="ghost" onClick={() => setRevokeInvite(i)}>Revoke</Button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Dialog
        open={inviting}
        onClose={closeInvite}
        title={inviteUrl ? "Share this invite link" : "Invite a member"}
        description={inviteUrl ? undefined : "Members sign in with a passkey. Nobody at Mother AI sets or sees a password."}
        footer={
          inviteUrl ? (
            <Button variant="primary" onClick={closeInvite}>Done</Button>
          ) : (
            <>
              <Button variant="ghost" onClick={closeInvite}>Cancel</Button>
              <Button variant="primary" type="submit" form="invite-form" loading={busy}>Create invite</Button>
            </>
          )
        }
      >
        {inviteUrl ? (
          <div className="secret-reveal">
            <Alert tone="warn" title="This link is shown once">It's single-use and expires in 72 hours. Send it privately — anyone with the link can join as this member.</Alert>
            <div className="secret-box">
              <code className="secret-value">{inviteUrl}</code>
              <CopyButton text={inviteUrl} label="Copy link" size="md" />
            </div>
          </div>
        ) : (
          <form id="invite-form" className="form-grid" onSubmit={createInvite}>
            <Field label="Name" htmlFor="i-name" error={fields.display_name}>
              <Input id="i-name" data-autofocus value={form.display_name} maxLength={120} onChange={(e) => setForm({ ...form, display_name: e.target.value })} required />
            </Field>
            <Field label="Email" htmlFor="i-email" optional error={fields.email}>
              <Input id="i-email" type="email" value={form.email} maxLength={254} onChange={(e) => setForm({ ...form, email: e.target.value })} />
            </Field>
            <Field label="Role" htmlFor="i-role" error={fields.role} hint={ROLE_HELP[form.role]}>
              <Select id="i-role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
                {grantable.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
              </Select>
            </Field>
            {err && <Alert tone="bad">{err}</Alert>}
          </form>
        )}
      </Dialog>

      <ConfirmDialog open={!!revokeInvite} onClose={() => setRevokeInvite(null)} onConfirm={() => void doRevokeInvite()} title="Revoke invite?" confirmLabel="Revoke invite" busy={busy}>
        <p>The invite link for {revokeInvite?.display_name} stops working immediately.</p>
      </ConfirmDialog>
    </>
  );
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

function SecurityTab() {
  const now = useNow(30_000);
  const { data, error, loading, reload } = useApi<{
    passkeys: Array<{ id: string; name: string; device_type: string | null; backed_up: number; created_at: string; last_used_at: string | null }>;
    sessions: Array<{ id: string; created_at: string; last_seen_at: string; expires_at: string; current: boolean }>;
  }>("/api/console/security");
  const [busy, setBusy] = useState(false);

  if (error && !data) return <ErrorState error={error} onRetry={() => void reload()} />;
  if (loading && !data) return <div className="card card-body"><Skeleton lines={5} /></div>;
  if (!data) return null;
  const others = data.sessions.filter((s) => !s.current).length;

  return (
    <>
      <Card title="Your passkeys" pad={false}>
        <ul className="member-list">
          {data.passkeys.map((p) => (
            <li key={p.id} className="member">
              <span className="avatar avatar-key" aria-hidden="true"><IconKey /></span>
              <div className="member-main">
                <div className="member-name">{p.name} <Mono className="muted">{p.id}</Mono></div>
                <div className="muted small">
                  {p.device_type === "multiDevice" ? "Synced passkey" : "Device-bound passkey"}
                  {p.backed_up ? " · backed up" : ""} · added {dateTime(p.created_at)} · last used {relativeTime(p.last_used_at, now)}
                </div>
              </div>
            </li>
          ))}
        </ul>
      </Card>
      <Card
        title="Active sessions"
        pad={false}
        actions={
          others > 0 && (
            <Button size="sm" variant="ghost" loading={busy} onClick={async () => {
              setBusy(true);
              try {
                const r = await api<{ revoked: number }>("/api/console/security/sessions/revoke-others", { body: {} });
                toast(`Signed out ${r.revoked} other session${r.revoked === 1 ? "" : "s"}`);
                void reload();
              } catch (e) {
                toast(errorMessage(e), "bad");
              } finally {
                setBusy(false);
              }
            }}>
              Sign out other sessions
            </Button>
          )
        }
      >
        <ul className="member-list">
          {data.sessions.map((s) => (
            <li key={s.id} className="member">
              <span className={cx("sdot", s.current ? "sdot-ok" : "sdot-muted")} aria-hidden="true" />
              <div className="member-main">
                <div className="member-name">{s.current ? "This session" : "Other session"} {s.current && <Tag tone="ok">current</Tag>}</div>
                <div className="muted small">Signed in {dateTime(s.created_at)} · active {relativeTime(s.last_seen_at, now)} · expires {dateTime(s.expires_at)}</div>
              </div>
            </li>
          ))}
        </ul>
      </Card>
      <p className="muted small mt-12">Sessions end after 12 hours, or after 2 hours without activity.</p>
    </>
  );
}

// ---------------------------------------------------------------------------
// Approval notifications
// ---------------------------------------------------------------------------

function NotificationsTab() {
  const { can } = useSession();
  const now = useNow(30_000);
  const { data, error, loading, reload, setData } = useApi<NotificationSettings>("/api/console/notifications");
  const [url, setUrl] = useState("");
  const [fieldError, setFieldError] = useState<string | undefined>();
  const [busy, setBusy] = useState<"save" | "test" | "remove" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [removing, setRemoving] = useState(false);
  const editable = can("manage_org");

  if (error && !data) return <ErrorState error={error} onRetry={() => void reload()} />;
  if (loading && !data) return <div className="card card-body"><Skeleton lines={6} /></div>;
  if (!data) return null;
  const slack = data.slack;

  const save = async () => {
    setBusy("save");
    setErr(null);
    setFieldError(undefined);
    try {
      const res = await api<{ slack: NotificationSettings["slack"] }>("/api/console/notifications/slack", { body: { webhook_url: url.trim() } });
      setUrl("");
      setData({ ...data, slack: res.slack });
      toast(slack.configured ? "Slack webhook replaced" : "Slack approval notifications enabled");
    } catch (e) {
      if (e instanceof ApiFailure && e.fields.webhook_url) setFieldError(e.fields.webhook_url);
      else setErr(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };

  const test = async () => {
    setBusy("test");
    setErr(null);
    try {
      const res = await api<{ test: { status: "SENT_TO_PROVIDER" | "FAILED"; http_status: number | null; error: string | null } }>("/api/console/notifications/slack/test", { body: {} });
      if (res.test.status === "SENT_TO_PROVIDER") toast("Test message sent to Slack — check the channel");
      else toast(`Test failed: ${describeNotificationError(res.test.error) ?? "unknown error"}`, "bad");
    } catch (e) {
      toast(errorMessage(e), "bad");
    } finally {
      setBusy(null);
    }
  };

  const remove = async () => {
    setBusy("remove");
    setErr(null);
    try {
      const res = await api<{ slack: NotificationSettings["slack"] }>("/api/console/notifications/slack/remove", { body: {} });
      setData({ ...data, slack: res.slack });
      setRemoving(false);
      toast("Slack approval notifications removed");
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="settings-grid">
      <Card title="Approval notifications">
        <div className="notify-status">
          <span className={cx("sdot", slack.configured ? "sdot-ok" : "sdot-muted")} aria-hidden="true" />
          <div>
            <div className="setting-title">{slack.configured ? "Slack · Enabled" : "Not configured"}</div>
            <p className="muted small">
              {slack.configured
                ? `Connected ${relativeTime(slack.configured_at, now)}${slack.configured_by_name ? ` by ${slack.configured_by_name}` : ""}${slack.updated_at !== slack.configured_at ? ` · webhook replaced ${relativeTime(slack.updated_at, now)}` : ""}.`
                : "Approvers only find pending requests by opening the Approvals queue."}
            </p>
          </div>
        </div>
        <p className="muted small mt-12">
          When a policy returns <Mono>review</Mono>, Mother posts one message with the agent, action, resource, policy, reason code, approval and decision ids, and the expiry — never the request context. Once that message is sent, Mother also posts when the request is approved, denied, expires, or its one-time grant is consumed. Approved does not mean executed.
        </p>
        <p className="muted small">Delivery problems never change a decision or an approval. Slack rate limits, server errors and timeouts are retried, for at most 3 attempts in total; other rejections are not retried.</p>
        {!data.available && <Alert tone="warn">Approval notifications are not available on this deployment yet.</Alert>}
      </Card>

      <Card title={slack.configured ? "Slack destination" : "Connect Slack"}>
        {editable ? (
          <>
            <Field
              label={slack.configured ? "Replace the incoming webhook URL" : "Slack incoming webhook URL"}
              htmlFor="n-webhook"
              error={fieldError}
              hint="Create an incoming webhook for your approvals channel in Slack. Mother stores it encrypted and never shows it again — not even to admins."
            >
              <Input
                id="n-webhook"
                type="password"
                autoComplete="off"
                spellCheck={false}
                placeholder="https://hooks.slack.com/services/…"
                value={url}
                maxLength={200}
                disabled={!data.available}
                onChange={(e) => setUrl(e.target.value)}
              />
            </Field>
            {err && <Alert tone="bad">{err}</Alert>}
            <div className="form-actions">
              {slack.configured && (
                <>
                  <Button variant="ghost" disabled={!!busy} onClick={() => { setErr(null); setRemoving(true); }}>Remove</Button>
                  <Button variant="secondary" loading={busy === "test"} disabled={!!busy && busy !== "test"} onClick={() => void test()}>Send test message</Button>
                </>
              )}
              <Button variant="primary" loading={busy === "save"} disabled={!url.trim() || !data.available || (!!busy && busy !== "save")} onClick={() => void save()}>
                {slack.configured ? "Replace webhook" : "Enable Slack notifications"}
              </Button>
            </div>
          </>
        ) : (
          <PermissionNotice what="Connecting or changing approval notifications" requires="Admin" />
        )}
      </Card>

      <Card title="Recent notifications" pad={false}>
        {data.recent.length === 0 ? (
          <Empty title="No approval notifications yet">
            {slack.configured ? "The next review decision will appear here with its delivery status." : "Connect Slack to alert approvers when a request needs review."}
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="table table-notify">
              <thead>
                <tr>
                  <th>Event</th>
                  <th>Approval</th>
                  <th>Status</th>
                  <th>Attempts</th>
                  <th>Queued</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {data.recent.map((n) => (
                  <tr key={n.id}>
                    <td data-label="Event" className="cell-title">{EVENT_LABEL[n.event]}</td>
                    <td data-label="Approval"><Mono>{n.approval_id}</Mono></td>
                    <td data-label="Status"><Tag tone={STATUS_TONE[n.status]}>{STATUS_LABEL[n.status]}</Tag></td>
                    <td data-label="Attempts" className="muted">{n.attempts} / {n.max_attempts}</td>
                    <td data-label="Queued" className="muted" title={dateTime(n.queued_at)}>{relativeTime(n.queued_at, now)}</td>
                    <td data-label="Detail" className="muted small">{describeNotificationError(n.last_error) ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <ConfirmDialog open={removing} onClose={() => setRemoving(false)} onConfirm={() => void remove()} title="Remove Slack notifications?" confirmLabel="Remove" busy={busy === "remove"} error={err}>
        <p>The stored webhook is deleted. Approvers will no longer be alerted in Slack; pending requests stay in the Approvals queue and nothing about them changes.</p>
      </ConfirmDialog>
    </div>
  );
}

export function SettingsPage() {
  useDocumentTitle("Settings");
  const query = useQuery();
  const { navigate } = useRouter();
  const { can } = useSession();
  const raw = query.get("tab");
  const tab: TabId = raw === "notifications" || raw === "keys" || raw === "members" || raw === "security" ? raw : "organization";
  return (
    <>
      <PageHeader title="Settings" description="Organization controls, approval notifications, gateway credentials, members and your own sign-in security." />
      <Tabs
        label="Settings sections"
        value={tab}
        onChange={(t) => navigate(`/app/settings${t === "organization" ? "" : `?tab=${t}`}`, { replace: true })}
        tabs={[
          { id: "organization", label: "Organization" },
          { id: "notifications", label: "Notifications" },
          ...(can("manage_keys") ? [{ id: "keys" as TabId, label: "API keys" }] : []),
          { id: "members", label: "Members" },
          { id: "security", label: "Security" },
        ]}
      />
      <div className="tab-panel">
        {tab === "organization" && <OrganizationTab />}
        {tab === "notifications" && <NotificationsTab />}
        {tab === "keys" && <KeysTab />}
        {tab === "members" && <MembersTab />}
        {tab === "security" && <SecurityTab />}
      </div>
    </>
  );
}
