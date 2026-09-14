import { useState } from "react";
import { api, errorMessage, type BadgeStatus } from "../lib/api";
import { useApi, useDocumentTitle } from "../lib/hooks";
import { dateTime, relativeTime } from "../lib/format";
import { useSession } from "../lib/session";
import { Link } from "../lib/router";
import { IconBadge, IconCheck, IconClose, IconExternal } from "../components/icons";
import { Alert, Button, Card, CodeBlock, ConfirmDialog, CopyButton, Empty, ErrorState, Mono, PageHeader, Skeleton, Tabs, cx, toast } from "../components/ui";

interface BadgeResponse {
  status: BadgeStatus;
  eligible: boolean;
  criteria: Array<{ key: string; label: string; met: boolean }>;
  last_gateway_activity: string | null;
  badge: null | {
    id: string;
    state: "enabled" | "suspended" | "revoked";
    token: string;
    created_at: string;
    activated_at: string | null;
    suspended_at: string | null;
    verify_url: string;
    svg_url: string;
    svg_light_url: string;
    snippets: { markdown: string; markdown_light: string; html: string; html_light: string };
  };
  revoked_badges: Array<{ id: string; created_at: string; revoked_at: string; revoked_reason: string | null }>;
  disclaimer: string;
}

const CRITERIA_LINK: Record<string, string> = {
  organization_active: "/app/settings",
  gateway_enabled: "/app/settings",
  audit_enabled: "/app/settings",
  active_agent: "/app/agents",
  enabled_policy: "/app/policies",
  live_api_key: "/app/settings?tab=keys",
};

const STATUS: Record<BadgeStatus, { label: string; text: string; cls: string }> = {
  active: { label: "Active", text: "Anyone viewing your badge sees Mother AI Protected — AI Controls Active, backed by a live verification page.", cls: "bs-active" },
  setup: { label: "Not active", text: "Your badge renders as not active until every eligibility check passes.", cls: "bs-setup" },
  suspended: { label: "Suspended", text: "Your badge is publicly shown as suspended. It returns to active automatically when you resume and every check passes.", cls: "bs-suspended" },
  revoked: { label: "Revoked", text: "This badge was revoked and can no longer show as active.", cls: "bs-revoked" },
};

export function BadgePage() {
  useDocumentTitle("Badge");
  const { can } = useSession();
  const { data, error, loading, reload, setData } = useApi<BadgeResponse>("/api/console/badge");
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [snippetTab, setSnippetTab] = useState<"html" | "markdown">("html");
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [cacheBust, setCacheBust] = useState(() => Date.now());
  const manage = can("manage_badge");

  const run = async (verb: "enable" | "suspend" | "resume" | "rotate", success: string) => {
    setBusy(verb);
    setActionError(null);
    try {
      const res = await api<BadgeResponse>(`/api/console/badge/${verb}`, { body: {} });
      setData(res);
      setCacheBust(Date.now());
      toast(success);
      return true;
    } catch (err) {
      setActionError(errorMessage(err));
      return false;
    } finally {
      setBusy(null);
    }
  };

  if (error && !data) return <ErrorState error={error} onRetry={() => void reload()} />;
  if (loading && !data) return <Skeleton lines={10} />;
  if (!data) return null;
  const s = STATUS[data.status];
  const b = data.badge;
  const metCount = data.criteria.filter((c) => c.met).length;

  return (
    <>
      <PageHeader
        title="Mother AI Protected"
        description="A live, verifiable badge that shows your customers AI access controls are actively deployed. It is rendered from your real configuration on every view."
      />
      {actionError && <Alert tone="bad">{actionError}</Alert>}

      <div className="grid-badge">
        <div className="stack">
          <Card className={cx("badge-status", s.cls)}>
            <div className="badge-status-row">
              <div>
                <div className="page-eyebrow">Current status</div>
                <div className="badge-status-label">{b ? s.label : "Not created"}</div>
                <p className="muted small">{b ? s.text : "Create your badge to get an embeddable image and a public verification page. It stays not-active until every check passes."}</p>
              </div>
              <div className="badge-status-actions">
                {manage && !b && (
                  <Button variant="primary" loading={busy === "enable"} onClick={() => void run("enable", "Badge created")}>
                    Create badge
                  </Button>
                )}
                {manage && b && b.state === "enabled" && (
                  <Button variant="ghost" loading={busy === "suspend"} onClick={() => void run("suspend", "Badge suspended")}>
                    Suspend
                  </Button>
                )}
                {manage && b && b.state === "suspended" && (
                  <Button variant="secondary" loading={busy === "resume"} onClick={() => void run("resume", "Badge resumed")}>
                    Resume
                  </Button>
                )}
                {manage && b && (
                  <Button variant="ghost" onClick={() => setConfirmRotate(true)}>
                    Rotate token
                  </Button>
                )}
              </div>
            </div>
            <div className="badge-meta">
              <span>Last gateway activity: <strong>{data.last_gateway_activity ? relativeTime(data.last_gateway_activity) : "none recorded"}</strong></span>
              {b?.activated_at && <span>First activated: <strong>{dateTime(b.activated_at)}</strong></span>}
            </div>
            <p className="muted small">Gateway activity is shown separately and is not an eligibility requirement, so low-traffic organizations keep a valid badge.</p>
          </Card>

          <Card title="Eligibility" actions={<span className="mono small muted">{metCount}/{data.criteria.length} checks</span>}>
            <ul className="criteria">
              {data.criteria.map((c) => (
                <li key={c.key} className={cx("criterion", c.met ? "is-met" : "is-unmet")}>
                  <span className="criterion-icon" aria-hidden="true">{c.met ? <IconCheck /> : <IconClose />}</span>
                  <span className="criterion-label">{c.label}</span>
                  {c.met ? <span className="sr-only">met</span> : <Link to={CRITERIA_LINK[c.key] ?? "/app/settings"} className="link-sm">Fix</Link>}
                </li>
              ))}
            </ul>
          </Card>

          {b && (
            <Card title="Embed">
              <div className="embed-toolbar">
                <Tabs label="Snippet format" value={snippetTab} onChange={setSnippetTab} tabs={[{ id: "html", label: "HTML" }, { id: "markdown", label: "Markdown" }]} />
                <div className="seg" role="radiogroup" aria-label="Badge theme">
                  <button type="button" role="radio" aria-checked={theme === "dark"} className={cx("seg-btn", theme === "dark" && "is-on")} onClick={() => setTheme("dark")}>Dark</button>
                  <button type="button" role="radio" aria-checked={theme === "light"} className={cx("seg-btn", theme === "light" && "is-on")} onClick={() => setTheme("light")}>Light</button>
                </div>
              </div>
              <CodeBlock
                language={snippetTab}
                code={snippetTab === "html" ? (theme === "dark" ? b.snippets.html : b.snippets.html_light) : theme === "dark" ? b.snippets.markdown : b.snippets.markdown_light}
              />
              <p className="muted small mt-12">Always embed the live image URL. A saved copy of the image can't prove anything — the verification link is what your customers should trust.</p>
            </Card>
          )}
        </div>

        <div className="stack">
          <Card title="Preview">
            {b ? (
              <>
                <div className="badge-swatch swatch-dark">
                  <img src={`${b.svg_url}?v=${cacheBust}`} alt="Mother AI badge preview on dark background" width={236} height={48} />
                </div>
                <div className="badge-swatch swatch-light">
                  <img src={`${b.svg_light_url}&v=${cacheBust}`} alt="Mother AI badge preview on light background" width={236} height={48} />
                </div>
                <div className="verify-url">
                  <div className="field-label">Public verification URL</div>
                  <div className="verify-url-row">
                    <Mono className="truncate">{b.verify_url}</Mono>
                    <CopyButton text={b.verify_url} />
                    <a className="btn btn-ghost btn-sm" href={b.verify_url} target="_blank" rel="noreferrer">
                      Open <IconExternal />
                    </a>
                  </div>
                </div>
              </>
            ) : (
              <Empty icon={<IconBadge width={22} height={22} />} title="No badge yet">
                {manage ? "Create a badge to preview it here." : "An admin can create your organization's badge."}
              </Empty>
            )}
          </Card>
          <Card title="What the badge means">
            <p className="small">{data.disclaimer}</p>
            <a className="link-sm mt-12" href="https://github.com/LHBUSA/Mother-AI/blob/main/docs/BADGE.md" target="_blank" rel="noreferrer">
              Exact badge criteria <IconExternal />
            </a>
          </Card>
          {data.revoked_badges.length > 0 && (
            <Card title="Revoked tokens">
              <ul className="versions">
                {data.revoked_badges.map((r) => (
                  <li key={r.id}>
                    <span className="mono small">{r.id}</span>
                    <span className="muted small">revoked {dateTime(r.revoked_at)}{r.revoked_reason ? ` · ${r.revoked_reason}` : ""}</span>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      </div>

      <ConfirmDialog
        open={confirmRotate}
        onClose={() => setConfirmRotate(false)}
        onConfirm={async () => {
          if (await run("rotate", "New badge token issued")) setConfirmRotate(false);
        }}
        title="Rotate the badge token?"
        confirmLabel="Rotate token"
        busy={busy === "rotate"}
        error={actionError}
      >
        <p>The current token is permanently revoked. Every existing embed and verification link will show <strong>Badge revoked</strong>. You'll need to update the snippet everywhere it's embedded.</p>
      </ConfirmDialog>
    </>
  );
}
