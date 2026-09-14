import { useEffect, useRef, useState, type ReactNode } from "react";
import { api, errorMessage } from "../lib/api";
import { Link, useRouter } from "../lib/router";
import { useSession } from "../lib/session";
import { ROLE_LABEL } from "../lib/format";
import {
  BrandMark,
  IconAgents,
  IconApprovals,
  IconAudit,
  IconBadge,
  IconClose,
  IconIntegrations,
  IconMenu,
  IconOverview,
  IconPolicies,
  IconSettings,
  IconSignOut,
} from "./icons";
import { Alert, cx, toast, useFocusTrap } from "./ui";

const NAV = [
  { to: "/app/", label: "Overview", icon: IconOverview, match: (p: string) => p === "/app/" || p === "/app" },
  { to: "/app/agents", label: "Agents", icon: IconAgents, match: (p: string) => p.startsWith("/app/agents") },
  { to: "/app/policies", label: "Policies", icon: IconPolicies, match: (p: string) => p.startsWith("/app/policies") },
  { to: "/app/approvals", label: "Approvals", icon: IconApprovals, match: (p: string) => p.startsWith("/app/approvals") },
  { to: "/app/audit", label: "Audit", icon: IconAudit, match: (p: string) => p.startsWith("/app/audit") },
  { to: "/app/integrations", label: "Integrations", icon: IconIntegrations, match: (p: string) => p.startsWith("/app/integrations") },
  { to: "/app/badge", label: "Badge", icon: IconBadge, match: (p: string) => p.startsWith("/app/badge") },
  { to: "/app/settings", label: "Settings", icon: IconSettings, match: (p: string) => p.startsWith("/app/settings") },
];

function initials(name: string): string {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((s) => s[0]!.toUpperCase())
    .join("");
}

function NavList({ onNavigate }: { onNavigate?: () => void }) {
  const { location } = useRouter();
  const { pendingApprovals } = useSession();
  return (
    <nav className="nav" aria-label="Primary">
      <ul>
        {NAV.map((item) => {
          const active = item.match(location.pathname);
          const Icon = item.icon;
          return (
            <li key={item.to}>
              <Link to={item.to} className={cx("nav-link", active && "is-active")} aria-current={active ? "page" : undefined} onClick={onNavigate}>
                <Icon />
                <span>{item.label}</span>
                {item.label === "Approvals" && pendingApprovals > 0 && (
                  <span className="nav-count" aria-label={`${pendingApprovals} pending`}>
                    {pendingApprovals}
                  </span>
                )}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

function OrgBlock() {
  const { session } = useSession();
  const [busy, setBusy] = useState(false);
  const switchOrg = async (id: string) => {
    if (id === session.organization.id) return;
    setBusy(true);
    try {
      await api("/api/auth/switch-organization", { body: { organization_id: id } });
      window.location.assign("/app/");
    } catch (err) {
      toast(errorMessage(err), "bad");
      setBusy(false);
    }
  };
  return (
    <div className="org-block">
      <div className="org-label">Organization</div>
      {session.memberships.length > 1 ? (
        <select className="org-select" value={session.organization.id} onChange={(e) => void switchOrg(e.target.value)} disabled={busy} aria-label="Switch organization">
          {session.memberships.map((m) => (
            <option key={m.id} value={m.id}>
              {m.display_name}
            </option>
          ))}
        </select>
      ) : (
        <div className="org-name" title={session.organization.display_name}>
          {session.organization.display_name}
        </div>
      )}
      <div className="org-meta">
        <span className={cx("sdot", session.organization.status === "active" ? "sdot-ok" : "sdot-warn")} />
        {session.organization.status === "active" ? "Active" : session.organization.status}
        <span className="org-sep">·</span>
        {session.organization.plan}
      </div>
    </div>
  );
}

function UserBlock() {
  const { session } = useSession();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);
  const signOut = async () => {
    try {
      await api("/api/auth/logout", { body: {} });
    } catch {
      /* the cookie is cleared server-side when reachable; redirect regardless */
    }
    window.location.assign("/app/login");
  };
  return (
    <div className="user-block" ref={ref}>
      <button type="button" className="user-btn" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <span className="avatar" aria-hidden="true">
          {initials(session.user.display_name)}
        </span>
        <span className="user-text">
          <span className="user-name">{session.user.display_name}</span>
          <span className="user-role">{ROLE_LABEL[session.role]}</span>
        </span>
      </button>
      {open && (
        <div className="menu" role="menu">
          <Link to="/app/settings?tab=security" className="menu-item" role="menuitem" onClick={() => setOpen(false)}>
            Security &amp; passkeys
          </Link>
          <button type="button" className="menu-item" role="menuitem" onClick={() => void signOut()}>
            <IconSignOut /> Sign out
          </button>
        </div>
      )}
    </div>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const { session } = useSession();
  const [mobileOpen, setMobileOpen] = useState(false);
  const { location } = useRouter();
  const drawerRef = useFocusTrap(mobileOpen, () => setMobileOpen(false));

  useEffect(() => setMobileOpen(false), [location.pathname]);

  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <aside className="sidebar" aria-label="Sidebar">
        <Link to="/app/" className="brand">
          <BrandMark size={24} />
          <span className="brand-name">Mother AI</span>
          <span className="brand-tag">Console</span>
        </Link>
        <OrgBlock />
        <NavList />
        <div className="sidebar-foot">
          <UserBlock />
        </div>
      </aside>

      <header className="topbar">
        <button type="button" className="icon-btn" aria-label="Open navigation" aria-expanded={mobileOpen} aria-controls="mobile-nav" onClick={() => setMobileOpen(true)}>
          <IconMenu />
        </button>
        <Link to="/app/" className="brand brand-compact">
          <BrandMark size={22} />
          <span className="brand-name">Mother AI</span>
        </Link>
        <span className="topbar-org" title={session.organization.display_name}>
          {session.organization.display_name}
        </span>
      </header>

      {mobileOpen && (
        <div className="drawer-backdrop" onMouseDown={(e) => e.target === e.currentTarget && setMobileOpen(false)}>
          <div id="mobile-nav" ref={drawerRef} className="drawer" role="dialog" aria-modal="true" aria-label="Navigation">
            <div className="drawer-head">
              <Link to="/app/" className="brand">
                <BrandMark size={22} />
                <span className="brand-name">Mother AI</span>
              </Link>
              <button type="button" className="icon-btn" aria-label="Close navigation" onClick={() => setMobileOpen(false)}>
                <IconClose />
              </button>
            </div>
            <OrgBlock />
            <NavList onNavigate={() => setMobileOpen(false)} />
            <div className="sidebar-foot">
              <UserBlock />
            </div>
          </div>
        </div>
      )}

      <main id="main" className="main" tabIndex={-1}>
        {session.organization.status !== "active" && (
          <div className="banner">
            <Alert tone="warn" title={`Organization ${session.organization.status}`}>
              Mother AI has {session.organization.status} this organization. Gateway evaluations are rejected and changes are disabled. Contact Mother AI to restore access.
            </Alert>
          </div>
        )}
        <div className="page">{children}</div>
      </main>
    </div>
  );
}
