import { StrictMode, useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./console.css";
import { api, ApiFailure, setUnauthenticatedHandler, type Permission, type SessionInfo } from "./lib/api";
import { match, RouterProvider, useRouter } from "./lib/router";
import { SessionProvider } from "./lib/session";
import { useVisibleInterval } from "./lib/hooks";
import { Shell } from "./components/Shell";
import { BrandMark } from "./components/icons";
import { Button, ErrorState, Toaster } from "./components/ui";
import { LoginPage } from "./pages/Login";
import { AcceptInvitePage } from "./pages/AcceptInvite";
import { OverviewPage } from "./pages/Overview";
import { AgentsPage } from "./pages/Agents";
import { AgentDetailPage } from "./pages/AgentDetail";
import { PoliciesPage } from "./pages/Policies";
import { PolicyEditorPage } from "./pages/PolicyEditor";
import { ApprovalsPage } from "./pages/Approvals";
import { IncidentPage, SecurityPage } from "./pages/Security";
import { AuditPage } from "./pages/Audit";
import { IntegrationsPage } from "./pages/Integrations";
import { BadgePage } from "./pages/Badge";
import { SettingsPage } from "./pages/Settings";
import { NotFoundPage } from "./pages/NotFound";

function Splash() {
  return (
    <div className="splash" aria-busy="true">
      <BrandMark size={34} />
      <span className="splash-bar" />
    </div>
  );
}

function AuthedApp() {
  const { location, navigate } = useRouter();
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [pending, setPending] = useState(0);

  const loadSession = useCallback(async () => {
    try {
      const s = await api<SessionInfo>("/api/auth/session", { allow401: true });
      setSession(s);
      setError(null);
    } catch (err) {
      if (err instanceof ApiFailure && err.status === 401) {
        navigate("/app/login", { replace: true });
        return;
      }
      setError(err);
    }
  }, [navigate]);

  useEffect(() => {
    setUnauthenticatedHandler(() => navigate("/app/login", { replace: true }));
    void loadSession();
  }, [loadSession, navigate]);

  const refreshPending = useCallback(async () => {
    if (!session) return;
    try {
      const r = await api<{ counts: Record<string, number> }>("/api/console/approvals?status=pending");
      setPending(r.counts.pending ?? 0);
    } catch {
      /* non-critical */
    }
  }, [session]);
  useEffect(() => {
    void refreshPending();
  }, [refreshPending]);
  useVisibleInterval(() => void refreshPending(), 30_000);

  const value = useMemo(
    () =>
      session
        ? {
            session,
            can: (p: Permission) => session.permissions.includes(p),
            reloadSession: loadSession,
            pendingApprovals: pending,
            setPendingApprovals: setPending,
          }
        : null,
    [session, loadSession, pending],
  );

  if (error) {
    return (
      <div className="auth-screen">
        <div className="auth-card">
          <ErrorState error={error} onRetry={() => void loadSession()} />
        </div>
      </div>
    );
  }
  if (!value) return <Splash />;

  const path = location.pathname;
  let page: React.ReactNode;
  let params: Record<string, string> | null;
  if (path === "/app/" || path === "/app") page = <OverviewPage />;
  else if (match("/app/agents", path)) page = <AgentsPage />;
  else if ((params = match("/app/agents/:id", path))) page = <AgentDetailPage id={params.id!} />;
  else if (match("/app/policies", path)) page = <PoliciesPage />;
  else if (match("/app/policies/new", path)) page = <PolicyEditorPage id={null} />;
  else if ((params = match("/app/policies/:id", path))) page = <PolicyEditorPage key={params.id} id={params.id!} />;
  else if (match("/app/approvals", path)) page = <ApprovalsPage />;
  else if (match("/app/security", path)) page = <SecurityPage />;
  else if ((params = match("/app/security/incidents/:id", path))) page = <IncidentPage key={params.id} id={params.id!} />;
  else if (match("/app/audit", path)) page = <AuditPage />;
  else if (match("/app/integrations", path)) page = <IntegrationsPage />;
  else if (match("/app/badge", path)) page = <BadgePage />;
  else if (match("/app/settings", path)) page = <SettingsPage />;
  else page = <NotFoundPage />;

  return (
    <SessionProvider value={value}>
      <Shell>{page}</Shell>
    </SessionProvider>
  );
}

function App() {
  const { location } = useRouter();
  if (match("/app/login", location.pathname)) return <LoginPage />;
  if (match("/app/accept-invite", location.pathname)) return <AcceptInvitePage />;
  return <AuthedApp />;
}

function Root() {
  return (
    <RouterProvider>
      <App />
      <Toaster />
    </RouterProvider>
  );
}

// Keep Button referenced for tree-shaking stability in error boundary fallbacks.
void Button;

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
