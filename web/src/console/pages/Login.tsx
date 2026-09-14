import { useEffect, useState } from "react";
import { startAuthentication, type PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser";
import { api, ApiFailure } from "../lib/api";
import { useDocumentTitle } from "../lib/hooks";
import { BrandMark, IconPasskey } from "../components/icons";
import { Alert, Button } from "../components/ui";

export function AuthLayout({ children, aside }: { children: React.ReactNode; aside?: React.ReactNode }) {
  return (
    <div className="auth-screen">
      <div className="auth-grid">
        <div className="auth-card">
          <a href="/" className="brand auth-brand">
            <BrandMark size={26} />
            <span className="brand-name">Mother AI</span>
          </a>
          {children}
        </div>
        {aside && <aside className="auth-aside">{aside}</aside>}
      </div>
      <footer className="auth-foot">
        <a href="/">mother ai</a>
        <span>·</span>
        <a href="https://github.com/LHBUSA/Mother-AI/blob/main/docs/SECURITY_MODEL.md" target="_blank" rel="noreferrer">
          Security model
        </a>
      </footer>
    </div>
  );
}

export function AuthAside() {
  return (
    <div className="auth-aside-inner">
      <p className="eyebrow-mono">Control plane</p>
      <h2 className="auth-aside-title">Every protected action, evaluated before it runs.</h2>
      <ul className="auth-points">
        <li>
          <span className="pill pill-allow pill-sm">ALLOW</span>
          <span>Deterministic policy enforcement for every registered agent.</span>
        </li>
        <li>
          <span className="pill pill-review pill-sm">REVIEW</span>
          <span>High-risk actions wait for a human approver.</span>
        </li>
        <li>
          <span className="pill pill-block pill-sm">BLOCK</span>
          <span>Unknown agents and malformed policy state fail closed.</span>
        </li>
      </ul>
      <p className="auth-aside-note">Mother AI stores no passwords. Console access uses passkeys bound to this site.</p>
    </div>
  );
}

function describeWebAuthnError(err: unknown): string {
  if (err instanceof ApiFailure) {
    if (err.code === "PASSKEY_UNKNOWN") return "This passkey isn't registered with Mother AI. Use the passkey you created when accepting your invite.";
    if (err.status === 429) return "Too many sign-in attempts. Wait a minute and try again.";
    if (err.code === "NO_ACTIVE_MEMBERSHIP") return "This account has no active organization. Ask an administrator to restore your access.";
    return err.message;
  }
  if (err instanceof Error) {
    if (err.name === "NotAllowedError" || err.name === "AbortError") return "Sign-in was cancelled or timed out. You can try again whenever you're ready.";
    if (err.name === "SecurityError") return "Passkeys aren't available on this origin.";
    return err.message || "Your browser couldn't complete passkey sign-in.";
  }
  return "Sign-in failed.";
}

export function LoginPage() {
  useDocumentTitle("Sign in");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cancelled, setCancelled] = useState(false);
  const [supported, setSupported] = useState(true);

  useEffect(() => {
    setSupported(typeof window.PublicKeyCredential === "function");
  }, []);

  const signIn = async () => {
    setBusy(true);
    setError(null);
    setCancelled(false);
    try {
      const options = await api<PublicKeyCredentialRequestOptionsJSON>("/api/auth/login/options", { body: {} });
      const response = await startAuthentication({ optionsJSON: options });
      await api("/api/auth/login/verify", { body: { response } });
      window.location.assign("/app/");
    } catch (err) {
      if (err instanceof Error && (err.name === "NotAllowedError" || err.name === "AbortError")) setCancelled(true);
      else setError(describeWebAuthnError(err));
      setBusy(false);
    }
  };

  return (
    <AuthLayout aside={<AuthAside />}>
      <h1 className="auth-title">Sign in to the console</h1>
      <p className="auth-text">Use the passkey you registered for your Mother AI organization — Touch ID, Windows Hello, a phone, or a security key.</p>
      {!supported && (
        <Alert tone="warn" title="Passkeys unavailable">
          This browser doesn't support passkeys. Use a current version of Chrome, Edge, Safari or Firefox.
        </Alert>
      )}
      <Button variant="primary" className="auth-cta" onClick={() => void signIn()} loading={busy} disabled={!supported}>
        {!busy && <IconPasskey />}
        Sign in with passkey
      </Button>
      {cancelled && <p className="auth-muted" role="status">Sign-in was cancelled. Nothing was changed — try again when ready.</p>}
      {error && <Alert tone="bad">{error}</Alert>}
      <div className="auth-divider" />
      <p className="auth-small">
        Access is invite-only during Founding Access. New organization? <a href="/#founding-access">Request Founding Access</a>. Joining an existing team? Ask an administrator for an invite link.
      </p>
    </AuthLayout>
  );
}
