import { useEffect, useRef, useState } from "react";
import { startRegistration, type PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/browser";
import { api, ApiFailure } from "../lib/api";
import { useDocumentTitle } from "../lib/hooks";
import { ROLE_LABEL, dateTime } from "../lib/format";
import { IconPasskey } from "../components/icons";
import { Alert, Button, Field, Input, Skeleton } from "../components/ui";
import { AuthAside, AuthLayout } from "./Login";

interface InviteInfo {
  organization: string;
  role: string;
  display_name: string;
  expires_at: string;
}

const INVITE_ERRORS: Record<string, { title: string; text: string }> = {
  INVITE_INVALID: { title: "This invite link isn't valid", text: "The link may be incomplete or revoked. Ask your administrator for a new invite." },
  INVITE_USED: { title: "This invite was already used", text: "Invites are single-use. If you already accepted it, sign in with your passkey." },
  INVITE_EXPIRED: { title: "This invite has expired", text: "Invites expire after 72 hours. Ask your administrator to send a new one." },
};

export function AcceptInvitePage() {
  useDocumentTitle("Accept invite");
  // The token is read once from the fragment and kept only in memory.
  const tokenRef = useRef<string | null>(null);
  if (tokenRef.current === null) {
    const params = new URLSearchParams(window.location.hash.replace(/^#/, ""));
    tokenRef.current = params.get("token") ?? "";
  }
  const [invite, setInvite] = useState<InviteInfo | null>(null);
  const [inviteError, setInviteError] = useState<{ title: string; text: string } | null>(null);
  const [deviceName, setDeviceName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (window.location.hash) window.history.replaceState(null, "", window.location.pathname);
    const token = tokenRef.current;
    if (!token) {
      setInviteError(INVITE_ERRORS.INVITE_INVALID!);
      return;
    }
    api<InviteInfo>("/api/auth/invite/inspect", { body: { token } })
      .then(setInvite)
      .catch((err) => {
        if (err instanceof ApiFailure && INVITE_ERRORS[err.code]) setInviteError(INVITE_ERRORS[err.code]!);
        else if (err instanceof ApiFailure && err.status === 429) setInviteError({ title: "Too many attempts", text: "Wait a minute, then reload this page from your original invite link." });
        else setInviteError({ title: "Couldn't check this invite", text: err instanceof Error ? err.message : "Try again." });
      });
  }, []);

  const register = async () => {
    const token = tokenRef.current!;
    setBusy(true);
    setError(null);
    try {
      const options = await api<PublicKeyCredentialCreationOptionsJSON>("/api/auth/register/options", { body: { token } });
      const response = await startRegistration({ optionsJSON: options });
      await api("/api/auth/register/verify", { body: { token, response, device_name: deviceName.trim() || undefined } });
      tokenRef.current = "";
      window.location.assign("/app/");
    } catch (err) {
      if (err instanceof ApiFailure && INVITE_ERRORS[err.code]) setInviteError(INVITE_ERRORS[err.code]!);
      else if (err instanceof Error && (err.name === "NotAllowedError" || err.name === "AbortError")) setError("Passkey creation was cancelled. Your invite is still valid — try again.");
      else if (err instanceof Error && err.name === "InvalidStateError") setError("This authenticator already has a passkey for Mother AI. Sign in instead, or use a different authenticator.");
      else setError(err instanceof Error ? err.message : "Passkey registration failed.");
      setBusy(false);
    }
  };

  return (
    <AuthLayout aside={<AuthAside />}>
      {inviteError ? (
        <>
          <h1 className="auth-title">{inviteError.title}</h1>
          <p className="auth-text">{inviteError.text}</p>
          <a className="btn btn-secondary auth-cta" href="/app/login">
            Go to sign in
          </a>
        </>
      ) : !invite ? (
        <>
          <h1 className="auth-title">Checking your invite…</h1>
          <Skeleton lines={3} />
        </>
      ) : (
        <>
          <p className="eyebrow-mono">Invitation</p>
          <h1 className="auth-title">Join {invite.organization}</h1>
          <p className="auth-text">
            You've been invited as <strong>{ROLE_LABEL[invite.role] ?? invite.role}</strong>, {invite.display_name}. Create a passkey to finish — no password is ever created.
          </p>
          <div className="invite-meta">
            <span>Organization</span>
            <strong>{invite.organization}</strong>
            <span>Role</span>
            <strong>{ROLE_LABEL[invite.role] ?? invite.role}</strong>
            <span>Expires</span>
            <strong>{dateTime(invite.expires_at)}</strong>
          </div>
          <Field label="Device name" htmlFor="device" optional hint="Helps you recognise this passkey later, e.g. “Work MacBook”.">
            <Input id="device" value={deviceName} maxLength={60} onChange={(e) => setDeviceName(e.target.value)} placeholder="Work laptop" />
          </Field>
          <Button variant="primary" className="auth-cta" onClick={() => void register()} loading={busy}>
            {!busy && <IconPasskey />}
            Create passkey &amp; join
          </Button>
          {error && <Alert tone="bad">{error}</Alert>}
          <p className="auth-small">This link is single-use. After you join, sign in with this passkey from the console sign-in page.</p>
        </>
      )}
    </AuthLayout>
  );
}
