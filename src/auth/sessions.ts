// Console sessions: opaque 256-bit tokens in a __Host- cookie (HttpOnly, Secure,
// SameSite=Strict). Only sha256(token) is stored.

import type { Env } from "../env";
import { generateToken, newId, sha256Hex } from "../lib/crypto";
import { ApiError } from "../lib/http";
import { iso } from "../lib/time";
import type { OrganizationRow } from "../lib/db";
import type { Role } from "./rbac";
import { allowedBrowserOrigins } from "../lib/site";

export const SESSION_COOKIE = "__Host-mai_session";
export const CHALLENGE_COOKIE = "__Host-mai_chal";
export const SESSION_ABSOLUTE_MS = 12 * 60 * 60 * 1000;
export const SESSION_IDLE_MS = 2 * 60 * 60 * 1000;
const TOUCH_INTERVAL_MS = 5 * 60 * 1000;

export interface ConsoleSession {
  sessionId: string;
  user: { id: string; display_name: string; email: string | null };
  role: Role;
  organization: OrganizationRow;
}

export function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("Cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return rest.join("=") || null;
  }
  return null;
}

export function cookieHeader(name: string, value: string, maxAgeSeconds: number): string {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAgeSeconds}`;
}

export function clearCookieHeader(name: string): string {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

export async function createSession(db: D1Database, userId: string, organizationId: string, nowMs: number): Promise<{ statement: D1PreparedStatement; cookie: string }> {
  const token = generateToken(32);
  const now = iso(nowMs);
  const statement = db
    .prepare(
      `INSERT INTO sessions (id, token_hash, user_id, organization_id, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(newId("ses"), await sha256Hex(token), userId, organizationId, now, now, iso(nowMs + SESSION_ABSOLUTE_MS));
  return { statement, cookie: cookieHeader(SESSION_COOKIE, token, SESSION_ABSOLUTE_MS / 1000) };
}

interface SessionJoinRow extends OrganizationRow {
  session_id: string;
  session_last_seen_at: string;
  session_expires_at: string;
  user_id: string;
  user_display_name: string;
  user_email: string | null;
  role: Role;
}

export async function loadSession(request: Request, env: Env, nowMs: number): Promise<ConsoleSession | null> {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token || token.length < 32 || token.length > 128) return null;
  const hash = await sha256Hex(token);
  const row = await env.DB.prepare(
    `SELECT o.*, s.id AS session_id, s.last_seen_at AS session_last_seen_at, s.expires_at AS session_expires_at,
            u.id AS user_id, u.display_name AS user_display_name, u.email AS user_email, m.role
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       JOIN memberships m ON m.user_id = s.user_id AND m.organization_id = s.organization_id AND m.status = 'active'
       JOIN organizations o ON o.id = s.organization_id
      WHERE s.token_hash = ? AND s.revoked_at IS NULL`,
  )
    .bind(hash)
    .first<SessionJoinRow>();
  if (!row) return null;
  if (Date.parse(row.session_expires_at) <= nowMs) return null;
  if (Date.parse(row.session_last_seen_at) + SESSION_IDLE_MS <= nowMs) return null;
  if (row.status === "revoked") return null;

  if (nowMs - Date.parse(row.session_last_seen_at) > TOUCH_INTERVAL_MS) {
    await env.DB.prepare(`UPDATE sessions SET last_seen_at = ? WHERE id = ?`).bind(iso(nowMs), row.session_id).run();
  }

  const { session_id, session_last_seen_at: _l, session_expires_at: _e, user_id, user_display_name, user_email, role, ...org } = row;
  return {
    sessionId: session_id,
    user: { id: user_id, display_name: user_display_name, email: user_email },
    role,
    organization: org as OrganizationRow,
  };
}

/**
 * CSRF defense for cookie-authenticated mutations. The UI (mother.proptechusa.ai) and
 * this API (api.mother.proptechusa.ai) are different origins on the same site, so:
 *   - SameSite=Strict host-only session cookie (sent on same-site requests only),
 *   - Origin must EXACTLY equal the UI origin (browser-set, not scriptable),
 *   - Sec-Fetch-Site, when present, must be same-site (UI -> API) or same-origin.
 * Cross-site writes, other proptechusa.ai subdomains and missing Origin are rejected.
 */
export function assertBrowserOrigin(request: Request, environment: string): void {
  const origin = request.headers.get("Origin");
  if (!origin || !allowedBrowserOrigins(environment).includes(origin)) {
    throw new ApiError(403, "CSRF_REJECTED", "Cross-origin request rejected.");
  }
  const site = request.headers.get("Sec-Fetch-Site");
  if (site && site !== "same-site" && site !== "same-origin") {
    throw new ApiError(403, "CSRF_REJECTED", "Cross-site request rejected.");
  }
}
