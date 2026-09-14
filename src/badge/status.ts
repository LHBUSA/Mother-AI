// Mother AI Protected — eligibility and status. See docs/BADGE.md; this file is
// the executable definition and the doc must match it.

import type { BadgeRow, OrganizationRow } from "../lib/db";
import { iso } from "../lib/time";

export type BadgeStatus = "setup" | "active" | "suspended" | "revoked";

export interface BadgeCriterion {
  key: "organization_active" | "gateway_enabled" | "audit_enabled" | "active_agent" | "enabled_policy" | "live_api_key";
  label: string;
  met: boolean;
}

export interface BadgeFacts {
  active_agents: number;
  enabled_policies: number;
  live_keys: number;
  last_activity: string | null;
}

export function badgeFactsStatement(db: D1Database, organizationId: string): D1PreparedStatement {
  return db
    .prepare(
      `SELECT
         (SELECT COUNT(*) FROM agents WHERE organization_id = ?1 AND status = 'active') AS active_agents,
         (SELECT COUNT(*) FROM policies WHERE organization_id = ?1 AND enabled = 1 AND archived_at IS NULL) AS enabled_policies,
         (SELECT COUNT(*) FROM api_keys WHERE organization_id = ?1 AND environment = 'live' AND revoked_at IS NULL) AS live_keys,
         (SELECT MAX(created_at) FROM decisions WHERE organization_id = ?1) AS last_activity`,
    )
    .bind(organizationId);
}

export function badgeCriteria(org: Pick<OrganizationRow, "status" | "gateway_enabled" | "audit_enabled">, facts: BadgeFacts): BadgeCriterion[] {
  return [
    { key: "organization_active", label: "Organization active", met: org.status === "active" },
    { key: "gateway_enabled", label: "Policy enforcement gateway enabled", met: org.gateway_enabled === 1 },
    { key: "audit_enabled", label: "Audit logging enabled", met: org.audit_enabled === 1 },
    { key: "active_agent", label: "At least one active registered agent", met: facts.active_agents > 0 },
    { key: "enabled_policy", label: "At least one enabled policy", met: facts.enabled_policies > 0 },
    { key: "live_api_key", label: "Active production (live) API key", met: facts.live_keys > 0 },
  ];
}

export function computeBadgeStatus(
  badge: Pick<BadgeRow, "state" | "activated_at"> | null,
  org: Pick<OrganizationRow, "status">,
  criteria: BadgeCriterion[],
): BadgeStatus {
  if (!badge) return "setup";
  if (badge.state === "revoked" || org.status === "revoked") return "revoked";
  if (badge.state === "suspended" || org.status === "suspended") return "suspended";
  if (criteria.every((c) => c.met)) return "active";
  // A badge that was active and then lost a control is visibly suspended, not quietly "setup".
  return badge.activated_at ? "suspended" : "setup";
}

/** Records the first moment a badge became active (idempotent). */
export function markActivatedStatement(db: D1Database, badgeId: string, nowMs: number): D1PreparedStatement {
  return db.prepare(`UPDATE badges SET activated_at = ? WHERE id = ? AND activated_at IS NULL`).bind(iso(nowMs), badgeId);
}

export const BADGE_TOKEN = /^[0-9A-Za-z]{32}$/;

export const BADGE_DISCLAIMER =
  "Mother AI Protected indicates that this organization has configured and enabled Mother AI agent access controls. It is not a certification of the organization's entire cybersecurity program or a guarantee against security incidents.";

export function badgeUrls(origin: string, token: string) {
  return {
    verify_url: `${origin}/verify/${token}`,
    svg_url: `${origin}/badge/${token}.svg`,
    svg_light_url: `${origin}/badge/${token}.svg?theme=light`,
  };
}

export function badgeSnippets(origin: string, token: string) {
  const u = badgeUrls(origin, token);
  const alt = "Mother AI Protected — AI Controls Active";
  return {
    markdown: `[![${alt}](${u.svg_url})](${u.verify_url})`,
    markdown_light: `[![${alt}](${u.svg_light_url})](${u.verify_url})`,
    html: `<a href="${u.verify_url}">\n  <img src="${u.svg_url}" alt="${alt}" width="236" height="48">\n</a>`,
    html_light: `<a href="${u.verify_url}">\n  <img src="${u.svg_light_url}" alt="${alt}" width="236" height="48">\n</a>`,
  };
}
