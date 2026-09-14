// Human approval lifecycle.
//
//   review decision ──> approval(pending, expires_at)
//        pending ──approve──> approved(grant_expires_at) ──consume (once)──> executed
//        pending ──deny─────> denied
//        pending ──time─────> expired
//
// The original decision row is never modified. Every transition is an UPDATE on
// the approval row that the schema trigger validates, plus an appended control event.

import { ApiError } from "../lib/http";
import { addSeconds, iso, isPast } from "../lib/time";
import type { ApprovalRow } from "../lib/db";
import { controlEventStatement, SYSTEM_ACTOR, type Actor } from "./audit";

export type ApprovalStatus = ApprovalRow["status"];

export interface ApprovalView {
  approval_id: string;
  status: ApprovalStatus;
  requested_at: string;
  expires_at: string;
  grant_expires_at: string | null;
  consumed_at: string | null;
  /** True only when the downstream action may execute right now. */
  executable: boolean;
}

/** Effective status at `nowMs` (a pending approval past its expiry is expired even before the sweep persists it). */
export function effectiveStatus(
  a: { status: ApprovalStatus; expires_at: string },
  nowMs: number,
): ApprovalStatus {
  return a.status === "pending" && isPast(a.expires_at, nowMs) ? "expired" : a.status;
}

export function approvalView(
  a: Pick<ApprovalRow, "id" | "status" | "requested_at" | "expires_at" | "grant_expires_at" | "consumed_at">,
  nowMs: number,
): ApprovalView {
  const status = effectiveStatus(a, nowMs);
  return {
    approval_id: a.id,
    status,
    requested_at: a.requested_at,
    expires_at: a.expires_at,
    grant_expires_at: a.grant_expires_at,
    consumed_at: a.consumed_at,
    executable: status === "approved" && !a.consumed_at && !!a.grant_expires_at && !isPast(a.grant_expires_at, nowMs),
  };
}

export async function getApproval(db: D1Database, organizationId: string, approvalId: string): Promise<ApprovalRow | null> {
  return db
    .prepare(`SELECT * FROM approvals WHERE id = ? AND organization_id = ?`)
    .bind(approvalId, organizationId)
    .first<ApprovalRow>();
}

/** Persists expiry for pending approvals past expires_at. Scoped to one org, or all orgs when null (cron). */
export async function sweepExpiredApprovals(db: D1Database, organizationId: string | null, nowMs: number, limit = 200): Promise<number> {
  const now = iso(nowMs);
  const rows = organizationId
    ? await db
        .prepare(`SELECT id, organization_id, decision_id, expires_at FROM approvals WHERE organization_id = ? AND status = 'pending' AND expires_at <= ? LIMIT ?`)
        .bind(organizationId, now, limit)
        .all<{ id: string; organization_id: string; decision_id: string; expires_at: string }>()
    : await db
        .prepare(`SELECT id, organization_id, decision_id, expires_at FROM approvals WHERE status = 'pending' AND expires_at <= ? LIMIT ?`)
        .bind(now, limit)
        .all<{ id: string; organization_id: string; decision_id: string; expires_at: string }>();
  if (!rows.results.length) return 0;
  const statements: D1PreparedStatement[] = [];
  for (const row of rows.results) {
    statements.push(
      db
        .prepare(`UPDATE approvals SET status = 'expired', acted_at = ? WHERE id = ? AND organization_id = ? AND status = 'pending' AND expires_at <= ?`)
        .bind(row.expires_at, row.id, row.organization_id, now),
      controlEventStatement(db, row.organization_id, SYSTEM_ACTOR, "approval.expired", { type: "approval", id: row.id }, { decision_id: row.decision_id }, now, {
        onlyIfChanged: true,
      }),
    );
  }
  await db.batch(statements);
  return rows.results.length;
}

export interface ApprovalActionInput {
  action: "approve" | "deny";
  note: string | null;
  actor: Actor & { type: "user"; id: string; label: string };
  grantTtlSeconds: number;
}

export async function actOnApproval(
  db: D1Database,
  organizationId: string,
  approvalId: string,
  input: ApprovalActionInput,
  nowMs: number,
): Promise<ApprovalRow> {
  const current = await getApproval(db, organizationId, approvalId);
  if (!current) throw new ApiError(404, "APPROVAL_NOT_FOUND", "Approval not found.");
  const status = effectiveStatus(current, nowMs);
  if (status === "expired") {
    await sweepExpiredApprovals(db, organizationId, nowMs);
    throw new ApiError(409, "APPROVAL_EXPIRED", "This approval request expired before it was acted on.", { status: "expired" });
  }
  if (status !== "pending") {
    throw new ApiError(409, "APPROVAL_NOT_PENDING", `This approval request is already ${status}.`, { status });
  }

  const now = iso(nowMs);
  const newStatus = input.action === "approve" ? "approved" : "denied";
  const grantExpiresAt = input.action === "approve" ? addSeconds(now, input.grantTtlSeconds) : null;
  const results = await db.batch([
    db
      .prepare(
        `UPDATE approvals SET status = ?, acted_at = ?, acted_by = ?, acted_by_name = ?, note = ?, grant_expires_at = ?
          WHERE id = ? AND organization_id = ? AND status = 'pending' AND expires_at > ?`,
      )
      .bind(newStatus, now, input.actor.id, input.actor.label, input.note, grantExpiresAt, approvalId, organizationId, now),
    controlEventStatement(
      db,
      organizationId,
      input.actor,
      input.action === "approve" ? "approval.approved" : "approval.denied",
      { type: "approval", id: approvalId },
      { decision_id: current.decision_id, note: input.note, grant_expires_at: grantExpiresAt },
      now,
      { onlyIfChanged: true },
    ),
  ]);
  if ((results[0]!.meta.changes ?? 0) !== 1) {
    throw new ApiError(409, "APPROVAL_NOT_PENDING", "This approval request changed state; reload and try again.");
  }
  return (await getApproval(db, organizationId, approvalId))!;
}

/**
 * One-time consumption of an approved grant by the agent integration, immediately
 * before it executes the downstream action. Prevents replaying an approval.
 */
export async function consumeApproval(
  db: D1Database,
  organizationId: string,
  approvalId: string,
  actor: Actor,
  nowMs: number,
): Promise<ApprovalRow> {
  const current = await getApproval(db, organizationId, approvalId);
  if (!current) throw new ApiError(404, "APPROVAL_NOT_FOUND", "Approval not found.");
  const status = effectiveStatus(current, nowMs);
  if (status === "pending") throw new ApiError(409, "APPROVAL_PENDING", "This action is still awaiting human approval.", { status });
  if (status === "denied") throw new ApiError(409, "APPROVAL_DENIED", "A human denied this action.", { status });
  if (status === "expired") throw new ApiError(409, "APPROVAL_EXPIRED", "The approval request expired before a decision was made.", { status });
  if (current.consumed_at) throw new ApiError(409, "APPROVAL_ALREADY_CONSUMED", "This approval was already used.", { status, consumed_at: current.consumed_at });
  if (!current.grant_expires_at || isPast(current.grant_expires_at, nowMs)) {
    throw new ApiError(409, "APPROVAL_GRANT_EXPIRED", "The approval grant expired before the action was executed.", { status });
  }

  const now = iso(nowMs);
  const results = await db.batch([
    db
      .prepare(
        `UPDATE approvals SET consumed_at = ?
          WHERE id = ? AND organization_id = ? AND status = 'approved' AND consumed_at IS NULL AND grant_expires_at > ?`,
      )
      .bind(now, approvalId, organizationId, now),
    controlEventStatement(db, organizationId, actor, "approval.consumed", { type: "approval", id: approvalId }, { decision_id: current.decision_id }, now, {
      onlyIfChanged: true,
    }),
  ]);
  if ((results[0]!.meta.changes ?? 0) !== 1) {
    throw new ApiError(409, "APPROVAL_ALREADY_CONSUMED", "This approval was already used or its grant expired.");
  }
  return (await getApproval(db, organizationId, approvalId))!;
}
