import { useEffect, useState } from "react";
import type { Decision, DecisionSummary } from "../lib/api";
import { relativeTime, dateTime } from "../lib/format";
import { Link } from "../lib/router";
import { IconCheck, IconCopy } from "./icons";
import { DecisionPill, copyText, cx } from "./ui";

export type DecisionRowData = DecisionSummary & { policy_name?: string | null; approval_status?: string | null };

export const APPROVAL_LABEL: Record<string, string> = {
  pending: "Awaiting approval",
  approved: "Approved",
  denied: "Denied",
  expired: "Expired",
};

export function ApprovalChip({ status }: { status: string }) {
  return <span className={cx("dl-approval", `ap-${status}`)}>{APPROVAL_LABEL[status] ?? status}</span>;
}

/** Last characters of an id, with the full id on hover and a copy action. Never nested inside another control. */
export function IdCopy({ id, label = "decision ID" }: { id: string; label?: string }) {
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (!done) return;
    const t = window.setTimeout(() => setDone(false), 1600);
    return () => window.clearTimeout(t);
  }, [done]);
  return (
    <button type="button" className={cx("id-copy", done && "is-done")} title={id} aria-label={done ? `Copied ${label}` : `Copy ${label} ${id}`} onClick={async () => setDone(await copyText(id))}>
      <span className="id-copy-text mono">…{id.slice(-6)}</span>
      {done ? <IconCheck width={12} height={12} /> : <IconCopy width={12} height={12} />}
    </button>
  );
}

export function DecisionLine({ d, now, onOpen, active }: { d: DecisionRowData; now: number; onOpen?: () => void; active?: boolean }) {
  const mcpTarget = d.protocol === "mcp" && (d.mcp_server || d.mcp_tool) ? `${d.mcp_server ?? "?"}/${d.mcp_tool ?? "?"}` : null;
  const content = (
    <>
      <span className={cx("tl-rail", `tl-${d.decision}`)} aria-hidden="true" />
      <span className="dl-pill">
        <DecisionPill decision={d.decision} size="sm" />
      </span>
      <span className="dl-main">
        <span className="dl-action">
          <span className="mono dl-act-text" title={`${d.capability} · ${d.operation}`}>
            {d.capability}
            <span className="dl-sep" aria-hidden="true"> · </span>
            {d.operation}
          </span>
          {d.protocol === "mcp" && (
            <span className="tag tag-mcp" title={mcpTarget ? `MCP ${mcpTarget}` : "MCP"}>
              MCP
            </span>
          )}
        </span>
        <span className="dl-sub">
          <span className="mono dl-agent">{d.agent_key}</span>
          {(d.resource || mcpTarget) && (
            <>
              <span className="dl-sep" aria-hidden="true">→</span>
              <span className="mono dl-resource" title={d.resource ?? mcpTarget ?? undefined}>
                {d.resource ?? mcpTarget}
              </span>
            </>
          )}
        </span>
      </span>
      <span className="dl-reason">
        <span className="mono dl-code" title={d.reason}>
          {d.reason_code}
        </span>
        <span className="dl-why">
          {d.approval_status && <ApprovalChip status={d.approval_status} />}
          <span className="dl-policy" title={d.policy_name ?? d.reason}>
            {d.policy_name ?? d.reason}
          </span>
        </span>
      </span>
      <time className="dl-time" dateTime={d.created_at} title={dateTime(d.created_at)}>
        {relativeTime(d.created_at, now)}
      </time>
    </>
  );
  return (
    <div className={cx("decision-row", active && "is-active")}>
      {onOpen ? (
        <button type="button" className={cx("decision-line", active && "is-active")} onClick={onOpen} aria-expanded={active}>
          {content}
        </button>
      ) : (
        <Link to={`/app/audit?q=${encodeURIComponent(d.id)}&open=${encodeURIComponent(d.id)}`} className="decision-line">
          {content}
        </Link>
      )}
      <IdCopy id={d.id} />
    </div>
  );
}

export function MiniBars({ allow, review, block }: Record<Decision, number>) {
  const total = allow + review + block;
  if (total === 0) return <span className="minibars-empty">No decisions</span>;
  return (
    <span className="minibars" role="img" aria-label={`${allow} allowed, ${review} review, ${block} blocked`}>
      <span className="minibars-track">
        {allow > 0 && <span className="mb-allow" style={{ flexGrow: allow }} />}
        {review > 0 && <span className="mb-review" style={{ flexGrow: review }} />}
        {block > 0 && <span className="mb-block" style={{ flexGrow: block }} />}
      </span>
      <span className="minibars-legend mono" aria-hidden="true">
        <span className="t-allow">{allow}</span>
        <span className="t-review">{review}</span>
        <span className="t-block">{block}</span>
      </span>
    </span>
  );
}
