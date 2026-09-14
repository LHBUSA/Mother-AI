import type { Decision, DecisionSummary } from "../lib/api";
import { relativeTime, dateTime } from "../lib/format";
import { Link } from "../lib/router";
import { DecisionPill, cx } from "./ui";

export function DecisionLine({ d, now, onOpen, active }: { d: DecisionSummary & { policy_name?: string | null; approval_status?: string | null }; now: number; onOpen?: () => void; active?: boolean }) {
  const content = (
    <>
      <span className={cx("tl-rail", `tl-${d.decision}`)} aria-hidden="true" />
      <span className="dl-pill">
        <DecisionPill decision={d.decision} size="sm" />
      </span>
      <span className="dl-main">
        <span className="dl-action">
          <span className="mono">{d.capability}</span>
          <span className="dl-sep">·</span>
          <span className="mono">{d.operation}</span>
          {d.protocol === "mcp" && <span className="tag tag-mcp">MCP</span>}
        </span>
        <span className="dl-sub">
          <span className="mono dl-agent">{d.agent_key}</span>
          {d.resource && (
            <>
              <span className="dl-sep">→</span>
              <span className="mono dl-resource">{d.resource}</span>
            </>
          )}
        </span>
      </span>
      <span className="dl-reason mono" title={d.reason}>
        {d.reason_code}
        {d.approval_status && <span className={cx("dl-approval", `ap-${d.approval_status}`)}>{d.approval_status}</span>}
      </span>
      <time className="dl-time" dateTime={d.created_at} title={dateTime(d.created_at)}>
        {relativeTime(d.created_at, now)}
      </time>
    </>
  );
  if (onOpen) {
    return (
      <button type="button" className={cx("decision-line", active && "is-active")} onClick={onOpen} aria-expanded={active}>
        {content}
      </button>
    );
  }
  return (
    <Link to={`/app/audit?q=${encodeURIComponent(d.id)}&open=${encodeURIComponent(d.id)}`} className="decision-line">
      {content}
    </Link>
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
      <span className="minibars-legend mono">
        <span className="t-allow">{allow}</span>
        <span className="t-review">{review}</span>
        <span className="t-block">{block}</span>
      </span>
    </span>
  );
}
