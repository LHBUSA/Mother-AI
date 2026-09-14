import { useState } from "react";
import { useDocumentTitle } from "../lib/hooks";
import { Link } from "../lib/router";
import { useSession } from "../lib/session";
import { IconExternal } from "../components/icons";
import { Alert, Card, CodeBlock, PageHeader, Tabs } from "../components/ui";

type Lang = "rest" | "ts" | "python" | "mcp";

function snippets(origin: string): Record<Lang, { language: string; code: string }> {
  return {
    rest: {
      language: "bash",
      code: `# 1. Ask Mother before the agent acts
curl -sS -X POST ${origin}/v1/evaluate \\
  -H "Authorization: Bearer $MOTHER_AI_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "request_id": "refund-8812-attempt-1",
    "agent_id": "billing-agent-prod",
    "capability": "payments",
    "operation": "refund",
    "resource": "payment:pi_123",
    "destination": "internal",
    "data_class": "financial",
    "context": { "amount": 4200, "currency": "USD" }
  }'

# -> { "decision": "allow" | "review" | "block", "reason_code": "...", "decision_id": "dec_...", ... }
# Only "allow" means execute. Any error response also carries "decision": "block".

# 2. If the decision was "review", check the approval
curl -sS ${origin}/v1/approvals/apr_... \\
  -H "Authorization: Bearer $MOTHER_AI_API_KEY"

# 3. Immediately before executing an approved action, consume the grant (single use)
curl -sS -X POST ${origin}/v1/approvals/apr_.../consume \\
  -H "Authorization: Bearer $MOTHER_AI_API_KEY"`,
    },
    ts: {
      language: "typescript",
      code: `// mother.ts — no SDK required. Fail closed: only "allow" executes.
const MOTHER = "${origin}";
const KEY = process.env.MOTHER_AI_API_KEY!; // server-side only, never in a browser bundle

type Action = {
  request_id: string; // stable per action, so retries are idempotent
  agent_id: string;
  capability: string;
  operation: string;
  resource?: string;
  destination?: string;
  data_class?: string;
  context?: Record<string, unknown>;
};

async function mother(path: string, init: RequestInit = {}) {
  const res = await fetch(MOTHER + path, {
    ...init,
    headers: { Authorization: \`Bearer \${KEY}\`, "Content-Type": "application/json", ...init.headers },
  });
  const body = await res.json().catch(() => ({ decision: "block" }));
  return { ok: res.ok, status: res.status, body };
}

/** Runs \`execute\` only if Mother allows it (waiting for human approval if required). */
export async function guarded<T>(action: Action, execute: () => Promise<T>, opts = { waitMs: 10 * 60_000 }): Promise<T> {
  const { ok, body } = await mother("/v1/evaluate", { method: "POST", body: JSON.stringify(action) });
  if (!ok) throw new Error(\`Mother AI refused: \${body?.error?.code ?? "GATEWAY_ERROR"}\`);

  if (body.decision === "allow") return execute();

  if (body.decision === "review") {
    const deadline = Date.now() + opts.waitMs;
    while (Date.now() < deadline) {
      const { body: approval } = await mother(\`/v1/approvals/\${body.approval_id}\`);
      if (approval.status === "approved" && approval.executable) {
        const consumed = await mother(\`/v1/approvals/\${body.approval_id}/consume\`, { method: "POST" });
        if (!consumed.ok) throw new Error(\`Approval not usable: \${consumed.body?.error?.code}\`);
        return execute();
      }
      if (approval.status === "denied" || approval.status === "expired") break;
      await new Promise((r) => setTimeout(r, 5_000));
    }
    throw new Error(\`Action not approved (\${body.reason_code})\`);
  }

  throw new Error(\`Blocked by Mother AI: \${body.reason_code}\`);
}

// Usage
await guarded(
  { request_id: "refund-8812-attempt-1", agent_id: "billing-agent-prod", capability: "payments", operation: "refund",
    resource: "payment:pi_123", data_class: "financial", context: { amount: 4200, currency: "USD" } },
  () => stripe.refunds.create({ payment_intent: "pi_123", amount: 420000 }),
);`,
    },
    python: {
      language: "python",
      code: `# mother.py — requires \`httpx\`. Fail closed: only "allow" executes.
import os, time, httpx

MOTHER = "${origin}"
HEADERS = {"Authorization": f"Bearer {os.environ['MOTHER_AI_API_KEY']}"}

class NotPermitted(Exception):
    pass

def guarded(action: dict, execute, wait_seconds: int = 600):
    r = httpx.post(f"{MOTHER}/v1/evaluate", json=action, headers=HEADERS, timeout=10)
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"decision": "block"}
    if r.status_code != 200:
        raise NotPermitted(body.get("error", {}).get("code", "GATEWAY_ERROR"))

    if body["decision"] == "allow":
        return execute()

    if body["decision"] == "review":
        approval_id = body["approval_id"]
        deadline = time.time() + wait_seconds
        while time.time() < deadline:
            a = httpx.get(f"{MOTHER}/v1/approvals/{approval_id}", headers=HEADERS, timeout=10).json()
            if a.get("status") == "approved" and a.get("executable"):
                c = httpx.post(f"{MOTHER}/v1/approvals/{approval_id}/consume", headers=HEADERS, timeout=10)
                if c.status_code != 200:
                    raise NotPermitted(c.json().get("error", {}).get("code"))
                return execute()
            if a.get("status") in ("denied", "expired"):
                break
            time.sleep(5)
        raise NotPermitted(f"not approved: {body['reason_code']}")

    raise NotPermitted(body["reason_code"])

guarded(
    {"request_id": "refund-8812-attempt-1", "agent_id": "billing-agent-prod",
     "capability": "payments", "operation": "refund", "resource": "payment:pi_123",
     "data_class": "financial", "context": {"amount": 4200, "currency": "USD"}},
    lambda: issue_refund("pi_123", 4200),
)`,
    },
    mcp: {
      language: "typescript",
      code: `// MCP pattern: evaluate every tool call with Mother before your MCP client invokes it.
// Mother is the policy decision point here — it does not proxy MCP traffic.
import { randomUUID } from "node:crypto";

async function callToolWithMother(client, agentId: string, server: string, tool: string, args: Record<string, unknown>) {
  const res = await fetch("${origin}/v1/mcp/evaluate", {
    method: "POST",
    headers: { Authorization: \`Bearer \${process.env.MOTHER_AI_API_KEY}\`, "Content-Type": "application/json" },
    body: JSON.stringify({
      request_id: randomUUID(),     // reuse the same id if you retry this exact call
      agent_id: agentId,            // e.g. "sales-agent-prod"
      server,                       // becomes capability, e.g. "salesforce"
      tool,                         // becomes operation, e.g. "contacts.update"
      arguments: args,              // becomes context — policies can read context.<field>
      data_class: "confidential",
    }),
  });
  const verdict = await res.json().catch(() => ({ decision: "block" }));

  if (verdict.decision !== "allow") {
    // Surface the refusal to the model as a tool result instead of executing.
    return { isError: true, content: [{ type: "text", text: \`Mother AI \${verdict.decision}: \${verdict.reason_code ?? verdict.error?.code}\` }] };
  }
  return client.callTool({ name: tool, arguments: args });
}

// Policy example for this pattern:
//   IF protocol equals "mcp" AND mcp.server equals "salesforce" AND mcp.tool is one of ["contacts.read","contacts.update"]
//   THEN ALLOW   (scoped to sales-agent-prod; every other tool falls to default deny)`,
    },
  };
}

export function IntegrationsPage() {
  useDocumentTitle("Integrations");
  const { can } = useSession();
  const [lang, setLang] = useState<Lang>("rest");
  const origin = window.location.origin;
  const s = snippets(origin);

  return (
    <>
      <PageHeader
        title="Integrations"
        description="Call Mother AI from the code that executes an agent's actions — the tool layer, not the prompt. Every snippet here targets endpoints that exist today."
        actions={
          <a className="btn btn-ghost" href="https://github.com/LHBUSA/Mother-AI/blob/main/docs/API.md" target="_blank" rel="noreferrer">
            API reference <IconExternal />
          </a>
        }
      />

      <div className="grid-integrations">
        <div className="stack">
          <Card pad={false} className="snippet-card">
            <div className="snippet-tabs">
              <Tabs
                label="Integration"
                value={lang}
                onChange={setLang}
                tabs={[
                  { id: "rest", label: "REST" },
                  { id: "ts", label: "TypeScript" },
                  { id: "python", label: "Python" },
                  { id: "mcp", label: "MCP pattern" },
                ]}
              />
            </div>
            <div className="card-body">
              <CodeBlock code={s[lang].code} language={s[lang].language} />
            </div>
          </Card>
        </div>

        <div className="stack">
          <Card title="Before you start">
            <ol className="steps">
              <li>
                <strong>Create a gateway key.</strong>{" "}
                {can("manage_keys") ? <Link to="/app/settings?tab=keys">Settings → API keys</Link> : "Ask an admin for a key."} Keys are shown once — store them in your secret manager.
              </li>
              <li>
                <strong>Register each agent</strong> with a stable id in <Link to="/app/agents">Agents</Link>. Unknown ids are blocked.
              </li>
              <li>
                <strong>Write policies</strong> in <Link to="/app/policies">Policies</Link>. With none, everything is blocked by default.
              </li>
              <li>
                <strong>Execute only on <code className="mono-inline">"allow"</code>.</strong> Treat errors, timeouts, review and block as “do not execute”.
              </li>
            </ol>
          </Card>
          <Card title="Endpoints">
            <ul className="endpoints">
              <li><span className="method">POST</span><code className="mono-inline">/v1/evaluate</code><span className="muted small">direct actions</span></li>
              <li><span className="method">POST</span><code className="mono-inline">/v1/mcp/evaluate</code><span className="muted small">MCP tool calls</span></li>
              <li><span className="method method-get">GET</span><code className="mono-inline">/v1/approvals/:id</code><span className="muted small">approval state</span></li>
              <li><span className="method">POST</span><code className="mono-inline">/v1/approvals/:id/consume</code><span className="muted small">single-use grant</span></li>
            </ul>
          </Card>
          <Alert tone="info" title="What Mother does and doesn't do">
            Mother decides and records. Your integration enforces the decision. Mother does not transparently proxy MCP servers or third-party APIs today.
          </Alert>
        </div>
      </div>
    </>
  );
}
