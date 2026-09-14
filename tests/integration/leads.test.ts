import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { call, createEnv, ORIGIN, type TestEnv } from "../helpers/env";
import { buildSlackLeadPayload, slackEscape } from "../../src/leads/slack";
import site from "../../config/site.json";

const WEBHOOK = "https://hooks.slack.com/services/T000TEST/B000TEST/verysecretwebhooktoken123";
const SIGNING_KEY = "test-form-signing-key-0123456789abcdef";
const BOOKING = "https://calendly.com/proptechusa/new-meeting-1";

const lead = {
  name: "Dana Whitfield",
  company: "Northwind Logistics",
  work_email: "Dana@Northwind.example",
  use_case: "Our support agents issue refunds and update CRM records over MCP; we need approvals above $1,000.",
  agent_count: "6-25",
  uses_mcp: "yes",
  website: "",
};

interface SlackCall {
  url: string;
  body: string;
}

describe("Founding Access → Slack #leads", () => {
  const realFetch = globalThis.fetch;
  let slackCalls: SlackCall[];
  let slackMode: "ok" | "500" | "network";
  let env: TestEnv;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let warnSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    slackCalls = [];
    slackMode = "ok";
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (!url.startsWith("https://hooks.slack.com/")) return realFetch(input, init);
      slackCalls.push({ url, body: String(init?.body ?? "") });
      if (slackMode === "network") throw new TypeError(`fetch failed while connecting to ${url}`);
      return new Response(slackMode === "ok" ? "ok" : "internal_error", { status: slackMode === "ok" ? 200 : 500 });
    }) as typeof fetch;
    env = createEnv({ SLACK_LEADS_WEBHOOK_URL: WEBHOOK, FORM_SIGNING_KEY: SIGNING_KEY });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  async function formToken(): Promise<string> {
    return ((await (await call(env, "/api/founding-access/token")).json()) as { form_token: string }).form_token;
  }

  async function submit(body: Record<string, unknown>) {
    return call(env, "/api/founding-access", { json: body, origin: ORIGIN });
  }

  async function rows() {
    return (await env.DB.prepare(`SELECT * FROM founding_access_requests`).all<Record<string, string>>()).results;
  }

  async function afterMinimumAge<T>(fn: () => Promise<T>): Promise<T> {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 10_000);
    try {
      return await fn();
    } finally {
      vi.useRealTimers();
    }
  }

  it("1. valid new submission inserts one row, returns 201 and queues exactly one Slack notification", async () => {
    const token = await formToken();
    const res = await afterMinimumAge(() => submit({ ...lead, form_token: token }));
    expect(res.status).toBe(201);
    const stored = await rows();
    expect(stored).toHaveLength(1);
    expect(slackCalls).toHaveLength(1);
    expect(slackCalls[0]!.url).toBe(WEBHOOK);
    expect(JSON.parse(slackCalls[0]!.body).text).toContain(stored[0]!.id);
  });

  it("2. duplicate within 24h returns success, adds no row and sends no Slack notification", async () => {
    const token = await formToken();
    await afterMinimumAge(() => submit({ ...lead, form_token: token }));
    expect(slackCalls).toHaveLength(1);
    const again = await afterMinimumAge(() => submit({ ...lead, name: "Dana W.", form_token: token }));
    expect(again.status).toBe(201);
    expect(await rows()).toHaveLength(1);
    expect(slackCalls).toHaveLength(1);
  });

  it("3. honeypot stores nothing and sends no Slack notification", async () => {
    const token = await formToken();
    const res = await afterMinimumAge(() => submit({ ...lead, website: "http://spam.example", form_token: token }));
    expect(res.status).toBe(201);
    expect(await rows()).toHaveLength(0);
    expect(slackCalls).toHaveLength(0);
  });

  it("4. invalid, too-fast, forged-token and rate-limited submissions store nothing and send no Slack notification", async () => {
    const token = await formToken();
    const tooFast = await submit({ ...lead, form_token: token });
    expect(tooFast.status).toBe(400);
    const invalid = await afterMinimumAge(() => submit({ ...lead, work_email: "not-an-email", use_case: "short", form_token: token }));
    expect(invalid.status).toBe(400);
    const forged = await submit({ ...lead, form_token: `${Date.now() - 10_000}.${"0".repeat(64)}` });
    expect(forged.status).toBe(400);
    env.limiters.RL_FORMS!.blocked = true;
    const limited = await afterMinimumAge(() => submit({ ...lead, form_token: token }));
    expect(limited.status).toBe(429);
    expect(await rows()).toHaveLength(0);
    expect(slackCalls).toHaveLength(0);
  });

  it.each(["500", "network"] as const)("5. Slack %s: lead stays saved, visitor still gets 201, failure logged without the secret", async (mode) => {
    slackMode = mode;
    const token = await formToken();
    const res = await afterMinimumAge(() => submit({ ...lead, form_token: token }));
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ ok: true });
    const stored = await rows();
    expect(stored).toHaveLength(1);
    expect(slackCalls).toHaveLength(1);
    const failureLogs = errorSpy.mock.calls.filter((args: unknown[]) => String(args[0]).includes("slack lead notification failed"));
    expect(failureLogs).toHaveLength(1);
    expect(failureLogs[0]![1]).toMatchObject({ lead_id: stored[0]!.id, ...(mode === "500" ? { status: 500 } : { error: "TypeError" }) });
    const everything = JSON.stringify([...errorSpy.mock.calls, ...warnSpy.mock.calls, ...logSpy.mock.calls]);
    expect(everything).not.toContain(WEBHOOK);
    expect(everything).not.toContain("verysecretwebhooktoken123");
    expect(everything).not.toContain("hooks.slack.com");
  });

  it("6 + 7. payload carries the lead, source, Calendly and lead id — and nothing sensitive", async () => {
    const token = await formToken();
    await afterMinimumAge(() => submit({ ...lead, form_token: token }));
    const stored = (await rows())[0]!;
    const body = slackCalls[0]!.body;
    const payload = JSON.parse(body) as { text: string; blocks: unknown[] };

    for (const expected of ["Dana Whitfield", "Northwind Logistics", "dana@northwind.example", "approvals above $1,000", "6–25", "Yes", stored.id, "mother.proptechusa.ai", BOOKING]) {
      expect(payload.text).toContain(expected);
      expect(body).toContain(expected);
    }
    expect(payload.text.startsWith("🚨 NEW MOTHER AI LEAD — FOUNDING ACCESS")).toBe(true);
    expect(Array.isArray(payload.blocks) && payload.blocks.length).toBeTruthy();
    expect(site.bookingUrl).toBe(BOOKING);

    expect(stored.ip_hash).toMatch(/^[0-9a-f]{64}$/);
    for (const forbidden of [stored.ip_hash, "203.0.113.7", token, token.split(".")[1]!, SIGNING_KEY, WEBHOOK, "ip_hash", "form_token"]) {
      expect(body).not.toContain(forbidden);
    }
  });

  it("queues Slack via ctx.waitUntil and responds 201 while Slack is still pending", async () => {
    let release!: () => void;
    const slackHeld = new Promise<void>((resolve) => (release = resolve));
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      slackCalls.push({ url: String(input), body: String(init?.body ?? "") });
      await slackHeld;
      return new Response("ok", { status: 200 });
    }) as typeof fetch;
    const token = await formToken();
    const background: Promise<unknown>[] = [];
    const ctx = { waitUntil: (p: Promise<unknown>) => void background.push(p) };
    const request = new Request(`${site.apiOrigin}/api/founding-access`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: ORIGIN, "CF-Connecting-IP": "203.0.113.7" },
      body: JSON.stringify({ ...lead, form_token: token }),
    });
    const { foundingAccessSubmit } = await import("../../src/api/public");
    const res = await afterMinimumAge(() => foundingAccessSubmit(request, env, Date.now() + 10_000, ctx));
    expect(res.status).toBe(201);
    expect(background).toHaveLength(1);
    expect(slackCalls).toHaveLength(1);
    expect(await rows()).toHaveLength(1);
    release();
    await Promise.all(background);
  });

  it("does not notify (and still saves the lead) when the webhook secret is not configured", async () => {
    env = createEnv({ FORM_SIGNING_KEY: SIGNING_KEY });
    const token = await formToken();
    const res = await afterMinimumAge(() => submit({ ...lead, form_token: token }));
    expect(res.status).toBe(201);
    expect(await rows()).toHaveLength(1);
    expect(slackCalls).toHaveLength(0);
    expect(warnSpy.mock.calls.some((args: unknown[]) => String(args[0]).includes("SLACK_LEADS_WEBHOOK_URL is not configured"))).toBe(true);
  });
});

describe("Slack payload formatting", () => {
  it("escapes mrkdwn so lead text cannot inject mentions or links, and caps long use cases", () => {
    const payload = buildSlackLeadPayload({
      id: "fa_AAAAAAAAAAAAAAAAAAAAAA",
      name: "<!channel> Mallory",
      company: "Evil <https://phish.example|click> & Co",
      work_email: "m@evil.example",
      use_case: "x".repeat(5000),
      agent_count: "100+",
      uses_mcp: "no",
      created_at: "2026-09-14T16:00:00.000Z",
    });
    const text = payload.text as string;
    expect(text).not.toContain("<!channel>");
    expect(text).toContain("&lt;!channel&gt; Mallory");
    expect(text).not.toContain("<https://phish.example|click>");
    expect(text.length).toBeLessThan(2500);
    expect(JSON.stringify(payload.blocks).length).toBeLessThan(6000);
    expect(slackEscape("a & <b>")).toBe("a &amp; &lt;b&gt;");
  });
});
