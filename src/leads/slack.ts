// Slack notifications for new Founding Access leads.
//
// Called only after a NEW founding_access_requests row is inserted, in the background
// (ctx.waitUntil), so Slack availability never affects the visitor's response or the
// saved lead. The webhook URL is a Worker secret (SLACK_LEADS_WEBHOOK_URL) and is never
// logged. The payload carries lead fields only — no IP, IP hash, form token or secrets.

import site from "../../config/site.json";

export interface LeadForSlack {
  id: string;
  name: string;
  company: string;
  work_email: string;
  use_case: string;
  agent_count: string;
  uses_mcp: string;
  created_at: string;
}

const SOURCE = new URL(site.origin).host;
export const BOOKING_URL: string = site.bookingUrl;

const AGENT_COUNT_LABEL: Record<string, string> = { "1-5": "1–5", "6-25": "6–25", "26-100": "26–100", "100+": "100+", unknown: "Not sure yet" };
const MCP_LABEL: Record<string, string> = { yes: "Yes", evaluating: "Evaluating", no: "No" };

/** Escapes Slack mrkdwn control characters so lead text cannot inject mentions or links. */
export function slackEscape(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function cap(value: string, max: number): string {
  const clean = value.replace(/\r\n?/g, "\n").trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

export function buildSlackLeadPayload(lead: LeadForSlack): Record<string, unknown> {
  const name = slackEscape(cap(lead.name, 120));
  const company = slackEscape(cap(lead.company, 160));
  const email = slackEscape(cap(lead.work_email, 254));
  const useCase = slackEscape(cap(lead.use_case, 1500));
  const agents = AGENT_COUNT_LABEL[lead.agent_count] ?? slackEscape(lead.agent_count);
  const mcp = MCP_LABEL[lead.uses_mcp] ?? slackEscape(lead.uses_mcp);

  const text = [
    "🚨 NEW MOTHER AI LEAD — FOUNDING ACCESS",
    "",
    `Name: ${name}`,
    `Company: ${company}`,
    `Email: ${email}`,
    "",
    `Agent count: ${agents}`,
    `Uses MCP: ${mcp}`,
    "",
    "Use case:",
    useCase,
    "",
    `Source: ${SOURCE}`,
    `Submitted: ${lead.created_at}`,
    "",
    "Calendly:",
    BOOKING_URL,
    "",
    "Lead ID:",
    lead.id,
  ].join("\n");

  return {
    text,
    unfurl_links: false,
    unfurl_media: false,
    blocks: [
      { type: "header", text: { type: "plain_text", text: "🚨 New Mother AI lead — Founding Access", emoji: true } },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Name*\n${name}` },
          { type: "mrkdwn", text: `*Company*\n${company}` },
          { type: "mrkdwn", text: `*Email*\n${email}` },
          { type: "mrkdwn", text: `*Agent count*\n${agents}` },
          { type: "mrkdwn", text: `*Uses MCP*\n${mcp}` },
        ],
      },
      { type: "section", text: { type: "mrkdwn", text: `*Use case*\n${useCase}` } },
      {
        type: "actions",
        elements: [{ type: "button", text: { type: "plain_text", text: "Calendly: book 30 minutes", emoji: false }, url: BOOKING_URL }],
      },
      {
        type: "context",
        elements: [{ type: "mrkdwn", text: `Source: ${SOURCE} · Submitted: ${lead.created_at} · Lead ID: \`${lead.id}\`` }],
      },
    ],
  };
}

/** Sends the notification. Never throws; logs failures without the webhook URL. */
export async function notifySlackLead(webhookUrl: string | undefined, lead: LeadForSlack): Promise<void> {
  if (!webhookUrl) {
    console.warn("slack lead notification skipped: SLACK_LEADS_WEBHOOK_URL is not configured", { lead_id: lead.id });
    return;
  }
  if (!/^https:\/\//.test(webhookUrl)) {
    console.error("slack lead notification skipped: SLACK_LEADS_WEBHOOK_URL is not an https URL", { lead_id: lead.id });
    return;
  }
  try {
    const res = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildSlackLeadPayload(lead)),
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) {
      await res.text().catch(() => undefined);
      console.error("slack lead notification failed", { lead_id: lead.id, status: res.status });
      return;
    }
    await res.text().catch(() => undefined);
    console.log("slack lead notification sent", { lead_id: lead.id });
  } catch (err) {
    // Error names only: messages from some runtimes can include the request URL.
    console.error("slack lead notification failed", { lead_id: lead.id, error: err instanceof Error ? err.name : "unknown" });
  }
}
