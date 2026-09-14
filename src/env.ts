export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface Env {
  DB: D1Database;

  RL_GATEWAY_IP: RateLimiter;
  RL_GATEWAY_KEY: RateLimiter;
  RL_DEMO: RateLimiter;
  RL_FORMS: RateLimiter;
  RL_AUTH: RateLimiter;
  RL_CONSOLE: RateLimiter;
  RL_PUBLIC_BADGE: RateLimiter;

  ENVIRONMENT: string;
  GIT_SHA: string;

  /** Secret: signs founding-access form timing tokens. */
  FORM_SIGNING_KEY?: string;
  /** Secret: Slack Incoming Webhook for #leads. Never logged or returned. */
  SLACK_LEADS_WEBHOOK_URL?: string;
  /** Secret: 32-byte base64url AES-GCM key for per-organization notification destinations. Never logged. */
  NOTIFICATION_ENCRYPTION_KEY?: string;
}
