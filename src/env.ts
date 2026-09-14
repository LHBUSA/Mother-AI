export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;

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
  /** Secret: Turnstile widget site key (public value, stored as a secret so deploys never blank it). */
  TURNSTILE_SITE_KEY?: string;
  /** Secret: Turnstile siteverify secret. Turnstile is enforced only when both keys are set. */
  TURNSTILE_SECRET_KEY?: string;
}
