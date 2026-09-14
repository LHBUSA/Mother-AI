// Response hardening applied to every response the Worker returns.

const CSP = [
  "default-src 'self'",
  "script-src 'self' https://challenges.cloudflare.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "frame-src https://challenges.cloudflare.com",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "object-src 'none'",
  "upgrade-insecure-requests",
].join("; ");

export function withSecurityHeaders(response: Response, opts: { publicEmbed?: boolean } = {}): Response {
  const res = new Response(response.body, response);
  const h = res.headers;
  h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Referrer-Policy", "strict-origin-when-cross-origin");
  h.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()");
  if (!opts.publicEmbed) {
    h.set("X-Frame-Options", "DENY");
    h.set("Cross-Origin-Opener-Policy", "same-origin");
    if (!h.has("Content-Security-Policy")) h.set("Content-Security-Policy", CSP);
    if (!h.has("Cross-Origin-Resource-Policy")) h.set("Cross-Origin-Resource-Policy", "same-origin");
  }
  h.delete("Access-Control-Allow-Origin");
  // Zone-level edge features (e.g. Web Analytics auto-injection on the proptechusa.ai zone)
  // must never rewrite Mother AI pages or inject third-party scripts into the console,
  // invite or verification flows. Cloudflare skips response modification on no-transform.
  if ((h.get("Content-Type") ?? "").includes("text/html")) {
    const cc = h.get("Cache-Control");
    if (!cc) h.set("Cache-Control", "no-transform");
    else if (!/no-transform/i.test(cc)) h.set("Cache-Control", `${cc}, no-transform`);
  }
  return res;
}
