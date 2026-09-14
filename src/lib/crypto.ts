// Cryptographic helpers. Everything here uses WebCrypto, which is available in
// Workers and in Node >= 20 (tests).

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/** Unbiased base62 string from CSPRNG bytes (rejection sampling). */
export function randomBase62(length: number): string {
  let out = "";
  while (out.length < length) {
    const bytes = new Uint8Array(Math.max(16, (length - out.length) * 2));
    crypto.getRandomValues(bytes);
    for (const b of bytes) {
      // 248 = 62 * 4; values >= 248 would bias the distribution.
      if (b < 248) out += BASE62[b % 62];
      if (out.length === length) break;
    }
  }
  return out;
}

/** Prefixed random identifier, e.g. dec_4hK...; 22 base62 chars ≈ 131 bits. */
export function newId(prefix: string): string {
  return `${prefix}_${randomBase62(22)}`;
}

export async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(digest));
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/** Constant-time comparison of two strings of equal expected length. */
export function timingSafeEqual(a: string, b: string): boolean {
  const ea = new TextEncoder().encode(a);
  const eb = new TextEncoder().encode(b);
  // Compare against self when lengths differ so timing does not depend on where they diverge.
  const len = Math.max(ea.length, eb.length);
  let diff = ea.length ^ eb.length;
  for (let i = 0; i < len; i++) diff |= (ea[i] ?? 0) ^ (eb[i] ?? 0);
  return diff === 0;
}

export async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return bytesToHex(new Uint8Array(sig));
}

// ---------------------------------------------------------------------------
// Gateway API keys
// ---------------------------------------------------------------------------

export type KeyEnvironment = "live" | "test";

const KEY_PATTERN = /^mai_(live|test)_[0-9A-Za-z]{40}$/;
export const KEY_PREFIX_LENGTH = 17; // "mai_live_" + 8 chars

/**
 * Generates a gateway key: mai_live_<40 base62 chars> (~238 bits of entropy).
 * Keys are high-entropy random secrets, not passwords, so a fast SHA-256 digest
 * is the right storage primitive: brute-forcing the preimage is infeasible and a
 * slow KDF would only add latency to every gateway call.
 */
export async function generateApiKey(environment: KeyEnvironment): Promise<{ raw: string; prefix: string; hash: string }> {
  const raw = `mai_${environment}_${randomBase62(40)}`;
  return { raw, prefix: raw.slice(0, KEY_PREFIX_LENGTH), hash: await sha256Hex(raw) };
}

export function looksLikeApiKey(value: string): boolean {
  return KEY_PATTERN.test(value);
}

/** Opaque bearer tokens for sessions, invites and badges (256+ bits). */
export function generateToken(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return base64UrlEncode(buf);
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(value: string): Uint8Array<ArrayBuffer> {
  const pad = value.length % 4 === 0 ? "" : "=".repeat(4 - (value.length % 4));
  const bin = atob(value.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Canonical JSON (sorted keys) for fingerprints. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}
