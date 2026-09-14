// Redaction for anything that is persisted as evidence. Context is evaluated
// unredacted (in memory only) and stored redacted.

const SENSITIVE_KEY = /(pass(word|wd|phrase)|^pass$|secret|token|api[_-]?key|apikey|(^|[_-])auth($|[_-])|authorization|cookie|credential|private[_-]?key|session|bearer|signature|^ssn$|card[_-]?number|^cvv$|^cvc$|^pin$)/i;

const SENSITIVE_VALUE: RegExp[] = [
  /\bmai_(live|test)_[0-9A-Za-z]{10,}/, // Mother AI keys
  /\b(sk|rk|pk)_(live|test)_[0-9A-Za-z]{10,}/, // Stripe-style keys
  /\bgh[pousr]_[0-9A-Za-z]{20,}/, // GitHub tokens
  /\bxox[abprs]-[0-9A-Za-z-]{10,}/, // Slack tokens
  /\bAKIA[0-9A-Z]{16}\b/, // AWS access key ids
  /\bBearer\s+[A-Za-z0-9._~+/-]{10,}=*/i,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/, // JWTs
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bsk-[A-Za-z0-9_-]{20,}/, // common LLM provider keys
];

export const REDACTED = "[REDACTED]";

export function redactValue(value: unknown, depth = 0): unknown {
  if (depth > 8) return "[TRUNCATED]";
  if (typeof value === "string") return SENSITIVE_VALUE.some((re) => re.test(value)) ? REDACTED : value;
  if (Array.isArray(value)) return value.map((v) => redactValue(v, depth + 1));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = SENSITIVE_KEY.test(k) ? REDACTED : redactValue(v, depth + 1);
    }
    return out;
  }
  return value;
}

export function redactString(value: string | null): string | null {
  if (value === null) return null;
  return SENSITIVE_VALUE.some((re) => re.test(value)) ? REDACTED : value;
}
