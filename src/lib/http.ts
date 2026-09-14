// Structured HTTP helpers. Callers never receive stack traces or internal error text.

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

export function json(body: unknown, status = 200, headers: HeadersInit = {}): Response {
  const h = new Headers(headers);
  h.set("Content-Type", "application/json; charset=utf-8");
  if (!h.has("Cache-Control")) h.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(body), { status, headers: h });
}

export function errorResponse(err: ApiError, headers: HeadersInit = {}): Response {
  return json({ error: { code: err.code, message: err.message, ...err.extra } }, err.status, headers);
}

export const MAX_JSON_BYTES = 32 * 1024;

/** Reads a JSON object body with a hard size limit and content-type check. */
export async function readJsonObject(request: Request, maxBytes = MAX_JSON_BYTES): Promise<Record<string, unknown>> {
  const type = request.headers.get("Content-Type") ?? "";
  if (!/^application\/json\b/i.test(type)) {
    throw new ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json.");
  }
  const declared = Number(request.headers.get("Content-Length") ?? "0");
  if (declared > maxBytes) throw new ApiError(413, "PAYLOAD_TOO_LARGE", `Request body must be at most ${maxBytes} bytes.`);
  const buf = await request.arrayBuffer();
  if (buf.byteLength > maxBytes) throw new ApiError(413, "PAYLOAD_TOO_LARGE", `Request body must be at most ${maxBytes} bytes.`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(buf));
  } catch {
    throw new ApiError(400, "INVALID_JSON", "Request body is not valid JSON.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ApiError(400, "INVALID_REQUEST", "Request body must be a JSON object.");
  }
  return parsed as Record<string, unknown>;
}

export function clientIp(request: Request): string {
  return request.headers.get("CF-Connecting-IP") ?? "0.0.0.0";
}

export function methodNotAllowed(allowed: string[]): Response {
  return json({ error: { code: "METHOD_NOT_ALLOWED", message: `Allowed: ${allowed.join(", ")}` } }, 405, { Allow: allowed.join(", ") });
}

export function notFoundJson(): Response {
  return json({ error: { code: "NOT_FOUND", message: "Not found." } }, 404);
}
