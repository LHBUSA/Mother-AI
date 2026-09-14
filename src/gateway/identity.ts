// Gateway credential parsing. Keys are only accepted in the Authorization header —
// never in query strings or bodies.

import { ApiError } from "../lib/http";
import { looksLikeApiKey, sha256Hex } from "../lib/crypto";

export async function readBearerKey(request: Request): Promise<{ raw: string; hash: string }> {
  const header = request.headers.get("Authorization");
  if (!header) {
    throw new ApiError(401, "MISSING_API_KEY", "Provide a Mother AI API key: Authorization: Bearer mai_live_…");
  }
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
  if (!match || !looksLikeApiKey(match[1]!)) {
    throw new ApiError(401, "INVALID_API_KEY", "The API key is not valid.");
  }
  return { raw: match[1]!, hash: await sha256Hex(match[1]!) };
}

export function assertKeyUsable(
  row: { key_hash: string; revoked_at: string | null; org_status: string; gateway_enabled: number } | null,
  presentedHash: string,
  timingSafeEqual: (a: string, b: string) => boolean,
): void {
  if (!row || !timingSafeEqual(row.key_hash, presentedHash)) {
    throw new ApiError(401, "INVALID_API_KEY", "The API key is not valid.");
  }
  if (row.revoked_at) throw new ApiError(401, "API_KEY_REVOKED", "This API key has been revoked.");
  if (row.org_status !== "active") {
    throw new ApiError(403, "ORGANIZATION_DISABLED", "This organization is not active in Mother AI.");
  }
  if (row.gateway_enabled !== 1) {
    throw new ApiError(403, "GATEWAY_DISABLED", "The Mother AI gateway is disabled for this organization.");
  }
}
