// Encryption for notification destinations (Slack webhook URLs are bearer secrets).
//
// AES-256-GCM with the Worker secret NOTIFICATION_ENCRYPTION_KEY (32 bytes, base64url).
// The additional authenticated data binds each ciphertext to its organization and
// channel id: a ciphertext copied into another organization's row fails to decrypt.

import { base64UrlDecode, base64UrlEncode } from "../lib/crypto";

export const KEY_VERSION = 1;

export class SecretUnavailableError extends Error {
  constructor() {
    super("notification encryption key is not configured");
    this.name = "SecretUnavailableError";
  }
}

function aad(organizationId: string, channelId: string): Uint8Array<ArrayBuffer> {
  const bytes = new TextEncoder().encode(`mother-ai:notification-channel:v${KEY_VERSION}:${organizationId}:${channelId}`);
  const out = new Uint8Array(new ArrayBuffer(bytes.length));
  out.set(bytes);
  return out;
}

export function encryptionAvailable(rawKey: string | undefined): boolean {
  try {
    return !!rawKey && base64UrlDecode(rawKey).length === 32;
  } catch {
    return false;
  }
}

async function importKey(rawKey: string | undefined): Promise<CryptoKey> {
  if (!encryptionAvailable(rawKey)) throw new SecretUnavailableError();
  return crypto.subtle.importKey("raw", base64UrlDecode(rawKey!), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptSecret(rawKey: string | undefined, organizationId: string, channelId: string, plaintext: string): Promise<string> {
  const key = await importKey(rawKey);
  const iv = new Uint8Array(new ArrayBuffer(12));
  crypto.getRandomValues(iv);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(organizationId, channelId) }, key, new TextEncoder().encode(plaintext));
  return `v${KEY_VERSION}.${base64UrlEncode(iv)}.${base64UrlEncode(new Uint8Array(ct))}`;
}

/** Throws SecretUnavailableError without a key, or a generic Error when the ciphertext does not belong to this org/channel. */
export async function decryptSecret(rawKey: string | undefined, organizationId: string, channelId: string, stored: string): Promise<string> {
  const key = await importKey(rawKey);
  const [version, iv, ct] = stored.split(".");
  if (version !== `v${KEY_VERSION}` || !iv || !ct) throw new Error("unsupported ciphertext");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64UrlDecode(iv), additionalData: aad(organizationId, channelId) }, key, base64UrlDecode(ct));
  return new TextDecoder().decode(pt);
}
