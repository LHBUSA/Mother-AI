// Software WebAuthn authenticator (ES256, "none" attestation, discoverable credentials).
// Used by integration tests and production QA scripts to exercise the real passkey
// flow without a browser. It produces the same JSON a browser's
// @simplewebauthn/browser startRegistration/startAuthentication would send.

const te = new TextEncoder();

const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
const fromB64url = (s) => new Uint8Array(Buffer.from(s, "base64url"));

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// --- minimal CBOR encoder -----------------------------------------------------
function head(major, value) {
  if (value < 24) return Uint8Array.of((major << 5) | value);
  if (value < 256) return Uint8Array.of((major << 5) | 24, value);
  if (value < 65536) return Uint8Array.of((major << 5) | 25, value >> 8, value & 255);
  return Uint8Array.of((major << 5) | 26, (value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255);
}

function cbor(value) {
  if (typeof value === "number") return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === "string") {
    const b = te.encode(value);
    return concat(head(3, b.length), b);
  }
  if (value instanceof Uint8Array) return concat(head(2, value.length), value);
  if (value instanceof Map) {
    const parts = [head(5, value.size)];
    for (const [k, v] of value) parts.push(cbor(k), cbor(v));
    return concat(...parts);
  }
  throw new Error("unsupported CBOR value");
}

function rawToDer(raw) {
  const int = (bytes) => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    let v = bytes.slice(i);
    if (v[0] & 0x80) v = concat(Uint8Array.of(0), v);
    return concat(Uint8Array.of(0x02, v.length), v);
  };
  const r = int(raw.slice(0, 32));
  const s = int(raw.slice(32));
  return concat(Uint8Array.of(0x30, r.length + s.length), r, s);
}

const counterBytes = (n) => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);

export class SoftwareAuthenticator {
  constructor() {
    /** @type {Map<string, {privateKey: CryptoKey, rpId: string, userHandle: string, counter: number, jwk?: JsonWebKey}>} */
    this.credentials = new Map();
  }

  /** @param {any} options PublicKeyCredentialCreationOptionsJSON @param {string} origin */
  async register(options, origin) {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const credId = crypto.getRandomValues(new Uint8Array(32));
    const id = b64url(credId);
    const rpId = options.rp.id;
    const clientData = te.encode(JSON.stringify({ type: "webauthn.create", challenge: options.challenge, origin, crossOrigin: false }));
    const cose = new Map([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, fromB64url(jwk.x)],
      [-3, fromB64url(jwk.y)],
    ]);
    const authData = concat(await sha256(te.encode(rpId)), Uint8Array.of(0x45), counterBytes(0), new Uint8Array(16), Uint8Array.of(credId.length >> 8, credId.length & 255), credId, cbor(cose));
    const attestationObject = cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
    this.credentials.set(id, { privateKey: pair.privateKey, rpId, userHandle: options.user.id, counter: 0 });
    return {
      id,
      rawId: id,
      type: "public-key",
      response: { clientDataJSON: b64url(clientData), attestationObject: b64url(attestationObject), transports: ["internal"] },
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
    };
  }

  /** @param {any} options PublicKeyCredentialRequestOptionsJSON @param {string} origin @param {string=} credentialId */
  async authenticate(options, origin, credentialId) {
    const id = credentialId ?? [...this.credentials.keys()][0];
    const cred = this.credentials.get(id);
    if (!cred) throw new Error("no credential");
    cred.counter += 1;
    const clientData = te.encode(JSON.stringify({ type: "webauthn.get", challenge: options.challenge, origin, crossOrigin: false }));
    const authData = concat(await sha256(te.encode(options.rpId ?? cred.rpId)), Uint8Array.of(0x05), counterBytes(cred.counter));
    const signed = concat(authData, await sha256(clientData));
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, cred.privateKey, signed));
    return {
      id,
      rawId: id,
      type: "public-key",
      response: { clientDataJSON: b64url(clientData), authenticatorData: b64url(authData), signature: b64url(rawToDer(raw)), userHandle: cred.userHandle },
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
    };
  }

  /** Serializable export so a QA identity can be reused across runs (store outside Git). */
  async export() {
    const out = [];
    for (const [id, c] of this.credentials) {
      out.push({ id, rpId: c.rpId, userHandle: c.userHandle, counter: c.counter, jwk: await crypto.subtle.exportKey("jwk", c.privateKey) });
    }
    return out;
  }

  static async import(entries) {
    const a = new SoftwareAuthenticator();
    for (const e of entries) {
      const privateKey = await crypto.subtle.importKey("jwk", e.jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
      a.credentials.set(e.id, { privateKey, rpId: e.rpId, userHandle: e.userHandle, counter: e.counter });
    }
    return a;
  }
}
