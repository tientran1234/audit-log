/**
 * Signing a checkpoint.
 *
 * An anchor is what lets verification catch a truncated chain: hashes alone
 * cannot tell a log that was never longer from one whose newest entries were
 * deleted. But an *unsigned* anchor only means something if the verifier already
 * trusts whoever handed it over — and the party most able to hand an auditor a
 * truncated export is the same party that would hand over an anchor matching it.
 * So the anchor carries a signature made with a key the database does not hold,
 * and a fabricated anchor fails before any chain is walked.
 *
 * This signs checkpoints, not entries. One signature over four fields, made as
 * often as you take a checkpoint, is a key that can live offline and be used by
 * hand. A signature per entry would put the signing key on the append path, and
 * then the log's integrity would depend on key management this package is in no
 * position to solve.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
import { frame } from "./canonical.js";
import { isHash } from "./chain.js";
import { AnchorSignatureError, MalformedEntryError, type Anchor, type SignedAnchor } from "./types.js";

/**
 * In every preimage and on the wire. If the signed field list below ever changes,
 * this changes with it, so anchors signed under the old rules are refused as a
 * version mismatch rather than reported as bad signatures.
 */
const ANCHOR_DOMAIN = "audit-log/anchor/v1";

/** Ed25519 signatures are 64 bytes, always. */
const SIGNATURE_BYTES = 64;

/**
 * 64 bits of the SHA-256 of the SPKI DER. It says *which* key, so a verifier
 * holding several can pick one and a mismatch gets a useful message instead of
 * "bad signature". It authenticates nothing — truncating it is safe precisely
 * because the signature, not the identifier, is what has to hold.
 */
const KEY_ID_CHARS = 16;

const KEY_ID = /^[0-9a-f]{16}$/;

export interface SigningKeyPair {
  /** PKCS#8 PEM. Keep it off the host that holds the database. */
  readonly privateKeyPem: string;
  /** SPKI PEM. Hand this to whoever verifies. */
  readonly publicKeyPem: string;
  readonly keyId: string;
}

/**
 * A fresh ed25519 keypair as PEM text, which is what `openssl` and every secret
 * store already understand — this package does not invent a key format and does
 * not store keys.
 */
export function generateSigningKey(): SigningKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    keyId: fingerprint(publicKey),
  };
}

/** The key id of a public key, or of the public half of a private key. */
export function publicKeyId(pem: string): string {
  return fingerprint(readKey(pem));
}

/**
 * Signs a position. `signedAt` is the signer's own claim about when — there is no
 * timestamp authority here — and it is covered by the signature so that two
 * checkpoints at the same position stay distinguishable and a verifier holding
 * several anchors can tell which one it was handed last.
 */
export function signAnchor(anchor: Anchor, privateKeyPem: string, signedAt: Date = new Date()): SignedAnchor {
  requireAnchor(anchor);
  if (Number.isNaN(signedAt.getTime())) {
    throw new MalformedEntryError("signedAt is not a time");
  }

  let key: KeyObject;
  try {
    key = createPrivateKey(privateKeyPem);
  } catch (error) {
    throw new AnchorSignatureError(`not a readable private key: ${reason(error)}`);
  }
  requireEd25519(key, "private");

  // A copy: a Date is mutable and the caller still holds theirs, so an anchor
  // whose time could change after it was signed is not signed.
  const at = new Date(signedAt.getTime());
  const signature = sign(null, preimage(anchor, at), key);

  return {
    anchor: { tenant: anchor.tenant, seq: anchor.seq, hash: anchor.hash },
    signedAt: at,
    keyId: fingerprint(createPublicKey(key)),
    signature: signature.toString("base64"),
  };
}

/**
 * Checks the signature and hands back the anchor inside it. The only function
 * that produces an {@link Anchor} from a {@link SignedAnchor}, and the reason
 * `SignedAnchor` holds its anchor in a field rather than extending it: a signed
 * anchor is not assignable to `Anchor`, so it cannot reach `verify()` with the
 * signature unchecked. Nothing stops a caller reaching into `.anchor` on
 * purpose — but nothing in this package, and no path through the CLI, does.
 */
export function openSignedAnchor(signed: SignedAnchor, publicKeyPem: string): Anchor {
  requireAnchor(signed.anchor);

  const key = readKey(publicKeyPem);
  const supplied = fingerprint(key);
  if (signed.keyId !== supplied) {
    throw new AnchorSignatureError(
      `the anchor was signed by key ${signed.keyId}, but the key supplied is ${supplied}`,
    );
  }

  const signature = decodeSignature(signed.signature);
  // `verify` returns false for a bad signature and throws for a key it cannot
  // use; both mean the same thing to the caller.
  let ok: boolean;
  try {
    ok = verify(null, preimage(signed.anchor, signed.signedAt), key, signature);
  } catch {
    ok = false;
  }
  if (!ok) {
    throw new AnchorSignatureError(
      `the signature does not match ${signed.anchor.tenant} ${signed.anchor.seq}:${signed.anchor.hash} signed at ${signed.signedAt.toISOString()}`,
    );
  }

  return { tenant: signed.anchor.tenant, seq: signed.anchor.seq, hash: signed.anchor.hash };
}

/**
 * One line of JSON, flat rather than nested, because it gets pasted into a commit
 * message or a ticket and read there. `v` is the domain tag that went into the
 * signature, so a reader can refuse a version it does not understand.
 */
export function encodeSignedAnchor(signed: SignedAnchor): string {
  return JSON.stringify({
    v: ANCHOR_DOMAIN,
    tenant: signed.anchor.tenant,
    seq: signed.anchor.seq,
    hash: signed.anchor.hash,
    signedAt: signed.signedAt.toISOString(),
    keyId: signed.keyId,
    sig: signed.signature,
  });
}

export function decodeSignedAnchor(text: string): SignedAnchor {
  let raw: unknown;
  try {
    raw = JSON.parse(text) as unknown;
  } catch {
    throw new MalformedEntryError("a signed anchor must be one JSON object");
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new MalformedEntryError("a signed anchor must be one JSON object");
  }
  const row = raw as Record<string, unknown>;

  const version = row["v"];
  if (version !== ANCHOR_DOMAIN) {
    throw new MalformedEntryError(
      `this is a "${String(version)}" anchor; this version of audit-log signs "${ANCHOR_DOMAIN}"`,
    );
  }

  const tenant = row["tenant"];
  const seq = row["seq"];
  const hash = row["hash"];
  const signedAt = row["signedAt"];
  const keyId = row["keyId"];
  const sig = row["sig"];

  if (typeof tenant !== "string" || tenant === "") {
    throw new MalformedEntryError("tenant must be a non-empty string");
  }
  if (typeof seq !== "number" || !Number.isInteger(seq) || seq < 1) {
    throw new MalformedEntryError("seq must be a positive integer");
  }
  if (typeof hash !== "string" || !isHash(hash)) {
    throw new MalformedEntryError("hash must be 64 lowercase hex characters");
  }
  if (typeof signedAt !== "string") {
    throw new MalformedEntryError("signedAt must be a string");
  }
  const at = new Date(signedAt);
  if (Number.isNaN(at.getTime())) {
    throw new MalformedEntryError(`signedAt is not a timestamp: ${signedAt}`);
  }
  // The signature covers the millisecond ISO form, so a time written any other
  // way — more precision, an offset instead of Z — would parse here and then
  // fail to verify. Refusing it says which of the two is actually wrong.
  if (at.toISOString() !== signedAt) {
    throw new MalformedEntryError(
      `signedAt must be a millisecond UTC timestamp like ${at.toISOString()}, not ${signedAt}`,
    );
  }
  if (typeof keyId !== "string" || !KEY_ID.test(keyId)) {
    throw new MalformedEntryError(`keyId must be ${KEY_ID_CHARS} lowercase hex characters`);
  }
  if (typeof sig !== "string") {
    throw new MalformedEntryError("sig must be a string");
  }
  // Validated here rather than at verification time so that a mangled line is
  // reported as mangled, not as a forgery.
  decodeSignature(sig);

  return { anchor: { tenant, seq, hash }, signedAt: at, keyId, signature: sig };
}

/**
 * The bytes the signature is over, framed the same way an entry's preimage is:
 * each part prefixed with its length, so no field can borrow bytes from its
 * neighbour. Today every field after the tenant has a constrained alphabet and a
 * joined preimage would happen to be unambiguous too; framing means that stays
 * true if a field is ever added, and that there is one rule to understand rather
 * than two. The domain tag keeps an anchor signature from being replayed as
 * anything else this package hashes.
 */
function preimage(anchor: Anchor, signedAt: Date): Uint8Array {
  return frame([ANCHOR_DOMAIN, anchor.tenant, String(anchor.seq), anchor.hash, signedAt.toISOString()]);
}

function decodeSignature(base64: string): Buffer {
  const bytes = Buffer.from(base64, "base64");
  // Buffer.from ignores characters it does not recognise, so a mangled signature
  // decodes to something shorter rather than failing. Re-encoding catches that,
  // and also catches a re-encoded-by-hand signature that is no longer canonical.
  if (bytes.length !== SIGNATURE_BYTES || bytes.toString("base64") !== base64) {
    throw new MalformedEntryError(
      `sig must be ${SIGNATURE_BYTES} bytes of base64, got ${bytes.length}`,
    );
  }
  return bytes;
}

function readKey(pem: string): KeyObject {
  let key: KeyObject;
  try {
    // Accepts a private key PEM too, deriving the public half: someone verifying
    // with the file they signed with has made a key-hygiene mistake, not a
    // verification one, and failing here would not tell them that.
    key = createPublicKey(pem);
  } catch (error) {
    throw new AnchorSignatureError(`not a readable public key: ${reason(error)}`);
  }
  requireEd25519(key, "public");
  return key;
}

function requireEd25519(key: KeyObject, which: string): void {
  if (key.asymmetricKeyType !== "ed25519") {
    throw new AnchorSignatureError(
      `the ${which} key is ${key.asymmetricKeyType ?? "of an unknown type"}; anchors are signed with ed25519`,
    );
  }
}

function fingerprint(key: KeyObject): string {
  const der = key.export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, KEY_ID_CHARS);
}

function requireAnchor(anchor: Anchor): void {
  if (typeof anchor.tenant !== "string" || anchor.tenant === "") {
    throw new MalformedEntryError("anchor tenant must be a non-empty string");
  }
  if (!Number.isInteger(anchor.seq) || anchor.seq < 1) {
    throw new MalformedEntryError(`anchor seq must be a positive integer, got ${anchor.seq}`);
  }
  if (!isHash(anchor.hash)) {
    throw new MalformedEntryError("anchor hash must be 64 lowercase hex characters");
  }
}

function reason(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
