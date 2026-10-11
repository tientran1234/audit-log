import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  decodeSignedAnchor,
  encodeSignedAnchor,
  generateSigningKey,
  openSignedAnchor,
  publicKeyId,
  signAnchor,
} from "../src/signature.js";
import { verifyChain } from "../src/chain.js";
import { decodeEntry, encodeEntry } from "../src/wire.js";
import { AnchorSignatureError, MalformedEntryError, type Anchor, type SignedAnchor } from "../src/types.js";
import { chain, tenantName } from "./helpers.js";

const SIGNED_AT = new Date("2026-06-02T10:00:00.000Z");

function anchorOf(tenant: string, seq = 3): Anchor {
  const entries = chain(tenant, seq);
  const head = entries.at(-1)!;
  return { tenant, seq: head.seq, hash: head.hash };
}

describe("signing keys", () => {
  it("makes an ed25519 keypair as PEM, with a key id derived from the public key", () => {
    const key = generateSigningKey();

    expect(key.privateKeyPem).toContain("BEGIN PRIVATE KEY");
    expect(key.publicKeyPem).toContain("BEGIN PUBLIC KEY");
    expect(key.keyId).toMatch(/^[0-9a-f]{16}$/);
    expect(publicKeyId(key.publicKeyPem)).toBe(key.keyId);
    // The public half of the private key names the same key, so an operator who
    // kept only the private file can still say which anchors are theirs.
    expect(publicKeyId(key.privateKeyPem)).toBe(key.keyId);
  });

  it("gives two keypairs two ids", () => {
    expect(generateSigningKey().keyId).not.toBe(generateSigningKey().keyId);
  });

  it("refuses a key that is not ed25519, rather than signing with it", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const pub = publicKey.export({ type: "spki", format: "pem" }).toString();
    const anchor = anchorOf(tenantName());

    expect(() => signAnchor(anchor, pem, SIGNED_AT)).toThrow(AnchorSignatureError);
    expect(() => publicKeyId(pub)).toThrow(/ed25519/);
  });

  it("refuses text that is not a key", () => {
    const anchor = anchorOf(tenantName());
    expect(() => signAnchor(anchor, "not a key", SIGNED_AT)).toThrow(/not a readable private key/);
    expect(() => publicKeyId("not a key")).toThrow(/not a readable public key/);
  });
});

describe("signing an anchor", () => {
  it("round-trips: what was signed is what comes back out", () => {
    const tenant = tenantName();
    const anchor = anchorOf(tenant);
    const key = generateSigningKey();

    const signed = signAnchor(anchor, key.privateKeyPem, SIGNED_AT);
    expect(signed.keyId).toBe(key.keyId);
    expect(signed.signedAt).toEqual(SIGNED_AT);
    expect(openSignedAnchor(signed, key.publicKeyPem)).toEqual(anchor);
  });

  it("does not keep the caller's Date, so the signed time cannot change afterwards", () => {
    const anchor = anchorOf(tenantName());
    const key = generateSigningKey();
    const at = new Date(SIGNED_AT.getTime());

    const signed = signAnchor(anchor, key.privateKeyPem, at);
    at.setFullYear(2099);

    expect(signed.signedAt.getTime()).toBe(SIGNED_AT.getTime());
    expect(openSignedAnchor(signed, key.publicKeyPem).seq).toBe(anchor.seq);
  });

  it("refuses to sign something that is not an anchor", () => {
    const key = generateSigningKey();
    const good = anchorOf(tenantName());

    expect(() => signAnchor({ ...good, tenant: "" }, key.privateKeyPem)).toThrow(MalformedEntryError);
    expect(() => signAnchor({ ...good, seq: 0 }, key.privateKeyPem)).toThrow(MalformedEntryError);
    expect(() => signAnchor({ ...good, seq: 1.5 }, key.privateKeyPem)).toThrow(MalformedEntryError);
    expect(() => signAnchor({ ...good, hash: "nope" }, key.privateKeyPem)).toThrow(MalformedEntryError);
  });
});

describe("opening a signed anchor", () => {
  it("names the key when the wrong one is supplied, instead of saying bad signature", () => {
    const key = generateSigningKey();
    const other = generateSigningKey();
    const signed = signAnchor(anchorOf(tenantName()), key.privateKeyPem, SIGNED_AT);

    expect(() => openSignedAnchor(signed, other.publicKeyPem)).toThrow(
      new RegExp(`signed by key ${key.keyId}, but the key supplied is ${other.keyId}`),
    );
  });

  // Every field in the preimage, one at a time. Remove any of them from
  // `preimage()` and the matching case here stops throwing.
  const mutations: ReadonlyArray<readonly [string, (s: SignedAnchor) => SignedAnchor]> = [
    ["tenant", (s) => ({ ...s, anchor: { ...s.anchor, tenant: `${s.anchor.tenant}-other` } })],
    ["seq", (s) => ({ ...s, anchor: { ...s.anchor, seq: s.anchor.seq + 1 } })],
    ["hash", (s) => ({ ...s, anchor: { ...s.anchor, hash: "f".repeat(64) } })],
    ["signedAt", (s) => ({ ...s, signedAt: new Date(s.signedAt.getTime() + 1) })],
  ];

  for (const [field, mutate] of mutations) {
    it(`rejects an anchor whose ${field} was changed after signing`, () => {
      const key = generateSigningKey();
      const signed = signAnchor(anchorOf(tenantName()), key.privateKeyPem, SIGNED_AT);

      expect(() => openSignedAnchor(mutate(signed), key.publicKeyPem)).toThrow(
        /the signature does not match/,
      );
    });
  }

  it("rejects a signature from a different position signed by the same key", () => {
    const tenant = tenantName();
    const key = generateSigningKey();
    const three = signAnchor(anchorOf(tenant, 3), key.privateKeyPem, SIGNED_AT);
    const five = signAnchor(anchorOf(tenant, 5), key.privateKeyPem, SIGNED_AT);

    // Lifting a valid signature onto another valid anchor: both halves are
    // genuine, the pairing is not.
    expect(() => openSignedAnchor({ ...three, signature: five.signature }, key.publicKeyPem)).toThrow(
      /the signature does not match/,
    );
  });

  it("rejects a signature that is the right length but not the right bytes", () => {
    const key = generateSigningKey();
    const signed = signAnchor(anchorOf(tenantName()), key.privateKeyPem, SIGNED_AT);
    const bytes = Buffer.from(signed.signature, "base64");
    bytes[0] = bytes[0]! ^ 0xff;

    expect(() =>
      openSignedAnchor({ ...signed, signature: bytes.toString("base64") }, key.publicKeyPem),
    ).toThrow(AnchorSignatureError);
  });

  it("cannot be handed to verify() without being opened first", () => {
    const tenant = tenantName();
    const key = generateSigningKey();
    const signed = signAnchor(anchorOf(tenant), key.privateKeyPem, SIGNED_AT);

    // The point of holding the anchor in a field: a SignedAnchor is not an
    // Anchor, so there is no accidental path into verification. Drop the nesting
    // and this line compiles, which is why the expect-error is the test.
    // @ts-expect-error a SignedAnchor is not an Anchor
    const unchecked: { anchor: Anchor } = { anchor: signed };
    void unchecked;
    expect(openSignedAnchor(signed, key.publicKeyPem).tenant).toBe(tenant);
  });
});

describe("the signed anchor wire format", () => {
  it("is one line of JSON that round-trips", () => {
    const key = generateSigningKey();
    const signed = signAnchor(anchorOf(tenantName()), key.privateKeyPem, SIGNED_AT);
    const line = encodeSignedAnchor(signed);

    expect(line).not.toContain("\n");
    expect(decodeSignedAnchor(line)).toEqual(signed);
    expect(openSignedAnchor(decodeSignedAnchor(line), key.publicKeyPem)).toEqual(signed.anchor);
  });

  it("carries the version tag that went into the signature", () => {
    const key = generateSigningKey();
    const signed = signAnchor(anchorOf(tenantName()), key.privateKeyPem, SIGNED_AT);

    expect(JSON.parse(encodeSignedAnchor(signed))).toMatchObject({ v: "audit-log/anchor/v1" });
  });

  const bad: ReadonlyArray<readonly [string, (row: Record<string, unknown>) => void]> = [
    ["an unknown version", (row) => void (row["v"] = "audit-log/anchor/v2")],
    ["a missing version", (row) => void delete row["v"]],
    ["an empty tenant", (row) => void (row["tenant"] = "")],
    ["a zero seq", (row) => void (row["seq"] = 0)],
    ["a fractional seq", (row) => void (row["seq"] = 2.5)],
    ["a short hash", (row) => void (row["hash"] = "abc")],
    ["an uppercase hash", (row) => void (row["hash"] = "A".repeat(64))],
    ["a nonsense time", (row) => void (row["signedAt"] = "last tuesday")],
    ["a time at another precision", (row) => void (row["signedAt"] = "2026-06-02T10:00:00Z")],
    ["a key id that is not a fingerprint", (row) => void (row["keyId"] = "nope")],
    ["a truncated signature", (row) => void (row["sig"] = "AAAA")],
    ["a signature that is not base64", (row) => void (row["sig"] = "!".repeat(88))],
    // Node's base64 decoder skips characters it does not recognise, so this
    // decodes to exactly the right 64 bytes and only the re-encoding check
    // notices. A signature that was reflowed by an editor is a mangled line, and
    // saying so is more use than reporting a forgery.
    [
      "a signature with whitespace folded into it",
      (row) => {
        const sig = String(row["sig"]);
        row["sig"] = `${sig.slice(0, 40)} ${sig.slice(40)}`;
      },
    ],
  ];

  for (const [what, mutate] of bad) {
    it(`refuses ${what}`, () => {
      const key = generateSigningKey();
      const signed = signAnchor(anchorOf(tenantName()), key.privateKeyPem, SIGNED_AT);
      const row = JSON.parse(encodeSignedAnchor(signed)) as Record<string, unknown>;
      mutate(row);

      expect(() => decodeSignedAnchor(JSON.stringify(row))).toThrow(MalformedEntryError);
    });
  }

  it("refuses something that is not a JSON object", () => {
    expect(() => decodeSignedAnchor("not json")).toThrow(MalformedEntryError);
    expect(() => decodeSignedAnchor("[]")).toThrow(MalformedEntryError);
    expect(() => decodeSignedAnchor("null")).toThrow(MalformedEntryError);
  });
});

describe("what signing the checkpoint is for", () => {
  it("catches a truncated export that arrives with an anchor built to match it", async () => {
    const tenant = tenantName();
    const key = generateSigningKey();
    const entries = chain(tenant, 6);

    // The honest checkpoint, taken when the log had six entries and kept
    // somewhere the database cannot reach.
    const real = signAnchor(
      { tenant, seq: 6, hash: entries[5]!.hash },
      key.privateKeyPem,
      SIGNED_AT,
    );

    // What an operator hiding entries 5 and 6 hands the auditor: a shorter
    // export, which is itself a perfectly valid chain...
    const truncated = entries.slice(0, 4).map((e) => decodeEntry(encodeEntry(e)));
    expect((await verifyChain(tenant, truncated)).ok).toBe(true);

    // ...plus an anchor for its head. Without the signature there is nothing to
    // tell it from the real one.
    const forged = signAnchor(
      { tenant, seq: 4, hash: entries[3]!.hash },
      generateSigningKey().privateKeyPem,
      SIGNED_AT,
    );
    expect(() => openSignedAnchor(forged, key.publicKeyPem)).toThrow(AnchorSignatureError);

    // And the real anchor, which they cannot forge, names what is missing.
    const result = await verifyChain(tenant, truncated, {
      anchor: openSignedAnchor(real, key.publicKeyPem),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.break.kind).toBe("truncated");
    expect(result.break.seq).toBe(6);
  });
});
