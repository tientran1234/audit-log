import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { AuditLog } from "../src/log.js";
import {
  MerkleBuilder,
  inclusionPathLength,
  leafHash,
  nodeHash,
  proveInChain,
  rootOfChain,
  verifyInclusion,
  type InclusionProof,
  type PublishedRoot,
} from "../src/merkle.js";
import { MemoryStore } from "../src/store/memory.js";
import { decodeProof, encodeProof, parseRoot } from "../src/wire.js";
import { chain, edit, reseal, tenantName } from "./helpers.js";
import type { AuditEntry } from "../src/types.js";

/**
 * MTH and PATH from RFC 6962, written recursively over an array — the definition
 * the streaming builder has to agree with. Keeping a second implementation here
 * is the point: the stack folding in `MerkleBuilder` is the part that is easy to
 * get subtly wrong, and "it matches the definition for every size and every
 * position" is a stronger statement than any hand-written expectation.
 */
function mth(hashes: readonly string[]): string {
  if (hashes.length === 1) return leafHash(hashes[0]!);
  const k = splitAt(hashes.length);
  return nodeHash(mth(hashes.slice(0, k)), mth(hashes.slice(k)));
}

function refPath(m: number, hashes: readonly string[]): string[] {
  if (hashes.length === 1) return [];
  const k = splitAt(hashes.length);
  return m < k
    ? [...refPath(m, hashes.slice(0, k)), mth(hashes.slice(k))]
    : [...refPath(m - k, hashes.slice(k)), mth(hashes.slice(0, k))];
}

function splitAt(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** Stand-in entry hashes: 64 hex characters, distinct, and not secret. */
function hashes(n: number): string[] {
  return Array.from({ length: n }, (_, i) =>
    createHash("sha256").update(`leaf-${i}`).digest("hex"),
  );
}

function build(leaves: readonly string[], target?: number): {
  root: string;
  size: number;
  path: readonly string[];
} {
  const builder = new MerkleBuilder(target === undefined ? {} : { target });
  for (const leaf of leaves) builder.push(leaf);
  return builder.finish();
}

function logOf(entries: readonly AuditEntry[]): AuditLog {
  return new AuditLog({ store: MemoryStore.from(entries) });
}

/** A proof for `seq` over a healthy chain of `count` entries. */
async function proofOf(
  count: number,
  seq: number,
  size?: number,
): Promise<{ proof: InclusionProof; trusted: PublishedRoot; tenant: string }> {
  const tenant = tenantName();
  const entries = chain(tenant, count);
  const log = logOf(entries);
  const result = await log.prove(tenant, seq, size === undefined ? {} : { size });
  if (!result.ok) throw new Error(`could not prove: ${result.break.detail}`);
  const rooted = await log.root(tenant, size === undefined ? {} : { size });
  if (!rooted.ok || rooted.root === null) throw new Error("could not root");
  return { proof: result.proof, trusted: rooted.root, tenant };
}

describe("the tree is the one RFC 6962 defines", () => {
  it("hashes a leaf under its own domain, so an entry hash is not a root", () => {
    const [a] = hashes(1) as [string];
    expect(build([a]).root).toBe(leafHash(a));
    expect(build([a]).root).not.toBe(a);
  });

  it("promotes an odd node instead of duplicating it", () => {
    const [a, b, c] = hashes(3) as [string, string, string];
    expect(build([a, b, c]).root).toBe(
      nodeHash(nodeHash(leafHash(a), leafHash(b)), leafHash(c)),
    );
  });

  it("gives three leaves a different root than three leaves with the last repeated", () => {
    // The Bitcoin construction duplicates the last leaf to even out a level, and
    // then a root commits to two different logs at once. This is that test.
    const [a, b, c] = hashes(3) as [string, string, string];
    expect(build([a, b, c]).root).not.toBe(build([a, b, c, c]).root);
  });

  it("streams to the same root the recursive definition gives, for every size", () => {
    for (const n of [...Array.from({ length: 33 }, (_, i) => i + 1), 64, 100, 129]) {
      const leaves = hashes(n);
      expect(build(leaves).root, `size ${n}`).toBe(mth(leaves));
      expect(build(leaves).size).toBe(n);
    }
  });

  it("streams the same path the recursive definition gives, for every position", () => {
    for (let n = 1; n <= 17; n += 1) {
      const leaves = hashes(n);
      for (let m = 0; m < n; m += 1) {
        const built = build(leaves, m);
        expect(built.path, `size ${n}, leaf ${m}`).toEqual(refPath(m, leaves));
        expect(built.path.length).toBe(inclusionPathLength(m, n));
      }
    }
  });

  it("refuses to root an empty tree, or to path a leaf that is not there", () => {
    expect(() => build([])).toThrow(/at least one entry/);
    expect(() => build(hashes(3), 3)).toThrow(/leaf 3 of 3/);
    expect(() => new MerkleBuilder({ target: -1 })).toThrow(/non-negative/);
  });

  it("keeps the hashes it already published", () => {
    // Golden vectors. They pin the preimages — the two domain strings and the
    // framing — so a change to either fails here instead of silently invalidating
    // every root and proof anybody has written down.
    const zero = "0".repeat(64);
    expect(leafHash(zero)).toBe("2b33af916e369a200dad95f6372d0e94e71e6eddda6f1a94fbd47d217c65d481");
    expect(nodeHash(zero, zero)).toBe("b223ab4be7e2386de47af0fd7439663e952d587acc18450cc4d0cb43b6dacfc2");
    expect(build(hashes(5)).root).toBe("5ec873dce9c52676d415fb9f6d6fbcc85b07867938cfebc555895f5b83535ce5");
  });
});

describe("a root commits to a prefix", () => {
  it("does not change when the log grows past it", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 12);

    const early = await rootOfChain(tenant, entries.slice(0, 5));
    const later = await rootOfChain(tenant, entries, { size: 5 });
    if (!early.ok || !later.ok) throw new Error("expected a root");
    expect(later.root).toEqual(early.root);

    // And an old proof still checks against the old root, which is what makes a
    // published root worth publishing.
    const proof = await proveInChain(tenant, 2, entries, { size: 5 });
    if (!proof.ok) throw new Error("expected a proof");
    expect(verifyInclusion(proof.proof, early.root!).ok).toBe(true);
  });

  it("differs at every size, so a root without its size is not checkable", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 6);
    const roots = new Set<string>();
    for (let size = 1; size <= 6; size += 1) {
      const result = await rootOfChain(tenant, entries, { size });
      if (!result.ok || result.root === null) throw new Error("expected a root");
      roots.add(result.root.root);
    }
    expect(roots.size).toBe(6);
  });
});

describe("verifyInclusion", () => {
  it("accepts every position of a log", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 9);
    const rooted = await rootOfChain(tenant, entries);
    if (!rooted.ok || rooted.root === null) throw new Error("expected a root");

    for (let seq = 1; seq <= 9; seq += 1) {
      const proof = await proveInChain(tenant, seq, entries);
      if (!proof.ok) throw new Error("expected a proof");
      expect(verifyInclusion(proof.proof, rooted.root), `seq ${seq}`).toMatchObject({
        ok: true,
        seq,
        size: 9,
      });
    }
  });

  it("accepts the only entry of a one-entry log, whose path is empty", async () => {
    const { proof, trusted } = await proofOf(1, 1);
    expect(proof.path).toEqual([]);
    expect(verifyInclusion(proof, trusted)).toMatchObject({ ok: true, seq: 1, size: 1 });
    // And still refuses it against a root that is not this log's.
    expect(verifyInclusion(proof, parseRoot(proof.tenant, `1:${"c".repeat(64)}`))).toMatchObject({
      ok: false,
      kind: "root_mismatch",
    });
  });

  it("rejects a flipped sibling, wherever in the path it is", async () => {
    const { proof, trusted } = await proofOf(9, 4);
    expect(proof.path.length).toBeGreaterThan(2);

    for (let i = 0; i < proof.path.length; i += 1) {
      const path = [...proof.path];
      path[i] = createHash("sha256").update(`other-${i}`).digest("hex");
      const result = verifyInclusion({ ...proof, path }, trusted);
      expect(result.ok, `path[${i}]`).toBe(false);
      if (result.ok) continue;
      expect(result.kind).toBe("self_inconsistent");
    }
  });

  it("names an edited entry as edited, not as a path that does not add up", async () => {
    const { proof, trusted } = await proofOf(8, 3);
    const tampered = verifyInclusion(
      { ...proof, entry: edit(proof.entry, { actor: "somebody else" }) },
      trusted,
    );
    expect(tampered).toMatchObject({ ok: false, kind: "entry_tampered" });
  });

  it("rejects an entry that was edited and resealed", async () => {
    const { proof, trusted } = await proofOf(8, 3);
    // A rewritten row whose hash was recomputed passes its own hash check. The
    // leaf is a different leaf, so the path no longer reaches the root.
    const result = verifyInclusion(
      { ...proof, entry: reseal(proof.entry, { actor: "somebody else" }) },
      trusted,
    );
    expect(result).toMatchObject({ ok: false, kind: "self_inconsistent" });
  });

  it("rejects an entry presented at a position it was not written at", async () => {
    const { proof, trusted } = await proofOf(9, 3);
    // seq 3 and seq 4 of a nine-entry log need a path of the same length, so this
    // gets past the shape check and is caught by the hash covering the position.
    expect(inclusionPathLength(2, 9)).toBe(inclusionPathLength(3, 9));
    expect(verifyInclusion({ ...proof, seq: 4 }, trusted)).toMatchObject({
      ok: false,
      kind: "entry_tampered",
    });
  });

  it("rejects a path that is not the length this position needs", async () => {
    const { proof, trusted } = await proofOf(8, 3);
    const padded = verifyInclusion({ ...proof, path: [...proof.path, proof.path[0]!] }, trusted);
    expect(padded).toMatchObject({ ok: false, kind: "wrong_shape" });
    const short = verifyInclusion({ ...proof, path: proof.path.slice(1) }, trusted);
    expect(short).toMatchObject({ ok: false, kind: "wrong_shape" });
  });

  it("rejects a root taken at another size, and says which size to ask for", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 10);
    const proof = await proveInChain(tenant, 2, entries, { size: 4 });
    const rooted = await rootOfChain(tenant, entries, { size: 10 });
    if (!proof.ok || !rooted.ok || rooted.root === null) throw new Error("expected both");

    const result = verifyInclusion(proof.proof, rooted.root);
    expect(result).toMatchObject({ ok: false, kind: "different_commitment" });
    if (!result.ok) expect(result.detail).toContain("size 10");
  });

  it("rejects a root for another tenant", async () => {
    const { proof } = await proofOf(5, 2);
    const other = await proofOf(5, 2);
    expect(verifyInclusion(proof, other.trusted)).toMatchObject({
      ok: false,
      kind: "different_commitment",
    });
  });

  it("rejects a proof that contradicts the root it carries", async () => {
    const { proof, trusted } = await proofOf(5, 2);
    const result = verifyInclusion({ ...proof, root: "f".repeat(64) }, trusted);
    expect(result).toMatchObject({ ok: false, kind: "self_inconsistent" });
  });

  it("separates a wrong root from a proof that cannot be read at all", async () => {
    const { proof, tenant } = await proofOf(5, 2);
    // Same size and tenant, a root that simply is not this log's.
    const foreign = parseRoot(tenant, `5:${"a".repeat(64)}`);
    expect(verifyInclusion(proof, foreign)).toMatchObject({
      ok: false,
      kind: "root_mismatch",
    });
  });

  it("rejects a position that is not inside the size it claims", async () => {
    const { proof, trusted } = await proofOf(5, 2);
    expect(verifyInclusion({ ...proof, seq: 9 }, trusted)).toMatchObject({
      ok: false,
      kind: "out_of_range",
    });
    expect(verifyInclusion({ ...proof, seq: 0 }, trusted)).toMatchObject({
      ok: false,
      kind: "out_of_range",
    });
  });

  it("rejects a path element that is not a hash", async () => {
    const { proof, trusted } = await proofOf(5, 2);
    expect(verifyInclusion({ ...proof, path: ["not a hash"] }, trusted)).toMatchObject({
      ok: false,
      kind: "wrong_shape",
    });
  });
});

describe("rooting and proving refuse a chain that does not verify", () => {
  it("returns the break instead of a root", async () => {
    const tenant = tenantName();
    const entries: AuditEntry[] = [...chain(tenant, 6)];
    entries[2] = edit(entries[2]!, { action: "invoice.unvoid" });

    const rooted = await rootOfChain(tenant, entries);
    expect(rooted).toMatchObject({ ok: false, break: { kind: "tampered", seq: 3 } });

    // Including when the entry asked about is before the break: a root is a
    // statement about the whole prefix, so half of one is not an answer.
    const proof = await proveInChain(tenant, 1, entries);
    expect(proof).toMatchObject({ ok: false, break: { kind: "tampered", seq: 3 } });
  });

  it("reports a chain that no longer reaches the size asked for", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 4);
    const rooted = await rootOfChain(tenant, entries, { size: 6 });
    expect(rooted).toMatchObject({ ok: false, break: { kind: "truncated", seq: 6 } });
    if (!rooted.ok) expect(rooted.break.detail).toContain("ends at seq 4");
  });

  it("reports a proof asked for past the end of the chain", async () => {
    const tenant = tenantName();
    const proof = await proveInChain(tenant, 7, chain(tenant, 4));
    expect(proof).toMatchObject({ ok: false, break: { kind: "truncated", seq: 7 } });
  });

  it("has no root for an empty chain, rather than a root over nothing", async () => {
    const tenant = tenantName();
    const rooted = await rootOfChain(tenant, []);
    expect(rooted).toMatchObject({ ok: true, root: null });
  });

  it("refuses a request that contradicts itself", async () => {
    const tenant = tenantName();
    await expect(proveInChain(tenant, 5, chain(tenant, 9), { size: 4 })).rejects.toThrow(
      /not inside a root over 4/,
    );
    await expect(rootOfChain(tenant, chain(tenant, 9), { size: 0 })).rejects.toThrow(
      /positive integer/,
    );
    await expect(proveInChain(tenant, 0, chain(tenant, 9))).rejects.toThrow(/positive integer/);
  });
});

describe("a proof survives the wire", () => {
  it("encodes, decodes and still verifies", async () => {
    const { proof, trusted } = await proofOf(11, 7);
    const decoded = decodeProof(encodeProof(proof));
    expect(decoded).toEqual(proof);
    expect(verifyInclusion(decoded, trusted).ok).toBe(true);
  });

  it("verifies against a root that was written down as text and read back", async () => {
    const { proof, trusted, tenant } = await proofOf(11, 7);
    const written = `${trusted.size}:${trusted.root}`;
    expect(verifyInclusion(proof, parseRoot(tenant, written)).ok).toBe(true);
  });

  it("carries only the one entry it is about", async () => {
    const { proof } = await proofOf(11, 7);
    const text = encodeProof(proof);
    expect(text).toContain("invoice:7");
    // The other ten entries' resources are not in the file; their hashes are.
    for (const seq of [1, 2, 3, 4, 5, 6, 8, 9, 10, 11]) {
      expect(text).not.toContain(`invoice:${seq}`);
    }
  });
});
