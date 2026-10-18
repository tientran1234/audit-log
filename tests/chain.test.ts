import { describe, expect, it } from "vitest";
import { GENESIS_HASH, entryHash, isHash, seal, verifyChain } from "../src/chain.js";
import { canonicalJson } from "../src/canonical.js";
import { AnchorConflictError, type AuditEntry, type SealedEntry } from "../src/types.js";
import { at, chain, draft, edit, reseal, tenantName } from "./helpers.js";

/** Every break test is the same shape: hand `verifyChain` a chain and read the verdict. */
async function verdict(tenant: string, entries: readonly AuditEntry[], anchorSeq?: number) {
  const anchorEntry = anchorSeq === undefined ? undefined : entries[anchorSeq - 1];
  return verifyChain(
    tenant,
    entries,
    anchorEntry === undefined
      ? {}
      : { anchor: { tenant, seq: anchorEntry.seq, hash: anchorEntry.hash } },
  );
}

describe("entryHash", () => {
  it("is pinned to a known value, so a change to the preimage cannot pass unnoticed", () => {
    const entry = {
      tenant: "acme",
      seq: 1,
      recordedAt: new Date("2026-06-01T09:00:00.000Z"),
      actor: "user:42",
      action: "invoice.void",
      resource: "invoice:1001",
      payloadJson: '{"reason":"duplicate"}',
      prevHash: GENESIS_HASH,
    };
    expect(entryHash(entry)).toBe(
      "6416ba488c22862a2490785a2a08979ef25df9c43b8263e2454ff58884aa98f4",
    );
  });

  it("covers the position, so an entry cannot be moved within the chain", () => {
    const base = {
      tenant: "acme",
      recordedAt: at(0),
      actor: "a",
      action: "b",
      resource: "c",
      payloadJson: "null",
      prevHash: GENESIS_HASH,
    };
    expect(entryHash({ ...base, seq: 1 })).not.toBe(entryHash({ ...base, seq: 2 }));
  });

  it("covers the tenant, so an entry cannot be moved between chains", () => {
    const base = {
      seq: 1,
      recordedAt: at(0),
      actor: "a",
      action: "b",
      resource: "c",
      payloadJson: "null",
      prevHash: GENESIS_HASH,
    };
    expect(entryHash({ ...base, tenant: "acme" })).not.toBe(
      entryHash({ ...base, tenant: "acme2" }),
    );
  });

  it("covers the time, so an entry cannot be backdated", () => {
    const base = {
      tenant: "acme",
      seq: 1,
      actor: "a",
      action: "b",
      resource: "c",
      payloadJson: "null",
      prevHash: GENESIS_HASH,
    };
    expect(entryHash({ ...base, recordedAt: at(0) })).not.toBe(
      entryHash({ ...base, recordedAt: at(1) }),
    );
  });

  it("cannot be forged by moving text across a field boundary", () => {
    const base = {
      tenant: "acme",
      seq: 1,
      recordedAt: at(0),
      payloadJson: "null",
      prevHash: GENESIS_HASH,
    };
    expect(entryHash({ ...base, actor: "user:4", action: "2.void", resource: "x" })).not.toBe(
      entryHash({ ...base, actor: "user:42", action: ".void", resource: "x" }),
    );
  });

  it("produces a lowercase hex digest", () => {
    expect(isHash(chain("acme", 1)[0]!.hash)).toBe(true);
  });
});

describe("verifyChain", () => {
  it("accepts a healthy chain and reports its head", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 5);
    const result = await verdict(tenant, entries);

    expect(result.ok).toBe(true);
    expect(result.entries).toBe(5);
    if (result.ok) expect(result.head).toEqual({ tenant, seq: 5, hash: entries[4]!.hash });
  });

  it("accepts an empty chain, and says so", async () => {
    const result = await verdict("nobody", []);
    expect(result).toEqual({ ok: true, tenant: "nobody", entries: 0, head: null });
  });

  it.each(["actor", "action", "resource"] as const)(
    "reports an edited %s as tampered, at the entry that was edited",
    async (field) => {
      const tenant = tenantName();
      const entries = chain(tenant, 4);
      entries[1] = edit(entries[1]!, { [field]: "rewritten" }) as SealedEntry;

      const result = await verdict(tenant, entries);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.break.kind).toBe("tampered");
        expect(result.break.seq).toBe(2);
      }
      // One entry verified before the break.
      expect(result.entries).toBe(1);
    },
  );

  it("reports an edited payload as tampered", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 3);
    entries[1] = edit(entries[1]!, {
      payloadJson: canonicalJson({ reason: "authorised" }),
    }) as SealedEntry;

    const result = await verdict(tenant, entries);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.break).toMatchObject({ kind: "tampered", seq: 2 });
  });

  it("reports a backdated entry as tampered", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 3);
    entries[2] = edit(entries[2]!, { recordedAt: at(0) }) as SealedEntry;

    const result = await verdict(tenant, entries);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.break).toMatchObject({ kind: "tampered", seq: 3 });
  });

  it("reports a removed entry as missing, and names the position that is gone", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 5);
    const withHole = [...entries.slice(0, 2), ...entries.slice(3)];

    const result = await verdict(tenant, withHole);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.break.kind).toBe("missing");
      expect(result.break.seq).toBe(3);
      expect(result.break.detail).toContain("1 entry is gone");
    }
  });

  it("counts a run of removed entries", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 6);
    const result = await verdict(tenant, [...entries.slice(0, 1), ...entries.slice(4)]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.break.detail).toContain("3 entries are gone");
  });

  it("catches a rewritten entry even when its own hash was recomputed", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 4);
    // The patient attack: edit the row *and* fix its hash. Only the next entry's
    // prevHash notices.
    entries[1] = reseal(entries[1]!, { actor: "user:99" }) as SealedEntry;

    const result = await verdict(tenant, entries);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.break).toMatchObject({ kind: "broken_link", seq: 3 });
  });

  it("catches an entry re-linked to skip its predecessor", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 3);
    entries[2] = reseal(entries[2]!, { prevHash: entries[0]!.hash }) as SealedEntry;

    const result = await verdict(tenant, entries);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.break).toMatchObject({ kind: "broken_link", seq: 3 });
  });

  it("refuses a chain that does not start at seq 1", async () => {
    const tenant = tenantName();
    const result = await verdict(tenant, chain(tenant, 3).slice(1));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.break).toMatchObject({ kind: "bad_genesis", seq: 1 });
  });

  it("refuses a first entry that does not link to genesis", async () => {
    const tenant = tenantName();
    const rebased = reseal(chain(tenant, 1)[0]!, { prevHash: "a".repeat(64) });
    const result = await verdict(tenant, [rebased]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.break).toMatchObject({ kind: "bad_genesis", seq: 1 });
  });

  it("refuses an entry spliced in from another tenant", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 3);
    const foreign = chain("someone-else", 3)[1]!;
    entries[1] = foreign as SealedEntry;

    const result = await verdict(tenant, entries);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.break.kind).toBe("broken_link");
      expect(result.break.detail).toContain('tenant "someone-else"');
    }
  });

  it("refuses an entry whose stored payload is not canonical", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 2);
    // Sealed honestly, but over a payload whose keys are in the wrong order. Only
    // a writer that is not this package can produce this.
    entries[1] = reseal(entries[1]!, { payloadJson: '{"b":1,"a":2}' }) as SealedEntry;

    const result = await verdict(tenant, entries);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.break).toMatchObject({ kind: "non_canonical_payload", seq: 2 });
  });

  it("refuses an entry whose payload is not JSON at all", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 1);
    entries[0] = reseal(entries[0]!, { payloadJson: "not json" }) as SealedEntry;

    const result = await verdict(tenant, entries);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.break.kind).toBe("non_canonical_payload");
  });

  it("reports time running backwards between two otherwise valid entries", async () => {
    const tenant = tenantName();
    const first = seal({
      tenant,
      seq: 1,
      prevHash: GENESIS_HASH,
      recordedAt: at(1000),
      draft: draft(),
    });
    const second = seal({
      tenant,
      seq: 2,
      prevHash: first.hash,
      recordedAt: at(0),
      draft: draft(),
    });

    const result = await verdict(tenant, [first, second]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.break).toMatchObject({ kind: "non_monotonic_time", seq: 2 });
  });

  it("accepts two entries recorded in the same millisecond", async () => {
    const tenant = tenantName();
    const first = seal({ tenant, seq: 1, prevHash: GENESIS_HASH, recordedAt: at(5), draft: draft() });
    const second = seal({ tenant, seq: 2, prevHash: first.hash, recordedAt: at(5), draft: draft() });
    expect((await verdict(tenant, [first, second])).ok).toBe(true);
  });

  describe("anchors", () => {
    it("cannot detect a truncated tail on its own — which is why anchors exist", async () => {
      const tenant = tenantName();
      const cut = chain(tenant, 5).slice(0, 3);
      // Deliberate: a chain with its newest entries deleted is a valid chain. If
      // this ever starts failing, someone has claimed a guarantee the hashes
      // cannot give.
      expect((await verdict(tenant, cut)).ok).toBe(true);
    });

    it("detects a truncated tail against an anchor", async () => {
      const tenant = tenantName();
      const entries = chain(tenant, 5);
      const result = await verifyChain(tenant, entries.slice(0, 3), {
        anchor: { tenant, seq: 5, hash: entries[4]!.hash },
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.break).toMatchObject({ kind: "truncated", seq: 5 });
        expect(result.break.detail).toContain("ends at seq 3");
      }
    });

    it("detects an emptied chain against an anchor", async () => {
      const tenant = tenantName();
      const entries = chain(tenant, 2);
      const result = await verifyChain(tenant, [], {
        anchor: { tenant, seq: 2, hash: entries[1]!.hash },
      });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.break.kind).toBe("truncated");
    });

    it("detects history rewritten and replayed to the same length", async () => {
      const tenant = tenantName();
      const original = chain(tenant, 3);
      const rewritten: SealedEntry[] = chain(tenant, 1);
      // Rebuild entries 2 and 3 with different content on top of the same genesis.
      let prev = rewritten[0]!;
      for (const seq of [2, 3]) {
        prev = seal({
          tenant,
          seq,
          prevHash: prev.hash,
          recordedAt: at(seq),
          draft: draft({ action: "invoice.approve" }),
        });
        rewritten.push(prev);
      }

      // Internally consistent, and undetectable without the anchor.
      expect((await verdict(tenant, rewritten)).ok).toBe(true);

      const result = await verifyChain(tenant, rewritten, {
        anchor: { tenant, seq: 3, hash: original[2]!.hash },
      });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.break).toMatchObject({ kind: "anchor_mismatch", seq: 3 });
    });

    it("accepts a chain that has grown past its anchor", async () => {
      const tenant = tenantName();
      const entries = chain(tenant, 5);
      const result = await verifyChain(tenant, entries, {
        anchor: { tenant, seq: 2, hash: entries[1]!.hash },
      });
      expect(result.ok).toBe(true);
    });

    it("refuses an anchor for a different tenant instead of ignoring it", async () => {
      const entries = chain("a", 1);
      await expect(
        verifyChain("a", entries, { anchor: { tenant: "b", seq: 1, hash: entries[0]!.hash } }),
      ).rejects.toThrow(/anchor is for tenant "b"/);
    });
  });

  describe("a journal's worth of anchors", () => {
    /** The original chain, and the same positions rewritten from `from` onwards. */
    function rewriteFrom(tenant: string, length: number, from: number) {
      const original = chain(tenant, length);
      const rewritten: SealedEntry[] = [...original.slice(0, from - 1)];
      for (let seq = from; seq <= length; seq += 1) {
        rewritten.push(
          seal({
            tenant,
            seq,
            prevHash: rewritten.at(-1)?.hash ?? GENESIS_HASH,
            recordedAt: at(seq),
            draft: draft({ action: "invoice.approve" }),
          }),
        );
      }
      return { original, rewritten };
    }

    it("reports the oldest anchor the chain no longer matches, not the newest", async () => {
      const tenant = tenantName();
      const { original, rewritten } = rewriteFrom(tenant, 5, 2);
      const anchors = [2, 4].map((seq) => ({ tenant, seq, hash: original[seq - 1]!.hash }));

      const result = await verifyChain(tenant, rewritten, { anchors });
      expect(result.ok).toBe(false);
      // Every anchor at or below an entry is settled as the walk passes it, so the
      // break names the earliest position that diverged. Checking only the newest
      // anchor would report seq 4 and hide how far back the rewrite reaches.
      if (!result.ok) expect(result.break).toMatchObject({ kind: "anchor_mismatch", seq: 2 });
    });

    it("reports the lowest anchor a truncated chain fails to reach", async () => {
      const tenant = tenantName();
      const entries = chain(tenant, 5);
      const anchors = [3, 5].map((seq) => ({ tenant, seq, hash: entries[seq - 1]!.hash }));

      const result = await verifyChain(tenant, entries.slice(0, 2), { anchors });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.break).toMatchObject({ kind: "truncated", seq: 3 });
    });

    it("accepts a chain that reaches every anchor in the journal", async () => {
      const tenant = tenantName();
      const entries = chain(tenant, 4);
      const anchors = [1, 2, 4].map((seq) => ({ tenant, seq, hash: entries[seq - 1]!.hash }));
      expect((await verifyChain(tenant, entries, { anchors })).ok).toBe(true);
    });

    it("merges a single --anchor with the journal's anchors", async () => {
      const tenant = tenantName();
      const entries = chain(tenant, 5);
      const result = await verifyChain(tenant, entries.slice(0, 4), {
        anchor: { tenant, seq: 5, hash: entries[4]!.hash },
        anchors: [{ tenant, seq: 2, hash: entries[1]!.hash }],
      });
      // The journal's anchor is satisfied; the one passed by hand is not.
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.break).toMatchObject({ kind: "truncated", seq: 5 });
    });

    it("tolerates the same position anchored twice", async () => {
      const tenant = tenantName();
      const entries = chain(tenant, 2);
      const anchor = { tenant, seq: 2, hash: entries[1]!.hash };
      expect((await verifyChain(tenant, entries, { anchors: [anchor, anchor] })).ok).toBe(true);
    });

    it("refuses two anchors that disagree about one position", async () => {
      const tenant = tenantName();
      const { original, rewritten } = rewriteFrom(tenant, 3, 2);
      // No chain can satisfy both, so there is no verdict to give about the
      // entries — the pair of anchors is itself the finding.
      await expect(
        verifyChain(tenant, rewritten, {
          anchors: [
            { tenant, seq: 3, hash: original[2]!.hash },
            { tenant, seq: 3, hash: rewritten[2]!.hash },
          ],
        }),
      ).rejects.toThrow(AnchorConflictError);
    });

    it("refuses a journal anchor belonging to another tenant", async () => {
      const entries = chain("a", 1);
      await expect(
        verifyChain("a", entries, { anchors: [{ tenant: "b", seq: 1, hash: entries[0]!.hash }] }),
      ).rejects.toThrow(/anchor is for tenant "b"/);
    });
  });
});
