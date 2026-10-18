import { describe, expect, it } from "vitest";
import {
  decodeAnchorRecord,
  encodeAnchorRecord,
  readJournal,
} from "../src/journal.js";
import { AnchorConflictError, MalformedEntryError } from "../src/types.js";
import { chain, tenantName } from "./helpers.js";

const OBSERVED = new Date("2026-10-11T09:00:00.000Z");

function line(tenant: string, seq: number, hash: string, observedAt = OBSERVED): string {
  return encodeAnchorRecord({ tenant, seq, hash, observedAt });
}

describe("the journal line format", () => {
  it("round-trips a record", () => {
    const hash = "a".repeat(64);
    const decoded = decodeAnchorRecord(line("acme", 7, hash));
    expect(decoded).toEqual({ tenant: "acme", seq: 7, hash, observedAt: OBSERVED });
  });

  it("is one line, so a checkpoint can be appended without reading the file", () => {
    expect(line("acme", 1, "b".repeat(64))).not.toContain("\n");
  });

  it("refuses a line that is not a hash, rather than anchoring to nonsense", () => {
    const bad = JSON.stringify({ tenant: "acme", seq: 1, hash: "beef", observedAt: "2026-01-01" });
    expect(() => decodeAnchorRecord(bad)).toThrow(MalformedEntryError);
  });

  it.each([
    ["not JSON at all", "{ nope"],
    ["an array", "[]"],
    ["no tenant", JSON.stringify({ seq: 1, hash: "a".repeat(64), observedAt: "2026-01-01" })],
    ["seq 0", JSON.stringify({ tenant: "a", seq: 0, hash: "a".repeat(64), observedAt: "x" })],
    [
      "a time that is not a time",
      JSON.stringify({ tenant: "a", seq: 1, hash: "a".repeat(64), observedAt: "whenever" }),
    ],
  ])("refuses %s", (_name, text) => {
    expect(() => decodeAnchorRecord(text)).toThrow(MalformedEntryError);
  });
});

describe("readJournal", () => {
  it("groups anchors by tenant, lowest position first", async () => {
    const entries = chain("acme", 3);
    const journal = await readJournal([
      line("zz", 1, entries[0]!.hash),
      line("acme", 3, entries[2]!.hash),
      "",
      line("acme", 1, entries[0]!.hash),
    ]);

    expect(journal.tenants).toEqual(["acme", "zz"]);
    expect(journal.anchorsFor("acme").map((a) => a.seq)).toEqual([1, 3]);
    expect(journal.anchorsFor("nobody")).toEqual([]);
  });

  it("keeps the earliest observation of a position that was anchored twice", async () => {
    const hash = "c".repeat(64);
    const later = new Date(OBSERVED.getTime() + 86_400_000);
    const journal = await readJournal([line("acme", 2, hash), line("acme", 2, hash, later)]);

    expect(journal.anchorsFor("acme")).toHaveLength(1);
    // The earliest line is the one that proves how long the position has held.
    expect(journal.recordAt("acme", 2)?.observedAt).toEqual(OBSERVED);
  });

  it("refuses a journal that disagrees with itself about one position", async () => {
    const first = line("acme", 2, "d".repeat(64));
    const second = line("acme", 2, "e".repeat(64));
    // This needs no database: whichever line is right, something wrote a chain
    // this file has already seen a different version of.
    await expect(readJournal([first, second])).rejects.toThrow(AnchorConflictError);
  });

  it("keeps a position that went backwards, because that is the evidence", async () => {
    const entries = chain("acme", 5);
    const journal = await readJournal([
      line("acme", 5, entries[4]!.hash),
      line("acme", 2, entries[1]!.hash),
    ]);
    // Someone truncated the chain and checkpointed it. Dropping the higher anchor
    // as "stale" would throw away the only thing that reports the truncation.
    expect(journal.anchorsFor("acme").map((a) => a.seq)).toEqual([2, 5]);
  });

  it("reads an empty file as a journal with no anchors", async () => {
    const journal = await readJournal(["", "  "]);
    expect(journal.tenants).toEqual([]);
  });

  it("does not confuse two tenants that anchored the same position", async () => {
    const a = tenantName();
    const b = tenantName();
    const journal = await readJournal([line(a, 1, "f".repeat(64)), line(b, 1, "0".repeat(64))]);
    expect(journal.anchorsFor(a)[0]?.hash).toBe("f".repeat(64));
    expect(journal.anchorsFor(b)[0]?.hash).toBe("0".repeat(64));
  });
});
