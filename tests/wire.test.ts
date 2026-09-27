import { describe, expect, it } from "vitest";
import { decodeEntries, decodeEntry, encodeEntry, formatAnchor, parseAnchor } from "../src/wire.js";
import { verifyChain } from "../src/chain.js";
import { MalformedEntryError } from "../src/types.js";
import { chain, tenantName } from "./helpers.js";

describe("the export format", () => {
  it("round-trips an entry without disturbing its hash", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 4);
    const decoded = entries.map((entry) => decodeEntry(encodeEntry(entry)));

    expect(decoded).toEqual([...entries].map((e) => ({ ...e })));
    expect((await verifyChain(tenant, decoded)).ok).toBe(true);
  });

  it("writes one line per entry, with the payload readable as JSON", () => {
    const [entry] = chain(tenantName(), 1);
    const line = encodeEntry(entry!);

    expect(line).not.toContain("\n");
    expect((JSON.parse(line) as { payload: unknown }).payload).toEqual({ reason: "duplicate" });
  });

  it("carries a chain break through the export", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 3);
    const lines = entries.map(encodeEntry);
    // An auditor's copy of the log with entry 2's payload rewritten, the way a
    // text editor would do it.
    lines[1] = lines[1]!.replace('"duplicate"', '"authorised"');

    const result = await verifyChain(tenant, decodeEntries(linesOf(lines)));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.break).toMatchObject({ kind: "tampered", seq: 2 });
  });

  it("survives a re-ordered payload in the file, because canonical form is a function of the value", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 1);
    const line = JSON.parse(encodeEntry(entries[0]!)) as Record<string, unknown>;
    // A tool that pretty-printed and re-serialised the export must not turn an
    // intact log into a broken one.
    const shuffled = JSON.stringify({ hash: line["hash"], ...line });

    expect(decodeEntry(shuffled).hash).toBe(entries[0]!.hash);
    expect((await verifyChain(tenant, [decodeEntry(shuffled)])).ok).toBe(true);
  });

  it("skips blank lines", async () => {
    const entries = chain(tenantName(), 2);
    const decoded = [];
    for await (const entry of decodeEntries(linesOf([encodeEntry(entries[0]!), "", "  "]))) {
      decoded.push(entry);
    }
    expect(decoded).toHaveLength(1);
  });

  it.each([
    ["not json", "{"],
    ["a JSON array", "[]"],
    ["a missing field", '{"tenant":"a"}'],
    ["a zero sequence", '{"tenant":"a","seq":0,"at":"2026-01-01T00:00:00.000Z"}'],
    ["a hash that is not hex", '{"tenant":"a","seq":1,"at":"2026-01-01T00:00:00.000Z","actor":"a","action":"b","resource":"c","payload":null,"prevHash":"zz","hash":"zz"}'],
    ["an unparseable time", '{"tenant":"a","seq":1,"at":"whenever","actor":"a","action":"b","resource":"c","payload":null,"prevHash":"0","hash":"0"}'],
  ])("refuses %s", (_label, line) => {
    expect(() => decodeEntry(line)).toThrow(MalformedEntryError);
  });
});

describe("anchors", () => {
  it("round-trips through the text an operator writes down", () => {
    const tenant = tenantName();
    const [entry] = chain(tenant, 1);
    const anchor = { tenant, seq: entry!.seq, hash: entry!.hash };
    expect(parseAnchor(tenant, formatAnchor(anchor))).toEqual(anchor);
  });

  it("accepts an uppercase hash, because that is how people paste them", () => {
    const [entry] = chain("a", 1);
    expect(parseAnchor("a", `1:${entry!.hash.toUpperCase()}`).hash).toBe(entry!.hash);
  });

  it.each([["no colon", "abc"], ["no sequence", ":" + "a".repeat(64)], ["a short hash", "1:abc"]])(
    "refuses an anchor with %s",
    (_label, text) => {
      expect(() => parseAnchor("a", text)).toThrow(MalformedEntryError);
    },
  );
});

async function* linesOf(lines: readonly string[]): AsyncGenerator<string> {
  for (const line of lines) yield line;
}
