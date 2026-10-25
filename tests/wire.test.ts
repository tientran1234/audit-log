import { describe, expect, it } from "vitest";
import {
  decodeEntries,
  decodeEntry,
  decodeProof,
  encodeEntry,
  encodeProof,
  formatAnchor,
  formatRoot,
  parseAnchor,
  parseRoot,
} from "../src/wire.js";
import { proveInChain } from "../src/merkle.js";
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

describe("the root format", () => {
  it("round-trips a size and a hash", () => {
    const tenant = tenantName();
    const root = parseRoot(tenant, `12:${"a".repeat(64)}`);
    expect(root).toMatchObject({ tenant, size: 12, root: "a".repeat(64) });
    expect(formatRoot(root)).toBe(`12:${"a".repeat(64)}`);
  });

  it("refuses a root without a size, or with a size that is not one", () => {
    const tenant = tenantName();
    expect(() => parseRoot(tenant, "a".repeat(64))).toThrow(MalformedEntryError);
    expect(() => parseRoot(tenant, `0:${"a".repeat(64)}`)).toThrow(/positive integer/);
    expect(() => parseRoot(tenant, "12:nope")).toThrow(/64 hex/);
  });
});

describe("the proof format", () => {
  it("is indented, because somebody has to read the entry in it", async () => {
    const tenant = tenantName();
    const proof = await proveInChain(tenant, 2, chain(tenant, 5));
    if (!proof.ok) throw new Error("expected a proof");
    const text = encodeProof(proof.proof);
    expect(text).toContain("\n  \"tenant\"");
    expect(JSON.parse(text)).toMatchObject({ format: "audit-log/inclusion/v1" });
  });

  it("refuses a file written under another format", async () => {
    const tenant = tenantName();
    const proof = await proveInChain(tenant, 2, chain(tenant, 5));
    if (!proof.ok) throw new Error("expected a proof");
    const row = JSON.parse(encodeProof(proof.proof)) as Record<string, unknown>;

    row["format"] = "audit-log/inclusion/v2";
    expect(() => decodeProof(JSON.stringify(row))).toThrow(/unknown proof format/);
    delete row["format"];
    expect(() => decodeProof(JSON.stringify(row))).toThrow(/unknown proof format/);
  });

  it("refuses a proof whose parts are not what they have to be", async () => {
    const tenant = tenantName();
    const proof = await proveInChain(tenant, 2, chain(tenant, 5));
    if (!proof.ok) throw new Error("expected a proof");
    const text = encodeProof(proof.proof);
    const reread = (change: (row: Record<string, unknown>) => void): void => {
      const row = JSON.parse(text) as Record<string, unknown>;
      change(row);
      decodeProof(JSON.stringify(row));
    };

    expect(() => reread((row) => (row["seq"] = 0))).toThrow(/positive integer/);
    expect(() => reread((row) => (row["size"] = 1.5))).toThrow(/positive integer/);
    expect(() => reread((row) => (row["root"] = "short"))).toThrow(/64 hex/);
    expect(() => reread((row) => (row["path"] = "nope"))).toThrow(/array of hashes/);
    expect(() => reread((row) => (row["path"] = ["nope"]))).toThrow(/64 hex/);
    expect(() => reread((row) => delete row["entry"])).toThrow(MalformedEntryError);
    expect(() => decodeProof("not json")).toThrow(/not valid JSON/);
    expect(() => decodeProof("[]")).toThrow(/not a JSON object/);
  });
});
