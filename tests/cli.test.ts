import { describe, expect, it } from "vitest";
import { EXIT_BROKEN, EXIT_OK, EXIT_USAGE, run, type CliIo } from "../src/cli.js";
import { MemoryStore } from "../src/store/memory.js";
import { AuditLog } from "../src/log.js";
import { at, tenantName } from "./helpers.js";
import type { AuditEntry } from "../src/types.js";

interface Harness {
  readonly io: CliIo;
  readonly out: string[];
  readonly err: string[];
  readonly store: MemoryStore;
}

function harness(store: MemoryStore, files: Record<string, string[]> = {}): Harness {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    store,
    io: {
      out: (line) => out.push(line),
      err: (line) => err.push(line),
      env: {},
      // The same store for every command in a test. `MemoryStore.close()` releases
      // nothing, so the commands' own `close()` calls are harmless here.
      openStore: async () => store,
      readLines: (path) => linesOf(files[path] ?? []),
    },
  };
}

async function seed(tenant: string, count: number): Promise<MemoryStore> {
  const store = new MemoryStore();
  const log = new AuditLog({ store });
  for (let i = 0; i < count; i += 1) {
    await log.append({ tenant, actor: "user:1", action: "act", resource: `r:${i}`, at: at(i) });
  }
  return store;
}

describe("audit-log verify", () => {
  it("reports an intact chain and exits 0", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 3));
    expect(await run(["verify", "--tenant", tenant], h.io)).toBe(EXIT_OK);
    expect(h.out[0]).toMatch(new RegExp(`^${tenant}  ok  3 entries  head 3:[0-9a-f]{64}$`));
  });

  it("reports a broken chain and exits 1, so cron notices", async () => {
    const tenant = tenantName();
    const entries = await entriesOf(await seed(tenant, 4), tenant);
    entries[1] = { ...entries[1]!, actor: "somebody else" };
    const h = harness(MemoryStore.from(entries));

    expect(await run(["verify", "--tenant", tenant], h.io)).toBe(EXIT_BROKEN);
    expect(h.out[0]).toContain("BROKEN at seq 2");
    expect(h.out[0]).toContain("tampered");
  });

  it("prints a machine-readable result with --json", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 2));
    await run(["verify", "--tenant", tenant, "--json"], h.io);
    expect(JSON.parse(h.out[0]!)).toMatchObject({ ok: true, tenant, entries: 2 });
  });

  it("verifies every tenant with --all, and exits 1 if any is broken", async () => {
    const good = tenantName();
    const bad = tenantName();
    const store = await seed(good, 2);
    const badEntries = await entriesOf(await seed(bad, 3), bad);
    badEntries.splice(1, 1);
    const combined = MemoryStore.from([...(await entriesOf(store, good)), ...badEntries]);

    const h = harness(combined);
    expect(await run(["verify", "--all"], h.io)).toBe(EXIT_BROKEN);
    expect(h.out.join("\n")).toContain(`${good}  ok`);
    expect(h.out.join("\n")).toContain("BROKEN");
  });

  it("accepts an anchor and rejects a truncated chain against it", async () => {
    const tenant = tenantName();
    const full = await entriesOf(await seed(tenant, 5), tenant);
    const anchor = `5:${full[4]!.hash}`;

    const intact = harness(MemoryStore.from(full));
    expect(await run(["verify", "--tenant", tenant, "--anchor", anchor], intact.io)).toBe(EXIT_OK);

    const cut = harness(MemoryStore.from(full.slice(0, 3)));
    // Without the anchor the shortened chain looks fine — that is the point of it.
    expect(await run(["verify", "--tenant", tenant], cut.io)).toBe(EXIT_OK);
    expect(await run(["verify", "--tenant", tenant, "--anchor", anchor], cut.io)).toBe(EXIT_BROKEN);
    expect(cut.out.at(-1)).toContain("truncated");
  });

  it("refuses one anchor for every tenant at once", async () => {
    const h = harness(await seed(tenantName(), 1));
    expect(await run(["verify", "--all", "--anchor", `1:${"a".repeat(64)}`], h.io)).toBe(EXIT_USAGE);
    expect(h.err.join("\n")).toContain("--anchor names one tenant's position");
  });

  it("refuses a malformed anchor rather than verifying against nothing", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 1));
    expect(await run(["verify", "--tenant", tenant, "--anchor", "nonsense"], h.io)).toBe(EXIT_USAGE);
  });

  it("needs a tenant", async () => {
    const h = harness(await seed(tenantName(), 1));
    expect(await run(["verify"], h.io)).toBe(EXIT_USAGE);
    expect(h.err.join("\n")).toContain("--tenant is required");
  });
});

describe("audit-log export and verify --file", () => {
  it("exports a chain an auditor can verify without the database", async () => {
    const tenant = tenantName();
    const store = await seed(tenant, 4);
    const exported = harness(store);
    expect(await run(["export", "--tenant", tenant], exported.io)).toBe(EXIT_OK);
    expect(exported.out).toHaveLength(4);

    // A different process, with the file and nothing else.
    const auditor = harness(new MemoryStore(), { "chain.ndjson": exported.out });
    expect(await run(["verify", "--file", "chain.ndjson", "--tenant", tenant], auditor.io)).toBe(
      EXIT_OK,
    );
    expect(auditor.out[0]).toContain("ok  4 entries");
  });

  it("catches an export that was edited on its way to the auditor", async () => {
    const tenant = tenantName();
    const store = await seed(tenant, 3);
    const exported = harness(store);
    await run(["export", "--tenant", tenant], exported.io);

    const edited = [...exported.out];
    edited[1] = edited[1]!.replace('"r:1"', '"r:9"');

    const auditor = harness(new MemoryStore(), { "chain.ndjson": edited });
    expect(await run(["verify", "--file", "chain.ndjson", "--tenant", tenant], auditor.io)).toBe(
      EXIT_BROKEN,
    );
    expect(auditor.out[0]).toContain("tampered");
  });

  it("refuses an export that belongs to another tenant", async () => {
    const tenant = tenantName();
    const exported = harness(await seed(tenant, 2));
    await run(["export", "--tenant", tenant], exported.io);

    const auditor = harness(new MemoryStore(), { "chain.ndjson": exported.out });
    expect(await run(["verify", "--file", "chain.ndjson", "--tenant", "someone-else"], auditor.io)).toBe(
      EXIT_BROKEN,
    );
  });

  it("reports a malformed export as a failure to answer, not as an intact log", async () => {
    const h = harness(new MemoryStore(), { "chain.ndjson": ["{ not json"] });
    expect(await run(["verify", "--file", "chain.ndjson", "--tenant", "acme"], h.io)).toBe(
      EXIT_USAGE,
    );
  });
});

describe("audit-log checkpoint", () => {
  it("prints an anchor that verify then accepts", async () => {
    const tenant = tenantName();
    const store = await seed(tenant, 3);
    const h = harness(store);

    expect(await run(["checkpoint", "--tenant", tenant], h.io)).toBe(EXIT_OK);
    const anchor = h.out[0]!;
    expect(anchor).toMatch(/^3:[0-9a-f]{64}$/);

    const check = harness(store);
    expect(await run(["verify", "--tenant", tenant, "--anchor", anchor], check.io)).toBe(EXIT_OK);
  });

  it("prints an anchor as JSON when asked", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 1));
    await run(["checkpoint", "--tenant", tenant, "--json"], h.io);
    expect(JSON.parse(h.out[0]!)).toMatchObject({ tenant, seq: 1 });
  });

  it("says so when a tenant has nothing to anchor", async () => {
    const h = harness(new MemoryStore());
    expect(await run(["checkpoint", "--tenant", "nobody"], h.io)).toBe(EXIT_OK);
    expect(h.err.join("\n")).toContain("no entries");
  });
});

describe("audit-log usage", () => {
  it("prints usage and exits 2 when given no command", async () => {
    const h = harness(new MemoryStore());
    expect(await run([], h.io)).toBe(EXIT_USAGE);
    expect(h.err.join("\n")).toContain("audit-log verify --tenant");
  });

  it("prints usage on --help and exits 0", async () => {
    const h = harness(new MemoryStore());
    expect(await run(["--help"], h.io)).toBe(EXIT_OK);
    expect(h.out.join("\n")).toContain("Exit codes");
  });

  it("refuses an unknown command", async () => {
    const h = harness(new MemoryStore());
    expect(await run(["delete", "--tenant", "acme"], h.io)).toBe(EXIT_USAGE);
    expect(h.err.join("\n")).toContain('unknown command "delete"');
  });

  it("refuses an unknown flag rather than ignoring it", async () => {
    const h = harness(new MemoryStore());
    expect(await run(["verify", "--tennant", "acme"], h.io)).toBe(EXIT_USAGE);
  });

  it("explains itself when DATABASE_URL is missing", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const code = await run(["verify", "--tenant", "acme"], {
      out: (line) => out.push(line),
      err: (line) => err.push(line),
      env: {},
    });
    expect(code).toBe(EXIT_USAGE);
    expect(err.join("\n")).toContain("DATABASE_URL is not set");
  });
});

describe("audit-log root", () => {
  it("prints <size>:<hash> for the whole chain", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 6));
    expect(await run(["root", "--tenant", tenant], h.io)).toBe(EXIT_OK);
    expect(h.out[0]).toMatch(/^6:[0-9a-f]{64}$/);
  });

  it("prints a root over a prefix with --size, and the same one every time", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 6));
    expect(await run(["root", "--tenant", tenant, "--size", "4"], h.io)).toBe(EXIT_OK);
    await run(["root", "--tenant", tenant, "--size", "4"], h.io);
    expect(h.out[0]).toMatch(/^4:[0-9a-f]{64}$/);
    expect(h.out[0]).toBe(h.out[1]);
    expect(h.out[0]).not.toBe(`6:${h.out[0]!.slice(2)}`);
  });

  it("refuses to publish a root for a chain that does not verify", async () => {
    const tenant = tenantName();
    const entries = await entriesOf(await seed(tenant, 5), tenant);
    entries[2] = { ...entries[2]!, action: "something else" };
    const h = harness(MemoryStore.from(entries));

    expect(await run(["root", "--tenant", tenant], h.io)).toBe(EXIT_BROKEN);
    expect(h.out[0]).toContain("BROKEN at seq 3");
  });

  it("reports a chain that no longer reaches a size somebody has a root for", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 3));
    expect(await run(["root", "--tenant", tenant, "--size", "5"], h.io)).toBe(EXIT_BROKEN);
    expect(h.out[0]).toContain("truncated");
  });

  it("says a tenant has no entries instead of rooting nothing", async () => {
    const tenant = tenantName();
    const h = harness(new MemoryStore());
    expect(await run(["root", "--tenant", tenant], h.io)).toBe(EXIT_OK);
    expect(h.err.join("\n")).toContain("has no entries");
    expect(h.out).toEqual([]);
  });

  it("refuses a size that is not a count", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 3));
    expect(await run(["root", "--tenant", tenant, "--size", "two"], h.io)).toBe(EXIT_USAGE);
    expect(h.err.join("\n")).toContain("--size must be a positive integer");
  });
});

describe("audit-log prove and verify-proof", () => {
  it("proves one entry, and the proof checks out against the published root", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 9));
    expect(await run(["root", "--tenant", tenant], h.io)).toBe(EXIT_OK);
    const root = h.out[0]!;

    expect(await run(["prove", "--tenant", tenant, "--seq", "4"], h.io)).toBe(EXIT_OK);
    const proof = h.out[1]!;

    // The auditor's side: a file, a root they already had, and no database.
    const checker = harness(new MemoryStore(), { "proof.json": proof.split("\n") });
    expect(
      await run(
        ["verify-proof", "--proof", "proof.json", "--tenant", tenant, "--root", root],
        checker.io,
      ),
    ).toBe(EXIT_OK);
    expect(checker.out[0]).toContain("seq 4 is in the log of 9 entries");
  });

  it("exits 1 when the proof does not hold against the root given", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 9));
    await run(["prove", "--tenant", tenant, "--seq", "4"], h.io);
    const proof = h.out[0]!;

    const checker = harness(new MemoryStore(), { "proof.json": proof.split("\n") });
    const other = `9:${"b".repeat(64)}`;
    expect(
      await run(
        ["verify-proof", "--proof", "proof.json", "--tenant", tenant, "--root", other],
        checker.io,
      ),
    ).toBe(EXIT_BROKEN);
    expect(checker.out[0]).toContain("root_mismatch");
  });

  it("exits 2 when the proof is for a different size than the root held", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 9));
    await run(["root", "--tenant", tenant, "--size", "5"], h.io);
    const rootAt5 = h.out[0]!;
    await run(["prove", "--tenant", tenant, "--seq", "2"], h.io);
    const proofAt9 = h.out[1]!;

    const checker = harness(new MemoryStore(), { "proof.json": proofAt9.split("\n") });
    expect(
      await run(
        ["verify-proof", "--proof", "proof.json", "--tenant", tenant, "--root", rootAt5],
        checker.io,
      ),
    ).toBe(EXIT_USAGE);
    expect(checker.out[0]).toContain("different_commitment");
  });

  it("exits 1 when the entry in the proof was edited", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 9));
    await run(["root", "--tenant", tenant], h.io);
    const root = h.out[0]!;
    await run(["prove", "--tenant", tenant, "--seq", "4"], h.io);
    const edited = JSON.parse(h.out[1]!) as { entry: Record<string, unknown> };
    edited.entry["actor"] = "somebody else";

    const checker = harness(new MemoryStore(), {
      "proof.json": JSON.stringify(edited).split("\n"),
    });
    expect(
      await run(
        ["verify-proof", "--proof", "proof.json", "--tenant", tenant, "--root", root],
        checker.io,
      ),
    ).toBe(EXIT_BROKEN);
    expect(checker.out[0]).toContain("entry_tampered");
  });

  it("refuses to check a proof against the root the proof itself carries", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 4));
    await run(["prove", "--tenant", tenant, "--seq", "2"], h.io);
    const checker = harness(new MemoryStore(), { "proof.json": h.out[0]!.split("\n") });

    expect(
      await run(["verify-proof", "--proof", "proof.json", "--tenant", tenant], checker.io),
    ).toBe(EXIT_USAGE);
    expect(checker.err.join("\n")).toContain("cannot vouch for itself");
  });

  it("works on an export, for a log whose database is gone", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 7));
    expect(await run(["export", "--tenant", tenant], h.io)).toBe(EXIT_OK);
    const ndjson = [...h.out];

    const archive = harness(new MemoryStore(), { "acme.ndjson": ndjson });
    expect(
      await run(["root", "--tenant", tenant, "--file", "acme.ndjson"], archive.io),
    ).toBe(EXIT_OK);
    const root = archive.out[0]!;
    expect(root).toMatch(/^7:[0-9a-f]{64}$/);

    const prover = harness(new MemoryStore(), { "acme.ndjson": ndjson });
    expect(
      await run(
        ["prove", "--tenant", tenant, "--seq", "3", "--file", "acme.ndjson"],
        prover.io,
      ),
    ).toBe(EXIT_OK);

    const checker = harness(new MemoryStore(), { "proof.json": prover.out[0]!.split("\n") });
    expect(
      await run(
        ["verify-proof", "--proof", "proof.json", "--tenant", tenant, "--root", root],
        checker.io,
      ),
    ).toBe(EXIT_OK);
  });

  it("needs a --seq, because a proof is about one entry", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 4));
    expect(await run(["prove", "--tenant", tenant], h.io)).toBe(EXIT_USAGE);
    expect(h.err.join("\n")).toContain("--seq is required");
  });

  it("reports a proof asked for past the end of the chain", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 4));
    expect(await run(["prove", "--tenant", tenant, "--seq", "9"], h.io)).toBe(EXIT_BROKEN);
    expect(h.out[0]).toContain("truncated");
  });

  it("exits 2 on a proof file it cannot read as a proof", async () => {
    const tenant = tenantName();
    const checker = harness(new MemoryStore(), { "proof.json": ["{\"nope\": true}"] });
    expect(
      await run(
        [
          "verify-proof",
          "--proof",
          "proof.json",
          "--tenant",
          tenant,
          "--root",
          `4:${"a".repeat(64)}`,
        ],
        checker.io,
      ),
    ).toBe(EXIT_USAGE);
    expect(checker.err.join("\n")).toContain("unknown proof format");
  });
});

async function entriesOf(store: MemoryStore, tenant: string): Promise<AuditEntry[]> {
  return store.read(tenant, 0, 1000);
}

async function* linesOf(lines: readonly string[]): AsyncGenerator<string> {
  for (const line of lines) yield line;
}
