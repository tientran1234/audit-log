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

async function entriesOf(store: MemoryStore, tenant: string): Promise<AuditEntry[]> {
  return store.read(tenant, 0, 1000);
}

async function* linesOf(lines: readonly string[]): AsyncGenerator<string> {
  for (const line of lines) yield line;
}
