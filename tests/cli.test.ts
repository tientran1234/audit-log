import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  /** The filesystem the CLI sees: journals it appends to land here. */
  readonly files: Record<string, string[]>;
}

/** The clock a journal record is stamped with, so assertions can name it. */
const CHECKPOINTED_AT = new Date("2026-10-11T09:00:00.000Z");

function harness(store: MemoryStore, files: Record<string, string[]> = {}): Harness {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    store,
    files,
    io: {
      out: (line) => out.push(line),
      err: (line) => err.push(line),
      env: {},
      // The same store for every command in a test. `MemoryStore.close()` releases
      // nothing, so the commands' own `close()` calls are harmless here.
      openStore: async () => store,
      readLines: (path) => linesOf(files[path] ?? []),
      appendLines: async (path, lines) => {
        (files[path] ??= []).push(...lines);
      },
      now: () => CHECKPOINTED_AT,
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

describe("audit-log checkpoint --journal", () => {
  it("writes an anchor verify then checks without being told one", async () => {
    const tenant = tenantName();
    const store = await seed(tenant, 3);
    const h = harness(store);

    expect(await run(["checkpoint", "--tenant", tenant, "--journal", "a.ndjson"], h.io)).toBe(
      EXIT_OK,
    );
    expect(h.files["a.ndjson"]).toHaveLength(1);
    expect(JSON.parse(h.files["a.ndjson"]![0]!)).toMatchObject({ tenant, seq: 3 });

    // The anchor is now in a file, which is the whole point: nobody has to
    // remember a hash for the next run to detect a truncation.
    const check = harness(MemoryStore.from(await entriesOf(store, tenant)), h.files);
    expect(await run(["verify", "--tenant", tenant, "--journal", "a.ndjson"], check.io)).toBe(
      EXIT_OK,
    );
  });

  it("catches a tail deleted after the journal recorded it", async () => {
    const tenant = tenantName();
    const store = await seed(tenant, 5);
    const h = harness(store);
    await run(["checkpoint", "--tenant", tenant, "--journal", "a.ndjson"], h.io);

    const cut = harness(MemoryStore.from((await entriesOf(store, tenant)).slice(0, 2)), h.files);
    expect(await run(["verify", "--tenant", tenant, "--journal", "a.ndjson"], cut.io)).toBe(
      EXIT_BROKEN,
    );
    expect(cut.out.at(-1)).toContain("truncated");
    // When the anchor was taken brackets the damage: it happened after this.
    expect(cut.out.at(-1)).toContain(`(anchored ${CHECKPOINTED_AT.toISOString()})`);
  });

  it("does not append an identical line when nothing was appended to the log", async () => {
    const tenant = tenantName();
    const store = await seed(tenant, 2);
    const first = harness(store);
    await run(["checkpoint", "--tenant", tenant, "--journal", "a.ndjson"], first.io);

    const again = harness(store, first.files);
    expect(await run(["checkpoint", "--tenant", tenant, "--journal", "a.ndjson"], again.io)).toBe(
      EXIT_OK,
    );
    // A daily cron on a quiet tenant would otherwise add a line a day. The
    // journal records positions, not runs.
    expect(again.files["a.ndjson"]).toHaveLength(1);
    expect(again.out[0]).toMatch(/^2:[0-9a-f]{64}$/);
  });

  it("refuses to anchor a chain that no longer matches its own journal", async () => {
    const tenant = tenantName();
    const store = await seed(tenant, 4);
    const h = harness(store);
    await run(["checkpoint", "--tenant", tenant, "--journal", "a.ndjson"], h.io);

    // The tail is gone. What is left is a valid chain, and only the anchor
    // already in the file says so.
    const forged = MemoryStore.from((await entriesOf(store, tenant)).slice(0, 2));
    const after = harness(forged, h.files);

    expect(await run(["checkpoint", "--tenant", tenant, "--journal", "a.ndjson"], after.io)).toBe(
      EXIT_BROKEN,
    );
    // Nothing was written: a journal whose newest line agrees with the break
    // leaves the next operator a file that contradicts itself.
    expect(after.files["a.ndjson"]).toHaveLength(1);
    expect(after.err.join("\n")).toContain("not anchored");
  });

  it("anchors every tenant at once, for a cron job that does not enumerate them", async () => {
    const a = tenantName();
    const b = tenantName();
    const store = MemoryStore.from([
      ...(await entriesOf(await seed(a, 2), a)),
      ...(await entriesOf(await seed(b, 3), b)),
    ]);
    const h = harness(store);

    expect(await run(["checkpoint", "--all", "--journal", "a.ndjson"], h.io)).toBe(EXIT_OK);
    expect(h.files["a.ndjson"]).toHaveLength(2);
    expect(h.out.join("\n")).toContain(`${a}  2:`);
    expect(h.out.join("\n")).toContain(`${b}  3:`);
  });

  it("needs a tenant or --all", async () => {
    const h = harness(await seed(tenantName(), 1));
    expect(await run(["checkpoint", "--journal", "a.ndjson"], h.io)).toBe(EXIT_USAGE);
    expect(h.err.join("\n")).toContain("--tenant is required");
  });
});

describe("audit-log verify --journal", () => {
  it("reports a tenant that has vanished from the database entirely", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 3));
    await run(["checkpoint", "--tenant", tenant, "--journal", "a.ndjson"], h.io);

    // Every row dropped, so the tenant is not in `tenants()` at all. Without the
    // journal there is nothing left to notice its absence.
    const empty = harness(new MemoryStore(), h.files);
    expect(await run(["verify", "--all", "--json"], empty.io)).toBe(EXIT_OK);

    const checked = harness(new MemoryStore(), h.files);
    expect(await run(["verify", "--all", "--journal", "a.ndjson"], checked.io)).toBe(EXIT_BROKEN);
    expect(checked.out.join("\n")).toContain(`${tenant}  BROKEN`);
    expect(checked.out.join("\n")).toContain("truncated");
  });

  it("names the oldest anchor a rewritten chain stopped matching", async () => {
    const tenant = tenantName();
    const store = await seed(tenant, 4);
    const original = await entriesOf(store, tenant);

    // Two checkpoints, taken as the log grew.
    const early = harness(MemoryStore.from(original.slice(0, 2)));
    await run(["checkpoint", "--tenant", tenant, "--journal", "a.ndjson"], early.io);
    const late = harness(store, early.files);
    await run(["checkpoint", "--tenant", tenant, "--journal", "a.ndjson"], late.io);
    expect(late.files["a.ndjson"]).toHaveLength(2);

    // A different chain of the same length: seq 1 kept, seq 2 onwards replaced
    // with entries that are internally consistent and hash correctly.
    const forged = MemoryStore.from([original[0]!]);
    const forgedLog = new AuditLog({ store: forged });
    for (let i = 1; i < 4; i += 1) {
      await forgedLog.append({
        tenant,
        actor: "user:1",
        action: "forged",
        resource: `r:${i}`,
        at: at(i),
      });
    }
    expect((await entriesOf(forged, tenant)).map((e) => e.seq)).toEqual([1, 2, 3, 4]);
    const h = harness(forged, late.files);

    expect(await run(["verify", "--tenant", tenant, "--journal", "a.ndjson"], h.io)).toBe(
      EXIT_BROKEN,
    );
    // Checking only the newest anchor would report seq 4 and hide how far back
    // the rewrite reaches.
    expect(h.out.at(-1)).toContain("BROKEN at seq 2");
    expect(h.out.at(-1)).toContain("anchor_mismatch");
  });

  it("treats a self-contradicting journal as a finding, not as a bad argument", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 2), {
      "a.ndjson": [
        JSON.stringify({ tenant, seq: 2, hash: "a".repeat(64), observedAt: "2026-01-01T00:00:00.000Z" }),
        JSON.stringify({ tenant, seq: 2, hash: "b".repeat(64), observedAt: "2026-02-01T00:00:00.000Z" }),
      ],
    });
    expect(await run(["verify", "--tenant", tenant, "--journal", "a.ndjson"], h.io)).toBe(
      EXIT_BROKEN,
    );
    expect(h.err.join("\n")).toContain("two anchors disagree about seq 2");
  });

  it("creates the journal on disk and reads it back, without the test doubles", async () => {
    const dir = await mkdtemp(join(tmpdir(), "audit-log-journal-"));
    const path = join(dir, "anchors.ndjson");
    const tenant = tenantName();
    const store = await seed(tenant, 2);
    // No `readLines`, no `appendLines`: the real file paths, including the
    // missing-file case every first checkpoint starts from.
    const io: CliIo = { out: () => {}, err: () => {}, env: {}, openStore: async () => store };

    try {
      expect(await run(["checkpoint", "--tenant", tenant, "--journal", path], io)).toBe(EXIT_OK);
      const written = (await readFile(path, "utf8")).trimEnd().split("\n");
      expect(written).toHaveLength(1);
      expect(JSON.parse(written[0]!)).toMatchObject({ tenant, seq: 2 });

      expect(await run(["verify", "--tenant", tenant, "--journal", path], io)).toBe(EXIT_OK);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("refuses a journal line that is not a journal line", async () => {
    const tenant = tenantName();
    const h = harness(await seed(tenant, 1), { "a.ndjson": ["{ not json"] });
    expect(await run(["verify", "--tenant", tenant, "--journal", "a.ndjson"], h.io)).toBe(
      EXIT_USAGE,
    );
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
