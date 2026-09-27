import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditLog } from "../src/log.js";
import { migrate, PostgresStore, type PgPool } from "../src/store/postgres.js";
import { GENESIS_HASH, seal } from "../src/chain.js";
import { storeContract } from "./store-contract.js";
import { at, draft, tenantName } from "./helpers.js";

const url = process.env["DATABASE_URL"];

// Skipped rather than failed without a database: `pg` is an optional peer, and a
// contributor should be able to run the suite with nothing installed.
const describeWithDb = url === undefined ? describe.skip : describe;

describeWithDb("PostgresStore", () => {
  let pool: PgPool;

  beforeAll(async () => {
    // A variable specifier keeps `pg` out of the type graph, so the package still
    // builds for consumers who never install it.
    const specifier = "pg";
    const pg = (await import(specifier)) as {
      default: { Pool: new (config: unknown) => PgPool };
    };
    // Several connections, or "concurrent appends keep one chain" would be tested
    // against a single serialised connection and prove nothing.
    pool = new pg.default.Pool({ connectionString: url, max: 8 });
    await migrate(pool);
    // Idempotent: a second boot must not fail on the triggers.
    await migrate(pool);
  });

  afterAll(async () => {
    // Nothing is deleted afterwards, because the table does not permit it. Tests
    // use a fresh tenant each; to reset a test database, drop the table and
    // migrate again.
    await pool.end();
  });

  storeContract(async () => new PostgresStore(pool));

  it("records timestamps at millisecond precision, which is what the hash covers", async () => {
    const result = await pool.query(
      `select datetime_precision from information_schema.columns
        where table_name = 'audit_entry' and column_name = 'recorded_at'`,
    );
    expect((result.rows[0] as { datetime_precision: number }).datetime_precision).toBe(3);
  });

  describe("append-only", () => {
    it("refuses an UPDATE", async () => {
      const tenant = tenantName();
      await new PostgresStore(pool).append(tenant, draft(), at(0), seal);
      await expect(
        pool.query("update audit_entry set actor = 'nobody' where tenant = $1", [tenant]),
      ).rejects.toThrow(/append-only/);
    });

    it("refuses a DELETE", async () => {
      const tenant = tenantName();
      await new PostgresStore(pool).append(tenant, draft(), at(0), seal);
      await expect(pool.query("delete from audit_entry where tenant = $1", [tenant])).rejects.toThrow(
        /append-only/,
      );
    });

    it("refuses a TRUNCATE, which row triggers would have let through", async () => {
      await expect(pool.query("truncate audit_entry")).rejects.toThrow(/append-only/);
    });
  });

  describe("constraints, not conventions", () => {
    it("refuses a second entry at the same position", async () => {
      const tenant = tenantName();
      const first = await new PostgresStore(pool).append(tenant, draft(), at(0), seal);
      const error = await insertRaw(pool, {
        tenant,
        seq: first.seq,
        hash: "b".repeat(64),
        prevHash: "c".repeat(64),
      }).then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(code(error)).toBe("23505");
    });

    it("refuses a fork: two entries cannot claim the same predecessor", async () => {
      const tenant = tenantName();
      const store = new PostgresStore(pool);
      const first = await store.append(tenant, draft(), at(0), seal);
      await store.append(tenant, draft(), at(1), seal);

      // A different position, but pointing at entry 1 all the same.
      const error = await insertRaw(pool, {
        tenant,
        seq: 3,
        hash: "d".repeat(64),
        prevHash: first.hash,
      }).then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(code(error)).toBe("23505");
      expect(constraint(error)).toBe("audit_entry_no_fork");
    });

    it("refuses a second genesis for one tenant", async () => {
      const tenant = tenantName();
      await new PostgresStore(pool).append(tenant, draft(), at(0), seal);
      const error = await insertRaw(pool, {
        tenant,
        seq: 99,
        hash: "e".repeat(64),
        prevHash: GENESIS_HASH,
      }).then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(code(error)).toBe("23505");
    });

    it("refuses something that is not a hash in a hash column", async () => {
      const error = await insertRaw(pool, {
        tenant: tenantName(),
        seq: 1,
        hash: "NOT A HASH",
        prevHash: GENESIS_HASH,
      }).then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(code(error)).toBe("23514");
    });
  });

  /**
   * The trigger stops application bugs; it does not stop whoever owns the table.
   * These are the cases the hash chain exists for: someone with enough privilege to
   * turn the trigger off, doing exactly that.
   */
  describe("a privileged writer who disables the trigger", () => {
    it("is caught editing an entry", async () => {
      const tenant = tenantName();
      const log = await seedChain(pool, tenant, 4);
      await withTriggerOff(pool, () =>
        pool.query("update audit_entry set payload = $1 where tenant = $2 and seq = 2", [
          '{"reason":"authorised"}',
          tenant,
        ]),
      );

      const result = await log.verify(tenant);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.break).toMatchObject({ kind: "tampered", seq: 2 });
    });

    it("is caught removing an entry from the middle", async () => {
      const tenant = tenantName();
      const log = await seedChain(pool, tenant, 4);
      await withTriggerOff(pool, () =>
        pool.query("delete from audit_entry where tenant = $1 and seq = 3", [tenant]),
      );

      const result = await log.verify(tenant);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.break).toMatchObject({ kind: "missing", seq: 3 });
    });

    it("is caught cutting off the tail only when an anchor was kept", async () => {
      const tenant = tenantName();
      const log = await seedChain(pool, tenant, 4);
      const anchor = await log.head(tenant);
      expect(anchor).toBeDefined();

      await withTriggerOff(pool, () =>
        pool.query("delete from audit_entry where tenant = $1 and seq > 2", [tenant]),
      );

      // Without the anchor the remaining chain is perfectly valid. This is the
      // limitation anchors exist to close, asserted so nobody mistakes it.
      expect((await log.verify(tenant)).ok).toBe(true);

      const result = await log.verify(tenant, { anchor: anchor! });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.break).toMatchObject({ kind: "truncated", seq: 4 });
    });
  });
});

async function seedChain(pool: PgPool, tenant: string, count: number): Promise<AuditLog> {
  const log = new AuditLog({ store: new PostgresStore(pool) });
  for (let i = 0; i < count; i += 1) {
    await log.append({ tenant, actor: "user:1", action: "act", resource: `r:${i}`, at: at(i) });
  }
  return log;
}

async function withTriggerOff(pool: PgPool, body: () => Promise<unknown>): Promise<void> {
  await pool.query("alter table audit_entry disable trigger audit_entry_no_change");
  try {
    await body();
  } finally {
    await pool.query("alter table audit_entry enable trigger audit_entry_no_change");
  }
}

function insertRaw(
  pool: PgPool,
  row: { tenant: string; seq: number; hash: string; prevHash: string },
): Promise<unknown> {
  return pool.query(
    `insert into audit_entry
       (tenant, seq, recorded_at, actor, action, resource, payload, prev_hash, hash)
     values ($1, $2, now(), 'x', 'y', 'z', 'null', $3, $4)`,
    [row.tenant, row.seq, row.prevHash, row.hash],
  );
}

function code(error: unknown): string | undefined {
  return (error as { code?: string } | undefined)?.code;
}

function constraint(error: unknown): string | undefined {
  return (error as { constraint?: string } | undefined)?.constraint;
}
