import { expect, it } from "vitest";
import { GENESIS_HASH, seal, verifyChain } from "../src/chain.js";
import { AuditLog } from "../src/log.js";
import { NonMonotonicTimeError, type AuditStore } from "../src/types.js";
import { at, draft, tenantName } from "./helpers.js";

/**
 * One suite, run against every store. A store that passes this behaves the same
 * whether it keeps entries in a Map or in Postgres, and anything relied on here is
 * a guarantee of the interface rather than of an implementation.
 */
export function storeContract(makeStore: () => Promise<AuditStore>): void {
  const withStore = async (body: (store: AuditStore, tenant: string) => Promise<void>) => {
    const store = await makeStore();
    await body(store, tenantName());
  };

  it("starts a tenant's chain at seq 1, linked to genesis", async () => {
    await withStore(async (store, tenant) => {
      const entry = await store.append(tenant, draft(), at(0), seal);
      expect(entry.seq).toBe(1);
      expect(entry.prevHash).toBe(GENESIS_HASH);
      expect(entry.tenant).toBe(tenant);
    });
  });

  it("assigns gapless sequence numbers and links each entry to the last", async () => {
    await withStore(async (store, tenant) => {
      const first = await store.append(tenant, draft(), at(0), seal);
      const second = await store.append(tenant, draft(), at(1), seal);
      const third = await store.append(tenant, draft(), at(2), seal);

      expect([first.seq, second.seq, third.seq]).toEqual([1, 2, 3]);
      expect(second.prevHash).toBe(first.hash);
      expect(third.prevHash).toBe(second.hash);
    });
  });

  it("keeps one chain per tenant: both start at 1 and neither links to the other", async () => {
    await withStore(async (store, tenant) => {
      const other = tenantName();
      const mine = await store.append(tenant, draft(), at(0), seal);
      const theirs = await store.append(other, draft(), at(0), seal);

      expect(mine.seq).toBe(1);
      expect(theirs.seq).toBe(1);
      expect(theirs.prevHash).toBe(GENESIS_HASH);
      expect(theirs.hash).not.toBe(mine.hash);

      const log = new AuditLog({ store });
      expect((await log.verify(tenant)).ok).toBe(true);
      expect((await log.verify(other)).ok).toBe(true);
    });
  });

  it("produces a chain that verifies", async () => {
    await withStore(async (store, tenant) => {
      for (let i = 0; i < 12; i += 1) {
        await store.append(tenant, draft({ resource: `invoice:${i}` }), at(i), seal);
      }
      const result = await new AuditLog({ store, pageSize: 5 }).verify(tenant);
      expect(result.ok).toBe(true);
      expect(result.entries).toBe(12);
    });
  });

  it("reports the head, and nothing for a tenant that has never been written to", async () => {
    await withStore(async (store, tenant) => {
      expect(await store.head(tenant)).toBeUndefined();
      const entry = await store.append(tenant, draft(), at(0), seal);
      expect(await store.head(tenant)).toEqual({ tenant, seq: 1, hash: entry.hash });
    });
  });

  it("reads pages in ascending seq order, after a cursor", async () => {
    await withStore(async (store, tenant) => {
      for (let i = 0; i < 5; i += 1) await store.append(tenant, draft(), at(i), seal);

      const firstPage = await store.read(tenant, 0, 2);
      expect(firstPage.map((e) => e.seq)).toEqual([1, 2]);
      const secondPage = await store.read(tenant, 2, 2);
      expect(secondPage.map((e) => e.seq)).toEqual([3, 4]);
      expect(await store.read(tenant, 5, 2)).toEqual([]);
    });
  });

  it("lists the tenants that have entries", async () => {
    await withStore(async (store, tenant) => {
      const other = `${tenant}-b`;
      await store.append(tenant, draft(), at(0), seal);
      await store.append(other, draft(), at(0), seal);
      const tenants = await store.tenants();
      expect(tenants).toContain(tenant);
      expect(tenants).toContain(other);
      expect([...tenants]).toEqual([...tenants].sort());
    });
  });

  it("returns the payload bytes it was given, including non-ASCII", async () => {
    await withStore(async (store, tenant) => {
      const payloadJson = '{"lý do":"trùng lặp","n":1}';
      await store.append(tenant, draft({ payloadJson }), at(0), seal);
      const [entry] = await store.read(tenant, 0, 1);
      expect(entry?.payloadJson).toBe(payloadJson);
    });
  });

  it("refuses an entry timed before the tenant's last one", async () => {
    await withStore(async (store, tenant) => {
      await store.append(tenant, draft(), at(1000), seal);
      await expect(store.append(tenant, draft(), at(999), seal)).rejects.toThrow(
        NonMonotonicTimeError,
      );
      // The rejected append left nothing behind.
      expect(await store.head(tenant)).toMatchObject({ seq: 1 });
    });
  });

  it("allows two entries in the same millisecond", async () => {
    await withStore(async (store, tenant) => {
      await store.append(tenant, draft(), at(5), seal);
      const second = await store.append(tenant, draft(), at(5), seal);
      expect(second.seq).toBe(2);
    });
  });

  it("uses its own clock when the caller gives no time, and stays non-decreasing", async () => {
    await withStore(async (store, tenant) => {
      const before = Date.now();
      const first = await store.append(tenant, draft(), undefined, seal);
      const second = await store.append(tenant, draft(), undefined, seal);

      expect(second.recordedAt.getTime()).toBeGreaterThanOrEqual(first.recordedAt.getTime());
      // Within a minute of this process's clock: enough to catch a store that
      // stamped 1970 or read the time in seconds.
      expect(Math.abs(first.recordedAt.getTime() - before)).toBeLessThan(60_000);
      // Milliseconds, because the hash covers a millisecond ISO string.
      expect(first.recordedAt.getTime() % 1).toBe(0);
      expect((await new AuditLog({ store }).verify(tenant)).ok).toBe(true);
    });
  });

  it("keeps one chain under concurrent appends to the same tenant", async () => {
    await withStore(async (store, tenant) => {
      const writers = 20;
      const entries = await Promise.all(
        Array.from({ length: writers }, (_, i) =>
          store.append(tenant, draft({ resource: `r:${i}` }), undefined, seal),
        ),
      );

      // Every writer got a distinct position, and together they cover 1..20 with
      // no gap. This is the property the unique constraint buys.
      expect([...entries.map((e) => e.seq)].sort((a, b) => a - b)).toEqual(
        Array.from({ length: writers }, (_, i) => i + 1),
      );

      const result = await verifyChain(tenant, new AuditLog({ store }).stream(tenant));
      expect(result.ok).toBe(true);
      expect(result.entries).toBe(writers);
    });
  });
}
