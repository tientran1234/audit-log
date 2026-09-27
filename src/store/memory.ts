import { GENESIS_HASH } from "../chain.js";
import {
  NonMonotonicTimeError,
  type Anchor,
  type AuditEntry,
  type AuditStore,
  type EntryDraft,
  type SealedEntry,
  type Sealer,
} from "../types.js";

/**
 * The same guarantees in one process. Useful in tests — including your own, where
 * asserting that a code path audited what it claims to is the point — and as a
 * way to verify an export without a database.
 *
 * Exclusivity is free here: there is no `await` between reading the tail and
 * pushing the new entry, so no second append can interleave. The Postgres store
 * has to earn the same property from a unique constraint.
 */
export class MemoryStore implements AuditStore {
  readonly #chains = new Map<string, AuditEntry[]>();

  /**
   * Adopts entries as they are, without checking them. That is the point: a chain
   * that a store would have refused to write — a gap, an edited row, a broken link
   * — has to be representable, or `verifyChain` could not be tested against
   * anything but healthy input. Use it to inspect an export, not to append to.
   */
  static from(entries: Iterable<AuditEntry>): MemoryStore {
    const store = new MemoryStore();
    for (const entry of entries) {
      const chain = store.#chains.get(entry.tenant) ?? [];
      chain.push(entry);
      store.#chains.set(entry.tenant, chain);
    }
    for (const chain of store.#chains.values()) {
      chain.sort((a, b) => a.seq - b.seq);
    }
    return store;
  }

  async append(
    tenant: string,
    draft: EntryDraft,
    at: Date | undefined,
    seal: Sealer,
  ): Promise<SealedEntry> {
    const chain = this.#chains.get(tenant) ?? [];
    const tail = chain.at(-1);
    const recordedAt = at ?? new Date();

    if (tail !== undefined && recordedAt.getTime() < tail.recordedAt.getTime()) {
      throw new NonMonotonicTimeError(tenant, recordedAt, tail.recordedAt);
    }

    const entry = seal({
      tenant,
      seq: (tail?.seq ?? 0) + 1,
      prevHash: tail?.hash ?? GENESIS_HASH,
      recordedAt,
      draft,
    });

    chain.push(entry);
    this.#chains.set(tenant, chain);
    return entry;
  }

  async head(tenant: string): Promise<Anchor | undefined> {
    const tail = this.#chains.get(tenant)?.at(-1);
    return tail === undefined ? undefined : { tenant, seq: tail.seq, hash: tail.hash };
  }

  async read(tenant: string, afterSeq: number, limit: number): Promise<AuditEntry[]> {
    const chain = this.#chains.get(tenant) ?? [];
    return chain
      .filter((entry) => entry.seq > afterSeq)
      .slice(0, Math.max(0, limit))
      // Copies, so that a caller holding a read entry cannot reach into the chain
      // through its mutable Date. A driver-backed store returns fresh rows anyway;
      // this keeps the two stores honest about the same thing.
      .map((entry) => ({ ...entry, recordedAt: new Date(entry.recordedAt.getTime()) }));
  }

  async tenants(): Promise<string[]> {
    return [...this.#chains.entries()]
      .filter(([, chain]) => chain.length > 0)
      .map(([tenant]) => tenant)
      .sort();
  }

  async close(): Promise<void> {
    // Nothing to release. Kept so callers can swap stores without a special case.
  }
}
