import { randomBytes } from "node:crypto";
import { seal } from "../src/chain.js";
import { canonicalJson } from "../src/canonical.js";
import { AuditLog } from "../src/log.js";
import { MemoryStore } from "../src/store/memory.js";
import type { AuditEntry, EntryDraft, SealedEntry } from "../src/types.js";

export const T0 = new Date("2026-06-01T09:00:00.000Z");
export const at = (ms: number): Date => new Date(T0.getTime() + ms);

/**
 * Tests never reuse a tenant, which is how they stay isolated from each other
 * against a shared Postgres: the table is append-only, so a test cannot clean up
 * after itself even if it wanted to.
 */
export function tenantName(): string {
  return `t-${randomBytes(6).toString("hex")}`;
}

export function memoryLog(): AuditLog {
  return new AuditLog({ store: new MemoryStore() });
}

export function draft(overrides: Partial<EntryDraft> = {}): EntryDraft {
  return {
    actor: "user:42",
    action: "invoice.void",
    resource: "invoice:1001",
    payloadJson: canonicalJson({ reason: "duplicate" }),
    ...overrides,
  };
}

/** A healthy chain of `count` entries, one millisecond apart. */
export function chain(tenant: string, count: number): SealedEntry[] {
  const entries: SealedEntry[] = [];
  for (let seq = 1; seq <= count; seq += 1) {
    const prev = entries.at(-1);
    entries.push(
      seal({
        tenant,
        seq,
        prevHash: prev?.hash ?? "0".repeat(64),
        recordedAt: at(seq),
        draft: draft({ resource: `invoice:${seq}` }),
      }),
    );
  }
  return entries;
}

/**
 * Rewrites a field and leaves the hash alone — what an UPDATE against the table
 * does. `reseal` is the harder case: a field rewritten *and* the hash recomputed,
 * which only the chain around it can catch.
 */
export function edit(entry: AuditEntry, changes: Partial<AuditEntry>): AuditEntry {
  return { ...entry, ...changes };
}

export function reseal(entry: AuditEntry, changes: Partial<AuditEntry>): AuditEntry {
  const next = { ...entry, ...changes };
  return seal({
    tenant: next.tenant,
    seq: next.seq,
    prevHash: next.prevHash,
    recordedAt: next.recordedAt,
    draft: {
      actor: next.actor,
      action: next.action,
      resource: next.resource,
      payloadJson: next.payloadJson,
    },
  });
}
