/**
 * The chain itself: what an entry's hash is computed over, and what it takes to
 * walk a chain and say where it was broken.
 */

import { createHash } from "node:crypto";
import { canonicalJson, frame, parsePayload } from "./canonical.js";
import {
  AnchorConflictError,
  mintSealed,
  type Anchor,
  type AuditEntry,
  type ChainBreak,
  type Sealer,
  type VerificationResult,
} from "./types.js";

/**
 * A version tag inside every preimage. If the field list below ever changes, this
 * changes with it, and entries hashed under the old rules stop verifying loudly
 * instead of appearing to be forgeries.
 */
const DOMAIN = "audit-log/v1";

/** The `prevHash` of the first entry in a tenant's chain. */
export const GENESIS_HASH = "0".repeat(64);

const HASH = /^[0-9a-f]{64}$/;

export function isHash(value: string): boolean {
  return HASH.test(value);
}

/**
 * The hash of an entry, over every field of it including `seq`, `tenant` and
 * `prevHash`. Because the preimage covers the position and the predecessor, an
 * entry cannot be moved to another place in the chain, into another tenant's
 * chain, or backdated, without its hash changing.
 *
 * The timestamp enters as a millisecond ISO-8601 string, which is why the
 * Postgres column is `timestamptz(3)`: a microsecond a JavaScript `Date` cannot
 * hold would make an honest row verify as tampered.
 */
export function entryHash(entry: Omit<AuditEntry, "hash">): string {
  const preimage = frame([
    DOMAIN,
    entry.tenant,
    String(entry.seq),
    entry.recordedAt.toISOString(),
    entry.actor,
    entry.action,
    entry.resource,
    entry.payloadJson,
    entry.prevHash,
  ]);
  return createHash("sha256").update(preimage).digest("hex");
}

/**
 * The only way to produce a writable entry. Stores call this with the position
 * they have just reserved; nothing else in the package constructs a hash.
 */
export const seal: Sealer = ({ tenant, seq, prevHash, recordedAt, draft }) => {
  const unsealed = {
    tenant,
    seq,
    // A copy, because a Date is mutable and the caller still holds theirs. An
    // entry whose timestamp can change after its hash was computed is not sealed.
    recordedAt: new Date(recordedAt.getTime()),
    actor: draft.actor,
    action: draft.action,
    resource: draft.resource,
    payloadJson: draft.payloadJson,
    prevHash,
  };
  return mintSealed({ ...unsealed, hash: entryHash(unsealed) });
};

/** Returns a one-line reason the payload text is not canonical, or undefined. */
function payloadProblem(payloadJson: string): string | undefined {
  let value: unknown;
  try {
    value = parsePayload(payloadJson);
  } catch {
    return "the payload is not valid JSON";
  }
  let canonical: string;
  try {
    canonical = canonicalJson(value);
  } catch (error) {
    return `the payload is not representable in canonical JSON: ${
      error instanceof Error ? error.message : String(error)
    }`;
  }
  return canonical === payloadJson ? undefined : "the payload is not in canonical form";
}

export interface VerifyOptions {
  /**
   * A position recorded outside the database. Without one, verification proves
   * that the entries present are consistent; it cannot prove that the newest ones
   * are still present, because a chain with its tail cut off is a valid chain.
   */
  readonly anchor?: Anchor;
  /**
   * Several such positions — a journal's worth. Every one is checked as the walk
   * reaches it, and the lowest that disagrees is the break, so a chain that was
   * rewritten and re-anchored is reported at the oldest anchor it no longer
   * matches rather than at the newest. Merged with `anchor` when both are given.
   */
  readonly anchors?: readonly Anchor[];
}

/**
 * The anchors to check, lowest position first. Checking them in the walk's own
 * order is what lets one cursor cover all of them in a single pass.
 */
function anchorsToCheck(tenant: string, opts: VerifyOptions): Anchor[] {
  const all = [...(opts.anchor === undefined ? [] : [opts.anchor]), ...(opts.anchors ?? [])];
  for (const anchor of all) {
    if (anchor.tenant !== tenant) {
      throw new Error(`anchor is for tenant "${anchor.tenant}", not "${tenant}"`);
    }
  }
  all.sort((a, b) => a.seq - b.seq);
  for (let i = 1; i < all.length; i += 1) {
    const prev = all[i - 1]!;
    const cur = all[i]!;
    if (cur.seq === prev.seq && cur.hash !== prev.hash) {
      // Not a chain break: no chain can satisfy both, so there is nothing to
      // report about the entries. `readJournal` raises the same error from a file.
      throw new AnchorConflictError(tenant, cur.seq, prev.hash, cur.hash);
    }
  }
  return all;
}

/**
 * Walks a tenant's chain in `seq` order and reports the first break. Consumes an
 * iterable one entry at a time and keeps only the previous one, so a log larger
 * than memory verifies the same way a short one does — the Postgres store pages
 * through it, and the CLI streams it from a file.
 *
 * Returns rather than throws: "this chain is broken at 41" is an answer, not an
 * exceptional condition, and the caller has to print it either way.
 */
export async function verifyChain(
  tenant: string,
  entries: AsyncIterable<AuditEntry> | Iterable<AuditEntry>,
  opts: VerifyOptions = {},
): Promise<VerificationResult> {
  const anchors = anchorsToCheck(tenant, opts);

  let prev: AuditEntry | undefined;
  let count = 0;
  /** How many anchors the walk has passed. Entries and anchors both ascend. */
  let checked = 0;

  const broken = (kind: ChainBreak["kind"], seq: number, detail: string): VerificationResult => ({
    ok: false,
    tenant,
    entries: count,
    break: { kind, seq, detail },
  });

  for await (const entry of entries) {
    if (entry.tenant !== tenant) {
      return broken(
        "broken_link",
        entry.seq,
        `entry is recorded under tenant "${entry.tenant}", not "${tenant}"`,
      );
    }

    if (prev === undefined) {
      if (entry.seq !== 1) {
        return broken("bad_genesis", 1, `the chain starts at seq ${entry.seq}, not 1`);
      }
      if (entry.prevHash !== GENESIS_HASH) {
        return broken("bad_genesis", 1, "the first entry does not link to the genesis hash");
      }
    } else if (entry.seq !== prev.seq + 1) {
      return broken(
        "missing",
        prev.seq + 1,
        `seq ${prev.seq} is followed by seq ${entry.seq}: ${entry.seq - prev.seq - 1} entr${
          entry.seq - prev.seq - 1 === 1 ? "y is" : "ies are"
        } gone`,
      );
    }

    // The stored payload text must be the canonical form of the payload it parses
    // to. Nothing in this package writes it otherwise, so a row that fails here
    // was written by something else — and an export of it would re-canonicalise
    // to different bytes, which is how the two verification paths stay in
    // agreement about the same chain.
    const canonicality = payloadProblem(entry.payloadJson);
    if (canonicality !== undefined) {
      return broken("non_canonical_payload", entry.seq, canonicality);
    }

    // The row against its own hash next: an edited row should be reported where
    // it was edited, not as a link failure one entry later.
    const recomputed = entryHash(entry);
    if (recomputed !== entry.hash) {
      return broken("tampered", entry.seq, `the entry hashes to ${recomputed}, not ${entry.hash}`);
    }

    if (prev !== undefined) {
      if (entry.prevHash !== prev.hash) {
        return broken(
          "broken_link",
          entry.seq,
          `prevHash is ${entry.prevHash}, but seq ${prev.seq} hashes to ${prev.hash}`,
        );
      }
      if (entry.recordedAt.getTime() < prev.recordedAt.getTime()) {
        return broken(
          "non_monotonic_time",
          entry.seq,
          `recorded at ${entry.recordedAt.toISOString()}, before seq ${
            prev.seq
          } at ${prev.recordedAt.toISOString()}`,
        );
      }
    }

    // Every anchor at or below this position is settled by the time the walk
    // moves on. An anchor strictly below it cannot be reached by a later entry,
    // and a chain that skipped one has already failed `bad_genesis` or `missing`.
    while (checked < anchors.length && anchors[checked]!.seq <= entry.seq) {
      const anchor = anchors[checked]!;
      if (anchor.seq === entry.seq && entry.hash !== anchor.hash) {
        return broken(
          "anchor_mismatch",
          entry.seq,
          `the anchor expects ${anchor.hash}, the chain has ${entry.hash}`,
        );
      }
      checked += 1;
    }

    count += 1;
    prev = entry;
  }

  // The lowest anchor the walk never reached: with a journal, that is the oldest
  // position the chain can no longer account for, not merely the newest.
  const unreached = anchors[checked];
  if (unreached !== undefined) {
    return broken(
      "truncated",
      unreached.seq,
      prev === undefined
        ? `the chain is empty, the anchor is at seq ${unreached.seq}`
        : `the chain ends at seq ${prev.seq}, the anchor is at seq ${unreached.seq}`,
    );
  }

  return {
    ok: true,
    tenant,
    entries: count,
    head: prev === undefined ? null : { tenant, seq: prev.seq, hash: prev.hash },
  };
}
