/**
 * The anchor journal: a file of anchors kept outside the database.
 *
 * An anchor is the only thing that catches a chain whose tail was deleted or
 * whose history was rewritten and re-sealed, and keeping one used to be a manual
 * step — run `checkpoint`, paste `<seq>:<hash>` into a ticket, remember to hand
 * it back to `verify` months later. A cron job cannot do that, so in practice
 * chains ran unanchored and the one guarantee hashes cannot give on their own
 * went unclaimed.
 *
 * This is the same anchor in a file: NDJSON, one line per checkpoint, appended
 * and never rewritten. What it deliberately does not do is decide where that
 * file lives. A journal in the audited database, or on the one host owned by
 * whoever can rewrite the table, is not an anchor — it is a second copy of the
 * thing it is supposed to check.
 *
 * Every line is kept and verification checks all of them, not just the newest.
 * That is what stops a checkpoint taken after a rewrite from laundering it: the
 * new anchor agrees with the rewritten chain, and the older lines do not.
 */

import { isHash } from "./chain.js";
import {
  AnchorConflictError,
  MalformedEntryError,
  type Anchor,
  type AnchorRecord,
} from "./types.js";

/** One anchor as a single line of NDJSON. */
export function encodeAnchorRecord(record: AnchorRecord): string {
  return JSON.stringify({
    tenant: record.tenant,
    seq: record.seq,
    hash: record.hash,
    observedAt: record.observedAt.toISOString(),
  });
}

export function decodeAnchorRecord(line: string): AnchorRecord {
  let raw: unknown;
  try {
    raw = JSON.parse(line) as unknown;
  } catch {
    throw new MalformedEntryError("the journal line is not valid JSON");
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new MalformedEntryError("the journal line is not a JSON object");
  }
  const row = raw as Record<string, unknown>;

  const tenant = row["tenant"];
  if (typeof tenant !== "string" || tenant === "") {
    throw new MalformedEntryError("tenant must be a non-empty string");
  }
  const seq = row["seq"];
  if (typeof seq !== "number" || !Number.isInteger(seq) || seq < 1) {
    throw new MalformedEntryError("seq must be a positive integer");
  }
  const hash = row["hash"];
  if (typeof hash !== "string" || !isHash(hash)) {
    throw new MalformedEntryError("hash must be 64 lowercase hex characters");
  }
  const observed = row["observedAt"];
  if (typeof observed !== "string") {
    throw new MalformedEntryError("observedAt must be a string");
  }
  const observedAt = new Date(observed);
  if (Number.isNaN(observedAt.getTime())) {
    throw new MalformedEntryError(`observedAt is not a timestamp: ${observed}`);
  }

  return { tenant, seq, hash, observedAt };
}

/** Reads records from NDJSON text, skipping blank lines. */
export async function* decodeAnchorRecords(
  lines: AsyncIterable<string> | Iterable<string>,
): AsyncGenerator<AnchorRecord> {
  for await (const line of lines) {
    if (line.trim() === "") continue;
    yield decodeAnchorRecord(line);
  }
}

/** A journal that has been read into memory and checked against itself. */
export interface Journal {
  /** Every tenant with at least one anchor, sorted. */
  readonly tenants: readonly string[];
  /** That tenant's anchors, lowest position first. Empty if it has none. */
  anchorsFor(tenant: string): readonly Anchor[];
  /** The record at exactly that position — for saying when it was written. */
  recordAt(tenant: string, seq: number): AnchorRecord | undefined;
}

/**
 * Reads a whole journal. Unlike an export, a journal is small by construction —
 * one line per checkpoint per tenant — so this collects rather than streams, and
 * can therefore check the file against itself.
 *
 * Two records claiming different hashes for the same position are an
 * {@link AnchorConflictError}: whichever of them is right, something has written
 * a chain this journal has already seen a different version of. The journal says
 * that on its own, without the database being reachable at all.
 *
 * Positions going backwards are *not* an error. A chain that was truncated and
 * then checkpointed produces exactly that, and it is evidence worth keeping: the
 * older, higher anchor is the one that reports the truncation.
 */
export async function readJournal(
  lines: AsyncIterable<string> | Iterable<string>,
): Promise<Journal> {
  const byTenant = new Map<string, Map<number, AnchorRecord>>();

  for await (const record of decodeAnchorRecords(lines)) {
    let positions = byTenant.get(record.tenant);
    if (positions === undefined) {
      positions = new Map<number, AnchorRecord>();
      byTenant.set(record.tenant, positions);
    }
    const seen = positions.get(record.seq);
    if (seen === undefined) {
      positions.set(record.seq, record);
    } else if (seen.hash !== record.hash) {
      throw new AnchorConflictError(record.tenant, record.seq, seen.hash, record.hash);
    }
    // An identical repeat is a cron job that ran twice. Keeping the first means
    // the reported observation time is the earliest one that proves the position.
  }

  const sorted = (positions: Map<number, AnchorRecord>): Anchor[] =>
    [...positions.values()]
      .sort((a, b) => a.seq - b.seq)
      .map(({ tenant, seq, hash }) => ({ tenant, seq, hash }));

  const anchors = new Map<string, readonly Anchor[]>();
  for (const [tenant, positions] of byTenant) {
    anchors.set(tenant, sorted(positions));
  }

  return {
    tenants: [...byTenant.keys()].sort(),
    anchorsFor: (tenant) => anchors.get(tenant) ?? [],
    recordAt: (tenant, seq) => byTenant.get(tenant)?.get(seq),
  };
}
