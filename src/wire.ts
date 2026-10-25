/**
 * The formats that leave the database and have to survive being copied into a
 * ticket, a git commit or an email to an auditor: the NDJSON export, the anchor,
 * the published root and the inclusion proof.
 *
 * The entry's wire shape is written and read in one place each — `entryRow` and
 * `decodeEntryRow` — because the export and a proof both carry entries, and two
 * spellings of the same shape would drift into two different hashes.
 */

import { canonicalJson, parsePayload } from "./canonical.js";
import { isHash } from "./chain.js";
import { mintRoot, type InclusionProof, type PublishedRoot } from "./merkle.js";
import { MalformedEntryError, type Anchor, type AuditEntry } from "./types.js";

/** One entry as a single line of NDJSON. */
export function encodeEntry(entry: AuditEntry): string {
  return JSON.stringify(entryRow(entry));
}

function entryRow(entry: AuditEntry): Record<string, unknown> {
  return {
    tenant: entry.tenant,
    seq: entry.seq,
    at: entry.recordedAt.toISOString(),
    actor: entry.actor,
    action: entry.action,
    resource: entry.resource,
    // Embedded as JSON, not as the canonical string. An auditor has to read this
    // file, and `"{\"amount\":100}"` is not reading material. Decoding
    // re-derives the canonical text, which is a function of the value, so the
    // hash still checks out — and `verifyChain` rejects a chain whose stored text
    // was not canonical in the first place, so the two paths cannot disagree.
    payload: parsePayload(entry.payloadJson),
    prevHash: entry.prevHash,
    hash: entry.hash,
  };
}

export function decodeEntry(line: string): AuditEntry {
  let raw: unknown;
  try {
    raw = JSON.parse(line) as unknown;
  } catch {
    return fail("the line is not valid JSON");
  }
  return decodeEntryRow(raw);
}

function decodeEntryRow(raw: unknown): AuditEntry {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return fail("the line is not a JSON object");
  }
  const row = raw as Record<string, unknown>;

  const tenant = str(row["tenant"], "tenant");
  const seq = row["seq"];
  if (typeof seq !== "number" || !Number.isInteger(seq) || seq < 1) {
    return fail("seq must be a positive integer");
  }
  const at = str(row["at"], "at");
  const recordedAt = new Date(at);
  if (Number.isNaN(recordedAt.getTime())) {
    return fail(`at is not a timestamp: ${at}`);
  }
  const prevHash = str(row["prevHash"], "prevHash");
  const hash = str(row["hash"], "hash");
  if (!isHash(prevHash) || !isHash(hash)) {
    return fail("prevHash and hash must be 64 lowercase hex characters");
  }

  return {
    tenant,
    seq,
    recordedAt,
    actor: str(row["actor"], "actor"),
    action: str(row["action"], "action"),
    resource: str(row["resource"], "resource"),
    payloadJson: canonicalJson(row["payload"] === undefined ? null : row["payload"]),
    prevHash,
    hash,
  };
}

/** Reads entries from NDJSON text, skipping blank lines. Streams; never buffers. */
export async function* decodeEntries(lines: AsyncIterable<string>): AsyncGenerator<AuditEntry> {
  for await (const line of lines) {
    if (line.trim() === "") continue;
    yield decodeEntry(line);
  }
}

/** `41:9f86d0…` — short enough to paste into a commit message. */
export function formatAnchor(anchor: Anchor): string {
  return `${anchor.seq}:${anchor.hash}`;
}

export function parseAnchor(tenant: string, text: string): Anchor {
  const at = text.indexOf(":");
  if (at < 0) {
    throw new MalformedEntryError(`anchor must look like "<seq>:<hash>", got "${text}"`);
  }
  const seq = Number(text.slice(0, at));
  const hash = text.slice(at + 1).toLowerCase();
  if (!Number.isInteger(seq) || seq < 1) {
    throw new MalformedEntryError(`anchor sequence must be a positive integer, got "${text}"`);
  }
  if (!isHash(hash)) {
    throw new MalformedEntryError("anchor hash must be 64 hex characters");
  }
  return { tenant, seq, hash };
}

/** `100:3f9a…` — a root and the size it commits to, in one pasteable token. */
export function formatRoot(root: PublishedRoot): string {
  return `${root.size}:${root.root}`;
}

/**
 * A root as the verifier holds it. The size travels with the hash because a root
 * without its size is not checkable: every append produces a new root, and
 * "which one was this?" has no answer afterwards.
 */
export function parseRoot(tenant: string, text: string): PublishedRoot {
  const at = text.indexOf(":");
  if (at < 0) {
    throw new MalformedEntryError(`root must look like "<size>:<hash>", got "${text}"`);
  }
  const size = Number(text.slice(0, at));
  const root = text.slice(at + 1).toLowerCase();
  if (!Number.isInteger(size) || size < 1) {
    throw new MalformedEntryError(`root size must be a positive integer, got "${text}"`);
  }
  if (!isHash(root)) {
    throw new MalformedEntryError("root hash must be 64 hex characters");
  }
  return mintRoot({ tenant, size, root });
}

const PROOF_FORMAT = "audit-log/inclusion/v1";

/**
 * One proof as a JSON document, indented because somebody is going to open it in
 * an editor and read the entry it is about. The format tag is checked on the way
 * in, so a file written under a future shape is refused rather than misread.
 */
export function encodeProof(proof: InclusionProof): string {
  return JSON.stringify(
    {
      format: PROOF_FORMAT,
      tenant: proof.tenant,
      seq: proof.seq,
      size: proof.size,
      root: proof.root,
      entry: entryRow(proof.entry),
      path: [...proof.path],
    },
    null,
    2,
  );
}

export function decodeProof(text: string): InclusionProof {
  let raw: unknown;
  try {
    raw = JSON.parse(text) as unknown;
  } catch {
    return fail("the proof is not valid JSON");
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return fail("the proof is not a JSON object");
  }
  const row = raw as Record<string, unknown>;

  if (row["format"] !== PROOF_FORMAT) {
    return fail(`unknown proof format: expected "${PROOF_FORMAT}", got ${JSON.stringify(row["format"])}`);
  }

  const tenant = str(row["tenant"], "tenant");
  const seq = int(row["seq"], "seq");
  const size = int(row["size"], "size");
  const root = str(row["root"], "root").toLowerCase();
  if (!isHash(root)) {
    return fail("root must be 64 hex characters");
  }

  const path = row["path"];
  if (!Array.isArray(path)) {
    return fail("path must be an array of hashes");
  }
  const siblings = path.map((hash, i) => {
    const value = str(hash, `path[${i}]`).toLowerCase();
    if (!isHash(value)) {
      return fail(`path[${i}] must be 64 hex characters`);
    }
    return value;
  });

  // The same decoder the export uses, so an entry in a proof and the same entry
  // in an export produce the same canonical payload text and the same hash.
  const entry = decodeEntryRow(row["entry"]);

  return { tenant, seq, size, root, entry, path: siblings };
}

function int(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new MalformedEntryError(`${field} must be a positive integer`);
  }
  return value;
}

function str(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new MalformedEntryError(`${field} must be a string`);
  }
  return value;
}

function fail(reason: string): never {
  throw new MalformedEntryError(reason);
}
