/**
 * The export format and the anchor format: the two things that leave the
 * database and have to survive being copied into a ticket or a git commit.
 */

import { canonicalJson, parsePayload } from "./canonical.js";
import { isHash } from "./chain.js";
import { MalformedEntryError, type Anchor, type AuditEntry } from "./types.js";

/** One entry as a single line of NDJSON. */
export function encodeEntry(entry: AuditEntry): string {
  return JSON.stringify({
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
  });
}

export function decodeEntry(line: string): AuditEntry {
  let raw: unknown;
  try {
    raw = JSON.parse(line) as unknown;
  } catch {
    return fail("the line is not valid JSON");
  }
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

function str(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new MalformedEntryError(`${field} must be a string`);
  }
  return value;
}

function fail(reason: string): never {
  throw new MalformedEntryError(reason);
}
