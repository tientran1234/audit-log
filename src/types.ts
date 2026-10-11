/**
 * The vocabulary of the log. Three rules are enforced here rather than in
 * documentation:
 *
 *  1. The payload is canonical JSON *text*, never a live object. The hash covers
 *     bytes, so the bytes are what is stored and what comes back out. An object
 *     that was re-serialised on the way to the database would verify as tampered
 *     the first time a key order changed.
 *  2. Only `seal()` can mint a `SealedEntry`, and only a `SealedEntry` can be
 *     written. A caller cannot hand the store a hash of its own choosing,
 *     because the type cannot be constructed outside this package.
 *  3. `seq`, `prevHash` and `recordedAt` are assigned by the store inside the
 *     transaction that writes the row. They are not parameters of `append`.
 */

declare const sealed: unique symbol;

/** What the caller knows about an event. Everything else is derived. */
export interface AuditInput {
  readonly tenant: string;
  /** Who did it: "user:42", "svc:billing", "system". Opaque to this package. */
  readonly actor: string;
  /** What they did: "invoice.void", "member.role_changed". Opaque. */
  readonly action: string;
  /** What they did it to: "invoice:1001". Opaque, and "" when there is no subject. */
  readonly resource: string;
  /** JSON-able detail. Canonicalised before hashing; see `canonicalJson`. */
  readonly payload?: unknown;
  /**
   * The event time. Omit it and the store uses its own clock — with more than one
   * writer that is the only safe choice, because entries must be non-decreasing
   * in time and two skewed application clocks will eventually disagree.
   */
  readonly at?: Date;
}

/** The parts of an entry the caller supplies, with the payload already canonical. */
export interface EntryDraft {
  readonly actor: string;
  readonly action: string;
  readonly resource: string;
  /** Canonical JSON. `"null"` when there was no payload. */
  readonly payloadJson: string;
}

/** An entry as read back from a store or an export. Hashes are lowercase hex. */
export interface AuditEntry extends EntryDraft {
  readonly tenant: string;
  /** 1 for the first entry in a tenant's chain, then gapless. */
  readonly seq: number;
  readonly recordedAt: Date;
  /** The hash of entry `seq - 1`, or {@link GENESIS_HASH} for the first. */
  readonly prevHash: string;
  readonly hash: string;
}

/**
 * An entry whose hash was computed by `seal()` over its own fields. Stores accept
 * nothing else. The brand is not a security boundary against a hostile writer —
 * anyone who can INSERT can write any bytes — it is a compile-time guarantee that
 * *this* package never writes a hash it did not compute.
 */
export interface SealedEntry extends AuditEntry {
  readonly [sealed]: true;
}

/** Internal: the one place a `SealedEntry` is minted. See `chain.ts`. */
export function mintSealed(entry: AuditEntry): SealedEntry {
  return entry as SealedEntry;
}

/**
 * A position in a tenant's chain, small enough to write down. Keep the newest one
 * somewhere the database cannot reach — a file on another host, a ticket, a
 * commit — and verification can then prove the tail was not cut off.
 */
export interface Anchor {
  readonly tenant: string;
  readonly seq: number;
  readonly hash: string;
}

/**
 * An anchor plus a signature over it, made with a key the database does not hold.
 * An unsigned anchor is only evidence if the verifier trusts whoever handed it
 * over; this one stands on its own, so a truncated export cannot be passed off
 * with an anchor made to match it.
 *
 * The anchor sits in a field instead of being spread across this interface so
 * that a `SignedAnchor` is *not* assignable to {@link Anchor}: the only way to
 * get one past the type system and into `verify()` is `openSignedAnchor`, which
 * checks the signature first.
 */
export interface SignedAnchor {
  readonly anchor: Anchor;
  /** The signer's claim about when, covered by the signature. Not a trusted time. */
  readonly signedAt: Date;
  /** Which key signed. See `publicKeyId`. */
  readonly keyId: string;
  /** Base64. Hex would add 40 characters to a line meant to be pasted by hand. */
  readonly signature: string;
}

export type BreakKind =
  /** The chain does not start at seq 1, or entry 1 does not link to genesis. */
  | "bad_genesis"
  /** A gap in `seq`: the entry that belongs here is gone. */
  | "missing"
  /** The stored hash is not the hash of the row's own fields: the row was edited. */
  | "tampered"
  /** The payload text is not the canonical form of the payload it parses to. */
  | "non_canonical_payload"
  /** The row's `prevHash` is not the previous entry's hash: the row was re-linked. */
  | "broken_link"
  /** Time went backwards between two entries. */
  | "non_monotonic_time"
  /** Entries stop before the anchor: the tail was removed. */
  | "truncated"
  /** The entry at the anchor's seq has a different hash: history was rewritten. */
  | "anchor_mismatch";

export interface ChainBreak {
  readonly kind: BreakKind;
  /** The sequence number the break is about. */
  readonly seq: number;
  /** One sentence, safe to print. */
  readonly detail: string;
}

export type VerificationResult =
  | {
      readonly ok: true;
      readonly tenant: string;
      readonly entries: number;
      /** The last entry, or null for an empty chain. */
      readonly head: Anchor | null;
    }
  | {
      readonly ok: false;
      readonly tenant: string;
      /** How many entries verified before the break. */
      readonly entries: number;
      readonly break: ChainBreak;
    };

/** Assigns the derived fields and returns a sealed entry. Supplied by `chain.ts`. */
export type Sealer = (position: {
  readonly tenant: string;
  readonly seq: number;
  readonly prevHash: string;
  readonly recordedAt: Date;
  readonly draft: EntryDraft;
}) => SealedEntry;

export interface ReadPage {
  readonly entries: readonly AuditEntry[];
}

export interface AuditStore {
  /**
   * Appends one entry. The store reads the tenant's tail, decides `seq`,
   * `prevHash` and `recordedAt`, calls `seal` and writes the row — all inside one
   * transaction. Two concurrent appends to one tenant never produce the same
   * `seq`: that is a unique constraint, and the loser is retried here.
   *
   * `at` is the caller's event time, or undefined to use the store's clock. A
   * time earlier than the tail's is rejected with {@link NonMonotonicTimeError}.
   */
  append(tenant: string, draft: EntryDraft, at: Date | undefined, seal: Sealer): Promise<SealedEntry>;

  /** The tenant's last entry as an anchor, or undefined when the chain is empty. */
  head(tenant: string): Promise<Anchor | undefined>;

  /** Up to `limit` entries with `seq > afterSeq`, in ascending `seq` order. */
  read(tenant: string, afterSeq: number, limit: number): Promise<AuditEntry[]>;

  /** Every tenant that has at least one entry, sorted. */
  tenants(): Promise<string[]>;

  close(): Promise<void>;
}

/** A payload that cannot be canonicalised, and so cannot be hashed. */
export class InvalidPayloadError extends Error {
  constructor(
    /** JSON-pointer-ish path to the offending value, e.g. `$.items[2].when`. */
    readonly path: string,
    reason: string,
  ) {
    super(`payload at ${path}: ${reason}`);
    this.name = "InvalidPayloadError";
  }
}

/** An append whose event time is before the tenant's last entry. */
export class NonMonotonicTimeError extends Error {
  constructor(
    readonly tenant: string,
    readonly at: Date,
    readonly tailAt: Date,
  ) {
    super(
      `${tenant}: cannot append at ${at.toISOString()}, the last entry is at ${tailAt.toISOString()}`,
    );
    this.name = "NonMonotonicTimeError";
  }
}

/**
 * A signed anchor that cannot be trusted: the wrong key, a signature that does
 * not match, or a key that cannot be read. Distinct from a chain break, because
 * it means the question was not answered rather than answered badly.
 */
export class AnchorSignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AnchorSignatureError";
  }
}

/** An entry in an export or a row that is not shaped like an entry. */
export class MalformedEntryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MalformedEntryError";
  }
}
