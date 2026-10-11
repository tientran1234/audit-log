import { canonicalJson } from "./canonical.js";
import { seal, verifyChain, type VerifyOptions } from "./chain.js";
import { signAnchor } from "./signature.js";
import {
  MalformedEntryError,
  type Anchor,
  type AuditEntry,
  type AuditInput,
  type AuditStore,
  type EntryDraft,
  type SealedEntry,
  type SignedAnchor,
  type VerificationResult,
} from "./types.js";

export interface CheckpointOptions {
  /** PKCS#8 PEM for an ed25519 key. See `generateSigningKey`. */
  readonly privateKeyPem: string;
  /** Defaults to now. Covered by the signature; see {@link SignedAnchor.signedAt}. */
  readonly signedAt?: Date;
}

export interface AuditLogOptions {
  readonly store: AuditStore;
  /** How many entries a verification or export pulls per round trip. */
  readonly pageSize?: number;
}

/**
 * The whole API: append, verify, read, export.
 *
 * There is deliberately no update and no delete. Not because they are guarded,
 * but because the chain makes them useless — anything that changes a row changes
 * its hash, and every later entry's `prevHash` covers it.
 */
export class AuditLog {
  readonly #store: AuditStore;
  readonly #pageSize: number;

  constructor(opts: AuditLogOptions) {
    this.#store = opts.store;
    this.#pageSize = opts.pageSize ?? 500;
    if (this.#pageSize < 1) {
      throw new RangeError("pageSize must be at least 1");
    }
  }

  /**
   * Appends one entry and returns it, sealed. `seq`, `prevHash` and the hash are
   * assigned by the store inside the writing transaction, so concurrent appends
   * to one tenant produce one chain rather than a race.
   */
  async append(input: AuditInput): Promise<SealedEntry> {
    const tenant = required(input.tenant, "tenant");
    const draft: EntryDraft = {
      actor: required(input.actor, "actor"),
      action: required(input.action, "action"),
      // A resource is optional in a way an actor and an action are not: "signed in"
      // has no object. It is still part of the preimage, as "".
      resource: input.resource,
      payloadJson: canonicalJson(input.payload === undefined ? null : input.payload),
    };
    return this.#store.append(tenant, draft, input.at, seal);
  }

  /** The tenant's newest position, or undefined when it has no entries yet. */
  head(tenant: string): Promise<Anchor | undefined> {
    return this.#store.head(required(tenant, "tenant"));
  }

  /**
   * The tenant's newest position, signed. Undefined for an empty chain: there is
   * no position to vouch for yet, and an anchor at seq 0 would be a claim that
   * the log is empty — which is exactly the claim a signature cannot support,
   * since nothing distinguishes an empty log from one that was emptied.
   *
   * Keep the result somewhere this database cannot reach. The private key belongs
   * somewhere this database's host cannot reach either, or the signature proves
   * nothing that the chain did not already prove.
   */
  async checkpoint(tenant: string, opts: CheckpointOptions): Promise<SignedAnchor | undefined> {
    const head = await this.head(tenant);
    if (head === undefined) return undefined;
    return opts.signedAt === undefined
      ? signAnchor(head, opts.privateKeyPem)
      : signAnchor(head, opts.privateKeyPem, opts.signedAt);
  }

  /**
   * Re-reads the tenant's whole chain and reports the first break. Pass the
   * anchor you last wrote down somewhere outside this database; without one, a log
   * whose newest entries were deleted verifies clean, because a truncated chain is
   * still a chain.
   */
  verify(tenant: string, opts: VerifyOptions = {}): Promise<VerificationResult> {
    const name = required(tenant, "tenant");
    return verifyChain(name, this.stream(name), opts);
  }

  /** Every entry, oldest first, one page at a time. */
  async *stream(tenant: string, afterSeq = 0): AsyncGenerator<AuditEntry> {
    const name = required(tenant, "tenant");
    let cursor = afterSeq;
    for (;;) {
      const page = await this.#store.read(name, cursor, this.#pageSize);
      if (page.length === 0) return;
      for (const entry of page) {
        yield entry;
        cursor = entry.seq;
      }
      if (page.length < this.#pageSize) return;
    }
  }

  read(tenant: string, afterSeq = 0, limit = 100): Promise<AuditEntry[]> {
    return this.#store.read(required(tenant, "tenant"), afterSeq, limit);
  }

  tenants(): Promise<string[]> {
    return this.#store.tenants();
  }

  close(): Promise<void> {
    return this.#store.close();
  }
}

function required(value: string, field: string): string {
  if (typeof value !== "string" || value === "") {
    throw new MalformedEntryError(`${field} must be a non-empty string`);
  }
  return value;
}
