import { canonicalJson } from "./canonical.js";
import { seal, verifyChain, type VerifyOptions } from "./chain.js";
import {
  proveInChain,
  rootOfChain,
  type CommitOptions,
  type ProveResult,
  type RootResult,
} from "./merkle.js";
import {
  MalformedEntryError,
  type Anchor,
  type AuditEntry,
  type AuditInput,
  type AuditStore,
  type EntryDraft,
  type SealedEntry,
  type VerificationResult,
} from "./types.js";

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
   * Re-reads the tenant's whole chain and reports the first break. Pass the
   * anchor you last wrote down somewhere outside this database; without one, a log
   * whose newest entries were deleted verifies clean, because a truncated chain is
   * still a chain.
   */
  verify(tenant: string, opts: VerifyOptions = {}): Promise<VerificationResult> {
    const name = required(tenant, "tenant");
    return verifyChain(name, this.stream(name), opts);
  }

  /**
   * The Merkle root over the tenant's first `size` entries — the whole chain by
   * default — after verifying them. Publish it the way you publish an anchor;
   * `prove` then shows one entry to somebody who may not see the rest.
   */
  root(tenant: string, opts: CommitOptions = {}): Promise<RootResult> {
    const name = required(tenant, "tenant");
    return rootOfChain(name, this.stream(name), opts);
  }

  /** An inclusion proof for one entry, against the root over `size` entries. */
  prove(tenant: string, seq: number, opts: CommitOptions = {}): Promise<ProveResult> {
    const name = required(tenant, "tenant");
    return proveInChain(name, seq, this.stream(name), opts);
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
