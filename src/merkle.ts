/**
 * A Merkle tree over the hashes a chain already has, so that one entry can be
 * shown to somebody who is not allowed to see the rest of the log.
 *
 * The chain remains the thing that proves the log is intact. This is a derived
 * commitment, computed on demand from the entry hashes, and it exists for one
 * situation the chain cannot serve: proving a single record to a third party.
 * With a chain, "entry 41 is in this log" is demonstrated by handing over
 * entries 41 to the head — every actor, action and payload in them — and an
 * auditor asking about one invoice has no business reading the other 900. An
 * inclusion proof is the one entry plus log2(n) sibling hashes, and a hash
 * reveals nothing.
 *
 * Two encoding rules make the tree worth trusting, and both are the same kind of
 * rule as the ones in `canonical.ts`:
 *
 *  - Leaves and interior nodes are hashed under different domain strings. The
 *    length-prefixed framing already gives them preimages of different lengths,
 *    so nothing here depends on the domains today; they are what keeps the
 *    separation true if either preimage ever gains a field, which is exactly when
 *    an interior node would otherwise become presentable as a leaf.
 *  - An odd node is promoted, never duplicated. Hashing the last leaf twice to
 *    even out a level — the familiar Bitcoin construction — gives a tree of three
 *    leaves the same root as a tree of four whose last two are equal, so a root
 *    commits to two different logs. The split rule below is the one RFC 6962
 *    uses: the left subtree is the largest power of two below the size.
 */

import { createHash } from "node:crypto";
import { frame } from "./canonical.js";
import { entryHash, isHash, verifyChain } from "./chain.js";
import type { AuditEntry, ChainBreak } from "./types.js";

/**
 * Only `parseRoot` and `AuditLog.root()` can mint a `PublishedRoot`, because the
 * brand is declared here and never exported. The rule it encodes is the whole
 * point of an inclusion proof: the root has to come from the verifier's own
 * records, not from the file the prover handed them. A proof carries a `root`
 * field for diagnostics, and because the brand is missing it cannot be passed
 * where a trusted root is wanted. Someone determined to fool themselves can
 * still run `parseRoot(tenant, formatRoot(proof))`; no type stops that, and
 * nothing here or in the CLI does it.
 */
declare const published: unique symbol;

/** A size and the root over the first `size` entries of a tenant's chain. */
export interface PublishedRoot {
  readonly tenant: string;
  /** How many entries the root commits to. A root is meaningless without it. */
  readonly size: number;
  readonly root: string;
  readonly [published]: true;
}

/** Internal: the one place a `PublishedRoot` is minted. */
export function mintRoot(root: Omit<PublishedRoot, typeof published>): PublishedRoot {
  return root as PublishedRoot;
}

/**
 * An entry, the hashes needed to walk it up to a root, and the position the
 * walk is over. There are no directions in it: whether a sibling joins on the
 * left or the right is a function of `seq` and `size`, derived during
 * verification, so a proof cannot misstate its own shape.
 */
export interface InclusionProof {
  readonly tenant: string;
  readonly seq: number;
  readonly size: number;
  /** The root the prover says this path leads to. Checked, never trusted. */
  readonly root: string;
  readonly entry: AuditEntry;
  /** Sibling hashes, nearest the leaf first. */
  readonly path: readonly string[];
}

export type ProofFailure =
  /** `seq` is not a position inside `size`: the proof is not about anything. */
  | "out_of_range"
  /** The path is not as long as a path from `seq` in a log of `size` must be. */
  | "wrong_shape"
  /** The root is for another tenant, or another size, than the proof. */
  | "different_commitment"
  /** The entry's hash is not the hash of its own fields: the record was edited. */
  | "entry_tampered"
  /** The path leads somewhere other than the root the prover claims. */
  | "self_inconsistent"
  /** The path leads somewhere other than the root the verifier holds. */
  | "root_mismatch";

export type ProofResult =
  | {
      readonly ok: true;
      readonly tenant: string;
      readonly seq: number;
      readonly size: number;
      readonly root: string;
    }
  | {
      readonly ok: false;
      readonly kind: ProofFailure;
      /** One sentence, safe to print. */
      readonly detail: string;
    };

const LEAF_DOMAIN = "audit-log/merkle/v1/leaf";
const NODE_DOMAIN = "audit-log/merkle/v1/node";

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/**
 * Both hashes take their inputs as the lowercase hex this package passes hashes
 * around as, rather than as 32 decoded bytes. The framing makes the length
 * explicit either way, and one less decode step is one less place to be wrong.
 */
export function leafHash(hash: string): string {
  return sha256(frame([LEAF_DOMAIN, hash]));
}

export function nodeHash(left: string, right: string): string {
  return sha256(frame([NODE_DOMAIN, left, right]));
}

/** The largest power of two strictly below `n`, for `n >= 2`. */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * How many siblings a path from leaf `index` must have in a tree of `size`
 * leaves. Checked before the fold, so a padded or truncated path is reported as
 * the wrong shape instead of being walked into a hash that happens to match.
 */
export function inclusionPathLength(index: number, size: number): number {
  if (size === 1) return 0;
  const k = splitPoint(size);
  return index < k
    ? inclusionPathLength(index, k) + 1
    : inclusionPathLength(index - k, size - k) + 1;
}

/**
 * Builds the root of a tenant's chain, and optionally the path for one leaf, from
 * entry hashes pushed in `seq` order.
 *
 * It keeps one subtree per set bit of the count — O(log n) hashes — so a log
 * larger than memory commits the same way a short one does, which is the same
 * property `verifyChain` has and for the same reason: the Postgres store pages
 * through the chain and nothing here can afford to hold it.
 */
export class MerkleBuilder {
  /** Complete subtrees, left to right, with strictly decreasing sizes. */
  readonly #stack: { hash: string; size: number }[] = [];
  readonly #target: number | undefined;
  /** Where in `#stack` the subtree containing the target leaf currently is. */
  #holder: number | undefined;
  readonly #path: string[] = [];
  #leaves = 0;

  /** `target` is a zero-based leaf index — `seq - 1`. */
  constructor(opts: { readonly target?: number } = {}) {
    if (opts.target !== undefined && (!Number.isInteger(opts.target) || opts.target < 0)) {
      throw new RangeError("target must be a non-negative integer");
    }
    this.#target = opts.target;
  }

  get size(): number {
    return this.#leaves;
  }

  push(hash: string): void {
    const index = this.#leaves;
    this.#leaves += 1;
    this.#stack.push({ hash: leafHash(hash), size: 1 });
    if (index === this.#target) {
      this.#holder = this.#stack.length - 1;
    }

    // Merge while the two rightmost subtrees are the same size. What is left is
    // the binary decomposition of the count, largest first.
    for (;;) {
      const length = this.#stack.length;
      if (length < 2) return;
      const left = this.#stack[length - 2]!;
      const right = this.#stack[length - 1]!;
      if (left.size !== right.size) return;

      this.#stack.length = length - 2;
      const leftAt = length - 2;
      const rightAt = length - 1;
      if (this.#holder === rightAt) this.#path.push(left.hash);
      else if (this.#holder === leftAt) this.#path.push(right.hash);
      this.#stack.push({ hash: nodeHash(left.hash, right.hash), size: left.size + right.size });
      if (this.#holder === leftAt || this.#holder === rightAt) {
        this.#holder = this.#stack.length - 1;
      }
    }
  }

  /**
   * Folds what is left right to left, which is what makes the rightmost
   * incomplete subtree the right child at every level it appears in.
   */
  finish(): { readonly root: string; readonly size: number; readonly path: readonly string[] } {
    if (this.#leaves === 0) {
      // A root over nothing commits to nothing, and would let anybody "prove"
      // against it. Refusing is the only honest answer.
      throw new RangeError("a Merkle root needs at least one entry");
    }
    if (this.#target !== undefined && this.#target >= this.#leaves) {
      throw new RangeError(
        `cannot build a path for leaf ${this.#target} of ${this.#leaves} leaves`,
      );
    }

    const last = this.#stack.length - 1;
    let acc = this.#stack[last]!;
    let accHoldsTarget = this.#holder === last;
    for (let i = last - 1; i >= 0; i -= 1) {
      const left = this.#stack[i]!;
      if (accHoldsTarget) {
        this.#path.push(left.hash);
      } else if (this.#holder === i) {
        this.#path.push(acc.hash);
        accHoldsTarget = true;
      }
      acc = { hash: nodeHash(left.hash, acc.hash), size: left.size + acc.size };
    }
    return { root: acc.hash, size: this.#leaves, path: [...this.#path] };
  }
}

/**
 * Walks `leaf` up through `path` the way the tree was built, and returns the root
 * it reaches. Recursive because the definition is: the sides are decided by the
 * position inside the size, never by the proof.
 */
function foldPath(
  index: number,
  size: number,
  hash: string,
  path: readonly string[],
  used: number,
): { hash: string; used: number } {
  if (size === 1) return { hash, used };
  const k = splitPoint(size);
  if (index < k) {
    const below = foldPath(index, k, hash, path, used);
    const sibling = path[below.used]!;
    return { hash: nodeHash(below.hash, sibling), used: below.used + 1 };
  }
  const below = foldPath(index - k, size - k, hash, path, used);
  const sibling = path[below.used]!;
  return { hash: nodeHash(sibling, below.hash), used: below.used + 1 };
}

/**
 * Checks one entry against a root the verifier already had. Needs no database,
 * no other entry and nothing from the prover beyond the proof itself.
 *
 * What a pass means, exactly: this entry, with these fields, was at this position
 * in the log that root commits to. It says nothing about the entries around it —
 * that is what `verify` is for, and the root was only produced after `verify`
 * passed.
 */
export function verifyInclusion(proof: InclusionProof, trusted: PublishedRoot): ProofResult {
  if (!Number.isInteger(proof.size) || proof.size < 1) {
    return bad("out_of_range", `size must be a positive integer, got ${proof.size}`);
  }
  if (!Number.isInteger(proof.seq) || proof.seq < 1 || proof.seq > proof.size) {
    return bad(
      "out_of_range",
      `seq ${proof.seq} is not a position in a log of ${proof.size} entries`,
    );
  }
  if (proof.tenant !== trusted.tenant) {
    return bad(
      "different_commitment",
      `the proof is for tenant "${proof.tenant}", the root is for "${trusted.tenant}"`,
    );
  }
  if (proof.size !== trusted.size) {
    // A root is only a root of a particular size. Walking the path against a root
    // taken at another size proves nothing either way, so say which size to ask
    // the prover for rather than reporting a hash that was never going to match.
    return bad(
      "different_commitment",
      `the proof commits to ${proof.size} entries, the root to ${trusted.size}: ask for a proof at size ${trusted.size}`,
    );
  }
  if (proof.path.some((hash) => !isHash(hash))) {
    return bad("wrong_shape", "every path element must be 64 lowercase hex characters");
  }

  const expected = inclusionPathLength(proof.seq - 1, proof.size);
  if (proof.path.length !== expected) {
    return bad(
      "wrong_shape",
      `the path has ${proof.path.length} step${
        proof.path.length === 1 ? "" : "s"
      }, seq ${proof.seq} of ${proof.size} needs ${expected}`,
    );
  }

  if (proof.entry.tenant !== proof.tenant || proof.entry.seq !== proof.seq) {
    return bad(
      "entry_tampered",
      `the proof is about ${proof.tenant} seq ${proof.seq}, the entry is ${proof.entry.tenant} seq ${proof.entry.seq}`,
    );
  }

  // The entry against its own fields first. An edited record has to be reported
  // as an edited record, not as a path that does not add up.
  const recomputed = entryHash(proof.entry);
  if (recomputed !== proof.entry.hash) {
    return bad(
      "entry_tampered",
      `the entry hashes to ${recomputed}, not ${proof.entry.hash}`,
    );
  }

  const reached = foldPath(proof.seq - 1, proof.size, leafHash(proof.entry.hash), proof.path, 0)
    .hash;
  if (reached !== proof.root) {
    return bad(
      "self_inconsistent",
      `the path leads to ${reached}, but the proof claims ${proof.root}`,
    );
  }
  if (reached !== trusted.root) {
    return bad(
      "root_mismatch",
      `the path leads to ${reached}, the root you hold is ${trusted.root}`,
    );
  }

  return { ok: true, tenant: proof.tenant, seq: proof.seq, size: proof.size, root: reached };
}

function bad(kind: ProofFailure, detail: string): ProofResult {
  return { ok: false, kind, detail };
}

export interface CommitOptions {
  /**
   * Commit to the first `size` entries instead of to the whole chain. Every
   * append produces a different root, so a proof has to be built at the size of
   * the root its reader already holds.
   */
  readonly size?: number;
}

/** A break instead of a root: the chain underneath did not verify. */
export interface Broken {
  readonly ok: false;
  readonly tenant: string;
  /** How many entries verified before the break. */
  readonly entries: number;
  readonly break: ChainBreak;
}

export type RootResult =
  | {
      readonly ok: true;
      readonly tenant: string;
      /** null when the chain is empty: there is nothing to commit to. */
      readonly root: PublishedRoot | null;
    }
  | Broken;

export type ProveResult =
  | { readonly ok: true; readonly tenant: string; readonly proof: InclusionProof }
  | Broken;

/**
 * Verifies a chain and commits to it in one pass.
 *
 * The verification is not a convenience: a root says "these entries are what the
 * log holds", and publishing one for a chain that does not verify would put this
 * package's name on whatever is in the table. So a break comes back instead of a
 * root, and `verifyChain` is what decides — the builder only ever sees entries it
 * has accepted.
 *
 * Asking for a root over a size the chain no longer reaches is how a missing tail
 * is noticed without an anchor: the answer is `truncated`.
 */
export async function rootOfChain(
  tenant: string,
  entries: AsyncIterable<AuditEntry> | Iterable<AuditEntry>,
  opts: CommitOptions = {},
): Promise<RootResult> {
  const walked = await walk(tenant, entries, checkedSize(opts.size), undefined);
  if (!walked.ok) return walked;
  return {
    ok: true,
    tenant,
    root:
      walked.tree === null
        ? null
        : mintRoot({ tenant, size: walked.tree.size, root: walked.tree.root }),
  };
}

/**
 * A proof that entry `seq` is in the log the root over `size` entries commits to:
 * the entry itself, and one sibling hash per level. Its reader needs neither the
 * database nor any other entry — see {@link verifyInclusion}.
 */
export async function proveInChain(
  tenant: string,
  seq: number,
  entries: AsyncIterable<AuditEntry> | Iterable<AuditEntry>,
  opts: CommitOptions = {},
): Promise<ProveResult> {
  const limit = checkedSize(opts.size);
  if (!Number.isInteger(seq) || seq < 1) {
    throw new RangeError("seq must be a positive integer");
  }
  if (limit !== undefined && seq > limit) {
    // The request contradicts itself, which is a caller bug rather than a state
    // a log could be in.
    throw new RangeError(`seq ${seq} is not inside a root over ${limit} entries`);
  }

  const walked = await walk(tenant, entries, limit, seq);
  if (!walked.ok) return walked;
  // `walk` only returns ok with a target when it found that entry, and a chain
  // containing an entry is not empty.
  const tree = walked.tree!;
  const entry = walked.entry!;
  return {
    ok: true,
    tenant,
    proof: { tenant, seq, size: tree.size, root: tree.root, entry, path: tree.path },
  };
}

type Walked =
  | {
      readonly ok: true;
      readonly tree: {
        readonly root: string;
        readonly size: number;
        readonly path: readonly string[];
      } | null;
      readonly entry: AuditEntry | undefined;
    }
  | Broken;

async function walk(
  tenant: string,
  entries: AsyncIterable<AuditEntry> | Iterable<AuditEntry>,
  limit: number | undefined,
  target: number | undefined,
): Promise<Walked> {
  const builder = new MerkleBuilder(target === undefined ? {} : { target: target - 1 });
  let found: AuditEntry | undefined;

  const result = await verifyChain(
    tenant,
    take(entries, limit, (entry) => {
      if (entry.seq === target) found = entry;
      // The stored hash, which `verifyChain` has just recomputed from the entry's
      // own fields — if the two disagreed we would be returning its break.
      builder.push(entry.hash);
    }),
  );
  if (!result.ok) return result;

  const reached = result.head?.seq ?? 0;
  if (limit !== undefined && reached < limit) {
    return broken(tenant, result.entries, {
      kind: "truncated",
      seq: limit,
      detail: `the chain ends at seq ${reached}, a root was asked for over ${limit} entries`,
    });
  }
  if (target !== undefined && found === undefined) {
    return broken(tenant, result.entries, {
      kind: "truncated",
      seq: target,
      detail: `the chain ends at seq ${reached}, a proof was asked for seq ${target}`,
    });
  }

  return { ok: true, tree: builder.size === 0 ? null : builder.finish(), entry: found };
}

function broken(tenant: string, entries: number, chainBreak: ChainBreak): Broken {
  return { ok: false, tenant, entries, break: chainBreak };
}

function checkedSize(value: number | undefined): number | undefined {
  if (value !== undefined && (!Number.isInteger(value) || value < 1)) {
    throw new RangeError("size must be a positive integer");
  }
  return value;
}

/** The first `limit` positions of a chain, tapping each entry on the way past. */
async function* take(
  entries: AsyncIterable<AuditEntry> | Iterable<AuditEntry>,
  limit: number | undefined,
  tap: (entry: AuditEntry) => void,
): AsyncGenerator<AuditEntry> {
  for await (const entry of entries) {
    if (limit !== undefined && entry.seq > limit) return;
    tap(entry);
    yield entry;
  }
}
