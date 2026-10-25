/**
 * An append-only, per-tenant, hash-chained audit log.
 *
 * The guarantee: within a tenant, entries are gapless and each one's hash covers
 * its own fields, its position, and the hash before it — so an entry that was
 * edited, removed, reordered or moved between tenants cannot be hidden, and
 * `verify()` names the sequence number where the chain broke. Pair it with an
 * anchor kept outside the database and the tail cannot be quietly cut off either.
 *
 * `seal()` is deliberately not exported: a `SealedEntry` can only be produced
 * inside this package, so no caller can hand a store a hash of its own choosing.
 * Neither is `mintRoot()`, for the same reason: a trusted root has to come from
 * the verifier's own records, not from the proof being checked.
 */

export { AuditLog, type AuditLogOptions } from "./log.js";
export { canonicalJson, parsePayload } from "./canonical.js";
export { GENESIS_HASH, entryHash, isHash, verifyChain, type VerifyOptions } from "./chain.js";
export {
  MerkleBuilder,
  inclusionPathLength,
  leafHash,
  nodeHash,
  proveInChain,
  rootOfChain,
  verifyInclusion,
  type Broken,
  type CommitOptions,
  type InclusionProof,
  type ProofFailure,
  type ProofResult,
  type ProveResult,
  type PublishedRoot,
  type RootResult,
} from "./merkle.js";
export {
  decodeEntries,
  decodeEntry,
  decodeProof,
  encodeEntry,
  encodeProof,
  formatAnchor,
  formatRoot,
  parseAnchor,
  parseRoot,
} from "./wire.js";
export { MemoryStore } from "./store/memory.js";
export {
  PostgresStore,
  migrate,
  type PgClient,
  type PgPool,
  type PgPoolClient,
  type PostgresStoreOptions,
} from "./store/postgres.js";
export {
  InvalidPayloadError,
  MalformedEntryError,
  NonMonotonicTimeError,
  type Anchor,
  type AuditEntry,
  type AuditInput,
  type AuditStore,
  type BreakKind,
  type ChainBreak,
  type EntryDraft,
  type SealedEntry,
  type Sealer,
  type VerificationResult,
} from "./types.js";
