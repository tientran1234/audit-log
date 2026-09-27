import { GENESIS_HASH } from "../chain.js";
import {
  MalformedEntryError,
  NonMonotonicTimeError,
  type Anchor,
  type AuditEntry,
  type AuditStore,
  type EntryDraft,
  type SealedEntry,
  type Sealer,
} from "../types.js";
import { SCHEMA_SQL } from "./schema.js";

/**
 * The slice of `pg` this store uses, declared structurally so that `pg` is an
 * optional peer dependency and never a build-time one. A `pg.Pool` satisfies it.
 */
export interface PgClient {
  query(text: string, values?: readonly unknown[]): Promise<{ rows: unknown[] }>;
}

export interface PgPool extends PgClient {
  connect(): Promise<PgPoolClient>;
  end(): Promise<void>;
}

export interface PgPoolClient extends PgClient {
  release(): void;
}

export interface PostgresStoreOptions {
  /** Closing the store ends the pool. Set true when the store owns it. */
  readonly ownsPool?: boolean;
  /**
   * How many times an append re-reads the tail after losing the race for a
   * position. Every retry means some other writer committed first, so the number
   * of losses is bounded by the number of writers contending for the same tenant
   * at the same instant — set this above that, not above your total throughput.
   */
  readonly appendRetries?: number;
}

/** Creates the table, constraints and triggers if they are missing. Idempotent. */
export async function migrate(pool: PgClient): Promise<void> {
  await pool.query(SCHEMA_SQL);
}

const UNIQUE_VIOLATION = "23505";

/**
 * The durable store.
 *
 * The interesting property is what stops two appends from becoming the same entry,
 * and it is not this file: it is `primary key (tenant, seq)`. Both writers read the
 * same tail, both compute the same next position, and the second INSERT fails. The
 * retry loop below turns that failure into a correct append at the next position,
 * which is a throughput decision — remove it and a concurrent append raises instead
 * of forking. Remove the primary key and the suite fails with two entry 5s.
 */
export class PostgresStore implements AuditStore {
  readonly #pool: PgPool;
  readonly #ownsPool: boolean;
  readonly #retries: number;

  constructor(pool: PgPool, opts: PostgresStoreOptions = {}) {
    this.#pool = pool;
    this.#ownsPool = opts.ownsPool ?? false;
    this.#retries = opts.appendRetries ?? 32;
  }

  async append(
    tenant: string,
    draft: EntryDraft,
    at: Date | undefined,
    seal: Sealer,
  ): Promise<SealedEntry> {
    const client = await this.#pool.connect();
    try {
      for (let attempt = 0; ; attempt += 1) {
        try {
          return await this.#appendOnce(client, tenant, draft, at, seal);
        } catch (error) {
          await client.query("rollback").catch(() => {
            // The transaction is already gone; the original error is the one to report.
          });
          if (!isUniqueViolation(error) || attempt >= this.#retries) throw error;
          // Another writer took this position. Its entry is now the tail, so read
          // it again — including its timestamp, which is why a new transaction
          // (and so a new `now()`) is needed rather than a second INSERT.
        }
      }
    } finally {
      client.release();
    }
  }

  async #appendOnce(
    client: PgPoolClient,
    tenant: string,
    draft: EntryDraft,
    at: Date | undefined,
    seal: Sealer,
  ): Promise<SealedEntry> {
    await client.query("begin");

    // One round trip for the tail and the clock. The left join on a one-row
    // relation keeps the clock when the tenant has no entries yet.
    const tail = await client.query(
      `select tail.seq, tail.recorded_at, tail.hash,
              date_trunc('milliseconds', now()) as clock
         from (values (1)) as one(ignored)
         left join (
           select seq, recorded_at, hash
             from audit_entry
            where tenant = $1
            order by seq desc
            limit 1
         ) as tail on true`,
      [tenant],
    );
    const row = asRow(tail.rows[0]);
    const clock = asDate(row["clock"], "clock");
    const tailSeq = row["seq"] === null ? 0 : asSeq(row["seq"]);
    const tailHash = row["hash"] === null ? GENESIS_HASH : asString(row["hash"], "hash");
    const tailAt = row["recorded_at"] === null ? undefined : asDate(row["recorded_at"], "recorded_at");

    const recordedAt = at ?? clock;
    if (tailAt !== undefined && recordedAt.getTime() < tailAt.getTime()) {
      // The caller's clock, not a race: `append` rolls back and rethrows.
      throw new NonMonotonicTimeError(tenant, recordedAt, tailAt);
    }

    const entry = seal({
      tenant,
      seq: tailSeq + 1,
      prevHash: tailHash,
      recordedAt,
      draft,
    });

    await client.query(
      `insert into audit_entry
         (tenant, seq, recorded_at, actor, action, resource, payload, prev_hash, hash)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        entry.tenant,
        entry.seq,
        entry.recordedAt,
        entry.actor,
        entry.action,
        entry.resource,
        entry.payloadJson,
        entry.prevHash,
        entry.hash,
      ],
    );
    await client.query("commit");
    return entry;
  }

  /** Same as the standalone {@link migrate}, for callers that only hold a store. */
  async migrate(): Promise<void> {
    await migrate(this.#pool);
  }

  async head(tenant: string): Promise<Anchor | undefined> {
    const result = await this.#pool.query(
      "select seq, hash from audit_entry where tenant = $1 order by seq desc limit 1",
      [tenant],
    );
    if (result.rows.length === 0) return undefined;
    const row = asRow(result.rows[0]);
    return { tenant, seq: asSeq(row["seq"]), hash: asString(row["hash"], "hash") };
  }

  async read(tenant: string, afterSeq: number, limit: number): Promise<AuditEntry[]> {
    const result = await this.#pool.query(
      `select tenant, seq, recorded_at, actor, action, resource, payload, prev_hash, hash
         from audit_entry
        where tenant = $1 and seq > $2
        order by seq
        limit $3`,
      [tenant, afterSeq, Math.max(0, limit)],
    );
    return result.rows.map(toEntry);
  }

  async tenants(): Promise<string[]> {
    const result = await this.#pool.query("select distinct tenant from audit_entry order by tenant");
    return result.rows.map((row) => asString(asRow(row)["tenant"], "tenant"));
  }

  async close(): Promise<void> {
    if (this.#ownsPool) await this.#pool.end();
  }
}

function isUniqueViolation(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    (error as { code?: unknown }).code === UNIQUE_VIOLATION
  );
}

function toEntry(raw: unknown): AuditEntry {
  const row = asRow(raw);
  return {
    tenant: asString(row["tenant"], "tenant"),
    seq: asSeq(row["seq"]),
    recordedAt: asDate(row["recorded_at"], "recorded_at"),
    actor: asString(row["actor"], "actor"),
    action: asString(row["action"], "action"),
    resource: asString(row["resource"], "resource"),
    payloadJson: asString(row["payload"], "payload"),
    prevHash: asString(row["prev_hash"], "prev_hash"),
    hash: asString(row["hash"], "hash"),
  };
}

function asRow(raw: unknown): Record<string, unknown> {
  if (typeof raw !== "object" || raw === null) {
    throw new MalformedEntryError("expected a row object from the driver");
  }
  return raw as Record<string, unknown>;
}

function asString(value: unknown, column: string): string {
  if (typeof value !== "string") {
    throw new MalformedEntryError(`column ${column} is not text`);
  }
  return value;
}

function asDate(value: unknown, column: string): Date {
  if (!(value instanceof Date)) {
    throw new MalformedEntryError(`column ${column} is not a timestamp`);
  }
  return value;
}

/**
 * `seq` is a bigint, which the driver hands back as a string rather than risk a
 * silent loss of precision. Refusing anything past 2^53 keeps that promise here
 * too: at a million entries a second it would take 285 years to reach, and a
 * wrong sequence number in an audit log is worse than an error.
 */
function asSeq(value: unknown): number {
  const seq = typeof value === "string" ? Number(value) : value;
  if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 1) {
    throw new MalformedEntryError(`seq ${String(value)} is not a safe positive integer`);
  }
  return seq;
}
