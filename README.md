# audit-log

An append-only audit log where each tenant's entries form a hash chain, so an
entry that was edited, removed, reordered or backdated cannot be hidden. A
verification CLI walks a chain — from the database or from an export — and either
says it is intact or names the sequence number where it broke.

The guarantee, stated so it can be tested: **within a tenant, entries are gapless
and every hash covers the entry's own fields, its position and the hash before it;
`verify()` reports the first break and what kind it is. With an anchor kept outside
the database, a chain whose newest entries were deleted is caught too.**

## Usage

```ts
import { AuditLog, PostgresStore, migrate } from "audit-log";
import { Pool } from "pg";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
await migrate(pool);

const log = new AuditLog({ store: new PostgresStore(pool) });

// Whatever you would have written to an `events` table, minus the id and the
// timestamp: the store assigns the position, links it to the previous entry and
// stamps it from the database clock, inside the transaction that writes the row.
await log.append({
  tenant: "acme",
  actor: "user:42",
  action: "invoice.void",
  resource: "invoice:1001",
  payload: { reason: "duplicate" },
});

// Written down last month, outside this database. `log.head("acme")` produced it.
const anchor = { tenant: "acme", seq: 3, hash: "e7db45dcdb1adbb4…" };

// A cron job, or a test in your release pipeline.
const result = await log.verify("acme", { anchor });
if (!result.ok) {
  // { kind: "tampered", seq: 41, detail: "the entry hashes to a55f41…, not d57e86…" }
  throw new Error(`${result.tenant} is broken at ${result.break.seq}: ${result.break.detail}`);
}
```

The same thing without writing any code:

```
$ audit-log migrate
$ audit-log checkpoint --tenant acme
3:e7db45dcdb1adbb42779e7b7353b45f010769f2acd7ac3cfba35a71b0b27ab89

$ audit-log verify --tenant acme --anchor 3:e7db45dc…
acme  ok  3 entries  head 3:e7db45dcdb1adbb42779e7b7353b45f010769f2acd7ac3cfba35a71b0b27ab89

$ audit-log verify --all --json | jq -c 'select(.ok == false)'
$ audit-log export --tenant acme > acme.ndjson    # hand this to an auditor
$ audit-log verify --file acme.ndjson --tenant acme
```

Exit codes are the answer: 0 intact, 1 a chain is broken, 2 the question could not
be answered. Someone who edits a row is caught by the same command:

```
$ audit-log verify --tenant acme; echo $?
acme  BROKEN at seq 1  tampered  the entry hashes to a55f4112…, not d57e86f3…
1
```

## Design decisions

**The hash preimage is length-prefixed, not joined.** Every field goes in as its
length in bytes followed by its bytes. Joining with a separator — `actor + ":" +
action` — maps `("user:4", "2.void")` and `("user:42", ".void")` to the same bytes,
so one entry can be rewritten into a different entry with the same hash. That is a
forgery, not a hash collision, and no amount of SHA-256 helps. The preimage also
starts with `audit-log/v1`, so entries hashed under a future field list fail loudly
instead of looking like tampering.

**The payload is canonical JSON text, and the column is `text`.** `jsonb` re-orders
keys, drops duplicates and normalises numbers, so the bytes that go in are not the
bytes that come out and the hash stops matching — usually months later, on one
payload. `canonicalJson` fixes a key order and rejects what JSON cannot hold
exactly: `undefined` and functions would vanish, `NaN` becomes `null`, a `Date`
becomes a string that no longer reads as a date. A failed append is better than a
recorded event that is quietly not what the caller passed. Query it with
`payload::jsonb`.

**The timestamp column is `timestamptz(3)`.** The hash covers a millisecond ISO-8601
string, because that is the precision a JavaScript `Date` has. A column keeping
microseconds would eventually hold a time the reader cannot reproduce, and an honest
row would verify as tampered.

**`seq`, `prevHash` and the time are assigned by the store, not passed to `append`.**
They are read and written in one transaction, so there is no window in which the
caller holds a position that someone else is also about to use. `at` is available
for events that really happened earlier, and is rejected if it is before the tenant's
last entry: a log whose timestamps go backwards is harder to read than an append
that fails. With more than one writer, omit it — two application clocks will
eventually disagree, and the database has one clock.

**What actually stops two appends becoming the same entry.** `primary key (tenant,
seq)`. Both writers read the same tail, both compute the same next position, and the
second INSERT fails; the retry loop in `PostgresStore` re-reads the tail and takes
the next one. The retry is throughput, not correctness — remove it and a concurrent
append raises instead of forking. Remove the primary key and the suite fails with
two entry 5s. Because every retry means another writer committed first, the number
of losses is bounded by the number of writers contending for one tenant, which is
what `appendRetries` has to exceed.

**Append-only is a trigger, and the trigger is not the point.** `audit_entry`
refuses UPDATE and DELETE, with a second statement-level trigger for TRUNCATE, which
row triggers do not fire for. That stops application bugs and careless fixes, which
is most of what actually edits an audit table. It does not stop whoever owns the
table: they can disable it in one statement. That is what the hash chain is for, and
the suite proves it — the Postgres tests disable the trigger, edit a row, and assert
that `verify` names it.

**Only `seal()` can produce a writable entry, and it is not exported.** `SealedEntry`
carries a branded property declared but never exported by `src/types.ts`, and stores
accept nothing else. This is not a defence against a hostile writer — anyone who can
INSERT can write any bytes — it is a compile-time guarantee that this package never
writes a hash it did not compute itself. `tests/log.test.ts` pins it with a
`@ts-expect-error`, so dropping the brand fails `pnpm typecheck`.

**Verification streams and returns, rather than loading and throwing.**
`verifyChain` consumes one entry at a time and keeps only the previous one, so a log
larger than memory verifies the same way a short one does: the Postgres store pages
through it, the CLI reads NDJSON off a pipe. And "broken at 41" is an answer the
caller has to print either way, so it comes back as a value with a `kind` —
`missing`, `tampered`, `broken_link`, `truncated` — not as an exception.

**Truncation needs an anchor, and nothing here pretends otherwise.** A chain with its
newest entries deleted is a valid chain; hashes cannot tell it from a chain that was
never longer. So `checkpoint` prints `<seq>:<hash>`, you keep it somewhere this
database cannot reach — a commit, a ticket, another host — and `verify --anchor`
fails if the chain no longer reaches it. There is a test asserting that verification
*without* an anchor accepts a truncated chain, so that nobody later claims a
guarantee the hashes do not give.

**The export embeds the payload as JSON, not as the canonical string.** An auditor
has to read the file, and `"{\"amount\":100}"` is not reading material. Decoding
re-derives the canonical form, which is a function of the value, so a tool that
pretty-printed the export does not turn an intact log into a broken one. To stop the
two verification paths from disagreeing, `verifyChain` also rejects an entry whose
stored text is not canonical — something only a writer that is not this package can
produce.

**`pg` is an optional peer dependency, declared structurally.** `PostgresStore` takes
anything with `query` and `connect`, so nothing is imported from `pg` at build time
and the package has no runtime dependencies. The CLI imports it through a variable
specifier and says what to install if it is missing. The Postgres tests skip when
`DATABASE_URL` is unset.

**The DDL lives in `schema.sql` and in `SCHEMA_SQL`.** Two copies drift, so
`tests/schema.test.ts` asserts they are byte-identical. Run the file by hand, call
`migrate()`, or run `audit-log migrate`.

## Layout

```
audit-log/
  schema.sql              the table, its constraints and the append-only triggers
  src/
    types.ts              vocabulary, the SealedEntry brand, the store interface
    canonical.ts          canonical JSON, and the length-prefixed framing
    chain.ts              the hash preimage, seal(), and the streaming verifier
    log.ts                AuditLog: append, verify, head, stream
    wire.ts               the NDJSON export format and the anchor format
    cli.ts                verify / checkpoint / export / migrate
    store/
      memory.ts           the same guarantees in one process, for tests
      postgres.ts         the durable store
      schema.ts           schema.sql, embedded
  tests/
    store-contract.ts     one suite, run against both stores
```

## What is deliberately not here

- **No query API.** `read` takes a cursor and a limit, because that is what
  verification and export need. "Everything user:42 did last March" is a projection
  built from these rows, with its own indexes and its own idea of what is worth
  filtering on; putting it here would mean guessing that for everyone.
- **No signatures and no external timestamp authority.** The chain proves that
  entries were not changed after they were written. It does not prove *who* wrote
  them or *when* in wall-clock terms — the writer supplies both. Signing entries
  needs key management, and trustworthy times need a third party; either is a larger
  project than this one.
- **No Merkle tree.** A linear chain verifies in one pass and explains a break in one
  sentence. A tree buys short inclusion proofs for a single entry, which matters when
  a third party verifies one record without seeing the log — a transparency-log
  problem, not an audit-table one.
- **No retention or pruning.** `audit_entry` grows forever, and the table will not let
  you delete from it. Trimming an audit log means breaking its chain on purpose, so
  it needs a decision — a sealed archive of the removed prefix, a new genesis — that
  this package should not make for you.
- **No automatic anchoring.** `checkpoint` prints an anchor; where it goes is yours.
  Writing it back into the same database would anchor the chain to something the same
  writer can edit, which is no anchor at all.
- **No HTTP endpoint and no UI.** `verify` is an exit code and a line of text,
  which is what a cron job and a pipeline want. Wrapping it in a status page is
  three lines in whatever framework you already have.
- **No tamper *prevention* beyond the trigger and the grants.** Anyone who owns the
  table can rewrite it. The point is that they cannot do so *undetectably*, which is
  the strongest thing a library inside your own database can honestly offer.
- **No other backend.** Postgres, plus an in-memory store for tests. The guarantees
  here are a primary key, two unique constraints and a trigger; a store that cannot
  express them would be the same API with less behind it.

## Tests

```
pnpm install
pnpm test                                   # 118 tests; Postgres suite skipped
DATABASE_URL=postgres://… pnpm test         # 141 tests
```

The suite is written so that removing a guarantee breaks it. Verified by mutation:
replacing the length-prefixed framing with a `":"` join, dropping the key sort from
`canonicalJson`, letting it accept `Date`s, skipping the hash recomputation, the
`prevHash` link check, the `seq` gap check or the unreached-anchor check in
`verifyChain`, allowing an entry timed before the tail, dropping `primary key
(tenant, seq)` or the append-only trigger from the schema, and removing the
append retry each fail at least one test. Dropping the `SealedEntry` brand fails
`pnpm typecheck` instead.
