# audit-log

An append-only audit log where each tenant's entries form a hash chain, so an
entry that was edited, removed, reordered or backdated cannot be hidden. A
verification CLI walks a chain — from the database or from an export — and either
says it is intact or names the sequence number where it broke.

The guarantee, stated so it can be tested: **within a tenant, entries are gapless
and every hash covers the entry's own fields, its position and the hash before it;
`verify()` reports the first break and what kind it is. With an anchor kept outside
the database, a chain whose newest entries were deleted is caught too.**

One entry can also be shown on its own: `prove` turns a published root and one
record into a file an outsider can check without the rest of the log.

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

### Showing one entry to somebody who may not read the log

A customer disputes one voided invoice, or a regulator asks about one record. The
chain can demonstrate that entry 41 is intact — by handing over entries 41 to the
head, every actor, action and payload in them. An inclusion proof is the one entry
plus one hash per level, and a sibling hash says nothing about the entry it stands
for.

```
$ audit-log root --tenant acme                 # publish this like an anchor
900:4f1c2e8a…

$ audit-log prove --tenant acme --seq 41 > invoice-1001.proof.json
```

Their side needs the file, the root they already had, and no database:

```
$ audit-log verify-proof --proof invoice-1001.proof.json \
    --tenant acme --root 900:4f1c2e8a…
acme  ok  seq 41 is in the log of 900 entries rooted at 4f1c2e8a…
```

`--root` is not optional. A proof carries the root it claims, and checking it
against itself would only prove that its author can add.

```ts
import { verifyInclusion, decodeProof, parseRoot } from "audit-log";

const result = verifyInclusion(
  decodeProof(await readFile("invoice-1001.proof.json", "utf8")),
  // From your records — a ticket, a commit, last quarter's report.
  parseRoot("acme", "900:4f1c2e8a…"),
);
// { ok: false, kind: "root_mismatch", detail: "the path leads to 81b0…, the root you hold is 4f1c…" }
```

Both commands also take `--file acme.ndjson`, because an export is a chain too —
and the archive is often the only copy still reachable when somebody asks about a
record from four years ago.

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

**The tree is derived, and the chain is still what proves the log.** No column, no
trigger and no change to `append`: a root is computed from the entry hashes the
table already holds, when somebody asks. The chain verifies in one pass and
explains a break in one sentence, which is what an audit table needs; the tree
exists for the one thing a chain cannot do, which is show a single record without
its neighbours. The cost is a full read per root or proof, and that is the right
trade — you already pay it for `verify`, and a proof is something you produce when
an auditor asks, not on every append.

**A root is only issued for a chain that has just verified.** `rootOfChain`
streams the entries through `verifyChain` and feeds the builder from the ones it
accepts, so a break comes back instead of a root. Publishing a root over an
unverified prefix would put this package's name on whatever is in the table. It is
one pass and O(log n) hashes — one subtree per set bit of the count — so a log
larger than memory commits the same way a short one does.

**An odd node is promoted, never duplicated.** Hashing the last leaf twice to even
out a level — the familiar Bitcoin construction — gives three leaves the same root
as four whose last two are equal, so one root commits to two different logs. The
split rule is RFC 6962's: the left subtree is the largest power of two below the
size. `tests/merkle.test.ts` asserts the two roots differ, and checks the
streaming builder against a recursive transcription of MTH and PATH for every size
up to 129 and every position up to 17 — the stack folding is the part that is easy
to get quietly wrong.

**A path is a list of hashes, with no directions in it.** Whether a sibling joins
on the left or the right is a function of `seq` and `size`, derived while
verifying, so a proof cannot misstate its own shape. The length is checked against
the one that position must have *before* the fold, which turns a padded or trimmed
path into "the path has 4 steps, seq 41 of 900 needs 10" instead of a walk that
ends on a hash that happens to match.

**The root has to come from the verifier's own records, and the type says so.**
`PublishedRoot` carries a brand declared in `src/merkle.ts` and never exported, so
only `parseRoot` and `AuditLog.root()` can produce one and a proof cannot be
passed where a trusted root is wanted. `tests/log.test.ts` pins it with a
`@ts-expect-error`: drop the brand and `pnpm typecheck` fails. Like `SealedEntry`,
this is not a defence against someone determined — `parseRoot(t, formatRoot(proof))`
compiles — it stops the mistake of checking a document against itself, which is
the one an honest implementation actually makes. The CLI refuses `verify-proof`
without `--root` for the same reason.

**A root travels with the size it commits to.** Every append produces a different
root, so `<size>:<hash>`; a bare hash is not checkable six months later because
"which one was this?" has no answer. Truncation detection falls out of it for
anyone holding a root: asking for a root over 900 entries when the chain now ends
at 880 reports `truncated`, with no anchor involved.

**Exit 1 means the proof was checked and failed; exit 2 means it could not be
checked against that root.** A root for another tenant, a root taken at another
size, or a path that is not the shape this position needs are all exit 2 — nothing
was learned about the entry, and the useful answer is "ask for a proof at size
900". An entry whose hash is not the hash of its fields, and a path that leads
somewhere else, are exit 1.

**What a proof does not say.** That this entry, with these fields, was at this
position in the log the root commits to — and nothing about the entries around it.
It does not show that the log is gapless or that nothing elsewhere was deleted;
`verify` over the whole chain does that, which is why a root is only issued after
it passed. The siblings disclose the existence and count of other entries, which
is the smallest thing a tree can leak and still be a tree.

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
    merkle.ts             the tree over entry hashes, proofs, and their checker
    log.ts                AuditLog: append, verify, head, stream, root, prove
    wire.ts               the export, anchor, root and proof formats
    cli.ts                verify / checkpoint / export / root / prove /
                          verify-proof / migrate
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
- **No consistency proofs between two roots.** `root` and `prove` are here — see
  the design notes — because showing one record without the other 899 turned out to
  be an audit-table problem after all. What is not here is the other half of a
  transparency log: a proof that the root over 900 entries extends the root over 50,
  so a client holding both can tell an append from a rewrite without reading the
  log. The operator can already demonstrate that by replaying the chain, and the
  audience for a root here is a handful of people who can ask. A log with
  thousands of independent monitors needs the proof; this is not that.
- **No log server, no gossip and no witnesses.** A root is a string you publish the
  way you already publish an anchor. Who published which root when, and whether two
  readers were shown the same one, is the problem a transparency log exists to
  solve, and it needs a service and an audience, not a library inside your
  database.
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
pnpm test                                   # 173 tests; Postgres suite skipped
DATABASE_URL=postgres://… pnpm test         # 196 tests
```

The suite is written so that removing a guarantee breaks it. Verified by mutation:
replacing the length-prefixed framing with a `":"` join, dropping the key sort from
`canonicalJson`, letting it accept `Date`s, skipping the hash recomputation, the
`prevHash` link check, the `seq` gap check or the unreached-anchor check in
`verifyChain`, allowing an entry timed before the tail, dropping `primary key
(tenant, seq)` or the append-only trigger from the schema, and removing the
append retry each fail at least one test. Dropping the `SealedEntry` brand fails
`pnpm typecheck` instead.

The same for the tree: duplicating the odd leaf instead of promoting it, dropping
the path-length check, skipping the entry's own hash recomputation, comparing the
path only against the root the proof carries, ignoring the size a root was taken
at, swapping the sides while folding a path, rooting a chain without verifying it
first, accepting a chain shorter than the size asked for, dropping a domain string
from the leaf preimage, and letting `verify-proof` fall back to the root inside the
proof all fail at least one test. Dropping the `PublishedRoot` brand fails
`pnpm typecheck`.
