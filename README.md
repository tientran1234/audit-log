# audit-log

An append-only audit log where each tenant's entries form a hash chain, so an
entry that was edited, removed, reordered or backdated cannot be hidden. A
verification CLI walks a chain — from the database or from an export — and either
says it is intact or names the sequence number where it broke.

The guarantee, stated so it can be tested: **within a tenant, entries are gapless
and every hash covers the entry's own fields, its position and the hash before it;
`verify()` reports the first break and what kind it is. With an anchor kept outside
the database, a chain whose newest entries were deleted is caught too — and when
that anchor is signed, an anchor made to match a shortened log is caught as well.**

## Usage

```ts
import { AuditLog, PostgresStore, migrate, openSignedAnchor } from "audit-log";
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

// Last month's position, signed with a key this database's host does not hold, and
// then written down somewhere this database cannot reach. `log.head("acme")` gives
// you the same position unsigned, if you are the only one who has to believe it.
const signed = await log.checkpoint("acme", { privateKeyPem });   // keep this
// ...and, wherever the checking happens, with only the public key:
const anchor = openSignedAnchor(signed!, publicKeyPem);
// `openSignedAnchor` throws if the signature does not hold, so there is no path
// from a signed anchor to a verification that did not check it.

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

A plain anchor is only evidence to someone who already trusts whoever handed it
over. Sign it once and it stands on its own:

```
$ audit-log keygen --out anchors              # once; anchors.key never leaves the safe
9f86d081884c7d65  anchors.key  anchors.pub

$ audit-log checkpoint --tenant acme --sign-key anchors.key > acme.anchor
$ cat acme.anchor
{"v":"audit-log/anchor/v1","tenant":"acme","seq":3,"hash":"e7db45dc…","signedAt":"2026-06-02T10:00:00.000Z","keyId":"9f86d081884c7d65","sig":"Mu1k…=="}

$ audit-log verify --file acme.ndjson --tenant acme \
    --anchor-file acme.anchor --public-key anchors.pub
acme  BROKEN at seq 6  truncated  the chain ends at seq 4, the anchor is at seq 6
```

An anchor the key did not sign is refused before any chain is read, so a shortened
export cannot be handed over with an anchor built to match it:

```
$ audit-log verify --tenant acme --anchor-file forged.anchor --public-key anchors.pub; echo $?
the anchor was signed by key 4c2b9f0ad1e37ac8, but the key supplied is 9f86d081884c7d65
2
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

**Checkpoints are signed; entries are not.** An anchor is only evidence if the
verifier trusts whoever handed it over — and the party best placed to hand an
auditor a shortened export is the same party that would hand over an anchor
matching it. A signature made with a key the database's host does not hold closes
that, and it closes it where the cost is lowest: one signature per checkpoint, over
four fields, taken as often as you take a checkpoint. Signing every entry would put
the signing key on the append path and make the log's integrity depend on key
management — the reason this README used to say signatures were out of scope, and
still the reason per-entry signatures are. Ed25519 from `node:crypto`, keys as PKCS#8
and SPKI PEM, so `openssl` and every secret store already handle them and this
package stores no keys and adds no dependency.

**A `SignedAnchor` is not an `Anchor`, structurally.** It holds its anchor in a
field rather than spreading the three columns across itself, so it will not satisfy
`verify({ anchor })` and there is no accidental path that uses a signed anchor
without checking the signature. `openSignedAnchor` is the only function that turns
one into an `Anchor`. `tests/signature.test.ts` pins this with a `@ts-expect-error`:
flatten the type and `pnpm typecheck` fails. Reaching into `.anchor` deliberately
still works — a type cannot stop that — but nothing here, and no flag on the CLI,
does it. `--anchor-file` without `--public-key` is refused rather than treated as a
plain anchor, because an unchecked signature is not weaker evidence than no
signature, it is the same evidence wearing something that looks like proof.

**A bad signature is exit 2, not exit 1.** The exit codes already mean 0 intact,
1 a chain is broken, 2 the question could not be answered. A forged anchor, the
wrong key file and a reflowed line are indistinguishable from outside, and in all
three cases nothing was checked against the chain — so the honest answer is the
third one. Exit 1 would make a mistyped filename look like tampering; exit 0 would
make a forgery look like proof.

**`signedAt` is in the signature but is not a trusted time.** The signer supplies
it, as they supply an entry's `at`; there is no timestamp authority here. It is
covered so that two checkpoints at one position stay distinguishable and so a
verifier holding several anchors can tell which is which. What it does not do is
prove a chain's *current* length: an old signed anchor is still valid, and proves
only that the chain once reached that point. Verify against the newest anchor you
hold, not the one you were handed.

**The key id is 64 bits of the public key's fingerprint, and authenticates
nothing.** It says *which* key, so a verifier holding several can pick one and a
mismatch gets a message naming both keys instead of "bad signature". Truncating it
is safe precisely because the signature, not the identifier, is what has to hold —
a wrong key fails the signature whatever its id says.

**`keygen` creates key files with `O_EXCL` and refuses to overwrite.** Overwriting
a signing key silently turns every anchor ever made with it into one nobody can
verify, and there is no way back from that; refusing and making the operator pick
another path is recoverable. The private key is created mode `0600`. A
check-then-write would leave a window, so the exclusive create is the check.

**The signature covers a length-prefixed preimage, like the entry hash.** Today
every field after the tenant has a constrained alphabet — digits, lowercase hex, a
fixed-width timestamp — so a joined preimage would happen to be unambiguous too.
Framing means that stays true if a field is ever added, and that there is one
encoding rule in this package rather than two. The domain tag `audit-log/anchor/v1`
is the first frame, so an anchor signature cannot be replayed as anything else here
hashes, and an anchor from a future field list is refused as a version mismatch
rather than reported as a forgery.

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
    signature.ts          ed25519 checkpoint signatures, and their one-line wire form
    log.ts                AuditLog: append, verify, head, checkpoint, stream
    wire.ts               the NDJSON export format and the anchor format
    cli.ts                verify / checkpoint / keygen / export / migrate
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
- **No per-entry signatures, and no external timestamp authority.** Checkpoints are
  signed; entries are not. A signature per entry would put the signing key on the
  append path, and the log's integrity would then rest on key management — rotation,
  custody, what to do with entries signed by a retired key — which is a larger
  project than this one. So the chain still does not prove *who* wrote an entry: the
  writer supplies the actor, and a signed checkpoint vouches for the position, not
  for the contents of any one row. Nor is there a trusted time anywhere here.
  `recordedAt` comes from the database clock and `signedAt` from the signer's; both
  are claims. A verifiable wall-clock time needs a third party, and this package
  does not reach outside your database for one.
- **No key management.** `keygen` writes two PEM files and that is the whole of it.
  There is no key store, no rotation, no revocation list, no expiry, and anchors do
  not chain to one another — so a compromised key is handled by generating another
  one and taking a fresh checkpoint, while old anchors signed by the old key simply
  stop being checked. Anything better than that is a secret store's job, and PEM is
  what secret stores already take.
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
pnpm test                                   # 167 tests; Postgres suite skipped
DATABASE_URL=postgres://… pnpm test         # 190 tests
```

The suite is written so that removing a guarantee breaks it. Verified by mutation:
replacing the length-prefixed framing with a `":"` join, dropping the key sort from
`canonicalJson`, letting it accept `Date`s, skipping the hash recomputation, the
`prevHash` link check, the `seq` gap check or the unreached-anchor check in
`verifyChain`, allowing an entry timed before the tail, dropping `primary key
(tenant, seq)` or the append-only trigger from the schema, and removing the
append retry each fail at least one test. So does dropping any one of the four
signed fields — tenant, seq, hash, `signedAt` — from a checkpoint's preimage,
dropping the key-id check, the millisecond-precision check or the base64
canonicality check when decoding an anchor, or letting `--anchor-file` be used
without `--public-key`. Dropping the `SealedEntry` brand fails `pnpm typecheck`
instead, as does flattening `SignedAnchor` into an `Anchor`.
