import { describe, expect, it } from "vitest";
import { AuditLog } from "../src/log.js";
import { MemoryStore } from "../src/store/memory.js";
import { GENESIS_HASH } from "../src/chain.js";
import { verifyInclusion, type PublishedRoot } from "../src/merkle.js";
import { InvalidPayloadError, MalformedEntryError, type SealedEntry } from "../src/types.js";
import { at, memoryLog, tenantName } from "./helpers.js";

const event = (overrides: Record<string, unknown> = {}) => ({
  tenant: "acme",
  actor: "user:42",
  action: "invoice.void",
  resource: "invoice:1001",
  ...overrides,
});

describe("AuditLog", () => {
  it("records an event and returns where it landed", async () => {
    const log = memoryLog();
    const tenant = tenantName();
    const entry = await log.append(event({ tenant, payload: { reason: "duplicate" } }));

    expect(entry).toMatchObject({
      tenant,
      seq: 1,
      prevHash: GENESIS_HASH,
      actor: "user:42",
      action: "invoice.void",
      resource: "invoice:1001",
      payloadJson: '{"reason":"duplicate"}',
    });
  });

  it("canonicalises the payload, so the same event written two ways is the same bytes", async () => {
    const log = memoryLog();
    const tenant = tenantName();
    const first = await log.append(event({ tenant, payload: { b: 1, a: 2 } }));
    const second = await log.append(event({ tenant, payload: { a: 2, b: 1 } }));
    expect(second.payloadJson).toBe(first.payloadJson);
  });

  it("records an absent payload as null rather than inventing one", async () => {
    const entry = await memoryLog().append(event({ tenant: tenantName() }));
    expect(entry.payloadJson).toBe("null");
  });

  it("refuses a payload it cannot hash exactly", async () => {
    await expect(
      memoryLog().append(event({ tenant: tenantName(), payload: { when: new Date(0) } })),
    ).rejects.toThrow(InvalidPayloadError);
  });

  it.each(["tenant", "actor", "action"] as const)("requires a %s", async (field) => {
    await expect(memoryLog().append(event({ tenant: tenantName(), [field]: "" }))).rejects.toThrow(
      MalformedEntryError,
    );
  });

  it("allows an empty resource, because not every action has an object", async () => {
    const entry = await memoryLog().append(
      event({ tenant: tenantName(), action: "session.start", resource: "" }),
    );
    expect(entry.resource).toBe("");
  });

  it("does not let a caller mutate the time it recorded, after the hash covered it", async () => {
    const log = memoryLog();
    const tenant = tenantName();
    const when = at(0);
    const entry = await log.append(event({ tenant, at: when }));
    when.setFullYear(1999);

    expect(entry.recordedAt.getFullYear()).toBe(2026);
    expect((await log.verify(tenant)).ok).toBe(true);
  });

  it("streams a chain longer than one page, in order", async () => {
    const store = new MemoryStore();
    const log = new AuditLog({ store, pageSize: 3 });
    const tenant = tenantName();
    for (let i = 0; i < 10; i += 1) {
      await log.append(event({ tenant, resource: `invoice:${i}`, at: at(i) }));
    }

    const seen: number[] = [];
    for await (const entry of log.stream(tenant)) seen.push(entry.seq);
    expect(seen).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  });

  it("verifies a chain longer than one page", async () => {
    const log = new AuditLog({ store: new MemoryStore(), pageSize: 2 });
    const tenant = tenantName();
    for (let i = 0; i < 7; i += 1) await log.append(event({ tenant, at: at(i) }));

    const result = await log.verify(tenant);
    expect(result.ok).toBe(true);
    expect(result.entries).toBe(7);
  });

  it("verifies an empty tenant as an empty chain", async () => {
    const result = await memoryLog().verify(tenantName());
    expect(result).toMatchObject({ ok: true, entries: 0, head: null });
  });

  it("refuses a pageSize below one, which would stream forever", () => {
    expect(() => new AuditLog({ store: new MemoryStore(), pageSize: 0 })).toThrow(RangeError);
  });

  it("round-trips head into an anchor that verify accepts", async () => {
    const log = memoryLog();
    const tenant = tenantName();
    await log.append(event({ tenant, at: at(0) }));
    await log.append(event({ tenant, at: at(1) }));

    const anchor = await log.head(tenant);
    expect(anchor).toMatchObject({ tenant, seq: 2 });
    expect((await log.verify(tenant, { anchor: anchor! })).ok).toBe(true);
  });

  it("has no update and no delete to call", () => {
    const log = memoryLog();
    expect((log as unknown as Record<string, unknown>)["update"]).toBeUndefined();
    expect((log as unknown as Record<string, unknown>)["delete"]).toBeUndefined();
  });
});

describe("the seal is a compile-time boundary", () => {
  it("cannot be forged outside the package", async () => {
    const log = memoryLog();
    const tenant = tenantName();
    const real = await log.append(event({ tenant, at: at(0) }));

    // The brand on SealedEntry is what stops anything outside this package from
    // writing a hash it did not compute. Drop the brand and the directive below
    // stops erroring, so `pnpm typecheck` fails — which is the only way to test a
    // guarantee that exists at compile time.
    // @ts-expect-error a plain object is not sealed, whatever its hash claims
    const forged: SealedEntry = {
      tenant: real.tenant,
      seq: real.seq,
      recordedAt: real.recordedAt,
      actor: "somebody else",
      action: real.action,
      resource: real.resource,
      payloadJson: real.payloadJson,
      prevHash: real.prevHash,
      hash: real.hash,
    };
    expect(forged.actor).toBe("somebody else");
  });
});

describe("AuditLog.root and AuditLog.prove", () => {
  it("roots the whole chain, and proves an entry against that root", async () => {
    const log = memoryLog();
    const tenant = tenantName();
    for (let i = 0; i < 7; i += 1) {
      await log.append(event({ tenant, resource: `invoice:${i}`, at: at(i) }));
    }

    const rooted = await log.root(tenant);
    if (!rooted.ok || rooted.root === null) throw new Error("expected a root");
    expect(rooted.root.size).toBe(7);
    expect(rooted.root.tenant).toBe(tenant);

    const proof = await log.prove(tenant, 5);
    if (!proof.ok) throw new Error("expected a proof");
    expect(verifyInclusion(proof.proof, rooted.root)).toMatchObject({ ok: true, seq: 5 });
  });

  it("commits to a chain that takes more than one read to page through", async () => {
    // `root` and `prove` stream the chain the way `verify` does, so a chain
    // longer than one page is where a wrapper around the stream would go wrong:
    // a dropped page gives a root over a prefix without saying so.
    const store = new MemoryStore();
    const paged = new AuditLog({ store, pageSize: 3 });
    const whole = new AuditLog({ store, pageSize: 1000 });
    const tenant = tenantName();
    for (let i = 0; i < 10; i += 1) {
      await paged.append(event({ tenant, resource: `invoice:${i}`, at: at(i) }));
    }

    const pagedRoot = await paged.root(tenant);
    const wholeRoot = await whole.root(tenant);
    if (!pagedRoot.ok || !wholeRoot.ok) throw new Error("expected a root");
    expect(pagedRoot.root).toEqual(wholeRoot.root);
    expect(pagedRoot.root?.size).toBe(10);

    const proof = await paged.prove(tenant, 8);
    if (!proof.ok) throw new Error("expected a proof");
    expect(verifyInclusion(proof.proof, wholeRoot.root!)).toMatchObject({ ok: true, seq: 8 });
  });

  it("has no root for a tenant with no entries", async () => {
    const log = memoryLog();
    expect(await log.root(tenantName())).toMatchObject({ ok: true, root: null });
  });

  it("refuses an empty tenant name the way every other method does", () => {
    const log = memoryLog();
    // Synchronously, because `verify`, `head` and `read` validate their tenant
    // the same way: the name is checked before any promise is made. Under `await`
    // — which is how all of them are called — there is no difference.
    expect(() => log.root("")).toThrow(MalformedEntryError);
    expect(() => log.prove("", 1)).toThrow(MalformedEntryError);
  });
});

describe("a trusted root is a compile-time boundary", () => {
  it("cannot be taken from the proof being checked", async () => {
    const log = memoryLog();
    const tenant = tenantName();
    await log.append(event({ tenant, at: at(0) }));
    const proof = await log.prove(tenant, 1);
    if (!proof.ok) throw new Error("expected a proof");

    // A proof carries the root it claims, and checking it against itself proves
    // only that its author can add. The brand on PublishedRoot is what stops that
    // from typechecking: drop it and the directive below stops erroring, so
    // `pnpm typecheck` fails. Nothing in this package or the CLI launders a
    // proof's own root into a trusted one — a type cannot stop someone who sets
    // out to, only someone who did not notice.
    // @ts-expect-error a proof's own root is not a root anybody published
    const circular: PublishedRoot = proof.proof;
    expect(circular.root).toBe(proof.proof.root);
  });
});
