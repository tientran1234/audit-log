import { describe, expect, it } from "vitest";
import { AuditLog } from "../src/log.js";
import { MemoryStore } from "../src/store/memory.js";
import { GENESIS_HASH } from "../src/chain.js";
import { InvalidPayloadError, MalformedEntryError, type SealedEntry } from "../src/types.js";
import { generateSigningKey, openSignedAnchor } from "../src/signature.js";
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

describe("log.checkpoint", () => {
  it("signs the head, and the signature opens to the position verify needs", async () => {
    const log = memoryLog();
    const tenant = tenantName();
    for (let i = 0; i < 3; i += 1) {
      await log.append(event({ tenant, resource: `r:${i}`, at: at(i) }));
    }
    const key = generateSigningKey();

    const signed = await log.checkpoint(tenant, { privateKeyPem: key.privateKeyPem });
    expect(signed).toBeDefined();
    const anchor = openSignedAnchor(signed!, key.publicKeyPem);

    expect(anchor).toEqual(await log.head(tenant));
    expect((await log.verify(tenant, { anchor })).ok).toBe(true);
  });

  it("has nothing to sign for an empty chain", async () => {
    const key = generateSigningKey();
    const signed = await memoryLog().checkpoint(tenantName(), { privateKeyPem: key.privateKeyPem });
    // Not an anchor at seq 0: "this log is empty" is the one claim a signature
    // cannot support, because an emptied log looks exactly like a new one.
    expect(signed).toBeUndefined();
  });

  it("takes the caller's time when one is given", async () => {
    const log = memoryLog();
    const tenant = tenantName();
    await log.append(event({ tenant, at: at(0) }));
    const key = generateSigningKey();
    const when = new Date("2026-07-01T00:00:00.000Z");

    const signed = await log.checkpoint(tenant, { privateKeyPem: key.privateKeyPem, signedAt: when });
    expect(signed?.signedAt).toEqual(when);
    expect(openSignedAnchor(signed!, key.publicKeyPem).seq).toBe(1);
  });

  it("rejects an empty tenant like every other method", async () => {
    const key = generateSigningKey();
    await expect(memoryLog().checkpoint("", { privateKeyPem: key.privateKeyPem })).rejects.toThrow(
      MalformedEntryError,
    );
  });
});
