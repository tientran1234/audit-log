import { describe, expect, it } from "vitest";
import { MemoryStore } from "../src/store/memory.js";
import { storeContract } from "./store-contract.js";
import { chain, tenantName } from "./helpers.js";

describe("MemoryStore", () => {
  storeContract(async () => new MemoryStore());

  it("adopts an existing chain so an export can be inspected without a database", async () => {
    const tenant = tenantName();
    const entries = chain(tenant, 3);
    const store = MemoryStore.from(entries);

    expect(await store.head(tenant)).toEqual({ tenant, seq: 3, hash: entries[2]!.hash });
    expect((await store.read(tenant, 0, 10)).map((e) => e.seq)).toEqual([1, 2, 3]);
  });

  it("sorts adopted entries by seq, whatever order they arrived in", async () => {
    const tenant = tenantName();
    const [first, second, third] = chain(tenant, 3);
    const store = MemoryStore.from([third!, first!, second!]);
    expect((await store.read(tenant, 0, 10)).map((e) => e.seq)).toEqual([1, 2, 3]);
  });
});
