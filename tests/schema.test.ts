import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { SCHEMA_SQL } from "../src/store/schema.js";

describe("schema.sql", () => {
  it("is byte-identical to the embedded copy", () => {
    // Two copies of DDL drift. `migrate()` runs the string, an operator runs the
    // file, and this is what keeps them the same thing.
    expect(SCHEMA_SQL).toBe(readFileSync(new URL("../schema.sql", import.meta.url), "utf8"));
  });

  it("states the guarantees it is supposed to enforce", () => {
    // A cheap guard against someone relaxing the schema and the suite still
    // passing because Postgres was not available in CI.
    expect(SCHEMA_SQL).toContain("primary key (tenant, seq)");
    expect(SCHEMA_SQL).toContain("constraint audit_entry_no_fork unique (tenant, prev_hash)");
    expect(SCHEMA_SQL).toContain("timestamptz(3)");
    expect(SCHEMA_SQL).toContain("before update or delete on audit_entry");
    expect(SCHEMA_SQL).toContain("before truncate on audit_entry");
  });
});
