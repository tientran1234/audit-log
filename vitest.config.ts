import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    // The Postgres suite creates and drops a schema per file.
    testTimeout: 20_000,
  },
});
