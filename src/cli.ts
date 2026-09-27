#!/usr/bin/env node
/**
 * The verification CLI.
 *
 * It exists because "the log is intact" has to be something an auditor, a cron job
 * or a release pipeline can check without reading this package's source. So it is
 * scriptable before it is pretty: the exit code is the answer (0 intact, 1 broken,
 * 2 could not tell), `--json` is machine-readable, and `verify --file` works on an
 * export from a database the auditor has no credentials for.
 */

import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { AuditLog } from "./log.js";
import { PostgresStore, type PgPool } from "./store/postgres.js";
import { verifyChain } from "./chain.js";
import { decodeEntries, encodeEntry, formatAnchor, parseAnchor } from "./wire.js";
import type { Anchor, AuditStore, VerificationResult } from "./types.js";

export const EXIT_OK = 0;
export const EXIT_BROKEN = 1;
export const EXIT_USAGE = 2;

export interface CliIo {
  readonly out: (line: string) => void;
  readonly err: (line: string) => void;
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** Overridden in tests; by default a Postgres store from DATABASE_URL. */
  readonly openStore?: () => Promise<AuditStore>;
  /** Overridden in tests; by default the lines of a file on disk. */
  readonly readLines?: (path: string) => AsyncIterable<string>;
}

/** A failure that is the operator's to fix, and so gets a message, not a stack. */
class CliError extends Error {}

const USAGE = `audit-log — verify a hash-chained audit log

  audit-log verify --tenant <t> [--anchor <seq:hash>] [--json]
  audit-log verify --all [--json]
  audit-log verify --file <export.ndjson> --tenant <t> [--anchor <seq:hash>] [--json]
  audit-log checkpoint --tenant <t> [--json]
  audit-log export --tenant <t>
  audit-log migrate

Database commands read DATABASE_URL and need the optional peer dependency "pg".

An anchor is a position you wrote down somewhere this database cannot reach, as
"<seq>:<hash>" — "checkpoint" prints one. Without it, verification cannot tell a
log that was never longer from one whose newest entries were deleted.

Exit codes: 0 intact, 1 a chain is broken, 2 the question could not be answered.`;

export async function run(argv: readonly string[], io: CliIo): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: [...argv],
      allowPositionals: true,
      options: {
        tenant: { type: "string" },
        anchor: { type: "string" },
        file: { type: "string" },
        all: { type: "boolean" },
        json: { type: "boolean" },
        help: { type: "boolean", short: "h" },
      },
    });
  } catch (error) {
    io.err(error instanceof Error ? error.message : String(error));
    io.err(USAGE);
    return EXIT_USAGE;
  }

  const { values, positionals } = parsed;
  const command = positionals[0];
  if (values.help === true || command === "help") {
    io.out(USAGE);
    return EXIT_OK;
  }
  if (command === undefined) {
    io.err(USAGE);
    return EXIT_USAGE;
  }

  try {
    switch (command) {
      case "verify":
        return await verifyCommand(values, io);
      case "checkpoint":
        return await checkpointCommand(values, io);
      case "export":
        return await exportCommand(values, io);
      case "migrate":
        return await migrateCommand(io);
      default:
        throw new CliError(`unknown command "${command}"`);
    }
  } catch (error) {
    if (error instanceof CliError) {
      io.err(error.message);
      return EXIT_USAGE;
    }
    // Anything else is a bug or an unreachable database; the message is still
    // more useful to an operator than a stack trace in a cron mail.
    io.err(error instanceof Error ? `${error.name}: ${error.message}` : String(error));
    return EXIT_USAGE;
  }
}

type Values = {
  tenant?: string | undefined;
  anchor?: string | undefined;
  file?: string | undefined;
  all?: boolean | undefined;
  json?: boolean | undefined;
};

async function verifyCommand(values: Values, io: CliIo): Promise<number> {
  if (values.file !== undefined) {
    const tenant = requireTenant(values);
    const lines = (io.readLines ?? fileLines)(values.file);
    const result = await verifyChain(tenant, decodeEntries(lines), anchorOptions(tenant, values));
    report(result, io, values.json === true);
    return result.ok ? EXIT_OK : EXIT_BROKEN;
  }

  const store = await openStore(io);
  const log = new AuditLog({ store });
  try {
    if (values.all === true) {
      if (values.anchor !== undefined) {
        // One anchor cannot vouch for several chains, and silently applying it to
        // the wrong one would be worse than refusing.
        throw new CliError("--anchor names one tenant's position; use it with --tenant");
      }
      const tenants = await log.tenants();
      if (tenants.length === 0) {
        io.err("no tenants have any entries");
        return EXIT_OK;
      }
      let worst = EXIT_OK;
      for (const tenant of tenants) {
        const result = await log.verify(tenant);
        report(result, io, values.json === true);
        if (!result.ok) worst = EXIT_BROKEN;
      }
      return worst;
    }

    const tenant = requireTenant(values);
    const result = await log.verify(tenant, anchorOptions(tenant, values));
    report(result, io, values.json === true);
    return result.ok ? EXIT_OK : EXIT_BROKEN;
  } finally {
    await store.close();
  }
}

async function checkpointCommand(values: Values, io: CliIo): Promise<number> {
  const tenant = requireTenant(values);
  const store = await openStore(io);
  const log = new AuditLog({ store });
  try {
    const head = await log.head(tenant);
    if (head === undefined) {
      io.err(`${tenant} has no entries`);
      return EXIT_OK;
    }
    io.out(values.json === true ? JSON.stringify(head) : formatAnchor(head));
    return EXIT_OK;
  } finally {
    await store.close();
  }
}

async function exportCommand(values: Values, io: CliIo): Promise<number> {
  const tenant = requireTenant(values);
  const store = await openStore(io);
  const log = new AuditLog({ store });
  try {
    for await (const entry of log.stream(tenant)) {
      io.out(encodeEntry(entry));
    }
    return EXIT_OK;
  } finally {
    await store.close();
  }
}

async function migrateCommand(io: CliIo): Promise<number> {
  const store = await openStore(io);
  try {
    if (!(store instanceof PostgresStore)) {
      throw new CliError("migrate needs a Postgres store");
    }
    await store.migrate();
    io.out("audit_entry is up to date");
    return EXIT_OK;
  } finally {
    await store.close();
  }
}

function report(result: VerificationResult, io: CliIo, json: boolean): void {
  if (json) {
    io.out(JSON.stringify(result));
    return;
  }
  if (result.ok) {
    const head = result.head === null ? "empty" : `head ${formatAnchor(result.head)}`;
    io.out(`${result.tenant}  ok  ${result.entries} entries  ${head}`);
    return;
  }
  io.out(
    `${result.tenant}  BROKEN at seq ${result.break.seq}  ${result.break.kind}  ${result.break.detail}`,
  );
}

function requireTenant(values: Values): string {
  if (values.tenant === undefined || values.tenant === "") {
    throw new CliError("--tenant is required");
  }
  return values.tenant;
}

function anchorOptions(tenant: string, values: Values): { anchor?: Anchor } {
  return values.anchor === undefined ? {} : { anchor: parseAnchor(tenant, values.anchor) };
}

async function* fileLines(path: string): AsyncGenerator<string> {
  const reader = createInterface({
    input: createReadStream(path, "utf8"),
    crlfDelay: Number.POSITIVE_INFINITY,
  });
  try {
    for await (const line of reader) yield line;
  } finally {
    reader.close();
  }
}

async function openStore(io: CliIo): Promise<AuditStore> {
  if (io.openStore !== undefined) return io.openStore();

  const env = io.env ?? process.env;
  const url = env["DATABASE_URL"];
  if (url === undefined || url === "") {
    throw new CliError("DATABASE_URL is not set");
  }

  // A variable specifier keeps `pg` out of the type graph, so the package still
  // builds and installs for consumers who only use the in-memory store.
  const specifier = "pg";
  let pg: { default: { Pool: new (config: unknown) => PgPool } };
  try {
    pg = (await import(specifier)) as typeof pg;
  } catch {
    throw new CliError('this command needs the optional peer dependency "pg": pnpm add pg');
  }
  return new PostgresStore(new pg.default.Pool({ connectionString: url }), { ownsPool: true });
}

// `run` is exported so the tests can drive every command against the in-memory
// store, which is why the argument parsing and the reporting live in functions
// rather than in a main(). Only run when this module is the process entry point.
if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const code = await run(process.argv.slice(2), {
    out: (line) => process.stdout.write(`${line}\n`),
    err: (line) => process.stderr.write(`${line}\n`),
  });
  process.exit(code);
}
