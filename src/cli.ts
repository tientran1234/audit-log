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
import { readFile, writeFile } from "node:fs/promises";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { AuditLog } from "./log.js";
import { PostgresStore, type PgPool } from "./store/postgres.js";
import { verifyChain } from "./chain.js";
import { decodeEntries, encodeEntry, formatAnchor, parseAnchor } from "./wire.js";
import {
  decodeSignedAnchor,
  encodeSignedAnchor,
  generateSigningKey,
  openSignedAnchor,
  signAnchor,
} from "./signature.js";
import { AnchorSignatureError } from "./types.js";
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
  /** Overridden in tests; by default the whole of a file on disk. */
  readonly readFile?: (path: string) => Promise<string>;
  /** Overridden in tests; by default creates a file and fails if it exists. */
  readonly createFile?: (path: string, data: string, mode: number) => Promise<void>;
}

/** A failure that is the operator's to fix, and so gets a message, not a stack. */
class CliError extends Error {}

const USAGE = `audit-log — verify a hash-chained audit log

  audit-log verify --tenant <t> [--anchor <seq:hash>] [--json]
  audit-log verify --tenant <t> --anchor-file <a.json> --public-key <k.pub> [--json]
  audit-log verify --all [--json]
  audit-log verify --file <export.ndjson> --tenant <t> [anchor options] [--json]
  audit-log checkpoint --tenant <t> [--sign-key <k.key>] [--json]
  audit-log keygen --out <prefix>
  audit-log export --tenant <t>
  audit-log migrate

Database commands read DATABASE_URL and need the optional peer dependency "pg".

An anchor is a position you wrote down somewhere this database cannot reach, as
"<seq>:<hash>" — "checkpoint" prints one. Without it, verification cannot tell a
log that was never longer from one whose newest entries were deleted.

A plain anchor is only evidence if you trust whoever handed it to you. "keygen"
makes an ed25519 keypair, "checkpoint --sign-key" signs the position with it, and
"verify --anchor-file --public-key" refuses an anchor that key did not sign — so
a truncated export cannot arrive with an anchor built to match it.

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
        "anchor-file": { type: "string" },
        "public-key": { type: "string" },
        "sign-key": { type: "string" },
        out: { type: "string" },
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
      case "keygen":
        return await keygenCommand(values, io);
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
    // An anchor whose signature does not hold is not a broken chain: nothing was
    // checked against it, so the honest answer is that the question could not be
    // answered. Reporting it as exit 1 would make a mistyped key file look like
    // tampering, and exit 0 would make a forged anchor look like proof.
    if (error instanceof AnchorSignatureError) {
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
  "anchor-file"?: string | undefined;
  "public-key"?: string | undefined;
  "sign-key"?: string | undefined;
  out?: string | undefined;
  file?: string | undefined;
  all?: boolean | undefined;
  json?: boolean | undefined;
};

async function verifyCommand(values: Values, io: CliIo): Promise<number> {
  if (values.file !== undefined) {
    const tenant = requireTenant(values);
    // The anchor is resolved before a single line is read: a signature that does
    // not hold has to stop the command, not colour a result it already printed.
    const opts = await anchorOptions(tenant, values, io);
    const lines = (io.readLines ?? fileLines)(values.file);
    const result = await verifyChain(tenant, decodeEntries(lines), opts);
    report(result, io, values.json === true);
    return result.ok ? EXIT_OK : EXIT_BROKEN;
  }

  if (values.all === true) {
    if (values.anchor !== undefined || values["anchor-file"] !== undefined) {
      // One anchor cannot vouch for several chains, and silently applying it to
      // the wrong one would be worse than refusing.
      throw new CliError("an anchor names one tenant's position; use it with --tenant");
    }
    const store = await openStore(io);
    const log = new AuditLog({ store });
    try {
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
    } finally {
      await store.close();
    }
  }

  const tenant = requireTenant(values);
  // Before the database is opened: resolving the anchor needs no connection, and
  // "that signature does not hold" is a more useful answer than whatever the
  // connection has to say about itself.
  const opts = await anchorOptions(tenant, values, io);
  const store = await openStore(io);
  const log = new AuditLog({ store });
  try {
    const result = await log.verify(tenant, opts);
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
    const signKey = values["sign-key"];
    if (signKey !== undefined) {
      const signed = signAnchor(head, await readWholeFile(io, signKey));
      // Already one line of JSON, so --json has nothing left to do.
      io.out(encodeSignedAnchor(signed));
      return EXIT_OK;
    }
    io.out(values.json === true ? JSON.stringify(head) : formatAnchor(head));
    return EXIT_OK;
  } finally {
    await store.close();
  }
}

async function keygenCommand(values: Values, io: CliIo): Promise<number> {
  const prefix = values.out;
  if (prefix === undefined || prefix === "") {
    throw new CliError("keygen needs --out <prefix>: it writes <prefix>.key and <prefix>.pub");
  }
  const keyPath = `${prefix}.key`;
  const pubPath = `${prefix}.pub`;
  const { privateKeyPem, publicKeyPem, keyId } = generateSigningKey();
  const create = io.createFile ?? createFileOnDisk;

  // Both files are created with O_EXCL rather than checked for first: the check
  // would leave a window, and overwriting a signing key turns every anchor ever
  // made with it into one nobody can verify. Refusing is recoverable; that is not.
  try {
    await create(keyPath, privateKeyPem, 0o600);
  } catch (error) {
    throw new CliError(
      `cannot create ${keyPath} (${reasonOf(error)}). If a key is already there, keep it: ` +
        `replacing it would leave every anchor signed with it unverifiable. Pick another --out.`,
    );
  }
  try {
    await create(pubPath, publicKeyPem, 0o644);
  } catch (error) {
    throw new CliError(
      `wrote ${keyPath} but could not create ${pubPath} (${reasonOf(error)}); ` +
        `remove ${keyPath} and pick another --out`,
    );
  }

  io.out(`${keyId}  ${keyPath}  ${pubPath}`);
  io.err(`keep ${keyPath} off the host that holds the database, or the signature proves nothing`);
  return EXIT_OK;
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

async function anchorOptions(
  tenant: string,
  values: Values,
  io: CliIo,
): Promise<{ anchor?: Anchor }> {
  const anchorFile = values["anchor-file"];
  const publicKey = values["public-key"];

  if (anchorFile === undefined) {
    if (publicKey !== undefined) {
      throw new CliError("--public-key checks a signed anchor; pass --anchor-file as well");
    }
    return values.anchor === undefined ? {} : { anchor: parseAnchor(tenant, values.anchor) };
  }

  if (values.anchor !== undefined) {
    throw new CliError("--anchor and --anchor-file are two answers to one question; pass one");
  }
  if (publicKey === undefined) {
    // There is deliberately no way to use a signed anchor without checking it.
    // An unchecked signature is not weaker evidence than a plain anchor, it is
    // the same evidence wearing something that looks like proof.
    throw new CliError("--anchor-file needs --public-key: an unchecked signature is not evidence");
  }

  const signed = decodeSignedAnchor((await readWholeFile(io, anchorFile)).trim());
  const anchor = openSignedAnchor(signed, await readWholeFile(io, publicKey));
  if (anchor.tenant !== tenant) {
    throw new CliError(
      `the anchor is signed for tenant "${anchor.tenant}", not "${tenant}"`,
    );
  }
  return { anchor };
}

async function readWholeFile(io: CliIo, path: string): Promise<string> {
  const read = io.readFile ?? ((at: string) => readFile(at, "utf8"));
  try {
    return await read(path);
  } catch (error) {
    throw new CliError(`cannot read ${path}: ${reasonOf(error)}`);
  }
}

function reasonOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function createFileOnDisk(path: string, data: string, mode: number): Promise<void> {
  // "wx" is O_CREAT | O_EXCL: the write fails if the path already exists.
  return writeFile(path, data, { encoding: "utf8", mode, flag: "wx" });
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
