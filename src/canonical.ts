/**
 * Turning a value into bytes that mean exactly one thing.
 *
 * A hash chain is only as good as the encoding underneath it. Two encoding
 * mistakes are easy to make and both are forgeries:
 *
 *  - Serialising a payload object with `JSON.stringify` and hashing that. Key
 *    order is insertion order, so the same event hashed on two code paths
 *    produces two hashes, and a round trip through a `jsonb` column produces a
 *    third. Canonical form fixes an order.
 *  - Joining fields with a separator before hashing. `actor + ":" + action` maps
 *    `("a:b", "c")` and `("a", "b:c")` to the same bytes, so an entry can be
 *    rewritten into a different entry with the same hash. Length-prefixed frames
 *    make every field boundary explicit.
 */

import { InvalidPayloadError } from "./types.js";

const encoder = new TextEncoder();

/**
 * Guards against cycles as much as against depth: an object that contains itself
 * would otherwise recurse until the stack gives out.
 */
const MAX_DEPTH = 64;

/**
 * Canonical JSON text for a payload: object keys sorted by UTF-16 code unit, no
 * insignificant whitespace, and no value that JSON cannot represent exactly.
 *
 * The ordering rule is the one RFC 8785 uses, but this is not a claim of
 * byte-compatibility with it — and it does not need to be, because the canonical
 * *text* is what gets stored and re-hashed. Nothing re-derives it later.
 *
 * Values JSON.stringify would quietly mangle are rejected instead:
 * `undefined` and functions vanish, `NaN` and `Infinity` become `null`, and a
 * `Date` becomes a string that no longer looks like a date to the reader. In an
 * audit log, a payload that is silently not what the caller passed is worse than
 * a failed append.
 */
export function canonicalJson(value: unknown): string {
  return write(value, "$", 0);
}

function write(value: unknown, path: string, depth: number): string {
  if (depth > MAX_DEPTH) {
    throw new InvalidPayloadError(path, `nested deeper than ${MAX_DEPTH} levels, or cyclic`);
  }
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new InvalidPayloadError(path, `${String(value)} is not representable in JSON`);
      }
      // -0 and 0 are the same JSON number; normalise so they are the same bytes.
      return JSON.stringify(value === 0 ? 0 : value);
    case "string":
      // Escapes control characters and lone surrogates the same way every time.
      return JSON.stringify(value);
    case "undefined":
      throw new InvalidPayloadError(path, "undefined would be dropped; omit the key or pass null");
    case "bigint":
      throw new InvalidPayloadError(path, "bigint has no JSON form; pass a string");
    case "function":
    case "symbol":
      throw new InvalidPayloadError(path, `${typeof value} cannot be recorded`);
    case "object":
      break;
  }

  if (Array.isArray(value)) {
    const items = value.map((item, i) => write(item, `${path}[${i}]`, depth + 1));
    return `[${items.join(",")}]`;
  }

  const proto = Object.getPrototypeOf(value) as unknown;
  if (proto !== Object.prototype && proto !== null) {
    // Dates, Maps, Sets, Buffers and class instances all land here. Each has a
    // lossy JSON form, and guessing which one the caller meant is not this
    // package's business.
    const name = (value as object).constructor?.name ?? "object";
    throw new InvalidPayloadError(path, `${name} is not plain JSON; convert it first`);
  }

  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const fields = keys.map((key) => {
    const encoded = write(record[key], `${path}.${key}`, depth + 1);
    return `${JSON.stringify(key)}:${encoded}`;
  });
  return `{${fields.join(",")}}`;
}

/** Parses the canonical text back. The text, not this object, is what was hashed. */
export function parsePayload(payloadJson: string): unknown {
  return JSON.parse(payloadJson) as unknown;
}

/**
 * Concatenates the parts, each prefixed with its length in bytes as a 64-bit
 * big-endian integer. Unambiguous: no part can borrow bytes from its neighbour,
 * whatever it contains.
 */
export function frame(parts: readonly string[]): Uint8Array {
  const bodies = parts.map((part) => encoder.encode(part));
  const total = bodies.reduce((sum, body) => sum + 8 + body.length, 0);
  const out = Buffer.allocUnsafe(total);

  let offset = 0;
  for (const body of bodies) {
    out.writeBigUInt64BE(BigInt(body.length), offset);
    offset += 8;
    out.set(body, offset);
    offset += body.length;
  }
  return out;
}
