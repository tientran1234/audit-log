import { describe, expect, it } from "vitest";
import { canonicalJson, frame, parsePayload } from "../src/canonical.js";
import { InvalidPayloadError } from "../src/types.js";

describe("canonicalJson", () => {
  it("does not depend on the order the keys were written in", () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe(canonicalJson({ a: 2, b: 1 }));
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it("sorts nested keys too, and leaves array order alone", () => {
    expect(canonicalJson({ z: [{ b: 1, a: 2 }], a: { d: 1, c: 2 } })).toBe(
      '{"a":{"c":2,"d":1},"z":[{"a":2,"b":1}]}',
    );
    expect(canonicalJson([3, 1, 2])).toBe("[3,1,2]");
  });

  it("is idempotent, so a stored payload re-canonicalises to itself", () => {
    const once = canonicalJson({ b: [1, { y: "ü", x: null }], a: -0, c: "a\u0000b" });
    expect(canonicalJson(parsePayload(once))).toBe(once);
  });

  it("normalises -0, which JSON cannot tell from 0", () => {
    expect(canonicalJson({ a: -0 })).toBe('{"a":0}');
  });

  it("escapes control characters and lone surrogates the same way every time", () => {
    expect(canonicalJson(" \ud800")).toBe(JSON.stringify(" \ud800"));
    expect(canonicalJson("tiếng Việt")).toBe('"tiếng Việt"');
  });

  it.each([
    ["undefined", undefined, "$"],
    ["NaN", Number.NaN, "$"],
    ["Infinity", Number.POSITIVE_INFINITY, "$"],
    ["a bigint", 1n, "$"],
    ["a function", () => 1, "$"],
    ["a symbol", Symbol("s"), "$"],
    ["a Date", new Date(0), "$"],
    ["a Map", new Map(), "$"],
    ["a class instance", new (class Thing {})(), "$"],
  ])("refuses %s rather than silently changing it", (_label, value, path) => {
    expect(() => canonicalJson(value)).toThrow(InvalidPayloadError);
    try {
      canonicalJson(value);
    } catch (error) {
      expect((error as InvalidPayloadError).path).toBe(path);
    }
  });

  it("names the path of the value it refused", () => {
    expect(() => canonicalJson({ items: [{ when: new Date(0) }] })).toThrow(
      /payload at \$\.items\[0\]\.when/,
    );
    expect(() => canonicalJson({ a: { b: undefined } })).toThrow(/payload at \$\.a\.b/);
  });

  it("refuses a cycle instead of recursing until the stack gives out", () => {
    const loop: Record<string, unknown> = {};
    loop["self"] = loop;
    expect(() => canonicalJson(loop)).toThrow(/cyclic/);
  });

  it("accepts an absent payload as null", () => {
    expect(canonicalJson(null)).toBe("null");
  });
});

describe("frame", () => {
  it("cannot be made to mean two things: a byte moved across a boundary changes it", () => {
    // The forgery a naive `parts.join(":")` allows.
    expect(frame(["a:b", "c"])).not.toEqual(frame(["a", "b:c"]));
    expect(frame(["ab", ""])).not.toEqual(frame(["a", "b"]));
    expect(frame([""])).not.toEqual(frame([]));
  });

  it("prefixes each part with its length in bytes, not its length in characters", () => {
    // "ü" is two bytes of UTF-8 and one UTF-16 code unit.
    expect(frame(["ü"])).toEqual(
      Buffer.concat([Buffer.from([0, 0, 0, 0, 0, 0, 0, 2]), Buffer.from("ü", "utf8")]),
    );
  });

  it("is deterministic", () => {
    expect(frame(["a", "b"])).toEqual(frame(["a", "b"]));
  });
});
