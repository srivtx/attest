import { describe, expect, test } from "bun:test";
import { decodeCbor, decodeCborSequence, encodeCbor, mapGetNumber, mapGetString } from "../src/cbor.ts";
import { fromHex, toHex } from "../src/bytes.ts";

describe("CBOR decoding", () => {
  test("decodes unsigned and negative integers", () => {
    expect(decodeCbor(fromHex("0a"))).toBe(10);
    expect(decodeCbor(fromHex("17"))).toBe(23);
    expect(decodeCbor(fromHex("1818"))).toBe(24);
    expect(decodeCbor(fromHex("190100"))).toBe(256);
    expect(decodeCbor(fromHex("20"))).toBe(-1);
    expect(decodeCbor(fromHex("3863"))).toBe(-100);
  });

  test("decodes byte and text strings", () => {
    expect(toHex(decodeCbor(fromHex("4401020304")) as Uint8Array)).toBe("01020304");
    expect(decodeCbor(fromHex("6568656c6c6f"))).toBe("hello");
  });

  test("decodes definite-length arrays and maps", () => {
    expect(decodeCbor(fromHex("83010203"))).toEqual([1, 2, 3]);
    const map = decodeCbor(fromHex("a261610161626162")) as Map<string, unknown>;
    expect(mapGetNumber(map as never, "a")).toBe(1);
    expect(mapGetString(map as never, "b")).toBe("b");
  });

  test("decodes indefinite-length arrays, maps, and byte strings", () => {
    expect(decodeCbor(fromHex("9f0102ff"))).toEqual([1, 2]);
    const map = decodeCbor(fromHex("bf616101ff")) as Map<unknown, unknown>;
    expect(map.get("a")).toBe(1);
    expect(toHex(decodeCbor(fromHex("5f42010243030405ff")) as Uint8Array)).toBe("0102030405");
    expect(decodeCbor(fromHex("7f6261626161ff"))).toBe("aba");
  });

  test("decodes booleans and null", () => {
    expect(decodeCbor(fromHex("f5"))).toBe(true);
    expect(decodeCbor(fromHex("f4"))).toBe(false);
    expect(decodeCbor(fromHex("f6"))).toBe(null);
  });

  test("rejects trailing bytes and truncated input", () => {
    expect(() => decodeCbor(fromHex("0102"))).toThrow(/trailing/);
    expect(() => decodeCbor(fromHex("6568656c"))).toThrow(/truncated/);
  });

  test("decodes a sequence of top-level items", () => {
    expect(decodeCborSequence(fromHex("010203"))).toEqual([1, 2, 3]);
  });

  test("round-trips every supported value", () => {
    const value = new Map<unknown, unknown>([
      ["name", "attest"],
      ["ok", true],
      [1, new Uint8Array([1, 2, 3])],
      ["list", [1, -2, "three"]],
    ]);
    const round = decodeCbor(encodeCbor(value as never)) as Map<unknown, unknown>;
    expect(round.get("name")).toBe("attest");
    expect(round.get("ok")).toBe(true);
    expect(toHex(round.get(1) as Uint8Array)).toBe("010203");
    expect(round.get("list")).toEqual([1, -2, "three"]);
  });
});
