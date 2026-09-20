import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const fixtureDir = new URL("../fixtures/", import.meta.url);

export function readFixture(name: string): Uint8Array {
  return new Uint8Array(readFileSync(fileURLToPath(new URL(name, fixtureDir))));
}

export function fixturePath(name: string): string {
  return fileURLToPath(new URL(name, fixtureDir));
}

export function tamper(bytes: Uint8Array, offset: number): Uint8Array {
  const copy = new Uint8Array(bytes);
  copy[offset] = copy[offset]! ^ 0x01;
  return copy;
}

const PNG_1X1 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

export function unsignedPng(): Uint8Array {
  const binary = atob(PNG_1X1);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export const SIGNED_JPEG = "C2PA-signed.jpg";
