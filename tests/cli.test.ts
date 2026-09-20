import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fixturePath, SIGNED_JPEG, tamper, readFixture } from "./helpers.ts";

const CLI = new URL("../src/cli.ts", import.meta.url).pathname;

function run(args: readonly string[]): { code: number; stdout: string; stderr: string } {
  const result = spawnSync("bun", [CLI, ...args], { encoding: "utf8" });
  return { code: result.status ?? -1, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

describe("attest CLI", () => {
  test("--help prints usage and exits 0 when a command is given with -h", () => {
    const help = run(["inspect", "-h"]);
    expect(help.code).toBe(0);
    expect(help.stdout).toContain("Usage");
    expect(help.stdout).toContain("attest inspect");
  });

  test("no arguments prints usage and exits 2", () => {
    const result = run([]);
    expect(result.code).toBe(2);
    expect(result.stdout).toContain("Usage");
  });

  test("an unknown option exits 2", () => {
    const result = run(["verify", fixturePath(SIGNED_JPEG), "--nope"]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("unknown option");
  });

  test("an unknown command exits 2", () => {
    const result = run(["frobnicate"]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("unknown command");
  });

  test("a missing file exits 3", () => {
    const result = run(["verify", "/nonexistent/does-not-exist.jpg"]);
    expect(result.code).toBe(3);
    expect(result.stderr).toContain("error:");
  });

  test("verify exits 0 for a valid signed image", () => {
    const result = run(["verify", fixturePath(SIGNED_JPEG)]);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("valid:");
    expect(result.stdout).toContain("hard binding matched");
  });

  test("inspect prints the full report", () => {
    const result = run(["inspect", fixturePath(SIGNED_JPEG)]);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("VALID  jpeg");
    expect(result.stdout).toContain("signature  valid (PS256)");
    expect(result.stdout).toContain("chain");
  });

  test("--json emits parseable JSON", () => {
    const result = run(["verify", fixturePath(SIGNED_JPEG), "--json"]);
    const parsed = JSON.parse(result.stdout) as { state: string };
    expect(parsed.state).toBe("valid");
  });

  test("--quiet suppresses output and keeps the exit code", () => {
    const result = run(["verify", fixturePath(SIGNED_JPEG), "--quiet"]);
    expect(result.code).toBe(0);
    expect(result.stdout.trim()).toBe("");
  });

  test("a tampered image exits 1", () => {
    const dir = mkdtempSync(join(tmpdir(), "attest-"));
    const path = join(dir, "tampered.jpg");
    writeFileSync(path, Buffer.from(tamper(readFixture(SIGNED_JPEG), readFixture(SIGNED_JPEG).length - 200)));
    const result = run(["verify", path]);
    expect(result.code).toBe(1);
    expect(result.stdout).toContain("invalid:");
  });

  test("card emits a provenance card", () => {
    const result = run(["card", fixturePath(SIGNED_JPEG)]);
    expect(result.code).toBe(0);
    const card = JSON.parse(result.stdout) as { version: string; asset: { sha256: string } };
    expect(card.version).toBe("attest/card/1");
    expect(card.asset.sha256).toHaveLength(64);
  });

  test("anchor appends to a registry and resolve finds it, then detects a change", () => {
    const dir = mkdtempSync(join(tmpdir(), "attest-reg-"));
    const registry = join(dir, "registry.jsonl");
    const anchored = run(["anchor", fixturePath(SIGNED_JPEG), "--registry", registry]);
    expect(anchored.code).toBe(0);
    expect(anchored.stdout).toContain("anchored");
    expect(readFileSync(registry, "utf8").trim().split("\n")).toHaveLength(1);

    const resolved = run(["resolve", fixturePath(SIGNED_JPEG), "--registry", registry]);
    expect(resolved.code).toBe(0);
    expect(resolved.stdout).toContain("anchored and unchanged");

    const changed = join(dir, "changed.jpg");
    writeFileSync(changed, Buffer.from(tamper(readFixture(SIGNED_JPEG), readFixture(SIGNED_JPEG).length - 200)));
    const changedResult = run(["resolve", changed, "--registry", registry]);
    expect(changedResult.code).toBe(1);

    const byHash = run(["resolve", readFileSync(registry, "utf8").trim().slice(0, 0) || "0".repeat(64), "--registry", registry]);
    expect(byHash.code).toBe(1);
  });

  test("resolve without --registry exits 2", () => {
    const result = run(["resolve", "0".repeat(64)]);
    expect(result.code).toBe(2);
  });

  test("mcp answers initialize and tools/list over stdio", () => {
    const input = ['{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}', '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'].join("\n");
    const result = spawnSync("bun", [CLI, "mcp"], { input, encoding: "utf8" });
    const lines = result.stdout.trim().split("\n").map((l) => JSON.parse(l) as Record<string, never>);
    expect(lines).toHaveLength(2);
    const tools = (lines[1] as unknown as { result: { tools: Array<{ name: string }> } }).result.tools.map((t) => t.name);
    expect(tools).toEqual(["provenance_verify", "provenance_inspect", "provenance_card"]);
  });
});
