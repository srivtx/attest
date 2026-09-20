#!/usr/bin/env bun
import { readFile, writeFile, appendFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { basename } from "node:path";
import { verifyBytes, type VerifyOptions } from "./verify.ts";
import { formatJson, formatReport, summarize } from "./report.ts";
import { cardId, matchCard, parseRegistry, resolveByHash, serializeCard, toCard } from "./resolve.ts";
import { parseTrustList, type TrustList } from "./trust.ts";
import { runMcpServer } from "./mcp.ts";

const VERSION = "0.1.0";

const USAGE = `attest ${VERSION} — verify C2PA Content Credentials offline

Usage
  attest inspect <file> [options]        verify and print a full report
  attest verify <file> [options]         verify; one summary line unless --verbose
  attest card <file>                     print a portable provenance card as JSON
  attest anchor <file> --registry <p>    append a provenance card to a registry
  attest resolve <hash|file> --registry <p>
                                         look up a card, and re-verify a file against it
  attest mcp                             run the MCP server over stdio

Options
  --trust <file>      trust list: a C2PA trust list JSON or PEM certificates
  --require-trusted   treat an untrusted signer as a failure
  --json              print machine-readable JSON
  --verbose, -v       include per-assertion detail and certificate windows
  --quiet, -q         suppress output; rely on the exit code
  --registry <path>   registry file for anchor and resolve (JSON Lines)
  -h, --help          show this text
  --version           print the version

Exit codes
  0  valid, or nothing to report
  1  invalid, untrusted, or a mismatch was found
  2  usage error
  3  I/O error, or a file that could not be read
`;

interface Parsed {
  command: string;
  target?: string;
  flags: Map<string, string | boolean>;
}

function parseArgs(argv: readonly string[]): Parsed {
  const flags = new Map<string, string | boolean>();
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "-h" || arg === "--help") flags.set("help", true);
    else if (arg === "--version") flags.set("version", true);
    else if (arg === "--json") flags.set("json", true);
    else if (arg === "--verbose" || arg === "-v") flags.set("verbose", true);
    else if (arg === "--quiet" || arg === "-q") flags.set("quiet", true);
    else if (arg === "--require-trusted") flags.set("requireTrusted", true);
    else if (arg === "--trust" || arg === "--registry") {
      const next = argv[++i];
      if (next === undefined) throw new UsageError(`${arg} requires a value`);
      flags.set(arg.slice(2), next);
    } else if (arg.startsWith("--")) throw new UsageError(`unknown option: ${arg}`);
    else positional.push(arg);
  }
  return { command: positional[0] ?? "", target: positional[1], flags };
}

class UsageError extends Error {}
class InputError extends Error {}

async function readTarget(target: string | undefined): Promise<{ bytes: Uint8Array; name: string }> {
  if (!target) throw new UsageError("a file path is required");
  if (target === "-") {
    const chunks: Uint8Array[] = [];
    const stream = Bun.stdin.stream();
    const reader = stream.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) chunks.push(value);
    }
    let total = 0;
    for (const chunk of chunks) total += chunk.length;
    const bytes = new Uint8Array(total);
    let at = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, at);
      at += chunk.length;
    }
    return { bytes, name: "stdin" };
  }
  try {
    const bytes = new Uint8Array(await readFile(target));
    return { bytes, name: basename(target) };
  } catch (error) {
    throw new InputError(error instanceof Error ? error.message : String(error));
  }
}

async function loadTrust(path: string | undefined): Promise<TrustList | undefined> {
  if (!path) return undefined;
  try {
    return await parseTrustList(await readFile(path, "utf8"), basename(path));
  } catch (error) {
    throw new InputError(error instanceof Error ? error.message : String(error));
  }
}

async function main(argv: readonly string[]): Promise<number> {
  let parsed: Parsed;
  try {
    parsed = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`${(error as Error).message}\n\n${USAGE}`);
    return 2;
  }
  if (parsed.flags.get("version") === true) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (parsed.flags.get("help") === true) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (parsed.command === "") {
    process.stdout.write(USAGE);
    return 2;
  }

  const quiet = parsed.flags.get("quiet") === true;
  const json = parsed.flags.get("json") === true;
  const verbose = parsed.flags.get("verbose") === true;
  const requireTrusted = parsed.flags.get("requireTrusted") === true;
  const registryPath = typeof parsed.flags.get("registry") === "string" ? (parsed.flags.get("registry") as string) : undefined;

  try {
    switch (parsed.command) {
      case "inspect":
      case "verify":
      case "check": {
        const { bytes } = await readTarget(parsed.target);
        const options = await buildOptions(parsed, requireTrusted);
        const asset = await verifyBytes(bytes, options);
        if (!quiet) {
          if (json) process.stdout.write(`${formatJson(asset)}\n`);
          else if (parsed.command === "verify" && !verbose) process.stdout.write(`${summarize(asset)}\n`);
          else process.stdout.write(`${formatReport(asset, { color: process.stdout.isTTY === true, verbose })}\n`);
        }
        return exitCodeFor(asset, requireTrusted);
      }

      case "card": {
        const { bytes } = await readTarget(parsed.target);
        const options = await buildOptions(parsed, requireTrusted);
        const asset = await verifyBytes(bytes, options);
        const card = toCard(asset);
        if (!quiet) process.stdout.write(`${JSON.stringify(card, null, json ? 2 : 2)}\n`);
        return exitCodeFor(asset, requireTrusted);
      }

      case "anchor": {
        const { bytes } = await readTarget(parsed.target);
        if (!registryPath) throw new UsageError("anchor requires --registry <path>");
        const options = await buildOptions(parsed, requireTrusted);
        const asset = await verifyBytes(bytes, options);
        const card = toCard(asset);
        const id = await cardId(card);
        await appendFile(registryPath, `${serializeCard(card)}\n`);
        if (!quiet) {
          process.stdout.write(json ? `${JSON.stringify({ id, card }, null, 2)}\n` : `anchored  ${id}\n  ${summarize(asset)}\n  ${registryPath}\n`);
        }
        return exitCodeFor(asset, requireTrusted);
      }

      case "resolve": {
        if (!registryPath) throw new UsageError("resolve requires --registry <path>");
        if (!parsed.target) throw new UsageError("resolve requires a sha256 or a file path");
        if (!existsSync(registryPath)) throw new InputError(`registry not found: ${registryPath}`);
        const cards = parseRegistry(await readFile(registryPath, "utf8"));
        const isHash = /^[0-9a-fA-F]{64}$/.test(parsed.target.replace(/^sha256:/, ""));
        if (isHash) {
          const card = resolveByHash(cards, parsed.target);
          if (!card) {
            if (!quiet) process.stdout.write("not found\n");
            return 1;
          }
          if (!quiet) process.stdout.write(json ? `${JSON.stringify(card, null, 2)}\n` : `${card.asset.sha256}\n  state     ${card.state}\n  issued    ${card.issuedAt}\n  manifests ${card.manifests.length}\n`);
          return 0;
        }
        const { bytes } = await readTarget(parsed.target);
        const options = await buildOptions(parsed, requireTrusted);
        const asset = await verifyBytes(bytes, options);
        const card = resolveByHash(cards, asset.file.hash);
        if (!card) {
          if (!quiet) {
            process.stdout.write(json ? `${JSON.stringify({ found: false, asset }, null, 2)}\n` : `not anchored\n  sha256 ${asset.file.hash}\n`);
          }
          return 1;
        }
        const match = matchCard(card, asset);
        if (!quiet) {
          if (json) process.stdout.write(`${JSON.stringify({ found: true, match: match.ok, reasons: match.reasons, card, asset }, null, 2)}\n`);
          else {
            process.stdout.write(`${match.ok ? "anchored and unchanged" : "anchored but CHANGED"}\n`);
            process.stdout.write(`  sha256   ${asset.file.hash}\n  issued   ${card.issuedAt}\n`);
            for (const reason of match.reasons) process.stdout.write(`  reason   ${reason}\n`);
          }
        }
        return match.ok ? 0 : 1;
      }

      case "mcp":
        await runMcpServer();
        return 0;

      default:
        process.stderr.write(`unknown command: ${parsed.command}\n\n${USAGE}`);
        return 2;
    }
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`${error.message}\n\n${USAGE}`);
      return 2;
    }
    if (error instanceof InputError) {
      process.stderr.write(`error: ${error.message}\n`);
      return 3;
    }
    process.stderr.write(`error: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
}

async function buildOptions(parsed: Parsed, requireTrusted: boolean): Promise<VerifyOptions> {
  const trustPath = typeof parsed.flags.get("trust") === "string" ? (parsed.flags.get("trust") as string) : undefined;
  const options: VerifyOptions = { assertTrusted: requireTrusted };
  const trustList = await loadTrust(trustPath);
  if (trustList) options.trustList = trustList;
  return options;
}

function exitCodeFor(asset: Awaited<ReturnType<typeof verifyBytes>>, requireTrusted: boolean): number {
  if (asset.state === "valid") return 0;
  if (asset.state === "unsigned") return 1;
  if (asset.state === "invalid") return 1;
  if (asset.state === "untrusted") return requireTrusted ? 1 : 0;
  return 1;
}

const code = await main(process.argv.slice(2));
if (code !== 0) process.exitCode = code;
