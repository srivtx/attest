import { verifyBytes } from "./verify.ts";
import { formatJson, formatReport, summarize } from "./report.ts";
import { toCard } from "./resolve.ts";
import { fromBase64 } from "./bytes.ts";

const SERVER_NAME = "attest";
const VERSION = "0.1.0";

const TOOLS = [
  {
    name: "provenance_verify",
    description:
      "Verify the C2PA Content Credentials of a media file. Pass the file bytes as base64. Returns the validation state, the signer chain, the hard binding result, the recorded actions, and any issues. No network access.",
    inputSchema: {
      type: "object",
      properties: {
        data: { type: "string", description: "The file bytes, base64 encoded." },
        name: { type: "string", description: "Optional file name, used only in the report." },
      },
      required: ["data"],
      additionalProperties: false,
    },
  },
  {
    name: "provenance_inspect",
    description:
      "Like provenance_verify, but returns the full verbose report including every assertion, its declared state, and its hash result.",
    inputSchema: {
      type: "object",
      properties: {
        data: { type: "string", description: "The file bytes, base64 encoded." },
        name: { type: "string", description: "Optional file name, used only in the report." },
      },
      required: ["data"],
      additionalProperties: false,
    },
  },
  {
    name: "provenance_card",
    description:
      "Return a compact, portable provenance card for a media file: the asset SHA-256, the validation state, the signer, and the recorded actions, as JSON.",
    inputSchema: {
      type: "object",
      properties: {
        data: { type: "string", description: "The file bytes, base64 encoded." },
      },
      required: ["data"],
      additionalProperties: false,
    },
  },
];

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

async function callTool(name: string, args: Record<string, unknown>): Promise<string> {
  const data = asString(args["data"]);
  if (data.trim().length === 0) return `${name} requires the file bytes as base64 in "data".`;
  let bytes: Uint8Array;
  try {
    bytes = fromBase64(data);
  } catch {
    return `${name}: "data" is not valid base64.`;
  }
  switch (name) {
    case "provenance_verify": {
      const asset = await verifyBytes(bytes);
      return `${summarize(asset)}\n\n${formatReport(asset)}`;
    }
    case "provenance_inspect": {
      const asset = await verifyBytes(bytes);
      return formatReport(asset, { verbose: true });
    }
    case "provenance_card": {
      const asset = await verifyBytes(bytes);
      return JSON.stringify({ card: toCard(asset), state: asset.state }, null, 2);
    }
    default:
      throw new Error(`unknown tool: ${name}`);
  }
}

function reply(id: unknown, body: Record<string, unknown>): void {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, ...body })}\n`);
}

async function handle(message: Record<string, unknown>, version: string): Promise<void> {
  const id = message["id"];
  const method = message["method"];
  if (typeof method !== "string") return;

  if (method === "initialize") {
    const params = (message["params"] ?? {}) as Record<string, unknown>;
    reply(id, {
      result: {
        protocolVersion: asString(params["protocolVersion"], "2024-11-05"),
        capabilities: { tools: {} },
        serverInfo: { name: SERVER_NAME, version },
      },
    });
    return;
  }
  if (method === "notifications/initialized") return;
  if (method === "ping") {
    reply(id, { result: {} });
    return;
  }
  if (method === "tools/list") {
    reply(id, { result: { tools: TOOLS } });
    return;
  }
  if (method === "tools/call") {
    const params = (message["params"] ?? {}) as Record<string, unknown>;
    const name = asString(params["name"]);
    const args = (params["arguments"] ?? {}) as Record<string, unknown>;
    try {
      const text = await callTool(name, args);
      reply(id, { result: { content: [{ type: "text", text }] } });
    } catch (err) {
      reply(id, {
        result: {
          content: [{ type: "text", text: err instanceof Error ? err.message : String(err) }],
          isError: true,
        },
      });
    }
    return;
  }
  if (id !== undefined) {
    reply(id, { error: { code: -32601, message: `method not found: ${method}` } });
  }
}

export async function runMcpServer(): Promise<void> {
  const reader = Bun.stdin.stream().getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let newline = buffer.indexOf("\n");
    while (newline !== -1) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      newline = buffer.indexOf("\n");
      if (line.length === 0) continue;
      let message: unknown;
      try {
        message = JSON.parse(line);
      } catch {
        continue;
      }
      if (typeof message === "object" && message !== null) {
        await handle(message as Record<string, unknown>, VERSION);
      }
    }
  }
  const tail = buffer.trim();
  if (tail.length > 0) {
    try {
      const message = JSON.parse(tail) as unknown;
      if (typeof message === "object" && message !== null) {
        await handle(message as Record<string, unknown>, VERSION);
      }
    } catch {
      /* ignore a trailing partial line */
    }
  }
}

export { TOOLS };
