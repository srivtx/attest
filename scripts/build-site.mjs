import { mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as esbuild from "esbuild";

const entry = new URL("../src/index.ts", import.meta.url);
const outfile = new URL("../site/assets/studio.js", import.meta.url);

async function main() {
  const entryPath = fileURLToPath(entry);

  if (!existsSync(entryPath)) {
    process.stdout.write(
      `skipping: ${entryPath} not found (build the library first)\n`,
    );
    return;
  }

  await mkdir(dirname(fileURLToPath(outfile)), { recursive: true });

  await esbuild.build({
    entryPoints: [entryPath],
    outfile: fileURLToPath(outfile),
    bundle: true,
    format: "iife",
    platform: "browser",
    target: "es2020",
    minify: true,
    globalName: "Attest",
    logLevel: "info",
  });

  process.stdout.write("built attest -> site/assets/studio.js\n");
}

main().catch((error) => {
  process.stderr.write(`${error?.stack ?? error}\n`);
  process.exit(1);
});
