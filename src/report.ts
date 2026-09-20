import type { AssetVerification, ManifestVerification, Issue } from "./verify.ts";

const ICON: Record<Issue["severity"], string> = { error: "ERROR", warning: "WARN", info: "INFO" };

export interface TextReportOptions {
  color?: boolean;
  verbose?: boolean;
}

export function formatReport(asset: AssetVerification, options: TextReportOptions = {}): string {
  const lines: string[] = [];
  const paint = (code: string, text: string) => (options.color ? `\u001b[${code}m${text}\u001b[0m` : text);
  const stateColor = asset.state === "valid" ? "32" : asset.state === "unsigned" ? "33" : "31";

  lines.push(paint(stateColor, `${asset.state.toUpperCase()}`) + `  ${asset.file.container ?? "unknown"}  ${asset.file.size} bytes`);
  lines.push(`sha256  ${asset.file.hash}`);

  if (asset.state === "unsigned") {
    lines.push("");
    lines.push("No Content Credentials were found. Anyone could have produced this file.");
    return lines.join("\n");
  }

  for (const manifest of asset.manifests) {
    lines.push("");
    lines.push(paint("1", `manifest  ${manifest.label}`));
    if (manifest.title) lines.push(`  title      ${manifest.title}`);
    if (manifest.generator) lines.push(`  generator  ${manifest.generator}`);
    if (manifest.format) lines.push(`  format     ${manifest.format}`);
    if (manifest.instanceId) lines.push(`  instance   ${manifest.instanceId}`);

    lines.push(`  signature  ${manifest.signature.valid ? "valid" : "INVALID"} (${manifest.signature.algorithm ?? "unknown"})`);
    lines.push(`  trust      ${manifest.trust.status}${manifest.trust.anchor ? ` — ${manifest.trust.anchor}` : manifest.trust.reason ? ` — ${manifest.trust.reason}` : ""}`);

    if (manifest.chain.length > 0) {
      lines.push("  chain");
      for (const link of manifest.chain) {
        const mark = link.signatureValid === false || link.errors.length > 0 ? "x" : ".";
        lines.push(`    ${mark} ${link.subject}${link.isCa ? "  [CA]" : ""}${link.expired ? "  (expired)" : ""}`);
        if (options.verbose) lines.push(`        ${link.notBefore} to ${link.notAfter}  ${link.fingerprint.slice(0, 16)}`);
      }
    }

    if (manifest.actions.length > 0) {
      lines.push("  actions");
      for (const action of manifest.actions) {
        const parts = [action.action ?? "unknown"];
        if (action.softwareAgent) parts.push(`by ${action.softwareAgent}`);
        if (action.when) parts.push(`at ${action.when}`);
        lines.push(`    ${parts.join("  ")}`);
      }
    }

    if (manifest.ingredients.length > 0) {
      lines.push("  ingredients");
      for (const ingredient of manifest.ingredients) {
        lines.push(`    ${ingredient.relationship ?? "component"}  ${ingredient.title ?? ingredient.instanceId ?? "(untitled)"}`);
      }
    }

    lines.push(`  hard binding  ${manifest.hardBinding.status}${manifest.hardBinding.algorithm ? ` (${manifest.hardBinding.algorithm})` : ""}`);
    if (options.verbose && manifest.hardBinding.computedHash) {
      lines.push(`    computed  ${manifest.hardBinding.computedHash}`);
      lines.push(`    asserted  ${manifest.hardBinding.assertedHash}`);
    }
    if (manifest.assertions.length > 0) {
      lines.push(`  assertions    ${manifest.assertions.length}`);
      if (options.verbose) {
        for (const assertion of manifest.assertions) {
          const flags = [assertion.declared ? "declared" : "undeclared", assertion.present ? "present" : "missing", assertion.hashMatched ? "hash ok" : "hash MISMATCH"];
          lines.push(`    ${assertion.label}  ${flags.join(", ")}`);
        }
      }
    }
  }

  const errors = asset.issues.filter((i) => i.severity === "error");
  const warnings = asset.issues.filter((i) => i.severity === "warning");
  lines.push("");
  lines.push(`${errors.length} error(s), ${warnings.length} warning(s)`);
  for (const issue of errors) lines.push(`  ${paint("31", ICON[issue.severity])}  ${issue.code}  ${issue.message}`);
  for (const issue of warnings) lines.push(`  ${paint("33", ICON[issue.severity])}  ${issue.code}  ${issue.message}`);
  if (options.verbose) {
    for (const issue of asset.issues.filter((i) => i.severity === "info")) {
      lines.push(`  ${ICON[issue.severity]}  ${issue.code}  ${issue.message}`);
    }
  }
  return lines.join("\n");
}

export function formatJson(asset: AssetVerification, indent = 2): string {
  return JSON.stringify(asset, null, indent);
}

export function summarize(asset: AssetVerification): string {
  const manifest = asset.manifests[asset.manifests.length - 1];
  if (!manifest) return `${asset.state}: no manifest`;
  return `${asset.state}: ${manifest.title ?? manifest.generator ?? "manifest"} — signature ${manifest.signature.valid ? "valid" : "invalid"}, hard binding ${manifest.hardBinding.status}`;
}

export function manifestToCard(manifest: ManifestVerification): Record<string, unknown> {
  return {
    label: manifest.label,
    title: manifest.title,
    generator: manifest.generator,
    format: manifest.format,
    instanceId: manifest.instanceId,
    signature: manifest.signature,
    trust: manifest.trust,
    hardBinding: manifest.hardBinding,
    actions: manifest.actions,
    ingredients: manifest.ingredients,
    chain: manifest.chain.map((link) => ({ subject: link.subject, fingerprint: link.fingerprint })),
  };
}
