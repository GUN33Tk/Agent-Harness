import { ToolDefinition } from "./registry";
import { wrapUntrusted } from "./untrusted";
import { scanForInjection } from "./sanitizer";
import { logDecision } from "./logger";
import { getCredential } from "./credentials";

// CHANGED: fetch_url now actually wraps its result as Untrusted and scans
// it before returning — this was previously dead code (untrusted.ts and
// sanitizer.ts existed but nothing called them). The scan result is
// logged either way; a flagged result is still returned to the model
// (the model is allowed to read suspicious content) but boundary.ts's
// derivedFromUntrusted check is what actually stops it from being acted
// on by a privileged tool afterward.
export function createFetchUrlTool(allowlist: Set<string>): ToolDefinition {
  return {
    name: "fetch_url",
    allowedInScopes: ["research", "pricing-research"],
    schema: (args) => typeof (args as any).url === "string",
    execute: async (args) => {
      const url = args.url as string;
      const res = await fetch(url);
      const rawText = await res.text();

      const data = wrapUntrusted(url, rawText);
      const scan = scanForInjection(data);
      logDecision({ tool: "fetch_url", event: "content_scanned", flagged: scan.flagged, reason: scan.reason });

      return data.content;
    },
  };
}

export const sendEmailTool: ToolDefinition = {
  name: "send_email",
  allowedInScopes: ["customer-support"],
  schema: (args) => typeof (args as any).to === "string" && typeof (args as any).body === "string",
  execute: async (args) => {
    // CHANGED: pulls a scope-bound credential instead of using a global
    // identity — a token issued for "customer-support" cannot be reused
    // by code running under any other scope. See credentials.ts.
    const cred = getCredential("customer-support");
    console.log(`[send_email] using cred=${cred} to=${args.to} body="${(args.body as string).slice(0, 80)}..."`);
    return "sent";
  },
};

// CHANGED: read_billing no longer runs inline in the Node process — it
// now executes inside the C++ sandbox via native/billing_tool, spawned
// through native/sandbox_launcher. This is the one tool in this project
// that gets genuine kernel-level isolation, not just an application-level
// scope check. See README for why this isn't (yet) true of every tool.
import { execFile } from "child_process";
import { promisify } from "util";
import * as path from "path";
const execFileAsync = promisify(execFile);

export const readBillingTool: ToolDefinition = {
  name: "read_billing",
  allowedInScopes: ["pricing-research"],
  schema: (args) => typeof (args as any).account_id === "string",
  execute: async (args) => {
    // NOTE: __dirname here is dist/src (this file's compiled location),
    // so it takes TWO levels up to reach the project root, then into
    // native/ — found this by actually running the test and seeing the
    // "not built" skip message when the binaries were, in fact, built.
    const launcher = path.join(__dirname, "..", "..", "native", "sandbox_launcher");
    const target = path.join(__dirname, "..", "..", "native", "billing_tool");
    try {
      const { stdout } = await execFileAsync(launcher, [target, args.account_id as string]);
      return stdout.trim();
    } catch (err) {
      return JSON.stringify({
        error: "sandboxed billing_tool unavailable — run `cd native && make` first",
        detail: String(err),
      });
    }
  },
};

import { resolveWithinRoot } from "./files";

export const readFileTool: ToolDefinition = {
  name: "read_file",
  allowedInScopes: ["file-access"],
  schema: (args) => typeof (args as any).path === "string",
  execute: async (args) => {
    const resolved = resolveWithinRoot(args.path as string);
    if (!resolved) throw new Error(`DENIED: path escapes the allowed root`);
    const fs = await import("fs/promises");
    const raw = await fs.readFile(resolved, "utf-8");

    // CHANGED: previously returned raw content with no scan at all —
    // fetch_url scanned its output but read_file didn't, even though a
    // local file can carry the same kind of embedded instruction. Now
    // both external-content tools log a scan result the same way.
    const data = wrapUntrusted(resolved, raw);
    const scan = scanForInjection(data);
    logDecision({ tool: "read_file", event: "content_scanned", flagged: scan.flagged, reason: scan.reason });

    return data.content;
  },
};

// NEW: a tool that lets the agent PROPOSE a file change — but the actual
// write only happens after (1) an injection scan passes and (2) a real
// human at the terminal explicitly approves it. The model can request
// this; it cannot make it happen on its own.
import { proposeAndApply } from "./verification";

export const proposeFileUpdateTool: ToolDefinition = {
  name: "propose_file_update",
  allowedInScopes: ["file-access"],
  schema: (args) => typeof (args as any).path === "string" && typeof (args as any).new_content === "string",
  execute: async (args) => {
    const resolved = resolveWithinRoot(args.path as string);
    if (!resolved) throw new Error(`DENIED: path escapes the allowed root`);
    return await proposeAndApply(resolved, args.new_content as string);
  },
};
