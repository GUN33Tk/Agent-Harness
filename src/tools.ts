import { ToolDefinition } from "./registry";
import { wrapUntrusted } from "./untrusted";
import { scanForInjection } from "./sanitizer";
import { logDecision } from "./logger";
import { getCredential } from "./credentials";
import { resolveWithinRoot } from "./files";
import { proposeAndApply } from "./verification";
import { EgressGateway } from "./network/egress-gateway";
import { classifyPath, sessionSecretTracker } from "./classification";
import { createProvenance } from "./provenance";
import { execFile } from "child_process";
import { promisify } from "util";
import * as path from "path";

const execFileAsync = promisify(execFile);

/**
 * Creates the fetch_url tool powered by the central EgressGateway.
 * The tool never calls raw fetch() directly. All outbound requests are evaluated against
 * SSRF filters, IP pinning, redirect validation, and data piggybacking policies.
 */
export function createFetchUrlTool(
  allowlistOrGateway: Set<string> | EgressGateway
): ToolDefinition {
  const gateway =
    allowlistOrGateway instanceof EgressGateway
      ? allowlistOrGateway
      : new EgressGateway({ allowedDomains: Array.from(allowlistOrGateway) });

  return {
    name: "fetch_url",
    allowedInScopes: ["research", "pricing-research"],
    schema: (args) => typeof (args as any).url === "string",
    jsonSchema: {
      type: "object",
      properties: { url: { type: "string" } },
      required: ["url"],
      additionalProperties: false,
    },
    execute: async (args) => {
      const url = args.url as string;
      const res = await gateway.request({
        method: "GET",
        url,
        provenance: createProvenance("UNTRUSTED", "PUBLIC", "fetch_url"),
        dataClassification: "PUBLIC",
      });

      const data = wrapUntrusted(url, res.body);
      const scan = scanForInjection(data);
      logDecision({
        tool: "fetch_url",
        event: "content_scanned",
        flagged: scan.flagged,
        reason: scan.reason,
      });

      return data.content;
    },
  };
}

export const sendEmailTool: ToolDefinition = {
  name: "send_email",
  allowedInScopes: ["customer-support"],
  schema: (args) => typeof (args as any).to === "string" && typeof (args as any).body === "string",
  jsonSchema: {
    type: "object",
    properties: {
      to: { type: "string" },
      body: { type: "string" },
    },
    required: ["to", "body"],
    additionalProperties: false,
  },
  execute: async (args) => {
    const cred = getCredential("customer-support");
    console.log(`[send_email] using cred=${cred} to=${args.to} body="${(args.body as string).slice(0, 80)}..."`);
    return "sent";
  },
};

export const readBillingTool: ToolDefinition = {
  name: "read_billing",
  allowedInScopes: ["pricing-research"],
  schema: (args) => typeof (args as any).account_id === "string",
  jsonSchema: {
    type: "object",
    properties: {
      account_id: { type: "string" },
    },
    required: ["account_id"],
    additionalProperties: false,
  },
  execute: async (args) => {
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

export const readFileTool: ToolDefinition = {
  name: "read_file",
  allowedInScopes: ["file-access"],
  schema: (args) => typeof (args as any).path === "string",
  jsonSchema: {
    type: "object",
    properties: {
      path: { type: "string" },
    },
    required: ["path"],
    additionalProperties: false,
  },
  execute: async (args) => {
    const resolved = resolveWithinRoot(args.path as string);
    if (!resolved) throw new Error(`DENIED: path escapes the allowed root`);

    const fs = await import("fs/promises");
    const raw = await fs.readFile(resolved, "utf-8");

    // Deterministic data classification
    const classification = classifyPath(resolved);
    if (classification === "SECRET" || classification === "CONFIDENTIAL") {
      sessionSecretTracker.registerSecret(raw);
    }

    const provenance = createProvenance("UNTRUSTED", classification, resolved);
    const data = wrapUntrusted(resolved, raw, provenance);
    const scan = scanForInjection(data);

    logDecision({
      tool: "read_file",
      event: "content_scanned",
      flagged: scan.flagged,
      reason: scan.reason,
      classification,
    });

    return data.content;
  },
};

export const proposeFileUpdateTool: ToolDefinition = {
  name: "propose_file_update",
  allowedInScopes: ["file-access"],
  schema: (args) => typeof (args as any).path === "string" && typeof (args as any).new_content === "string",
  jsonSchema: {
    type: "object",
    properties: {
      path: { type: "string" },
      new_content: { type: "string" },
    },
    required: ["path", "new_content"],
    additionalProperties: false,
  },
  execute: async (args) => {
    const resolved = resolveWithinRoot(args.path as string);
    if (!resolved) throw new Error(`DENIED: path escapes the allowed root`);
    return await proposeAndApply(resolved, args.new_content as string);
  },
};
