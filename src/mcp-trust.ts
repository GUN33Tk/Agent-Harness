import * as crypto from "crypto";
import { emitSecurityEvent } from "./security-events";

/**
 * MCP Tool Manifest Integrity / Rug-Pull Detection Layer.
 *
 * Simulates tool manifest verification for Model Context Protocol (MCP) servers.
 * Prevents "rug-pull" attacks where an MCP tool provider secretly updates a tool's
 * description, input schema, endpoint, or required permissions after human approval.
 */
export interface McpTool {
  serverName: string;
  name: string;
  description: string;
  inputSchema?: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  endpoint?: string;
  version?: string;
  permissions?: string[];
  capabilities?: Record<string, unknown>;
}

const approvedHashes = new Map<string, string>();

function key(t: McpTool): string {
  return `${t.serverName}:${t.name}`;
}

/**
 * Deterministically sorts object keys recursively to produce a canonical JSON string.
 */
export function canonicalizeJson(obj: unknown): string {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return `[${obj.map((item) => canonicalizeJson(item)).join(",")}]`;
  }

  const record = obj as Record<string, unknown>;
  const sortedKeys = Object.keys(record).sort();
  const entries = sortedKeys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(record[k])}`);
  return `{${entries.join(",")}}`;
}

/**
 * Computes SHA-256 hash across the canonical MCP tool manifest.
 */
export function computeToolManifestHash(tool: McpTool): string {
  const canonicalManifest = {
    capabilities: tool.capabilities ?? {},
    description: tool.description,
    endpoint: tool.endpoint ?? "",
    inputSchema: tool.inputSchema ?? {},
    name: tool.name,
    outputSchema: tool.outputSchema ?? {},
    permissions: tool.permissions ? [...tool.permissions].sort() : [],
    serverName: tool.serverName,
    version: tool.version ?? "1.0.0",
  };

  const canonicalString = canonicalizeJson(canonicalManifest);
  return crypto.createHash("sha256").update(canonicalString, "utf-8").digest("hex");
}

export function onToolsList(
  tools: McpTool[]
): { status: "OK" | "NEEDS_REVIEW" | "DENIED"; detail?: string } {
  for (const tool of tools) {
    const digest = computeToolManifestHash(tool);
    const prior = approvedHashes.get(key(tool));

    if (prior === undefined) {
      emitSecurityEvent({
        sessionId: "mcp-scan",
        agentId: "harness",
        type: "POLICY_EVALUATION",
        decision: "REVIEW",
        policy: "P-MCP-001",
        reason: `New unverified MCP tool: ${tool.name} from ${tool.serverName}`,
      });
      return { status: "NEEDS_REVIEW", detail: `new tool ${tool.name} from ${tool.serverName}` };
    }

    if (prior !== digest) {
      emitSecurityEvent({
        sessionId: "mcp-scan",
        agentId: "harness",
        type: "MCP_MANIFEST_CHANGE",
        decision: "DENY",
        policy: "P-MCP-002",
        reason: `MCP tool manifest changed after approval: ${tool.name}`,
        risk: "HIGH",
        details: { tool: tool.name, server: tool.serverName },
      });
      return {
        status: "DENIED",
        detail: `${tool.name} description changed since approval — re-review required`,
      };
    }
  }
  return { status: "OK" };
}

export function approveTool(t: McpTool): void {
  const digest = computeToolManifestHash(t);
  approvedHashes.set(key(t), digest);

  emitSecurityEvent({
    sessionId: "mcp-scan",
    agentId: "operator",
    type: "APPROVAL_GRANTED",
    decision: "ALLOW",
    policy: "P-MCP-APPROVE",
    reason: `Pinned canonical manifest hash for ${t.name}`,
  });
}

export function clearApprovedTools(): void {
  approvedHashes.clear();
}
