import * as crypto from "crypto";

export interface McpTool {
  serverName: string;
  name: string;
  description: string;
}

const approvedHashes = new Map<string, string>(); // persisted to disk in production — see memory.ts

function key(t: McpTool) {
  return `${t.serverName}:${t.name}`;
}

export function onToolsList(
  tools: McpTool[]
): { status: "OK" | "NEEDS_REVIEW" | "DENIED"; detail?: string } {
  for (const tool of tools) {
    const digest = crypto.createHash("sha256").update(tool.description).digest("hex");
    const prior = approvedHashes.get(key(tool));

    if (prior === undefined) {
      return { status: "NEEDS_REVIEW", detail: `new tool ${tool.name} from ${tool.serverName}` };
    }
    if (prior !== digest) {
      return {
        status: "DENIED",
        detail: `${tool.name} description changed since approval — re-review required`,
      };
    }
  }
  return { status: "OK" };
}

export function approveTool(t: McpTool): void {
  approvedHashes.set(key(t), crypto.createHash("sha256").update(t.description).digest("hex"));
}
