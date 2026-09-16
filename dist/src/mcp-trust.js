"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.canonicalizeJson = canonicalizeJson;
exports.computeToolManifestHash = computeToolManifestHash;
exports.onToolsList = onToolsList;
exports.approveTool = approveTool;
exports.clearApprovedTools = clearApprovedTools;
const crypto = __importStar(require("crypto"));
const security_events_1 = require("./security-events");
const approvedHashes = new Map();
function key(t) {
    return `${t.serverName}:${t.name}`;
}
/**
 * Deterministically sorts object keys recursively to produce a canonical JSON string.
 */
function canonicalizeJson(obj) {
    if (obj === null || typeof obj !== "object") {
        return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
        return `[${obj.map((item) => canonicalizeJson(item)).join(",")}]`;
    }
    const record = obj;
    const sortedKeys = Object.keys(record).sort();
    const entries = sortedKeys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(record[k])}`);
    return `{${entries.join(",")}}`;
}
/**
 * Computes SHA-256 hash across the canonical MCP tool manifest.
 */
function computeToolManifestHash(tool) {
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
function onToolsList(tools) {
    for (const tool of tools) {
        const digest = computeToolManifestHash(tool);
        const prior = approvedHashes.get(key(tool));
        if (prior === undefined) {
            (0, security_events_1.emitSecurityEvent)({
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
            (0, security_events_1.emitSecurityEvent)({
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
function approveTool(t) {
    const digest = computeToolManifestHash(t);
    approvedHashes.set(key(t), digest);
    (0, security_events_1.emitSecurityEvent)({
        sessionId: "mcp-scan",
        agentId: "operator",
        type: "APPROVAL_GRANTED",
        decision: "ALLOW",
        policy: "P-MCP-APPROVE",
        reason: `Pinned canonical manifest hash for ${t.name}`,
    });
}
function clearApprovedTools() {
    approvedHashes.clear();
}
