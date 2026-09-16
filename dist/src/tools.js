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
exports.proposeFileUpdateTool = exports.readFileTool = exports.readBillingTool = exports.sendEmailTool = void 0;
exports.createFetchUrlTool = createFetchUrlTool;
const untrusted_1 = require("./untrusted");
const sanitizer_1 = require("./sanitizer");
const logger_1 = require("./logger");
const credentials_1 = require("./credentials");
const files_1 = require("./files");
const verification_1 = require("./verification");
const egress_gateway_1 = require("./network/egress-gateway");
const classification_1 = require("./classification");
const provenance_1 = require("./provenance");
const child_process_1 = require("child_process");
const util_1 = require("util");
const path = __importStar(require("path"));
const execFileAsync = (0, util_1.promisify)(child_process_1.execFile);
/**
 * Creates the fetch_url tool powered by the central EgressGateway.
 * The tool never calls raw fetch() directly. All outbound requests are evaluated against
 * SSRF filters, IP pinning, redirect validation, and data piggybacking policies.
 */
function createFetchUrlTool(allowlistOrGateway) {
    const gateway = allowlistOrGateway instanceof egress_gateway_1.EgressGateway
        ? allowlistOrGateway
        : new egress_gateway_1.EgressGateway({ allowedDomains: Array.from(allowlistOrGateway) });
    return {
        name: "fetch_url",
        allowedInScopes: ["research", "pricing-research"],
        schema: (args) => typeof args.url === "string",
        jsonSchema: {
            type: "object",
            properties: { url: { type: "string" } },
            required: ["url"],
            additionalProperties: false,
        },
        execute: async (args) => {
            const url = args.url;
            const res = await gateway.request({
                method: "GET",
                url,
                provenance: (0, provenance_1.createProvenance)("UNTRUSTED", "PUBLIC", "fetch_url"),
                dataClassification: "PUBLIC",
            });
            const data = (0, untrusted_1.wrapUntrusted)(url, res.body);
            const scan = (0, sanitizer_1.scanForInjection)(data);
            (0, logger_1.logDecision)({
                tool: "fetch_url",
                event: "content_scanned",
                flagged: scan.flagged,
                reason: scan.reason,
            });
            return data.content;
        },
    };
}
exports.sendEmailTool = {
    name: "send_email",
    allowedInScopes: ["customer-support"],
    schema: (args) => typeof args.to === "string" && typeof args.body === "string",
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
        const cred = (0, credentials_1.getCredential)("customer-support");
        console.log(`[send_email] using cred=${cred} to=${args.to} body="${args.body.slice(0, 80)}..."`);
        return "sent";
    },
};
exports.readBillingTool = {
    name: "read_billing",
    allowedInScopes: ["pricing-research"],
    schema: (args) => typeof args.account_id === "string",
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
            const { stdout } = await execFileAsync(launcher, [target, args.account_id]);
            return stdout.trim();
        }
        catch (err) {
            return JSON.stringify({
                error: "sandboxed billing_tool unavailable — run `cd native && make` first",
                detail: String(err),
            });
        }
    },
};
exports.readFileTool = {
    name: "read_file",
    allowedInScopes: ["file-access"],
    schema: (args) => typeof args.path === "string",
    jsonSchema: {
        type: "object",
        properties: {
            path: { type: "string" },
        },
        required: ["path"],
        additionalProperties: false,
    },
    execute: async (args) => {
        const resolved = (0, files_1.resolveWithinRoot)(args.path);
        if (!resolved)
            throw new Error(`DENIED: path escapes the allowed root`);
        const fs = await Promise.resolve().then(() => __importStar(require("fs/promises")));
        const raw = await fs.readFile(resolved, "utf-8");
        // Deterministic data classification
        const classification = (0, classification_1.classifyPath)(resolved);
        if (classification === "SECRET" || classification === "CONFIDENTIAL") {
            classification_1.sessionSecretTracker.registerSecret(raw);
        }
        const provenance = (0, provenance_1.createProvenance)("UNTRUSTED", classification, resolved);
        const data = (0, untrusted_1.wrapUntrusted)(resolved, raw, provenance);
        const scan = (0, sanitizer_1.scanForInjection)(data);
        (0, logger_1.logDecision)({
            tool: "read_file",
            event: "content_scanned",
            flagged: scan.flagged,
            reason: scan.reason,
            classification,
        });
        return data.content;
    },
};
exports.proposeFileUpdateTool = {
    name: "propose_file_update",
    allowedInScopes: ["file-access"],
    schema: (args) => typeof args.path === "string" && typeof args.new_content === "string",
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
        const resolved = (0, files_1.resolveWithinRoot)(args.path);
        if (!resolved)
            throw new Error(`DENIED: path escapes the allowed root`);
        return await (0, verification_1.proposeAndApply)(resolved, args.new_content);
    },
};
