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
// CHANGED: fetch_url now actually wraps its result as Untrusted and scans
// it before returning — this was previously dead code (untrusted.ts and
// sanitizer.ts existed but nothing called them). The scan result is
// logged either way; a flagged result is still returned to the model
// (the model is allowed to read suspicious content) but boundary.ts's
// derivedFromUntrusted check is what actually stops it from being acted
// on by a privileged tool afterward.
function createFetchUrlTool(allowlist) {
    return {
        name: "fetch_url",
        allowedInScopes: ["research", "pricing-research"],
        schema: (args) => typeof args.url === "string",
        execute: async (args) => {
            const url = args.url;
            const res = await fetch(url);
            const rawText = await res.text();
            const data = (0, untrusted_1.wrapUntrusted)(url, rawText);
            const scan = (0, sanitizer_1.scanForInjection)(data);
            (0, logger_1.logDecision)({ tool: "fetch_url", event: "content_scanned", flagged: scan.flagged, reason: scan.reason });
            return data.content;
        },
    };
}
exports.sendEmailTool = {
    name: "send_email",
    allowedInScopes: ["customer-support"],
    schema: (args) => typeof args.to === "string" && typeof args.body === "string",
    execute: async (args) => {
        // CHANGED: pulls a scope-bound credential instead of using a global
        // identity — a token issued for "customer-support" cannot be reused
        // by code running under any other scope. See credentials.ts.
        const cred = (0, credentials_1.getCredential)("customer-support");
        console.log(`[send_email] using cred=${cred} to=${args.to} body="${args.body.slice(0, 80)}..."`);
        return "sent";
    },
};
// CHANGED: read_billing no longer runs inline in the Node process — it
// now executes inside the C++ sandbox via native/billing_tool, spawned
// through native/sandbox_launcher. This is the one tool in this project
// that gets genuine kernel-level isolation, not just an application-level
// scope check. See README for why this isn't (yet) true of every tool.
const child_process_1 = require("child_process");
const util_1 = require("util");
const path = __importStar(require("path"));
const execFileAsync = (0, util_1.promisify)(child_process_1.execFile);
exports.readBillingTool = {
    name: "read_billing",
    allowedInScopes: ["pricing-research"],
    schema: (args) => typeof args.account_id === "string",
    execute: async (args) => {
        // NOTE: __dirname here is dist/src (this file's compiled location),
        // so it takes TWO levels up to reach the project root, then into
        // native/ — found this by actually running the test and seeing the
        // "not built" skip message when the binaries were, in fact, built.
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
const files_1 = require("./files");
exports.readFileTool = {
    name: "read_file",
    allowedInScopes: ["file-access"],
    schema: (args) => typeof args.path === "string",
    execute: async (args) => {
        const resolved = (0, files_1.resolveWithinRoot)(args.path);
        if (!resolved)
            throw new Error(`DENIED: path escapes the allowed root`);
        const fs = await Promise.resolve().then(() => __importStar(require("fs/promises")));
        const raw = await fs.readFile(resolved, "utf-8");
        // CHANGED: previously returned raw content with no scan at all —
        // fetch_url scanned its output but read_file didn't, even though a
        // local file can carry the same kind of embedded instruction. Now
        // both external-content tools log a scan result the same way.
        const data = (0, untrusted_1.wrapUntrusted)(resolved, raw);
        const scan = (0, sanitizer_1.scanForInjection)(data);
        (0, logger_1.logDecision)({ tool: "read_file", event: "content_scanned", flagged: scan.flagged, reason: scan.reason });
        return data.content;
    },
};
// NEW: a tool that lets the agent PROPOSE a file change — but the actual
// write only happens after (1) an injection scan passes and (2) a real
// human at the terminal explicitly approves it. The model can request
// this; it cannot make it happen on its own.
const verification_1 = require("./verification");
exports.proposeFileUpdateTool = {
    name: "propose_file_update",
    allowedInScopes: ["file-access"],
    schema: (args) => typeof args.path === "string" && typeof args.new_content === "string",
    execute: async (args) => {
        const resolved = (0, files_1.resolveWithinRoot)(args.path);
        if (!resolved)
            throw new Error(`DENIED: path escapes the allowed root`);
        return await (0, verification_1.proposeAndApply)(resolved, args.new_content);
    },
};
