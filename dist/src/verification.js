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
exports.computeContentHash = computeContentHash;
exports.review = review;
exports.applyFix = applyFix;
exports.terminalApproval = terminalApproval;
exports.proposeAndApply = proposeAndApply;
const sanitizer_1 = require("./sanitizer");
const untrusted_1 = require("./untrusted");
const fs = __importStar(require("fs"));
const readline = __importStar(require("readline"));
const crypto = __importStar(require("crypto"));
const security_events_1 = require("./security-events");
function computeContentHash(content) {
    return crypto.createHash("sha256").update(content, "utf-8").digest("hex");
}
function review(code) {
    const snapshot = code;
    const scan = (0, sanitizer_1.scanForInjection)((0, untrusted_1.wrapUntrusted)("review-input", snapshot));
    const verdict = scan.flagged ? `possible prompt injection — ${scan.reason}` : "looks fine";
    return { verdict, flagged: scan.flagged, canFix: false };
}
function applyFix(path, newContent, dryRun = true) {
    if (dryRun)
        return `DRY RUN: would rewrite ${path}, nothing written`;
    fs.writeFileSync(path, newContent, "utf-8");
    return `wrote ${path}`;
}
function terminalApproval(promptText) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve) => {
        rl.question(`${promptText} [y/N] `, (answer) => {
            rl.close();
            resolve(answer.trim().toLowerCase() === "y");
        });
    });
}
/**
 * Human Approval Gate with Cryptographic Operation Binding.
 *
 * Enforces:
 * 1. Pre-approval tripwire scan: injection attempts are rejected immediately.
 * 2. Cryptographic binding: approval is locked to (targetPath, operation, contentHash).
 * 3. Exact verification before write: ensures content hasn't drifted or been swapped.
 * 4. Audit logging via SecurityEventBus.
 */
async function proposeAndApply(targetPath, newContent, requestApproval = terminalApproval, sessionId = "session-default") {
    // 1. Injection scan tripwire
    const result = review(newContent);
    if (result.flagged) {
        (0, security_events_1.emitSecurityEvent)({
            sessionId,
            agentId: "agent-main",
            type: "REQUEST_BLOCKED",
            decision: "DENY",
            policy: "P-INJECTION-TRIPWIRE",
            reason: `Proposed write flagged before review: ${result.verdict}`,
            risk: "HIGH",
        });
        return `DENIED: proposed content flagged before review — ${result.verdict}`;
    }
    // 2. Compute cryptographic digest of proposed content
    const contentHash = computeContentHash(newContent);
    const approvalRecord = {
        id: `appr-${Date.now()}-${contentHash.slice(0, 8)}`,
        tool: "propose_file_update",
        targetPath,
        operation: "write",
        contentHash,
        sessionId,
        timestamp: new Date().toISOString(),
        risk: "HIGH",
        policy: "P-HUMAN-APPROVAL",
        approved: false,
    };
    (0, security_events_1.emitSecurityEvent)({
        sessionId,
        agentId: "agent-main",
        type: "APPROVAL_REQUIRED",
        decision: "REVIEW",
        policy: "P-HUMAN-APPROVAL",
        reason: `Human review required to write to ${targetPath} (SHA-256: ${contentHash.slice(0, 12)}...)`,
        risk: "HIGH",
    });
    const dryRunMsg = applyFix(targetPath, newContent, true);
    const approved = await requestApproval(`${dryRunMsg}\nContent passed injection scan [hash: ${contentHash.slice(0, 12)}]. Apply this write for real?`);
    if (!approved) {
        (0, security_events_1.emitSecurityEvent)({
            sessionId,
            agentId: "operator",
            type: "APPROVAL_DENIED",
            decision: "DENY",
            policy: "P-HUMAN-APPROVAL",
            reason: `Operator rejected write proposal for ${targetPath}`,
            risk: "MEDIUM",
        });
        return "DECLINED: operator did not approve — nothing written";
    }
    // 3. Re-verify content hash immediately before application
    const preWriteHash = computeContentHash(newContent);
    if (preWriteHash !== approvalRecord.contentHash) {
        (0, security_events_1.emitSecurityEvent)({
            sessionId,
            agentId: "harness",
            type: "REQUEST_BLOCKED",
            decision: "DENY",
            policy: "P-HASH-MISMATCH",
            reason: "Content was modified after human approval was granted",
            risk: "CRITICAL",
        });
        return "DENIED: approved content hash mismatch — tampering detected";
    }
    approvalRecord.approved = true;
    (0, security_events_1.emitSecurityEvent)({
        sessionId,
        agentId: "operator",
        type: "APPROVAL_GRANTED",
        decision: "ALLOW",
        policy: "P-HUMAN-APPROVAL",
        reason: `Operator approved write to ${targetPath}`,
        risk: "LOW",
    });
    return applyFix(targetPath, newContent, false);
}
