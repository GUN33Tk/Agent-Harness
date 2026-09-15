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
exports.review = review;
exports.applyFix = applyFix;
exports.terminalApproval = terminalApproval;
exports.proposeAndApply = proposeAndApply;
const sanitizer_1 = require("./sanitizer");
const untrusted_1 = require("./untrusted");
const fs = __importStar(require("fs"));
const readline = __importStar(require("readline"));
// review() is read-only — it can flag a problem, it structurally cannot
// fix one (canFix: false is enforced by the type, not just convention).
// Uses the same scanner every other content-reading tool uses, so a
// verdict here means the same thing it means everywhere else it's shown.
function review(code) {
    const snapshot = code; // a copy — the reviewer has no path back to the original
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
// The default approver: actually pauses the process and waits for a real
// human typing at the terminal. This is deliberately NOT something the
// model can influence — same principle as killswitch.ts being external
// to the model's own reasoning. A function parameter (not a hardcoded
// call) so tests can substitute a mock approver instead of blocking on
// real stdin.
function terminalApproval(promptText) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve) => {
        rl.question(`${promptText} [y/N] `, (answer) => {
            rl.close();
            resolve(answer.trim().toLowerCase() === "y");
        });
    });
}
// NEW: the full human-in-the-loop flow requested — check for injection
// FIRST (and refuse immediately, no prompt at all, if flagged), only
// show a dry run and ask a real human for approval if the content is
// clean, and only write for real if that human says yes.
async function proposeAndApply(targetPath, newContent, requestApproval = terminalApproval) {
    const result = review(newContent);
    if (result.flagged) {
        // Refused before any prompt — an injection attempt doesn't even get
        // the courtesy of asking a human to rubber-stamp it.
        return `DENIED: proposed content flagged before review — ${result.verdict}`;
    }
    const dryRunMsg = applyFix(targetPath, newContent, true);
    const approved = await requestApproval(`${dryRunMsg}\nContent passed the injection scan. Apply this write for real?`);
    if (!approved)
        return "DECLINED: operator did not approve — nothing written";
    return applyFix(targetPath, newContent, false);
}
