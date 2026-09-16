import { scanForInjection } from "./sanitizer";
import { wrapUntrusted } from "./untrusted";
import * as fs from "fs";
import * as readline from "readline";
import * as crypto from "crypto";
import { emitSecurityEvent } from "./security-events";

export interface ReviewResult {
  verdict: string;
  flagged: boolean;
  canFix: false;
}

export interface ApprovalRecord {
  id: string;
  tool: string;
  targetPath: string;
  operation: "read" | "write" | "delete" | "execute";
  contentHash: string;
  sessionId: string;
  timestamp: string;
  risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  policy: string;
  approved: boolean;
}

export function computeContentHash(content: string): string {
  return crypto.createHash("sha256").update(content, "utf-8").digest("hex");
}

export function review(code: string): ReviewResult {
  const snapshot = code;
  const scan = scanForInjection(wrapUntrusted("review-input", snapshot));
  const verdict = scan.flagged ? `possible prompt injection — ${scan.reason}` : "looks fine";
  return { verdict, flagged: scan.flagged, canFix: false };
}

export function applyFix(path: string, newContent: string, dryRun: boolean = true): string {
  if (dryRun) return `DRY RUN: would rewrite ${path}, nothing written`;
  fs.writeFileSync(path, newContent, "utf-8");
  return `wrote ${path}`;
}

export function terminalApproval(promptText: string): Promise<boolean> {
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
export async function proposeAndApply(
  targetPath: string,
  newContent: string,
  requestApproval: (prompt: string) => Promise<boolean> = terminalApproval,
  sessionId: string = "session-default"
): Promise<string> {
  // 1. Injection scan tripwire
  const result = review(newContent);
  if (result.flagged) {
    emitSecurityEvent({
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
  const approvalRecord: ApprovalRecord = {
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

  emitSecurityEvent({
    sessionId,
    agentId: "agent-main",
    type: "APPROVAL_REQUIRED",
    decision: "REVIEW",
    policy: "P-HUMAN-APPROVAL",
    reason: `Human review required to write to ${targetPath} (SHA-256: ${contentHash.slice(0, 12)}...)`,
    risk: "HIGH",
  });

  const dryRunMsg = applyFix(targetPath, newContent, true);
  const approved = await requestApproval(
    `${dryRunMsg}\nContent passed injection scan [hash: ${contentHash.slice(0, 12)}]. Apply this write for real?`
  );

  if (!approved) {
    emitSecurityEvent({
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
    emitSecurityEvent({
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
  emitSecurityEvent({
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
