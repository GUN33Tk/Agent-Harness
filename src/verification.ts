import { scanForInjection } from "./sanitizer";
import { wrapUntrusted } from "./untrusted";
import * as fs from "fs";
import * as readline from "readline";

export interface ReviewResult {
  verdict: string;
  flagged: boolean;
  canFix: false;
}

// review() is read-only — it can flag a problem, it structurally cannot
// fix one (canFix: false is enforced by the type, not just convention).
// Uses the same scanner every other content-reading tool uses, so a
// verdict here means the same thing it means everywhere else it's shown.
export function review(code: string): ReviewResult {
  const snapshot = code; // a copy — the reviewer has no path back to the original
  const scan = scanForInjection(wrapUntrusted("review-input", snapshot));
  const verdict = scan.flagged ? `possible prompt injection — ${scan.reason}` : "looks fine";
  return { verdict, flagged: scan.flagged, canFix: false };
}

export function applyFix(path: string, newContent: string, dryRun: boolean = true): string {
  if (dryRun) return `DRY RUN: would rewrite ${path}, nothing written`;
  fs.writeFileSync(path, newContent, "utf-8");
  return `wrote ${path}`;
}

// The default approver: actually pauses the process and waits for a real
// human typing at the terminal. This is deliberately NOT something the
// model can influence — same principle as killswitch.ts being external
// to the model's own reasoning. A function parameter (not a hardcoded
// call) so tests can substitute a mock approver instead of blocking on
// real stdin.
export function terminalApproval(promptText: string): Promise<boolean> {
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
export async function proposeAndApply(
  targetPath: string,
  newContent: string,
  requestApproval: (prompt: string) => Promise<boolean> = terminalApproval
): Promise<string> {
  const result = review(newContent);
  if (result.flagged) {
    // Refused before any prompt — an injection attempt doesn't even get
    // the courtesy of asking a human to rubber-stamp it.
    return `DENIED: proposed content flagged before review — ${result.verdict}`;
  }

  const dryRunMsg = applyFix(targetPath, newContent, true);
  const approved = await requestApproval(
    `${dryRunMsg}\nContent passed the injection scan. Apply this write for real?`
  );

  if (!approved) return "DECLINED: operator did not approve — nothing written";
  return applyFix(targetPath, newContent, false);
}
