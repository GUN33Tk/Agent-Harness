import { Untrusted } from "./untrusted";

const INJECTION_PATTERNS: RegExp[] = [
  // Widened after actually testing this against real phrasing: the
  // original pattern only matched exactly "ignore previous instructions"
  // and missed the arguably more common "ignore all previous
  // instructions" (extra word breaks a rigid 3-token match). (all\s+)?
  // now makes that middle word optional instead of assuming a fixed shape.
  /ignore\s+(all\s+)?(previous|prior)\s+(instructions|constraints)/i,
  /system\s*:\s*/i,
  /override (settings|policy|permissions)/i,
  /before (answering|using any other tool)/i,
  /disregard (the|any) (above|previous)/i,
];

export interface ScanResult {
  flagged: boolean;
  reason?: string;
}

export function scanForInjection(data: Untrusted): ScanResult {
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(data.content)) return { flagged: true, reason: `matched: ${pattern}` };
  }
  return { flagged: false };
}
