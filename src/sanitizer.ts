import { Untrusted } from "./untrusted";

/**
 * PROMPT INJECTION TRIPWIRE (Heuristic Detection Layer)
 *
 * NOTE ON SECURITY ARCHITECTURE:
 * Regex pattern matching is a tripwire/sensor for early logging, NOT an impenetrable security boundary.
 * An attacker can always find paraphrased variations or encoded variants to bypass text heuristics.
 *
 * The REAL security boundary is enforced outside the LLM:
 * 1. Provenance / taint tracking (Untrusted content cannot trigger privileged calls)
 * 2. Data classification (SECRET data cannot cross network egress)
 * 3. Central Egress Gateway & SSRF filtering
 * 4. Human approval binding
 * 5. OS-level and seccomp sandboxing
 */
const INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(all\s+)?(previous|prior)\s+(instructions|constraints)/i,
  /system\s*:\s*/i,
  /\[SYSTEM\]/i,
  /override (settings|policy|permissions)/i,
  /before (answering|using any other tool)/i,
  /disregard (the|any) (above|previous)/i,
  /(developer|maintenance|god)\s+mode\s+active/i,
  /you are now an unfiltered/i,
];

export interface ScanResult {
  flagged: boolean;
  reason?: string;
}

export function scanForInjection(data: Untrusted): ScanResult {
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(data.content)) {
      return { flagged: true, reason: `matched: ${pattern}` };
    }
  }
  return { flagged: false };
}
