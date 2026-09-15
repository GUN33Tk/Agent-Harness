import * as fs from "fs";

// Step 8: durable, append-only log of every boundary decision, so a
// denied call is something a SOC-style review can see later — not just
// something the agent silently avoided in memory.
const LOG_PATH = process.env.HARNESS_LOG ?? "./harness-events.log";

export function logDecision(entry: Record<string, unknown>): void {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n";
  fs.appendFileSync(LOG_PATH, line);
}
