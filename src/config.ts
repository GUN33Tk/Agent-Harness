import * as fs from "fs";
import * as path from "path";

export interface HarnessConfig {
  killSwitchPath: string;
  budgetLimits: Record<string, number>;
  egressAllowlist: string[];
}

// Step 4: config lives outside the code — a real deployment points
// HARNESS_CONFIG at a reviewed file (or loads these from env/secret
// manager). The fallback below is for local dev only and should never
// be what runs in production.
const CONFIG_PATH = process.env.HARNESS_CONFIG ?? "/etc/agent/harness.config.json";

export function loadConfig(): HarnessConfig {
  if (fs.existsSync(CONFIG_PATH)) {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf-8"));
  }
  console.warn(`[config] ${CONFIG_PATH} not found — using local dev defaults. Do not run production like this.`);
  return {
    killSwitchPath: path.join(process.cwd(), ".dev-killswitch"),
    budgetLimits: { fetch_url: 20, send_email: 5, read_billing: 20 },
    egressAllowlist: ["example.com"],
  };
}
