import { ToolRegistry, ToolCallResult } from "./registry";
import { resolveAndCheckHost } from "./egress";
import { KillSwitch } from "./killswitch";
import { BudgetTracker } from "./budget";
import { logDecision } from "./logger";

export interface ToolCall {
  name: string;
  args: Record<string, unknown>;
  scope: string;
  derivedFromUntrusted?: boolean;
}

const PRIVILEGED_TOOLS = new Set(["send_email", "delete_file", "read_billing"]);

export class ExecutionBoundary {
  constructor(
    private registry: ToolRegistry,
    private killSwitch: KillSwitch,
    private budget: BudgetTracker,
    private egressAllowlist: Set<string>   // CHANGED (Step 4): injected, not hardcoded
  ) {}

  async run(call: ToolCall): Promise<ToolCallResult> {
    let result: ToolCallResult;

    if (this.killSwitch.isSet()) {
      result = { tool: call.name, ok: false, error: "HALTED: kill switch active" };
    } else if (call.derivedFromUntrusted && PRIVILEGED_TOOLS.has(call.name)) {
      result = { tool: call.name, ok: false, error: "DENIED: privileged call traced to untrusted source" };
    } else if (!this.budget.spend(call.name)) {
      result = { tool: call.name, ok: false, error: `DENIED: budget exhausted for ${call.name}` };
    } else if (call.name === "fetch_url") {
      const checked = await resolveAndCheckHost(call.args.url as string, this.egressAllowlist);
      if (!checked) {
        result = { tool: call.name, ok: false, error: "DENIED: host not allowlisted or resolves to a private range" };
      } else {
        call.args.url = checked;
        result = await this.registry.call(call.name, call.args, call.scope);
      }
    } else {
      result = await this.registry.call(call.name, call.args, call.scope);
    }

    // CHANGED (Step 8): every decision — allow or deny — is now durably logged.
    logDecision({
      tool: call.name,
      scope: call.scope,
      derivedFromUntrusted: !!call.derivedFromUntrusted,
      ok: result.ok,
      error: result.error,
    });

    return result;
  }
}
