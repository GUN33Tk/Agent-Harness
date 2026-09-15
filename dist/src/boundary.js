"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExecutionBoundary = void 0;
const egress_1 = require("./egress");
const logger_1 = require("./logger");
const PRIVILEGED_TOOLS = new Set(["send_email", "delete_file", "read_billing"]);
class ExecutionBoundary {
    constructor(registry, killSwitch, budget, egressAllowlist // CHANGED (Step 4): injected, not hardcoded
    ) {
        this.registry = registry;
        this.killSwitch = killSwitch;
        this.budget = budget;
        this.egressAllowlist = egressAllowlist;
    }
    async run(call) {
        let result;
        if (this.killSwitch.isSet()) {
            result = { tool: call.name, ok: false, error: "HALTED: kill switch active" };
        }
        else if (call.derivedFromUntrusted && PRIVILEGED_TOOLS.has(call.name)) {
            result = { tool: call.name, ok: false, error: "DENIED: privileged call traced to untrusted source" };
        }
        else if (!this.budget.spend(call.name)) {
            result = { tool: call.name, ok: false, error: `DENIED: budget exhausted for ${call.name}` };
        }
        else if (call.name === "fetch_url") {
            const checked = await (0, egress_1.resolveAndCheckHost)(call.args.url, this.egressAllowlist);
            if (!checked) {
                result = { tool: call.name, ok: false, error: "DENIED: host not allowlisted or resolves to a private range" };
            }
            else {
                call.args.url = checked;
                result = await this.registry.call(call.name, call.args, call.scope);
            }
        }
        else {
            result = await this.registry.call(call.name, call.args, call.scope);
        }
        // CHANGED (Step 8): every decision — allow or deny — is now durably logged.
        (0, logger_1.logDecision)({
            tool: call.name,
            scope: call.scope,
            derivedFromUntrusted: !!call.derivedFromUntrusted,
            ok: result.ok,
            error: result.error,
        });
        return result;
    }
}
exports.ExecutionBoundary = ExecutionBoundary;
