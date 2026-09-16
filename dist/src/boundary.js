"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExecutionBoundary = void 0;
const logger_1 = require("./logger");
const egress_gateway_1 = require("./network/egress-gateway");
const provenance_1 = require("./provenance");
const policy_1 = require("./policy");
const security_events_1 = require("./security-events");
const untrusted_1 = require("./untrusted");
const sanitizer_1 = require("./sanitizer");
class ExecutionBoundary {
    constructor(registry, killSwitch, budget, egressAllowlistOrGateway, customPolicies) {
        this.registry = registry;
        this.killSwitch = killSwitch;
        this.budget = budget;
        this.policies = customPolicies ?? policy_1.DEFAULT_TOOL_POLICIES;
        if (egressAllowlistOrGateway instanceof egress_gateway_1.EgressGateway) {
            this.gateway = egressAllowlistOrGateway;
        }
        else {
            this.gateway = new egress_gateway_1.EgressGateway({
                allowedDomains: Array.from(egressAllowlistOrGateway),
            });
        }
    }
    getGateway() {
        return this.gateway;
    }
    async run(call) {
        const sessionId = call.sessionId ?? "session-default";
        const agentId = call.agentId ?? "agent-main";
        let result;
        // 1. Kill Switch Check (Active Cancellation)
        if (this.killSwitch.isSet()) {
            result = { tool: call.name, ok: false, error: "HALTED: kill switch active" };
            this.recordAndEmit(call, result, "KILL_SWITCH_TRIGGERED", "CRITICAL");
            return result;
        }
        // 2. Resolve Provenance and Classification
        const effectiveProvenance = call.provenance ?? (0, provenance_1.createProvenance)(call.derivedFromUntrusted ? "UNTRUSTED" : "TRUSTED", call.dataClassification ?? "PUBLIC", call.name);
        const effectiveClassification = call.dataClassification ?? effectiveProvenance.classification ?? "PUBLIC";
        // 3. Tool Authorization Policy Check (Who, What, Scope, Risk, Untrusted Provenance)
        const authDecision = (0, policy_1.evaluateToolAuthorization)(call.name, call.scope, call.derivedFromUntrusted ?? (effectiveProvenance.trust !== "TRUSTED"), this.policies, call.agentPhase);
        if (authDecision.decision !== "ALLOW") {
            result = {
                tool: call.name,
                ok: false,
                error: authDecision.reason.startsWith("DENIED:") ? authDecision.reason : `DENIED: ${authDecision.reason}`,
            };
            this.recordAndEmit(call, result, "POLICY_EVALUATION", authDecision.risk, authDecision.policy);
            return result;
        }
        // 4. Budget Check (Max Tool Calls & Circuit Breaker)
        if (!this.budget.spend(call.name)) {
            result = { tool: call.name, ok: false, error: `DENIED: budget exhausted for ${call.name}` };
            this.recordAndEmit(call, result, "BUDGET_EXCEEDED", "HIGH", "P-BUDGET-TOOL");
            return result;
        }
        // 5. Tool Execution Dispatch
        if (call.name === "fetch_url") {
            // Direct enforcement through central EgressGateway
            const rawUrl = String(call.args.url ?? "");
            const netReq = {
                agentId,
                sessionId,
                method: "GET",
                url: rawUrl,
                purpose: "fetch_url tool execution",
                provenance: effectiveProvenance,
                dataClassification: effectiveClassification,
                signal: this.killSwitch.signal,
            };
            try {
                const netRes = await this.gateway.request(netReq);
                const data = (0, untrusted_1.wrapUntrusted)(rawUrl, netRes.body, effectiveProvenance);
                const scan = (0, sanitizer_1.scanForInjection)(data);
                (0, logger_1.logDecision)({
                    tool: "fetch_url",
                    event: "content_scanned",
                    flagged: scan.flagged,
                    reason: scan.reason,
                });
                result = {
                    tool: call.name,
                    ok: true,
                    output: data.content,
                    provenance: (0, provenance_1.createProvenance)("UNTRUSTED", "PUBLIC", rawUrl),
                };
            }
            catch (err) {
                const errMsg = err instanceof Error ? err.message : String(err);
                result = {
                    tool: call.name,
                    ok: false,
                    error: errMsg.startsWith("DENIED:") ? errMsg : `DENIED: ${errMsg}`,
                };
            }
        }
        else {
            // Standard local / sandboxed tool call via registry
            result = await this.registry.call(call.name, call.args, call.scope);
        }
        // 6. Record and Emit Security Event
        this.recordAndEmit(call, result, "POLICY_EVALUATION", result.ok ? "LOW" : "HIGH");
        return result;
    }
    recordAndEmit(call, result, type, risk, policy) {
        (0, logger_1.logDecision)({
            tool: call.name,
            scope: call.scope,
            derivedFromUntrusted: !!call.derivedFromUntrusted,
            ok: result.ok,
            error: result.error,
        });
        (0, security_events_1.emitSecurityEvent)({
            sessionId: call.sessionId ?? "session-default",
            agentId: call.agentId ?? "agent-main",
            type,
            tool: call.name,
            decision: result.ok ? "ALLOW" : "DENY",
            risk,
            policy: policy ?? (result.ok ? "P-ALLOW" : "P-DENY"),
            reason: result.error,
            provenance: call.provenance,
        });
    }
}
exports.ExecutionBoundary = ExecutionBoundary;
