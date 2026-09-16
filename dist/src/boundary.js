"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExecutionBoundary = void 0;
const logger_1 = require("./logger");
const egress_gateway_1 = require("./network/egress-gateway");
const provenance_1 = require("./provenance");
const policy_1 = require("./policy");
const schema_validator_1 = require("./schema-validator");
const security_events_1 = require("./security-events");
const untrusted_1 = require("./untrusted");
const sanitizer_1 = require("./sanitizer");
const session_1 = require("./session");
const classification_1 = require("./classification");
class ExecutionBoundary {
    constructor(registry, killSwitch, budget, egressAllowlistOrGateway, customPolicies, sessionManager) {
        this.registry = registry;
        this.killSwitch = killSwitch;
        this.budget = budget;
        this.policies = customPolicies ?? policy_1.DEFAULT_TOOL_POLICIES;
        this.sessionManager = sessionManager ?? new session_1.SessionManager();
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
    getSessionManager() {
        return this.sessionManager;
    }
    async run(call) {
        const sessionId = call.sessionId ?? "session-default";
        const agentId = call.agentId ?? "agent-main";
        let result;
        // ── 0. Record tool request entry ────────────────────────────────────────
        (0, security_events_1.emitSecurityEvent)({
            sessionId,
            agentId,
            type: "TOOL_REQUEST",
            tool: call.name,
            decision: "REVIEW",
            risk: "LOW",
            reason: `Tool '${call.name}' requested in scope '${call.scope}'`,
            provenance: call.provenance,
            details: { scope: call.scope, agentPhase: call.agentPhase },
        });
        // ── 1. Kill Switch Check ─────────────────────────────────────────────────
        if (this.killSwitch.isSet()) {
            result = { tool: call.name, ok: false, error: "HALTED: kill switch active" };
            this.recordAndEmit(call, result, "KILL_SWITCH_TRIGGERED", "CRITICAL");
            return result;
        }
        // ── 2. Resolve Monotonic Session Security Context ────────────────────────
        // Retrieve isolated session security context
        const session = this.sessionManager.getSession(sessionId);
        // Ingest explicit call taint into session context if provided
        if (call.provenance || call.dataClassification || call.derivedFromUntrusted) {
            const explicitProvenance = call.provenance ?? (0, provenance_1.createProvenance)(call.derivedFromUntrusted ? "UNTRUSTED" : "TRUSTED", call.dataClassification ?? "PUBLIC", call.name);
            this.sessionManager.updateTaint(sessionId, explicitProvenance, call.dataClassification ?? explicitProvenance.classification, call.name);
        }
        // Effective state is the more restrictive monotonic combination of call and session context
        const effectiveClassification = (0, provenance_1.combineClassification)(call.dataClassification ?? "PUBLIC", session.classification);
        const rawCallProvenance = call.provenance ?? (0, provenance_1.createProvenance)(call.derivedFromUntrusted ? "UNTRUSTED" : "TRUSTED", effectiveClassification, call.name);
        const effectiveProvenance = (0, provenance_1.combineProvenance)(rawCallProvenance, session.provenance);
        // ── 3. Tool Authorization Policy ─────────────────────────────────────────
        // Uses policy.ts exclusively — no hardcoded PRIVILEGED_TOOLS set here.
        // policy.ts defines risk, allowedScopes, blockUntrustedProvenance, requiresApproval, etc.
        const authDecision = (0, policy_1.evaluateToolAuthorization)(call.name, call.scope, effectiveProvenance, this.policies, call.agentPhase);
        if (authDecision.decision !== "ALLOW") {
            result = {
                tool: call.name,
                ok: false,
                error: authDecision.reason.startsWith("DENIED:") ? authDecision.reason : `DENIED: ${authDecision.reason}`,
            };
            this.recordAndEmit(call, result, "POLICY_EVALUATION", authDecision.risk, authDecision.policy);
            return result;
        }
        // ── 4. JSON Schema Validation ─────────────────────────────────────────────
        // Schema validation occurs in boundary BEFORE any tool execution.
        // This applies to ALL tools including fetch_url (which is dispatched below the registry).
        // Invalid arguments MUST NOT reach any tool implementation.
        const toolDef = this.registry.get(call.name);
        const schemaToValidate = toolDef?.jsonSchema ?? (typeof toolDef?.schema === "object" && toolDef?.schema !== null ? toolDef.schema : null);
        if (toolDef && schemaToValidate) {
            const schemaResult = (0, schema_validator_1.validateToolArgs)(schemaToValidate, call.args, call.name);
            if (!schemaResult.valid) {
                const errMsg = `schema validation failed: ${schemaResult.errors?.join("; ")}`;
                result = { tool: call.name, ok: false, error: `DENIED: ${errMsg}` };
                // Emit structured schema validation failure event
                (0, security_events_1.emitSecurityEvent)({
                    sessionId,
                    agentId,
                    type: "SCHEMA_VALIDATION_FAILURE",
                    tool: call.name,
                    decision: "DENY",
                    risk: "HIGH",
                    policy: "P-SCHEMA-001",
                    reason: errMsg,
                    details: { errors: schemaResult.errors, args: sanitizeArgsForLog(call.args) },
                });
                (0, logger_1.logDecision)({
                    tool: call.name,
                    scope: call.scope,
                    ok: false,
                    error: errMsg,
                });
                return result;
            }
        }
        else if (!toolDef) {
            // Tool not registered — fail closed
            result = { tool: call.name, ok: false, error: `DENIED: unknown tool: ${call.name}` };
            this.recordAndEmit(call, result, "POLICY_EVALUATION", "HIGH", "P-TOOL-UNKNOWN");
            return result;
        }
        // Note: tools with no schema at all are permitted through here.
        // The policy engine's risk level controls whether that's acceptable.
        // ── 5. Budget Check ──────────────────────────────────────────────────────
        if (!this.budget.spend(call.name)) {
            result = { tool: call.name, ok: false, error: `DENIED: budget exhausted for ${call.name}` };
            this.recordAndEmit(call, result, "BUDGET_EXCEEDED", "HIGH", "P-BUDGET-TOOL");
            return result;
        }
        // ── 6. Tool Execution Dispatch ───────────────────────────────────────────
        // fetch_url is dispatched directly through boundary's EgressGateway so that
        // provenance and classification from the call and session context are forwarded
        // to the network enforcement layer.
        if (call.name === "fetch_url") {
            const rawUrl = String(call.args.url ?? "");
            const netReq = {
                agentId,
                sessionId,
                method: "GET",
                url: rawUrl,
                purpose: "fetch_url tool execution",
                provenance: effectiveProvenance,
                dataClassification: effectiveClassification,
                sessionContext: session,
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
                // Update session context: incoming web content is UNTRUSTED + PUBLIC
                this.sessionManager.updateTaint(sessionId, (0, provenance_1.createProvenance)("UNTRUSTED", "PUBLIC", rawUrl), "PUBLIC", rawUrl);
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
            // Post-execution taint update for sensitive resource reads
            if (result.ok && call.name === "read_file" && call.args.path) {
                const filePath = String(call.args.path);
                const fileClass = (0, classification_1.classifyPath)(filePath);
                if (fileClass === "SECRET" || fileClass === "CONFIDENTIAL") {
                    this.sessionManager.updateTaint(sessionId, (0, provenance_1.createProvenance)("UNTRUSTED", fileClass, filePath), fileClass, filePath, result.output);
                }
            }
            else if (result.ok && result.provenance) {
                this.sessionManager.updateTaint(sessionId, result.provenance, result.provenance.classification, call.name, result.output);
            }
        }
        // ── 7. Record and Emit Final Security Event ──────────────────────────────
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
/**
 * Sanitize tool args for logging — redact any fields that look like credentials or secrets.
 * Never log actual secret content in security events.
 */
function sanitizeArgsForLog(args) {
    const sensitiveKeys = /password|secret|key|token|credential|auth/i;
    return Object.fromEntries(Object.entries(args).map(([k, v]) => [k, sensitiveKeys.test(k) ? "[REDACTED]" : v]));
}
