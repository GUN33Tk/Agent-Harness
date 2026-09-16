import { ToolRegistry, ToolCallResult } from "./registry";
import { KillSwitch } from "./killswitch";
import { BudgetTracker } from "./budget";
import { logDecision } from "./logger";
import { EgressGateway } from "./network/egress-gateway";
import { NetworkRequest, AgentPhase } from "./network/network-types";
import { Provenance, DataClassification, createProvenance } from "./provenance";
import { evaluateToolAuthorization, DEFAULT_TOOL_POLICIES, ToolSecurityPolicy } from "./policy";
import { validateToolArgs } from "./schema-validator";
import { emitSecurityEvent } from "./security-events";
import { wrapUntrusted } from "./untrusted";
import { scanForInjection } from "./sanitizer";

export interface ToolCall {
  name: string;
  args: Record<string, unknown>;
  scope: string;
  derivedFromUntrusted?: boolean;
  provenance?: Provenance;
  dataClassification?: DataClassification;
  agentPhase?: AgentPhase;
  sessionId?: string;
  agentId?: string;
}

export class ExecutionBoundary {
  private gateway: EgressGateway;
  private policies: Record<string, ToolSecurityPolicy>;

  constructor(
    private registry: ToolRegistry,
    private killSwitch: KillSwitch,
    private budget: BudgetTracker,
    egressAllowlistOrGateway: Set<string> | EgressGateway,
    customPolicies?: Record<string, ToolSecurityPolicy>
  ) {
    this.policies = customPolicies ?? DEFAULT_TOOL_POLICIES;

    if (egressAllowlistOrGateway instanceof EgressGateway) {
      this.gateway = egressAllowlistOrGateway;
    } else {
      this.gateway = new EgressGateway({
        allowedDomains: Array.from(egressAllowlistOrGateway),
      });
    }
  }

  getGateway(): EgressGateway {
    return this.gateway;
  }

  async run(call: ToolCall): Promise<ToolCallResult> {
    const sessionId = call.sessionId ?? "session-default";
    const agentId = call.agentId ?? "agent-main";
    let result: ToolCallResult;

    // ── 0. Record tool request entry ────────────────────────────────────────
    emitSecurityEvent({
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

    // ── 2. Resolve Provenance and Classification ─────────────────────────────
    // Structured provenance is carried through the full call chain.
    // derivedFromUntrusted is kept for backwards compatibility but the structured
    // Provenance object is always the authoritative source.
    const effectiveProvenance: Provenance = call.provenance ?? createProvenance(
      call.derivedFromUntrusted ? "UNTRUSTED" : "TRUSTED",
      call.dataClassification ?? "PUBLIC",
      call.name
    );
    const effectiveClassification: DataClassification =
      call.dataClassification ?? effectiveProvenance.classification ?? "PUBLIC";

    // ── 3. Tool Authorization Policy ─────────────────────────────────────────
    // Uses policy.ts exclusively — no hardcoded PRIVILEGED_TOOLS set here.
    // policy.ts defines risk, allowedScopes, blockUntrustedProvenance, requiresApproval, etc.
    const authDecision = evaluateToolAuthorization(
      call.name,
      call.scope,
      call.derivedFromUntrusted ?? (effectiveProvenance.trust !== "TRUSTED"),
      this.policies,
      call.agentPhase
    );

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
    const schemaToValidate = toolDef?.jsonSchema ?? (
      typeof toolDef?.schema === "object" && toolDef?.schema !== null ? toolDef.schema : null
    );

    if (toolDef && schemaToValidate) {
      const schemaResult = validateToolArgs(schemaToValidate, call.args, call.name);
      if (!schemaResult.valid) {
        const errMsg = `schema validation failed: ${schemaResult.errors?.join("; ")}`;
        result = { tool: call.name, ok: false, error: `DENIED: ${errMsg}` };

        // Emit structured schema validation failure event
        emitSecurityEvent({
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

        logDecision({
          tool: call.name,
          scope: call.scope,
          ok: false,
          error: errMsg,
        });
        return result;
      }
    } else if (!toolDef) {
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
    // provenance and classification from the call context are forwarded to the
    // network enforcement layer. This is the ONLY approved network execution path.
    // The tool's own execute() is not used for fetch_url to prevent a second
    // gateway instance from operating with different (or missing) provenance.
    if (call.name === "fetch_url") {
      const rawUrl = String(call.args.url ?? "");
      const netReq: NetworkRequest = {
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
        const data = wrapUntrusted(rawUrl, netRes.body, effectiveProvenance);
        const scan = scanForInjection(data);

        logDecision({
          tool: "fetch_url",
          event: "content_scanned",
          flagged: scan.flagged,
          reason: scan.reason,
        });

        result = {
          tool: call.name,
          ok: true,
          output: data.content,
          provenance: createProvenance("UNTRUSTED", "PUBLIC", rawUrl),
        };
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        result = {
          tool: call.name,
          ok: false,
          error: errMsg.startsWith("DENIED:") ? errMsg : `DENIED: ${errMsg}`,
        };
      }
    } else {
      // Standard local / sandboxed tool call via registry.
      // Registry.call() still performs its own validation, but boundary's
      // schema check above already validated args — registry is a secondary
      // defence-in-depth layer for direct registry.call() callers.
      result = await this.registry.call(call.name, call.args, call.scope);
    }

    // ── 7. Record and Emit Final Security Event ──────────────────────────────
    this.recordAndEmit(call, result, "POLICY_EVALUATION", result.ok ? "LOW" : "HIGH");

    return result;
  }

  private recordAndEmit(
    call: ToolCall,
    result: ToolCallResult,
    type: "POLICY_EVALUATION" | "KILL_SWITCH_TRIGGERED" | "BUDGET_EXCEEDED",
    risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
    policy?: string
  ): void {
    logDecision({
      tool: call.name,
      scope: call.scope,
      derivedFromUntrusted: !!call.derivedFromUntrusted,
      ok: result.ok,
      error: result.error,
    });

    emitSecurityEvent({
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

/**
 * Sanitize tool args for logging — redact any fields that look like credentials or secrets.
 * Never log actual secret content in security events.
 */
function sanitizeArgsForLog(args: Record<string, unknown>): Record<string, unknown> {
  const sensitiveKeys = /password|secret|key|token|credential|auth/i;
  return Object.fromEntries(
    Object.entries(args).map(([k, v]) => [k, sensitiveKeys.test(k) ? "[REDACTED]" : v])
  );
}
