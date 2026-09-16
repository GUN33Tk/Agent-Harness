import { ToolRegistry, ToolCallResult } from "./registry";
import { KillSwitch } from "./killswitch";
import { BudgetTracker } from "./budget";
import { logDecision } from "./logger";
import { EgressGateway } from "./network/egress-gateway";
import { NetworkRequest, AgentPhase } from "./network/network-types";
import { Provenance, DataClassification, createProvenance } from "./provenance";
import { evaluateToolAuthorization, DEFAULT_TOOL_POLICIES, ToolSecurityPolicy } from "./policy";
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

    // 1. Kill Switch Check (Active Cancellation)
    if (this.killSwitch.isSet()) {
      result = { tool: call.name, ok: false, error: "HALTED: kill switch active" };
      this.recordAndEmit(call, result, "KILL_SWITCH_TRIGGERED", "CRITICAL");
      return result;
    }

    // 2. Resolve Provenance and Classification
    const effectiveProvenance: Provenance = call.provenance ?? createProvenance(
      call.derivedFromUntrusted ? "UNTRUSTED" : "TRUSTED",
      call.dataClassification ?? "PUBLIC",
      call.name
    );
    const effectiveClassification: DataClassification =
      call.dataClassification ?? effectiveProvenance.classification ?? "PUBLIC";

    // 3. Tool Authorization Policy Check (Who, What, Scope, Risk, Untrusted Provenance)
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
          provenance: createProvenance(
            "UNTRUSTED",
            "PUBLIC",
            rawUrl
          ),
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
      // Standard local / sandboxed tool call via registry
      result = await this.registry.call(call.name, call.args, call.scope);
    }

    // 6. Record and Emit Security Event
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
