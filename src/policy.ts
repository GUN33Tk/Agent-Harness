import { AgentPhase } from "./network/network-types";
import { Provenance } from "./provenance";

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface ToolSecurityPolicy {
  name: string;
  risk: RiskLevel;
  allowedScopes: string[];
  requiresApproval?: boolean;
  blockUntrustedProvenance?: boolean;
  networkRequired?: boolean;
  filesystemAccess?: "NONE" | "READ" | "WRITE";
  sandboxRequired?: boolean;
}

export interface ToolAuthorizationDecision {
  decision: "ALLOW" | "DENY" | "REVIEW";
  policy: string;
  reason: string;
  risk: RiskLevel;
}

export const DEFAULT_TOOL_POLICIES: Record<string, ToolSecurityPolicy> = {
  send_email: {
    name: "send_email",
    risk: "HIGH",
    allowedScopes: ["customer-support"],
    blockUntrustedProvenance: true,
  },
  delete_file: {
    name: "delete_file",
    risk: "CRITICAL",
    allowedScopes: ["admin"],
    blockUntrustedProvenance: true,
    requiresApproval: true,
    filesystemAccess: "WRITE",
  },
  read_billing: {
    name: "read_billing",
    risk: "HIGH",
    allowedScopes: ["pricing-research"],
    blockUntrustedProvenance: true,
    sandboxRequired: true,
  },
  fetch_url: {
    name: "fetch_url",
    risk: "MEDIUM",
    allowedScopes: ["research", "pricing-research"],
    networkRequired: true,
  },
  read_file: {
    name: "read_file",
    risk: "LOW",
    allowedScopes: ["file-access"],
    filesystemAccess: "READ",
  },
  propose_file_update: {
    name: "propose_file_update",
    risk: "HIGH",
    allowedScopes: ["file-access"],
    requiresApproval: true,
    filesystemAccess: "WRITE",
  },
};

export function evaluateToolAuthorization(
  toolName: string,
  scope: string,
  provenance: Provenance | boolean | undefined,
  policyMap: Record<string, ToolSecurityPolicy> = DEFAULT_TOOL_POLICIES,
  _phase?: AgentPhase
): ToolAuthorizationDecision {
  const policy = policyMap[toolName];
  if (!policy) {
    return {
      decision: "DENY",
      policy: "P-TOOL-UNKNOWN",
      reason: `unknown tool: ${toolName}`,
      risk: "HIGH",
    };
  }

  // Scope verification
  if (!policy.allowedScopes.includes(scope)) {
    return {
      decision: "DENY",
      policy: "P-SCOPE-DENIED",
      reason: `scope '${scope}' not permitted for ${toolName}`,
      risk: "HIGH",
    };
  }

  // Provenance-based authorization check
  const isUntrusted = typeof provenance === "boolean"
    ? provenance
    : (provenance?.trust === "UNTRUSTED" || provenance?.trust === "MIXED");

  if (isUntrusted && policy.blockUntrustedProvenance) {
    return {
      decision: "DENY",
      policy: "P-PROVENANCE-BLOCK",
      reason: "privileged call traced to untrusted source",
      risk: policy.risk,
    };
  }

  return {
    decision: "ALLOW",
    policy: "P-TOOL-ALLOW",
    reason: `Tool call '${toolName}' authorized for scope '${scope}'`,
    risk: policy.risk,
  };
}
