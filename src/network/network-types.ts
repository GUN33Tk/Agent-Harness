import { Provenance, DataClassification } from "../provenance";

export type AgentPhase = "PLANNING" | "RESEARCH" | "EXECUTION" | "APPROVAL";

export interface EgressPolicy {
  allowedDomains: string[];
  allowedPorts: number[];
  allowedMethods: string[];
  allowRedirects: boolean;
  blockPrivateIPs: boolean;
  maxRequestBytes: number;
  maxResponseBytes: number;
  maxRequestsPerMinute: number;
  requireTls?: boolean;
  phase?: AgentPhase;
}

export interface NetworkRequest {
  agentId?: string;
  sessionId?: string;
  method: string;
  url: string;
  purpose?: string;
  provenance: Provenance;
  dataClassification: DataClassification;
  requestSize?: number;
  body?: string;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

export interface EgressDecision {
  decision: "ALLOW" | "DENY" | "REVIEW";
  policy: string;
  reason: string;
  risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  details?: Record<string, unknown>;
}

export interface NetworkResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  bytesReceived: number;
  finalUrl: string;
  redirectCount: number;
}
