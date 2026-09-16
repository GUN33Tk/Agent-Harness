import * as fs from "fs";
import { Provenance } from "./provenance";

export interface SecurityEvent {
  id?: string;
  timestamp: string;
  sessionId: string;
  agentId: string;
  type:
    | "TOOL_REQUEST"
    | "POLICY_EVALUATION"
    | "SCHEMA_VALIDATION_FAILURE"
    | "NETWORK_REQUEST"
    | "REQUEST_BLOCKED"
    | "SSRF_DETECTION"
    | "NETWORK_EXFILTRATION_ATTEMPT"
    | "APPROVAL_REQUIRED"
    | "APPROVAL_GRANTED"
    | "APPROVAL_DENIED"
    | "KILL_SWITCH_TRIGGERED"
    | "BUDGET_EXCEEDED"
    | "MCP_MANIFEST_CHANGE"
    | "SANDBOX_TERMINATION"
    | "CONTENT_SCANNED";
  tool?: string;
  decision?: "ALLOW" | "DENY" | "REVIEW";
  risk?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  policy?: string;
  reason?: string;
  provenance?: Provenance;
  destination?: string;
  details?: Record<string, unknown>;
}

export type SecurityEventListener = (event: SecurityEvent) => void;

class SecurityEventBus {
  private listeners: Set<SecurityEventListener> = new Set();
  private logPath: string = process.env.HARNESS_LOG ?? "./harness-events.log";

  subscribe(listener: SecurityEventListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  emit(event: Omit<SecurityEvent, "timestamp" | "id"> & { timestamp?: string; id?: string }): SecurityEvent {
    const fullEvent: SecurityEvent = {
      id: event.id ?? `evt-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: event.timestamp ?? new Date().toISOString(),
      ...event,
    };

    // Notify registered in-memory listeners (for SSE, WebSocket, test assertions)
    for (const listener of this.listeners) {
      try {
        listener(fullEvent);
      } catch (err) {
        console.error("Error in security event listener:", err);
      }
    }

    // Durable append-only write
    try {
      const line = JSON.stringify(fullEvent) + "\n";
      fs.appendFileSync(this.logPath, line);
    } catch {
      // Best-effort durable logging
    }

    return fullEvent;
  }
}

export const securityEventBus = new SecurityEventBus();

/**
 * Convenience helper to log and emit a security event.
 */
export function emitSecurityEvent(
  event: Omit<SecurityEvent, "timestamp" | "id"> & { timestamp?: string; id?: string }
): SecurityEvent {
  return securityEventBus.emit(event);
}
