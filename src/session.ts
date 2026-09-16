import {
  Provenance,
  DataClassification,
  createProvenance,
  combineClassification,
  combineProvenance,
} from "./provenance";
import { emitSecurityEvent } from "./security-events";

/**
 * Isolated session security context.
 * Maintains monotonic data classification, provenance trust lattice,
 * taint sources, and registered session secrets across sequential tool calls.
 */
export interface SessionSecurityContext {
  sessionId: string;
  provenance: Provenance;
  classification: DataClassification;
  taintSources: string[];
  secrets: Set<string>;
}

export class SessionManager {
  private sessions = new Map<string, SessionSecurityContext>();

  /**
   * Retrieves an existing session or initializes a clean one (PUBLIC + TRUSTED).
   */
  getSession(sessionId: string): SessionSecurityContext {
    let session = this.sessions.get(sessionId);
    if (!session) {
      session = {
        sessionId,
        provenance: createProvenance("TRUSTED", "PUBLIC", `session:${sessionId}`),
        classification: "PUBLIC",
        taintSources: [],
        secrets: new Set<string>(),
      };
      this.sessions.set(sessionId, session);
    }
    return session;
  }

  hasSession(sessionId: string): boolean {
    return this.sessions.has(sessionId);
  }

  /**
   * Monotonically updates session classification and trust level.
   * Security state can ONLY become more restrictive, never downgraded.
   */
  updateTaint(
    sessionId: string,
    incomingProvenance?: Provenance,
    incomingClassification?: DataClassification,
    source?: string,
    secretContent?: string
  ): SessionSecurityContext {
    const session = this.getSession(sessionId);
    const prevClass = session.classification;
    const prevTrust = session.provenance.trust;

    // 1. Monotonic classification upgrade
    if (incomingClassification) {
      session.classification = combineClassification(session.classification, incomingClassification);
    }

    // 2. Monotonic trust lattice combination
    if (incomingProvenance) {
      session.provenance = combineProvenance(session.provenance, incomingProvenance);
    }

    // 3. Track taint sources if sensitive or untrusted
    if (source && !session.taintSources.includes(source)) {
      const isSensitive =
        session.classification === "SECRET" ||
        session.classification === "CONFIDENTIAL" ||
        incomingClassification === "SECRET" ||
        incomingClassification === "CONFIDENTIAL";
      const isUntrusted =
        session.provenance.trust === "UNTRUSTED" ||
        session.provenance.trust === "MIXED" ||
        incomingProvenance?.trust === "UNTRUSTED" ||
        incomingProvenance?.trust === "MIXED";

      if (isSensitive || isUntrusted) {
        session.taintSources.push(source);
      }
    }

    // 4. Register sensitive tokens into session vault
    if (secretContent && (session.classification === "SECRET" || session.classification === "CONFIDENTIAL")) {
      const trimmed = secretContent.trim();
      if (trimmed.length >= 4) {
        session.secrets.add(trimmed);
        const lines = trimmed.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length >= 6);
        for (const line of lines) {
          session.secrets.add(line);
        }
      }
    }

    // 5. Emit structured security event if taint state transitioned to higher restriction
    if (session.classification !== prevClass || session.provenance.trust !== prevTrust) {
      emitSecurityEvent({
        sessionId,
        agentId: "system",
        type: "SESSION_TAINT_UPDATED",
        decision: "REVIEW",
        risk: session.classification === "SECRET" ? "CRITICAL" : "HIGH",
        reason: `Session taint updated: classification=${session.classification}, trust=${session.provenance.trust}`,
        provenance: session.provenance,
        details: {
          classification: session.classification,
          trust: session.provenance.trust,
          taintSources: [...session.taintSources],
          source: source ?? "unknown",
        },
      });
    }

    return session;
  }

  /**
   * Registers a known secret token directly into the session vault.
   */
  registerSecret(sessionId: string, secret: string): void {
    const session = this.getSession(sessionId);
    const trimmed = secret.trim();
    if (trimmed.length >= 4) {
      session.secrets.add(trimmed);
      const lines = trimmed.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length >= 6);
      for (const line of lines) {
        session.secrets.add(line);
      }
    }
  }

  clearSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  clearAll(): void {
    this.sessions.clear();
  }
}
