import { NetworkRequest, EgressDecision } from "./network-types";
import { sessionSecretTracker } from "../classification";
import { combineClassification, combineTrust } from "../provenance";
import { detectTransformedSecret, TransformationDetectionResult } from "./transformations";
import { emitSecurityEvent } from "../security-events";

/**
 * Evaluates network requests for piggybacking and data exfiltration attempts.
 *
 * Enforces:
 * 1. Persistent session taint & monotonic classification:
 *    Even if the request claims PUBLIC, if the session carries SECRET taint,
 *    outbound network egress is blocked under P-EXFIL-001.
 * 2. Deterministic transformation detection:
 *    Detects exact, URL-encoded, Base64, and Hex representations of sensitive tokens.
 */
export function detectPiggybacking(
  parsedUrl: URL,
  request: NetworkRequest
): EgressDecision {
  const { provenance, dataClassification, method, body, sessionId = "session-default" } = request;

  // 1. Calculate effective classification and trust combining request and session state
  const sessionClass = request.sessionContext?.classification ?? "PUBLIC";
  const sessionTrust = request.sessionContext?.provenance.trust ?? provenance.trust;

  const effectiveClassification = combineClassification(dataClassification, sessionClass);
  const effectiveTrust = combineTrust(provenance.trust, sessionTrust);

  const effectiveSources = Array.from(
    new Set([...provenance.sources, ...(request.sessionContext?.provenance.sources ?? [])])
  );

  // 2. Aggregate known secrets from both isolated session context and fallback tracker
  const combinedSecrets = new Set<string>([
    ...sessionSecretTracker.getSecrets(),
    ...(request.sessionContext?.secrets ?? []),
  ]);

  // 3. Transformation & Token Leak Inspection
  const checkLeak = (
    payload: string | undefined | null,
    location: "QUERY" | "PATH" | "BODY" | "HEADER"
  ): EgressDecision | null => {
    if (!payload) return null;
    const result: TransformationDetectionResult = detectTransformedSecret(payload, combinedSecrets);
    if (result.detected) {
      let locationText = "request body";
      if (location === "QUERY") locationText = "URL query parameters";
      else if (location === "PATH") locationText = "URL path";
      else if (location === "HEADER") locationText = "request header";

      emitSecurityEvent({
        sessionId,
        agentId: request.agentId ?? "agent-main",
        type: "PIGGYBACK_TRANSFORMATION_DETECTED",
        decision: "DENY",
        policy: "P-EXFIL-001",
        reason: `Transformed secret detected (${result.transformationType}) in ${locationText}`,
        risk: "CRITICAL",
        destination: parsedUrl.hostname,
        details: {
          transformation: result.transformationType,
          location,
          matchedSnippet: result.matchedSecretSnippet,
        },
      });

      return {
        decision: "DENY",
        policy: "P-EXFIL-001",
        reason: `Network piggybacking detected: ${locationText} contain sensitive session data (${result.matchedSecretSnippet})`,
        risk: "CRITICAL",
        details: {
          destination: parsedUrl.hostname,
          transformation: result.transformationType,
          location,
        },
      };
    }
    return null;
  };

  // Inspect Query Parameters
  const queryLeak = checkLeak(parsedUrl.search, "QUERY");
  if (queryLeak) return queryLeak;

  // Inspect URL Pathname
  const pathLeak = checkLeak(parsedUrl.pathname, "PATH");
  if (pathLeak) return pathLeak;

  // Inspect Request Body
  if (body) {
    const bodyLeak = checkLeak(body, "BODY");
    if (bodyLeak) return bodyLeak;
  }

  // Inspect Request Headers
  if (request.headers) {
    for (const [, headerValue] of Object.entries(request.headers)) {
      const headerLeak = checkLeak(headerValue, "HEADER");
      if (headerLeak) return headerLeak;
    }
  }

  // 4. Classification-based boundary check: SECRET data must NEVER cross external network boundaries
  // Evaluates both request classification AND monotonic session classification
  if (effectiveClassification === "SECRET") {
    return {
      decision: "DENY",
      policy: "P-EXFIL-001",
      reason: "SECRET data cannot cross external network boundary",
      risk: "CRITICAL",
      details: {
        classification: effectiveClassification,
        requestClassification: dataClassification,
        sessionClassification: sessionClass,
        trust: effectiveTrust,
        sources: effectiveSources,
        destination: parsedUrl.origin,
      },
    };
  }

  // 5. Taint & Provenance + Classification check:
  // Data classified as CONFIDENTIAL or derived from UNTRUSTED/MIXED sources cannot be exfiltrated
  if (
    (effectiveTrust === "UNTRUSTED" || effectiveTrust === "MIXED") &&
    effectiveClassification === "CONFIDENTIAL"
  ) {
    return {
      decision: "DENY",
      policy: "P-EXFIL-001",
      reason: `Sensitive (${effectiveClassification}) data derived from ${effectiveTrust} provenance cannot be transmitted externally`,
      risk: "CRITICAL",
      details: {
        classification: effectiveClassification,
        trust: effectiveTrust,
        sources: effectiveSources,
        destination: parsedUrl.origin,
      },
    };
  }

  return {
    decision: "ALLOW",
    policy: "P-EXFIL-CLEAN",
    reason: "No network piggybacking or sensitive data exfiltration detected",
    risk: "LOW",
  };
}
