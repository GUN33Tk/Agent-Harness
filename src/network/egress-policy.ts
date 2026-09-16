import { EgressPolicy, EgressDecision, NetworkRequest, AgentPhase } from "./network-types";

export const DEFAULT_EGRESS_POLICY: EgressPolicy = {
  allowedDomains: ["example.com"],
  allowedPorts: [80, 443],
  allowedMethods: ["GET", "POST", "HEAD"],
  allowRedirects: true,
  blockPrivateIPs: true,
  maxRequestBytes: 8192,
  maxResponseBytes: 1024 * 1024, // 1MB
  maxRequestsPerMinute: 10,
  requireTls: false,
  phase: "RESEARCH",
};

/**
 * Checks if a hostname matches an allowed domain pattern securely.
 * Supports:
 * - Exact match: "example.com" matches "example.com"
 * - Wildcard prefix: "*.example.com" matches "api.example.com"
 * - Dot prefix: ".example.com" matches "api.example.com" and "example.com"
 *
 * Strict protection against bypasses:
 * - "evil-example.com" does NOT match "example.com"
 * - "example.com.attacker.com" does NOT match "example.com"
 */
export function matchesDomain(hostname: string, allowedPattern: string): boolean {
  const host = hostname.toLowerCase().trim();
  const pattern = allowedPattern.toLowerCase().trim();

  // Exact match
  if (host === pattern) {
    return true;
  }

  // Wildcard pattern: *.example.com
  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return host === base || host.endsWith("." + base);
  }

  // Dot prefix: .example.com
  if (pattern.startsWith(".")) {
    const base = pattern.slice(1);
    return host === base || host.endsWith("." + base);
  }

  // By default, allow standard subdomains of the allowed domain (e.g. api.example.com for example.com)
  // but strictly require a leading dot boundary to prevent evil-example.com
  if (host.endsWith("." + pattern)) {
    return true;
  }

  return false;
}

/**
 * Evaluates contextual and static egress policy for a given request.
 */
export function evaluateEgressPolicy(
  parsedUrl: URL,
  request: NetworkRequest,
  policy: EgressPolicy
): EgressDecision {
  const phase: AgentPhase = policy.phase ?? "RESEARCH";

  // Phase-based network policy (Phase 10)
  if (phase === "PLANNING" || phase === "APPROVAL") {
    return {
      decision: "DENY",
      policy: "P-PHASE-001",
      reason: `Network access is disabled during agent '${phase}' phase`,
      risk: "HIGH",
    };
  }

  if (phase === "RESEARCH" && request.method.toUpperCase() !== "GET" && request.method.toUpperCase() !== "HEAD") {
    return {
      decision: "DENY",
      policy: "P-PHASE-002",
      reason: `During 'RESEARCH' phase only read-only HTTP GET/HEAD requests are permitted (attempted: ${request.method})`,
      risk: "HIGH",
    };
  }

  // Scheme validation
  const protocol = parsedUrl.protocol.toLowerCase();
  if (protocol !== "http:" && protocol !== "https:") {
    return {
      decision: "DENY",
      policy: "P-SCHEME-001",
      reason: `Scheme '${protocol}' is not allowed; only http: and https: are permitted`,
      risk: "CRITICAL",
    };
  }

  if (policy.requireTls && protocol !== "https:") {
    return {
      decision: "DENY",
      policy: "P-SCHEME-002",
      reason: "Policy requires TLS (https:)",
      risk: "HIGH",
    };
  }

  // Method validation
  const method = request.method.toUpperCase();
  if (!policy.allowedMethods.includes(method)) {
    return {
      decision: "DENY",
      policy: "P-METHOD-001",
      reason: `HTTP method '${method}' is not in allowed methods: [${policy.allowedMethods.join(", ")}]`,
      risk: "MEDIUM",
    };
  }

  // Port validation
  let port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : (protocol === "https:" ? 443 : 80);
  if (isNaN(port) || !policy.allowedPorts.includes(port)) {
    return {
      decision: "DENY",
      policy: "P-PORT-001",
      reason: `Port ${port} is not in allowed ports: [${policy.allowedPorts.join(", ")}]`,
      risk: "HIGH",
    };
  }

  // Domain allowlist validation (Default-Deny)
  const hostname = parsedUrl.hostname;
  const isAllowedDomain = policy.allowedDomains.some((d) => matchesDomain(hostname, d));

  if (!isAllowedDomain) {
    return {
      decision: "DENY",
      policy: "P-DOMAIN-001",
      reason: `Host '${hostname}' is not in the allowed domains list: [${policy.allowedDomains.join(", ")}]`,
      risk: "HIGH",
    };
  }

  // Request size validation
  const bodySize = request.body ? Buffer.byteLength(request.body, "utf-8") : (request.requestSize ?? 0);
  if (bodySize > policy.maxRequestBytes) {
    return {
      decision: "DENY",
      policy: "P-SIZE-001",
      reason: `Request body size (${bodySize} bytes) exceeds maximum permitted limit (${policy.maxRequestBytes} bytes)`,
      risk: "MEDIUM",
    };
  }

  return {
    decision: "ALLOW",
    policy: "P-EGRESS-ALLOW",
    reason: "Request conforms to egress policy rules",
    risk: "LOW",
  };
}
