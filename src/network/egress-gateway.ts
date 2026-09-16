import * as http from "http";
import * as https from "https";
import { URL } from "url";
import {
  EgressPolicy,
  EgressDecision,
  NetworkRequest,
  NetworkResponse,
} from "./network-types";
import { DEFAULT_EGRESS_POLICY, evaluateEgressPolicy } from "./egress-policy";
import { resolveAndValidateHostname, DnsResolverFn, systemDnsResolver } from "./dns";
import { detectPiggybacking } from "./piggybacking-detector";
import { emitSecurityEvent } from "../security-events";

export class EgressGateway {
  private policy: EgressPolicy;
  private requestTimestamps: number[] = [];
  private totalBytesSent = 0;
  private totalBytesReceived = 0;
  private dnsResolver: DnsResolverFn;

  constructor(policy: Partial<EgressPolicy> = {}, dnsResolver: DnsResolverFn = systemDnsResolver) {
    this.policy = { ...DEFAULT_EGRESS_POLICY, ...policy };
    this.dnsResolver = dnsResolver;
  }

  getPolicy(): EgressPolicy {
    return { ...this.policy };
  }

  setPolicy(policy: Partial<EgressPolicy>): void {
    this.policy = { ...this.policy, ...policy };
  }

  /**
   * Main entry point for all agent network operations.
   */
  async request(req: NetworkRequest): Promise<NetworkResponse> {
    const agentId = req.agentId ?? "agent-main";
    const sessionId = req.sessionId ?? "session-default";

    emitSecurityEvent({
      sessionId,
      agentId,
      type: "NETWORK_REQUEST",
      decision: "REVIEW",
      destination: req.url,
      provenance: req.provenance,
      details: { method: req.method, purpose: req.purpose },
    });

    let currentUrl = req.url;
    let redirectCount = 0;
    const maxRedirects = 5;

    while (true) {
      // 1. URL syntax & scheme validation
      let parsedUrl: URL;
      try {
        parsedUrl = new URL(currentUrl);
      } catch (err) {
        emitSecurityEvent({
          sessionId,
          agentId,
          type: "REQUEST_BLOCKED",
          decision: "DENY",
          policy: "P-MALFORMED-URL",
          reason: `Invalid URL format: ${String(err)}`,
          risk: "HIGH",
          destination: currentUrl,
        });
        throw new Error(`DENIED: Invalid URL '${currentUrl}'`);
      }

      // 2. Evaluate general egress policy (Scheme, Phase, Domain, Port, Method, Size)
      const policyDecision = evaluateEgressPolicy(parsedUrl, req, this.policy);
      if (policyDecision.decision !== "ALLOW") {
        emitSecurityEvent({
          sessionId,
          agentId,
          type: "REQUEST_BLOCKED",
          decision: "DENY",
          policy: policyDecision.policy,
          reason: policyDecision.reason,
          risk: policyDecision.risk,
          destination: parsedUrl.origin,
          provenance: req.provenance,
        });
        throw new Error(`DENIED: [${policyDecision.policy}] ${policyDecision.reason}`);
      }

      // 3. DNS resolution & Robust SSRF validation (Every IP checked; pinned to prevent rebinding)
      const dnsResult = await resolveAndValidateHostname(
        parsedUrl.hostname,
        this.dnsResolver,
        this.policy.blockPrivateIPs
      );
      if (!dnsResult.allowed || !dnsResult.pinnedIp) {
        emitSecurityEvent({
          sessionId,
          agentId,
          type: "SSRF_DETECTION",
          decision: "DENY",
          policy: "P-SSRF-001",
          reason: dnsResult.reason ?? "DNS resolution resolved to blocked or private range",
          risk: "CRITICAL",
          destination: parsedUrl.hostname,
          details: { addresses: dnsResult.addresses },
        });
        throw new Error(`DENIED: host not allowlisted or resolves to a private range (${dnsResult.reason})`);
      }

      // 4. Network Piggybacking & Exfiltration Defense (P-EXFIL-001)
      const piggybackDecision = detectPiggybacking(parsedUrl, req);
      if (piggybackDecision.decision !== "ALLOW") {
        emitSecurityEvent({
          sessionId,
          agentId,
          type: "NETWORK_EXFILTRATION_ATTEMPT",
          decision: "DENY",
          policy: piggybackDecision.policy,
          reason: piggybackDecision.reason,
          risk: piggybackDecision.risk,
          destination: parsedUrl.origin,
          provenance: req.provenance,
          details: piggybackDecision.details,
        });
        throw new Error(`DENIED: [${piggybackDecision.policy}] ${piggybackDecision.reason}`);
      }

      // 5. Rate limit & Budget check (Sliding 1-minute window)
      this.enforceRateLimit(sessionId, agentId);

      // 6. Execute request using IP-pinned HTTP/HTTPS Agent (Defeating DNS Rebinding / TOCTOU)
      const response = await this.executePinnedRequest(
        parsedUrl,
        req,
        dnsResult.pinnedIp,
        dnsResult.pinnedFamily ?? 4
      );

      // 7. Controlled Redirect Handling (Phase 4)
      const isRedirect = [301, 302, 303, 307, 308].includes(response.status);
      if (isRedirect && response.headers.location) {
        if (!this.policy.allowRedirects) {
          throw new Error(`DENIED: Redirects are disabled by egress policy`);
        }

        redirectCount++;
        if (redirectCount > maxRedirects) {
          throw new Error(`DENIED: Maximum redirect hops (${maxRedirects}) exceeded`);
        }

        // Resolve redirect location against current URL
        const nextUrl = new URL(response.headers.location, parsedUrl).toString();
        emitSecurityEvent({
          sessionId,
          agentId,
          type: "POLICY_EVALUATION",
          decision: "REVIEW",
          policy: "P-REDIRECT-EVAL",
          reason: `Evaluating redirect hop #${redirectCount} to ${nextUrl}`,
          destination: nextUrl,
        });

        currentUrl = nextUrl;
        continue; // Loop back and re-run all validation steps for the redirect destination
      }

      // Return the completed response
      return {
        ...response,
        finalUrl: currentUrl,
        redirectCount,
      };
    }
  }

  private enforceRateLimit(sessionId: string, agentId: string): void {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    this.requestTimestamps = this.requestTimestamps.filter((ts) => ts > oneMinuteAgo);

    if (this.requestTimestamps.length >= this.policy.maxRequestsPerMinute) {
      emitSecurityEvent({
        sessionId,
        agentId,
        type: "BUDGET_EXCEEDED",
        decision: "DENY",
        policy: "P-RATE-001",
        reason: `Rate limit of ${this.policy.maxRequestsPerMinute} requests/minute exceeded`,
        risk: "MEDIUM",
      });
      throw new Error(`DENIED: Network rate limit exceeded (${this.policy.maxRequestsPerMinute} req/min)`);
    }

    this.requestTimestamps.push(now);
  }

  /**
   * Executes HTTP request with TCP connection pinned strictly to the pre-validated IP address.
   * This guarantees that no subsequent DNS query can substitute a private IP (DNS rebinding / TOCTOU).
   */
  private executePinnedRequest(
    parsedUrl: URL,
    req: NetworkRequest,
    pinnedIp: string,
    family: 4 | 6
  ): Promise<Omit<NetworkResponse, "finalUrl" | "redirectCount">> {
    return new Promise((resolve, reject) => {
      const isHttps = parsedUrl.protocol === "https:";
      const port = parsedUrl.port
        ? parseInt(parsedUrl.port, 10)
        : (isHttps ? 443 : 80);

      // Custom DNS lookup that bypasses system DNS and supplies the validated IP
      const customLookup = (
        _hostname: string,
        options: any,
        callback: any
      ) => {
        let cb = callback;
        let opts = options;
        if (typeof opts === "function") {
          cb = opts;
          opts = {};
        }

        if (opts && opts.all) {
          cb(null, [{ address: pinnedIp, family }]);
        } else {
          cb(null, pinnedIp, family);
        }
      };

      const agent = isHttps
        ? new https.Agent({ lookup: customLookup, keepAlive: false })
        : new http.Agent({ lookup: customLookup, keepAlive: false });

      const requestHeaders: Record<string, string> = {
        Host: parsedUrl.host,
        "User-Agent": "Agent-Harness-Security-Gateway/1.0",
        Accept: "*/*",
        ...req.headers,
      };

      const requestOptions: http.RequestOptions = {
        protocol: parsedUrl.protocol,
        hostname: parsedUrl.hostname,
        port,
        method: req.method.toUpperCase(),
        path: `${parsedUrl.pathname}${parsedUrl.search}`,
        headers: requestHeaders,
        agent,
        signal: req.signal,
        timeout: 10000,
      };

      const transport = isHttps ? https : http;
      const clientReq = transport.request(requestOptions, (res) => {
        const chunks: Buffer[] = [];
        let bytesReceived = 0;

        res.on("data", (chunk: Buffer) => {
          bytesReceived += chunk.length;
          this.totalBytesReceived += chunk.length;

          if (bytesReceived > this.policy.maxResponseBytes) {
            clientReq.destroy();
            reject(
              new Error(
                `DENIED: Response size exceeded maximum limit of ${this.policy.maxResponseBytes} bytes`
              )
            );
            return;
          }

          chunks.push(chunk);
        });

        res.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf-8");
          const headers: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (typeof v === "string") headers[k.toLowerCase()] = v;
            else if (Array.isArray(v)) headers[k.toLowerCase()] = v.join(", ");
          }

          resolve({
            status: res.statusCode ?? 0,
            statusText: res.statusMessage ?? "",
            headers,
            body,
            bytesReceived,
          });
        });
      });

      clientReq.on("error", (err) => {
        reject(err);
      });

      clientReq.on("timeout", () => {
        clientReq.destroy();
        reject(new Error("Network request timed out"));
      });

      if (req.body) {
        clientReq.write(req.body);
        this.totalBytesSent += Buffer.byteLength(req.body);
      }

      clientReq.end();
    });
  }
}
