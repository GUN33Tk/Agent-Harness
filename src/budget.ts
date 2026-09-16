export interface BudgetConfig {
  toolLimits?: Record<string, number>;
  maxNetworkRequests?: number;
  maxRequestsPerMinute?: number;
  maxRequestBytes?: number;
  maxResponseBytes?: number;
  maxTotalBytesSent?: number;
  maxTotalBytesReceived?: number;
  maxRuntimeSeconds?: number;
  maxAgentTurns?: number;
}

export class BudgetTracker {
  private spent = new Map<string, number>();
  private networkRequests = 0;
  private networkRequestTimestamps: number[] = [];
  private totalBytesSent = 0;
  private totalBytesReceived = 0;
  private agentTurns = 0;
  private startTime = Date.now();
  private circuitBroken = false;
  private circuitBreakReason = "";

  private toolLimits: Record<string, number>;
  private maxNetworkRequests: number;
  private maxRequestsPerMinute: number;
  private maxRequestBytes: number;
  private maxResponseBytes: number;
  private maxTotalBytesSent: number;
  private maxTotalBytesReceived: number;
  private maxRuntimeSeconds: number;
  private maxAgentTurns: number;

  constructor(limitsOrConfig: Record<string, number> | BudgetConfig = {}) {
    if ("toolLimits" in limitsOrConfig || "maxNetworkRequests" in limitsOrConfig) {
      const cfg = limitsOrConfig as BudgetConfig;
      this.toolLimits = cfg.toolLimits ?? {};
      this.maxNetworkRequests = cfg.maxNetworkRequests ?? 20;
      this.maxRequestsPerMinute = cfg.maxRequestsPerMinute ?? 10;
      this.maxRequestBytes = cfg.maxRequestBytes ?? 8192;
      this.maxResponseBytes = cfg.maxResponseBytes ?? 1024 * 1024;
      this.maxTotalBytesSent = cfg.maxTotalBytesSent ?? 500000;
      this.maxTotalBytesReceived = cfg.maxTotalBytesReceived ?? 5000000;
      this.maxRuntimeSeconds = cfg.maxRuntimeSeconds ?? 300;
      this.maxAgentTurns = cfg.maxAgentTurns ?? 25;
    } else {
      this.toolLimits = limitsOrConfig as Record<string, number>;
      this.maxNetworkRequests = this.toolLimits.fetch_url ?? 20;
      this.maxRequestsPerMinute = 10;
      this.maxRequestBytes = 8192;
      this.maxResponseBytes = 1024 * 1024;
      this.maxTotalBytesSent = 500000;
      this.maxTotalBytesReceived = 5000000;
      this.maxRuntimeSeconds = 300;
      this.maxAgentTurns = 25;
    }
  }

  spend(toolName: string): boolean {
    if (this.circuitBroken) {
      return false;
    }

    const used = (this.spent.get(toolName) ?? 0) + 1;
    this.spent.set(toolName, used);
    const limit = this.toolLimits[toolName] ?? Infinity;

    if (used > limit) {
      return false;
    }

    // If tool is a network tool, also verify general network request ceilings
    if (toolName === "fetch_url") {
      const netCheck = this.spendNetworkRequest(0, 0);
      if (!netCheck.ok) {
        return false;
      }
    }

    return true;
  }

  usage(toolName: string): number {
    return this.spent.get(toolName) ?? 0;
  }

  spendNetworkRequest(bytesSent: number = 0, bytesReceived: number = 0): { ok: boolean; reason?: string } {
    if (this.circuitBroken) {
      return { ok: false, reason: `Circuit breaker active: ${this.circuitBreakReason}` };
    }

    const now = Date.now();
    const oneMinAgo = now - 60000;
    this.networkRequestTimestamps = this.networkRequestTimestamps.filter((ts) => ts > oneMinAgo);

    if (this.networkRequestTimestamps.length >= this.maxRequestsPerMinute) {
      this.triggerCircuitBreaker(`Rate limit exceeded (${this.maxRequestsPerMinute} req/min)`);
      return { ok: false, reason: `Network rate limit exceeded (${this.maxRequestsPerMinute} req/min)` };
    }

    if (this.networkRequests >= this.maxNetworkRequests) {
      return { ok: false, reason: `Max network requests ceiling reached (${this.maxNetworkRequests})` };
    }

    if (bytesSent > this.maxRequestBytes) {
      return { ok: false, reason: `Request size ${bytesSent} exceeds max request bytes ${this.maxRequestBytes}` };
    }

    if (bytesReceived > this.maxResponseBytes) {
      return { ok: false, reason: `Response size ${bytesReceived} exceeds max response bytes ${this.maxResponseBytes}` };
    }

    this.networkRequests++;
    this.networkRequestTimestamps.push(now);
    this.totalBytesSent += bytesSent;
    this.totalBytesReceived += bytesReceived;

    return { ok: true };
  }

  recordTurn(): { ok: boolean; reason?: string } {
    if (this.circuitBroken) {
      return { ok: false, reason: `Circuit breaker active: ${this.circuitBreakReason}` };
    }

    this.agentTurns++;
    if (this.agentTurns > this.maxAgentTurns) {
      this.triggerCircuitBreaker(`Max agent turns (${this.maxAgentTurns}) exceeded`);
      return { ok: false, reason: `Max agent turns exceeded` };
    }

    const elapsedSeconds = (Date.now() - this.startTime) / 1000;
    if (elapsedSeconds > this.maxRuntimeSeconds) {
      this.triggerCircuitBreaker(`Execution timeout: ${elapsedSeconds.toFixed(1)}s > ${this.maxRuntimeSeconds}s`);
      return { ok: false, reason: `Execution runtime timeout exceeded` };
    }

    return { ok: true };
  }

  isCircuitBroken(): boolean {
    return this.circuitBroken;
  }

  getCircuitBreakReason(): string {
    return this.circuitBreakReason;
  }

  triggerCircuitBreaker(reason: string): void {
    this.circuitBroken = true;
    this.circuitBreakReason = reason;
  }

  reset(): void {
    this.spent.clear();
    this.networkRequests = 0;
    this.networkRequestTimestamps = [];
    this.totalBytesSent = 0;
    this.totalBytesReceived = 0;
    this.agentTurns = 0;
    this.circuitBroken = false;
    this.circuitBreakReason = "";
    this.startTime = Date.now();
  }
}
