import * as fs from "fs";
import { emitSecurityEvent } from "./security-events";

export type KillSwitchState = "ACTIVE" | "HALTED";

export class KillSwitch {
  private abortController: AbortController = new AbortController();
  private state: KillSwitchState = "ACTIVE";

  constructor(private flagPath: string) {
    if (fs.existsSync(this.flagPath)) {
      this.state = "HALTED";
      this.abortController.abort("kill switch flag pre-exists on disk");
    }
  }

  get signal(): AbortSignal {
    return this.abortController.signal;
  }

  getState(): KillSwitchState {
    return this.isSet() ? "HALTED" : "ACTIVE";
  }

  isSet(): boolean {
    if (this.state === "HALTED") return true;
    if (fs.existsSync(this.flagPath)) {
      this.state = "HALTED";
      return true;
    }
    return false;
  }

  trigger(reason: string = "Manual kill switch operator intervention"): void {
    this.state = "HALTED";
    try {
      fs.writeFileSync(this.flagPath, "halted");
    } catch {
      // Best-effort flag write
    }

    // Abort in-flight operations (network, child processes, model calls)
    this.abortController.abort(reason);

    emitSecurityEvent({
      sessionId: "global",
      agentId: "operator",
      type: "KILL_SWITCH_TRIGGERED",
      decision: "DENY",
      policy: "P-KILL-SWITCH",
      reason: `Kill switch triggered: ${reason}`,
      risk: "CRITICAL",
    });
  }

  reset(): void {
    this.state = "ACTIVE";
    this.abortController = new AbortController();
    if (fs.existsSync(this.flagPath)) {
      try {
        fs.unlinkSync(this.flagPath);
      } catch {
        // Best-effort cleanup
      }
    }
  }
}
