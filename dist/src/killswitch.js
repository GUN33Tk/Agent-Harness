"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.KillSwitch = void 0;
const fs = __importStar(require("fs"));
const security_events_1 = require("./security-events");
class KillSwitch {
    constructor(flagPath) {
        this.flagPath = flagPath;
        this.abortController = new AbortController();
        this.state = "ACTIVE";
        if (fs.existsSync(this.flagPath)) {
            this.state = "HALTED";
            this.abortController.abort("kill switch flag pre-exists on disk");
        }
    }
    get signal() {
        return this.abortController.signal;
    }
    getState() {
        return this.isSet() ? "HALTED" : "ACTIVE";
    }
    isSet() {
        if (this.state === "HALTED")
            return true;
        if (fs.existsSync(this.flagPath)) {
            this.state = "HALTED";
            return true;
        }
        return false;
    }
    trigger(reason = "Manual kill switch operator intervention") {
        this.state = "HALTED";
        try {
            fs.writeFileSync(this.flagPath, "halted");
        }
        catch {
            // Best-effort flag write
        }
        // Abort in-flight operations (network, child processes, model calls)
        this.abortController.abort(reason);
        (0, security_events_1.emitSecurityEvent)({
            sessionId: "global",
            agentId: "operator",
            type: "KILL_SWITCH_TRIGGERED",
            decision: "DENY",
            policy: "P-KILL-SWITCH",
            reason: `Kill switch triggered: ${reason}`,
            risk: "CRITICAL",
        });
    }
    reset() {
        this.state = "ACTIVE";
        this.abortController = new AbortController();
        if (fs.existsSync(this.flagPath)) {
            try {
                fs.unlinkSync(this.flagPath);
            }
            catch {
                // Best-effort cleanup
            }
        }
    }
}
exports.KillSwitch = KillSwitch;
