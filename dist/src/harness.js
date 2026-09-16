"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.runAgent = runAgent;
async function runAgent(boundary, nextCall, maxTurns = 25, signal) {
    const observations = [];
    let turns = 0;
    while (turns < maxTurns) {
        if (signal?.aborted) {
            observations.push("HALTED: session cancelled via kill switch signal");
            break;
        }
        const call = await nextCall(observations);
        if (call === null)
            break;
        const result = await boundary.run(call);
        observations.push(result.ok ? result.output ?? "" : `ERROR: ${result.error}`);
        turns++;
        if (!result.ok && result.error?.includes("HALTED")) {
            break; // Stop agent loop immediately if halted
        }
    }
    return observations;
}
