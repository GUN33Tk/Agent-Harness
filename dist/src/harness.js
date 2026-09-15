"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.runAgent = runAgent;
// CHANGED (Step 2): nextCall is now async, since a real model call is a
// network request. The loop's shape is otherwise identical to the
// original six-line version — it still just repeats "ask, execute,
// observe" until there's nothing left to do or the turn cap is hit.
async function runAgent(boundary, nextCall, maxTurns = 25) {
    const observations = [];
    let turns = 0;
    while (turns < maxTurns) {
        const call = await nextCall(observations);
        if (call === null)
            break;
        const result = await boundary.run(call);
        observations.push(result.ok ? result.output ?? "" : `ERROR: ${result.error}`);
        turns++;
    }
    return observations;
}
