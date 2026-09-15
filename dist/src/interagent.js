"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.callSubagent = callSubagent;
const untrusted_1 = require("./untrusted");
async function callSubagent(query, runSubagent) {
    const rawResult = await runSubagent(query);
    const wrapped = (0, untrusted_1.wrapUntrusted)("subagent", rawResult);
    // The orchestrator reads wrapped.content but any tool call it decides to
    // make as a *result* of this still goes through ExecutionBoundary marked
    // derivedFromUntrusted: true — same path as fetched web content.
    return wrapped.content;
}
