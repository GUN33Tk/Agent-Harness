"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanForInjection = scanForInjection;
const INJECTION_PATTERNS = [
    // Widened after actually testing this against real phrasing: the
    // original pattern only matched exactly "ignore previous instructions"
    // and missed the arguably more common "ignore all previous
    // instructions" (extra word breaks a rigid 3-token match). (all\s+)?
    // now makes that middle word optional instead of assuming a fixed shape.
    /ignore\s+(all\s+)?(previous|prior)\s+(instructions|constraints)/i,
    /system\s*:\s*/i,
    /override (settings|policy|permissions)/i,
    /before (answering|using any other tool)/i,
    /disregard (the|any) (above|previous)/i,
];
function scanForInjection(data) {
    for (const pattern of INJECTION_PATTERNS) {
        if (pattern.test(data.content))
            return { flagged: true, reason: `matched: ${pattern}` };
    }
    return { flagged: false };
}
