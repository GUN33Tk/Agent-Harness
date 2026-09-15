"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveAndCheckHost = resolveAndCheckHost;
const dns_1 = require("dns");
const url_1 = require("url");
const PRIVATE_RANGES = ["127.", "10.", "169.254.", "192.168."];
// CHANGED (Step 4): allowlist is now passed in from config instead of a
// hardcoded constant, so tightening it doesn't require a code change.
async function resolveAndCheckHost(rawUrl, allowlist) {
    const url = new url_1.URL(rawUrl);
    if (!allowlist.has(url.hostname))
        return null;
    const { address } = await dns_1.promises.lookup(url.hostname);
    if (PRIVATE_RANGES.some((p) => address.startsWith(p)))
        return null;
    return url.toString();
}
