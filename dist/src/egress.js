"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveAndCheckHost = resolveAndCheckHost;
const url_1 = require("url");
const dns_1 = require("./network/dns");
const egress_policy_1 = require("./network/egress-policy");
/**
 * Backward-compatible host validator function.
 * Uses the robust DNS resolver and IP validation engine to verify
 * that the host is allowlisted and does not resolve to any private,
 * loopback, link-local, or IPv4-mapped private IP address.
 */
async function resolveAndCheckHost(rawUrl, allowlist) {
    let url;
    try {
        url = new url_1.URL(rawUrl);
    }
    catch {
        return null;
    }
    // Scheme must be http or https
    if (url.protocol !== "http:" && url.protocol !== "https:") {
        return null;
    }
    // Domain matching: check against allowlist using secure hostname-aware matching
    const isAllowed = Array.from(allowlist).some((allowed) => (0, egress_policy_1.matchesDomain)(url.hostname, allowed));
    if (!isAllowed) {
        return null;
    }
    // DNS resolution & multi-record IP validation
    const dnsResult = await (0, dns_1.resolveAndValidateHostname)(url.hostname);
    if (!dnsResult.allowed) {
        return null;
    }
    return url.toString();
}
