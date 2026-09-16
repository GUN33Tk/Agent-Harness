import { URL } from "url";
import { resolveAndValidateHostname } from "./network/dns";
import { matchesDomain } from "./network/egress-policy";

/**
 * Backward-compatible host validator function.
 * Uses the robust DNS resolver and IP validation engine to verify
 * that the host is allowlisted and does not resolve to any private,
 * loopback, link-local, or IPv4-mapped private IP address.
 */
export async function resolveAndCheckHost(
  rawUrl: string,
  allowlist: Set<string>
): Promise<string | null> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }

  // Scheme must be http or https
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return null;
  }

  // Domain matching: check against allowlist using secure hostname-aware matching
  const isAllowed = Array.from(allowlist).some((allowed) => matchesDomain(url.hostname, allowed));
  if (!isAllowed) {
    return null;
  }

  // DNS resolution & multi-record IP validation
  const dnsResult = await resolveAndValidateHostname(url.hostname);
  if (!dnsResult.allowed) {
    return null;
  }

  return url.toString();
}
