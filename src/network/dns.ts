import { promises as dnsPromises } from "dns";
import { validateIpAddress, isLiteralIp } from "./ip-utils";

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

export interface DnsValidationResult {
  allowed: boolean;
  addresses: ResolvedAddress[];
  pinnedIp?: string;
  pinnedFamily?: 4 | 6;
  reason?: string;
}

export type DnsResolverFn = (hostname: string) => Promise<ResolvedAddress[]>;

/**
 * Default system DNS resolver: resolves all IPv4 (A) and IPv6 (AAAA) records.
 */
export async function systemDnsResolver(hostname: string): Promise<ResolvedAddress[]> {
  try {
    const results = await dnsPromises.lookup(hostname, { all: true });
    return results.map((r) => ({
      address: r.address,
      family: (r.family === 6 ? 6 : 4) as 4 | 6,
    }));
  } catch (err) {
    throw new Error(`DNS resolution failed for '${hostname}': ${String(err)}`);
  }
}

/**
 * Resolves a hostname, validates EVERY returned IP against blocked/private subnets,
 * and chooses a pinned IP for the connection.
 *
 * Defense against DNS rebinding & TOCTOU:
 * 1. Resolves all addresses for the hostname upfront.
 * 2. Validates every single address (if ANY resolved address is private, the host is rejected).
 * 3. Selects a pinned IP address.
 * 4. The EgressGateway then uses a custom agent lookup pinned to this exact IP,
 *    preventing the HTTP client from performing a second unvalidated DNS query.
 */
export async function resolveAndValidateHostname(
  hostname: string,
  resolver: DnsResolverFn = systemDnsResolver,
  blockPrivateIPs: boolean = true
): Promise<DnsValidationResult> {
  const cleanHost = hostname.trim().toLowerCase();

  // Localhost names
  if (blockPrivateIPs && (
    cleanHost === "localhost" ||
    cleanHost.endsWith(".localhost") ||
    cleanHost === "local" ||
    cleanHost.endsWith(".local") ||
    cleanHost.endsWith(".internal")
  )) {
    return {
      allowed: false,
      addresses: [],
      reason: `Restricted hostname: '${hostname}' (local/internal name)`,
    };
  }

  // If the host is already a literal IP address, validate it directly
  if (isLiteralIp(cleanHost)) {
    if (blockPrivateIPs) {
      const check = validateIpAddress(cleanHost);
      if (check.blocked) {
        return {
          allowed: false,
          addresses: [],
          reason: `Host literal IP blocked: ${check.reason}`,
        };
      }
      const isV6 = cleanHost.includes(":");
      return {
        allowed: true,
        addresses: [{ address: check.normalized ?? cleanHost, family: isV6 ? 6 : 4 }],
        pinnedIp: check.normalized ?? cleanHost,
        pinnedFamily: isV6 ? 6 : 4,
      };
    } else {
      const isV6 = cleanHost.includes(":");
      return {
        allowed: true,
        addresses: [{ address: cleanHost, family: isV6 ? 6 : 4 }],
        pinnedIp: cleanHost,
        pinnedFamily: isV6 ? 6 : 4,
      };
    }
  }

  // Resolve hostname
  let addresses: ResolvedAddress[];
  try {
    addresses = await resolver(cleanHost);
  } catch (err) {
    return {
      allowed: false,
      addresses: [],
      reason: `DNS resolution error: ${String(err)}`,
    };
  }

  if (!addresses || addresses.length === 0) {
    return {
      allowed: false,
      addresses: [],
      reason: `DNS returned no addresses for '${hostname}'`,
    };
  }

  if (blockPrivateIPs) {
    for (const record of addresses) {
      const check = validateIpAddress(record.address);
      if (check.blocked) {
        return {
          allowed: false,
          addresses,
          reason: `DNS for '${hostname}' returned blocked address ${record.address}: ${check.reason}`,
        };
      }
    }
  }

  // Choose the first validated address as the pinned address
  const pinned = addresses[0];
  return {
    allowed: true,
    addresses,
    pinnedIp: pinned.address,
    pinnedFamily: pinned.family,
  };
}
