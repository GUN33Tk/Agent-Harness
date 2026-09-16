import * as ipaddr from "ipaddr.js";

/**
 * Explicit list of disallowed IPv4 CIDR blocks according to RFC standards:
 * - 0.0.0.0/8       - "This host on this network" / Current network (RFC 1122)
 * - 10.0.0.0/8      - Private-Use (RFC 1918)
 * - 100.64.0.0/10   - Shared Address Space / Carrier-Grade NAT (RFC 6598)
 * - 127.0.0.0/8     - Loopback (RFC 1122)
 * - 169.254.0.0/16  - Link Local (RFC 3927)
 * - 172.16.0.0/12   - Private-Use (RFC 1918)
 * - 192.0.0.0/24    - IETF Protocol Assignments (RFC 6890)
 * - 192.0.2.0/24    - TEST-NET-1 (RFC 5737)
 * - 192.168.0.0/16  - Private-Use (RFC 1918)
 * - 198.18.0.0/15   - Benchmarking (RFC 2544)
 * - 198.51.100.0/24 - TEST-NET-2 (RFC 5737)
 * - 203.0.113.0/24  - TEST-NET-3 (RFC 5737)
 * - 224.0.0.0/4     - Multicast (RFC 5771)
 * - 240.0.0.0/4     - Reserved for Future Use (RFC 1112)
 * - 255.255.255.255/32 - Limited Broadcast (RFC 919)
 */
const IPV4_BLOCKED_CIDRS: Array<[ipaddr.IPv4, number]> = [
  ipaddr.parseCIDR("0.0.0.0/8") as [ipaddr.IPv4, number],
  ipaddr.parseCIDR("10.0.0.0/8") as [ipaddr.IPv4, number],
  ipaddr.parseCIDR("100.64.0.0/10") as [ipaddr.IPv4, number],
  ipaddr.parseCIDR("127.0.0.0/8") as [ipaddr.IPv4, number],
  ipaddr.parseCIDR("169.254.0.0/16") as [ipaddr.IPv4, number],
  ipaddr.parseCIDR("172.16.0.0/12") as [ipaddr.IPv4, number],
  ipaddr.parseCIDR("192.0.0.0/24") as [ipaddr.IPv4, number],
  ipaddr.parseCIDR("192.0.2.0/24") as [ipaddr.IPv4, number],
  ipaddr.parseCIDR("192.168.0.0/16") as [ipaddr.IPv4, number],
  ipaddr.parseCIDR("198.18.0.0/15") as [ipaddr.IPv4, number],
  ipaddr.parseCIDR("198.51.100.0/24") as [ipaddr.IPv4, number],
  ipaddr.parseCIDR("203.0.113.0/24") as [ipaddr.IPv4, number],
  ipaddr.parseCIDR("224.0.0.0/4") as [ipaddr.IPv4, number],
  ipaddr.parseCIDR("240.0.0.0/4") as [ipaddr.IPv4, number],
  ipaddr.parseCIDR("255.255.255.255/32") as [ipaddr.IPv4, number],
];

/**
 * Explicit list of disallowed IPv6 CIDR blocks:
 * - ::/128          - Unspecified
 * - ::1/128         - Loopback
 * - fc00::/7        - Unique Local Address (ULA, RFC 4193)
 * - fe80::/10       - Link-Local Unicast (RFC 4291)
 * - ff00::/8        - Multicast (RFC 4291)
 * - 2001:db8::/32   - Documentation (RFC 3849)
 * - 100::/64        - Discard-Only Prefix (RFC 6666)
 * - 2002::/16       - 6to4 relay anycast (RFC 7526)
 */
const IPV6_BLOCKED_CIDRS: Array<[ipaddr.IPv6, number]> = [
  ipaddr.parseCIDR("::/128") as [ipaddr.IPv6, number],
  ipaddr.parseCIDR("::1/128") as [ipaddr.IPv6, number],
  ipaddr.parseCIDR("fc00::/7") as [ipaddr.IPv6, number],
  ipaddr.parseCIDR("fe80::/10") as [ipaddr.IPv6, number],
  ipaddr.parseCIDR("ff00::/8") as [ipaddr.IPv6, number],
  ipaddr.parseCIDR("2001:db8::/32") as [ipaddr.IPv6, number],
  ipaddr.parseCIDR("100::/64") as [ipaddr.IPv6, number],
  ipaddr.parseCIDR("2002::/16") as [ipaddr.IPv6, number],
];

export interface IpValidationResult {
  blocked: boolean;
  reason?: string;
  normalized?: string;
  isIpv4Mapped?: boolean;
}

/**
 * Parses and strictly validates whether an IP address is a private, loopback,
 * link-local, multicast, reserved, or IPv4-mapped private IP.
 */
export function validateIpAddress(rawIp: string): IpValidationResult {
  const trimmed = rawIp.trim();
  if (!trimmed) {
    return { blocked: true, reason: "empty IP address" };
  }

  // Handle IPv6 bracket format e.g. [::1]
  const cleanIp = trimmed.startsWith("[") && trimmed.endsWith("]")
    ? trimmed.slice(1, -1)
    : trimmed;

  if (!ipaddr.isValid(cleanIp)) {
    return { blocked: true, reason: `malformed IP address: ${rawIp}` };
  }

  let parsed: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    parsed = ipaddr.parse(cleanIp);
  } catch (err) {
    return { blocked: true, reason: `failed to parse IP: ${String(err)}` };
  }

  // Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 or ::ffff:10.0.0.1)
  if (parsed.kind() === "ipv6") {
    const ipv6 = parsed as ipaddr.IPv6;
    if (ipv6.isIPv4MappedAddress()) {
      const mappedIpv4 = ipv6.toIPv4Address();
      const v4Result = checkIpv4Address(mappedIpv4);
      if (v4Result.blocked) {
        return {
          blocked: true,
          reason: `IPv4-mapped IPv6 address maps to blocked range: ${v4Result.reason}`,
          normalized: cleanIp,
          isIpv4Mapped: true,
        };
      }
      return { blocked: false, normalized: cleanIp, isIpv4Mapped: true };
    }

    // Standard IPv6 check
    return checkIpv6Address(ipv6);
  }

  // Standard IPv4 check
  return checkIpv4Address(parsed as ipaddr.IPv4);
}

function checkIpv4Address(ipv4: ipaddr.IPv4): IpValidationResult {
  const normalized = ipv4.toString();
  const range = ipv4.range();

  // Check built-in range flags from ipaddr.js
  if (
    range === "loopback" ||
    range === "private" ||
    range === "linkLocal" ||
    range === "unspecified" ||
    range === "broadcast" ||
    range === "multicast" ||
    range === "carrierGradeNat" ||
    range === "reserved"
  ) {
    return {
      blocked: true,
      reason: `IPv4 address ${normalized} is in restricted range: ${range}`,
      normalized,
    };
  }

  // Explicit CIDR check for complete coverage
  for (const cidr of IPV4_BLOCKED_CIDRS) {
    if (ipv4.match(cidr)) {
      return {
        blocked: true,
        reason: `IPv4 address ${normalized} matches blocked subnet ${cidr[0].toString()}/${cidr[1]}`,
        normalized,
      };
    }
  }

  return { blocked: false, normalized };
}

function checkIpv6Address(ipv6: ipaddr.IPv6): IpValidationResult {
  const normalized = ipv6.toNormalizedString();
  const range = ipv6.range();

  if (
    range === "loopback" ||
    range === "uniqueLocal" ||
    range === "linkLocal" ||
    range === "unspecified" ||
    range === "multicast" ||
    range === "reserved"
  ) {
    return {
      blocked: true,
      reason: `IPv6 address ${normalized} is in restricted range: ${range}`,
      normalized,
    };
  }

  for (const cidr of IPV6_BLOCKED_CIDRS) {
    if (ipv6.match(cidr)) {
      return {
        blocked: true,
        reason: `IPv6 address ${normalized} matches blocked subnet ${cidr[0].toString()}/${cidr[1]}`,
        normalized,
      };
    }
  }

  return { blocked: false, normalized };
}

/**
 * Checks if a string is a literal IP address (IPv4 or IPv6).
 */
export function isLiteralIp(host: string): boolean {
  const clean = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  return ipaddr.isValid(clean);
}
