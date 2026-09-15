import { promises as dns } from "dns";
import { URL } from "url";

const PRIVATE_RANGES = ["127.", "10.", "169.254.", "192.168."];

// CHANGED (Step 4): allowlist is now passed in from config instead of a
// hardcoded constant, so tightening it doesn't require a code change.
export async function resolveAndCheckHost(rawUrl: string, allowlist: Set<string>): Promise<string | null> {
  const url = new URL(rawUrl);
  if (!allowlist.has(url.hostname)) return null;

  const { address } = await dns.lookup(url.hostname);
  if (PRIVATE_RANGES.some((p) => address.startsWith(p))) return null;

  return url.toString();
}
