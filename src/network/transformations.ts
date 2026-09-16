/**
 * Deterministic, bounded transformation detection for network piggybacking defense.
 * Detects:
 * 1. Exact secret strings
 * 2. URL-encoded secret strings
 * 3. Base64-encoded representations (standard, unpadded, and URL-encoded)
 * 4. Hex-encoded representations (lowercase and uppercase)
 *
 * Designed to be strictly CPU-bounded, memory-safe, and non-recursive.
 */

export interface TransformationDetectionResult {
  detected: boolean;
  transformationType?: "EXACT" | "URL_ENCODED" | "BASE64" | "HEX";
  matchedSecretSnippet?: string;
}

const MAX_SCAN_LENGTH = 1_000_000; // 1MB payload scan ceiling to prevent DoS
const MAX_CANDIDATE_TOKENS = 50;   // Max tokens to attempt decoding from payload

/**
 * Checks a payload for exact or transformed representations of known session secrets.
 */
export function detectTransformedSecret(
  rawPayload: string | undefined | null,
  secrets: Iterable<string>
): TransformationDetectionResult {
  if (!rawPayload) {
    return { detected: false };
  }

  // Bound the input size to guarantee CPU safety
  const payload = rawPayload.length > MAX_SCAN_LENGTH
    ? rawPayload.slice(0, MAX_SCAN_LENGTH)
    : rawPayload;

  const secretList: string[] = [];
  for (const s of secrets) {
    const trimmed = s.trim();
    if (trimmed.length >= 4) {
      secretList.push(trimmed);
    }
  }

  if (secretList.length === 0) {
    return { detected: false };
  }

  // 1. Direct Pattern Checking (Exact, URL-encoded, Base64, Hex of each secret)
  for (const secret of secretList) {
    const snippet = secret.length > 20 ? secret.slice(0, 20) + "..." : secret;

    // 1a. Exact substring match
    if (payload.includes(secret)) {
      return {
        detected: true,
        transformationType: "EXACT",
        matchedSecretSnippet: snippet,
      };
    }

    // 1b. URL-encoded match
    const urlEncoded = encodeURIComponent(secret);
    if (payload.includes(urlEncoded)) {
      return {
        detected: true,
        transformationType: "URL_ENCODED",
        matchedSecretSnippet: snippet,
      };
    }

    // 1c. Base64 representations
    try {
      const b64 = Buffer.from(secret, "utf-8").toString("base64");
      const b64Unpadded = b64.replace(/=+$/, "");
      const b64UrlEncoded = encodeURIComponent(b64);

      if (
        payload.includes(b64) ||
        payload.includes(b64Unpadded) ||
        payload.includes(b64UrlEncoded)
      ) {
        return {
          detected: true,
          transformationType: "BASE64",
          matchedSecretSnippet: snippet,
        };
      }
    } catch {
      // Safe fallback on any encoding failure
    }

    // 1d. Hex representations (both lower and upper case)
    try {
      const hexLower = Buffer.from(secret, "utf-8").toString("hex");
      const hexUpper = hexLower.toUpperCase();

      if (payload.includes(hexLower) || payload.includes(hexUpper)) {
        return {
          detected: true,
          transformationType: "HEX",
          matchedSecretSnippet: snippet,
        };
      }
    } catch {
      // Safe fallback
    }
  }

  // 2. Candidate Token Inspection: Bounded scanning for Base64 / Hex chunks in payload
  // This catches cases where the payload is wrapped inside a JSON or URL query as Base64/Hex
  try {
    // Look for Base64-like words of minimum length 8
    const b64Matches = payload.match(/[A-Za-z0-9+/]{8,}={0,2}/g);
    if (b64Matches) {
      const candidates = b64Matches.slice(0, MAX_CANDIDATE_TOKENS);
      for (const token of candidates) {
        try {
          // Verify valid Base64 length before decoding
          const decoded = Buffer.from(token, "base64").toString("utf-8");
          // Check if decoded contains any secret (and is printable ASCII/UTF-8)
          if (decoded && /^[\x20-\x7E\r\n\t]+$/.test(decoded)) {
            for (const secret of secretList) {
              if (decoded.includes(secret)) {
                return {
                  detected: true,
                  transformationType: "BASE64",
                  matchedSecretSnippet: secret.length > 20 ? secret.slice(0, 20) + "..." : secret,
                };
              }
            }
          }
        } catch {
          // Non-crashing on invalid Base64
        }
      }
    }

    // Look for Hex-like sequences of minimum 8 characters (4 bytes)
    const hexMatches = payload.match(/\b[0-9a-fA-F]{8,}\b/g);
    if (hexMatches) {
      const candidates = hexMatches.slice(0, MAX_CANDIDATE_TOKENS);
      for (const token of candidates) {
        try {
          if (token.length % 2 === 0) {
            const decoded = Buffer.from(token, "hex").toString("utf-8");
            if (decoded && /^[\x20-\x7E\r\n\t]+$/.test(decoded)) {
              for (const secret of secretList) {
                if (decoded.includes(secret)) {
                  return {
                    detected: true,
                    transformationType: "HEX",
                    matchedSecretSnippet: secret.length > 20 ? secret.slice(0, 20) + "..." : secret,
                  };
                }
              }
            }
          }
        } catch {
          // Non-crashing on invalid Hex
        }
      }
    }
  } catch {
    // Non-crashing guarantee
  }

  return { detected: false };
}
