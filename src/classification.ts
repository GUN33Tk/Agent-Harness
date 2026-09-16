import { DataClassification } from "./provenance";
import * as path from "path";

/**
 * Session-scoped sensitive content tracker.
 * Remembers exact sensitive strings, tokens, and content extracted from sensitive files
 * so the network piggybacking detector can inspect query params and body payloads deterministically.
 */
class SensitiveDataTracker {
  private secrets = new Set<string>();

  registerSecret(secret: string): void {
    const trimmed = secret.trim();
    if (trimmed.length >= 4) { // Only track meaningful tokens/strings, not single chars
      this.secrets.add(trimmed);
      // If the secret is multi-line, also track significant lines
      const lines = trimmed.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length >= 6);
      for (const line of lines) {
        this.secrets.add(line);
      }
    }
  }

  hasSecret(secret: string): boolean {
    return this.secrets.has(secret.trim());
  }

  containsAnySecret(payload: string): { leaked: boolean; matchedSecretSnippet?: string } {
    if (!payload || this.secrets.size === 0) {
      return { leaked: false };
    }

    for (const secret of this.secrets) {
      if (payload.includes(secret)) {
        return {
          leaked: true,
          matchedSecretSnippet: secret.length > 20 ? secret.slice(0, 20) + "..." : secret,
        };
      }

      // Also check URL-encoded version of secret
      const encoded = encodeURIComponent(secret);
      if (payload.includes(encoded)) {
        return {
          leaked: true,
          matchedSecretSnippet: secret.length > 20 ? secret.slice(0, 20) + "..." : secret,
        };
      }
    }

    return { leaked: false };
  }

  clear(): void {
    this.secrets.clear();
  }
}

export const sessionSecretTracker = new SensitiveDataTracker();

/**
 * Classifies data origin based on file path or resource identifier.
 */
export function classifyPath(filePath: string): DataClassification {
  const norm = filePath.replace(/\\/g, "/").toLowerCase();
  const base = path.basename(norm);

  if (
    base.includes("secret") ||
    base.includes("credential") ||
    base.includes("key") ||
    norm.includes("/secret") ||
    norm.includes("demo/secret.txt") ||
    norm.includes(".env")
  ) {
    return "SECRET";
  }

  if (
    base.includes("billing") ||
    base.includes("payroll") ||
    base.includes("customer-pii")
  ) {
    return "CONFIDENTIAL";
  }

  if (
    norm.includes("internal") ||
    norm.includes("sandbox-files")
  ) {
    return "INTERNAL";
  }

  return "PUBLIC";
}
