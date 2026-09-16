import * as path from "path";
import * as fs from "fs";

const ALLOWED_ROOT = path.resolve(process.cwd(), "sandbox-files");

/**
 * Hardened path resolver protecting against:
 * - Standard path traversal (../, ..\)
 * - Redundant dot slash sequences (....//, .././)
 * - URL-encoded path traversal (%2e%2e%2f, %252e)
 * - Null-byte injection (\0)
 * - UNC network paths (\\server\share, //server/share)
 * - Absolute path escapes (/etc/passwd, C:\...)
 * - Symlink escapes pointing outside ALLOWED_ROOT
 */
export function resolveWithinRoot(
  requestedPath: string,
  customRoot: string = ALLOWED_ROOT
): string | null {
  if (!requestedPath || typeof requestedPath !== "string") {
    return null;
  }

  // 1. Null byte check
  if (requestedPath.includes("\0")) {
    return null;
  }

  // 2. Decode URL-encoded traversal sequences
  let decoded = requestedPath;
  try {
    decoded = decodeURIComponent(requestedPath);
    // Double decoding check to catch nested encoding like %252e
    if (decoded.includes("%")) {
      try {
        decoded = decodeURIComponent(decoded);
      } catch {
        // Keep single decoded
      }
    }
  } catch {
    return null;
  }

  // 3. UNC and device paths rejection
  if (
    decoded.startsWith("\\\\") ||
    decoded.startsWith("//") ||
    /^[a-zA-Z]:[/\\]/.test(decoded) // Explicit drive letter like C:\
  ) {
    // If an absolute path is requested, only allow if it is already explicitly within customRoot
    const normalizedRoot = path.resolve(customRoot);
    const resolvedAbsolute = path.resolve(decoded);
    if (!resolvedAbsolute.startsWith(normalizedRoot + path.sep) && resolvedAbsolute !== normalizedRoot) {
      return null;
    }
  }

  // 4. Resolve candidate path against the root
  const candidate = path.resolve(customRoot, decoded);

  // 5. Ensure real root exists and resolve its canonical real path
  let realRoot: string;
  try {
    realRoot = fs.realpathSync(customRoot);
  } catch {
    realRoot = path.resolve(customRoot);
  }

  // 6. Symlink resolution & realpath boundary check
  let realTarget: string;
  try {
    realTarget = fs.realpathSync(candidate);
  } catch {
    // If the target file doesn't exist yet, check its parent directory
    let current = path.dirname(candidate);
    let resolvedParent: string | null = null;
    while (current && current !== path.dirname(current)) {
      try {
        resolvedParent = fs.realpathSync(current);
        break;
      } catch {
        current = path.dirname(current);
      }
    }

    if (resolvedParent) {
      if (resolvedParent !== realRoot && !resolvedParent.startsWith(realRoot + path.sep)) {
        return null;
      }
    }
    realTarget = candidate;
  }

  // 7. Verify realTarget is strictly inside realRoot
  if (realTarget !== realRoot && !realTarget.startsWith(realRoot + path.sep)) {
    return null; // Escapes allowed root
  }

  return realTarget;
}
