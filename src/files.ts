import * as path from "path";
import * as fs from "fs";

// The article's own bug, generalized: a check that runs on the string
// the agent typed is not the same as a check on where that string
// actually resolves to. realpath collapses BOTH ../ and symlinks —
// normpath alone only collapses the former.
const ALLOWED_ROOT = path.resolve(process.cwd(), "sandbox-files");

export function resolveWithinRoot(requestedPath: string): string | null {
  const candidate = path.resolve(ALLOWED_ROOT, requestedPath);

  // realpath requires the path to exist; for a read tool that's fine —
  // if it doesn't exist yet, resolve its directory instead so a legitimate
  // "create under this root" case doesn't get rejected for the wrong reason.
  let real: string;
  try {
    real = fs.realpathSync(candidate);
  } catch {
    real = candidate;
  }

  const realRoot = fs.realpathSync(ALLOWED_ROOT);
  if (real !== realRoot && !real.startsWith(realRoot + path.sep)) {
    return null; // escapes the allowed root — deny
  }
  return real;
}
