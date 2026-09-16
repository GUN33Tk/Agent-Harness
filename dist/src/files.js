"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveWithinRoot = resolveWithinRoot;
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
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
function resolveWithinRoot(requestedPath, customRoot = ALLOWED_ROOT) {
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
            }
            catch {
                // Keep single decoded
            }
        }
    }
    catch {
        return null;
    }
    // 3. UNC and device paths rejection
    if (decoded.startsWith("\\\\") ||
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
    let realRoot;
    try {
        realRoot = fs.realpathSync(customRoot);
    }
    catch {
        realRoot = path.resolve(customRoot);
    }
    // 6. Symlink resolution & realpath boundary check
    let realTarget;
    try {
        realTarget = fs.realpathSync(candidate);
    }
    catch {
        // If the target file doesn't exist yet, check its parent directory
        let current = path.dirname(candidate);
        let resolvedParent = null;
        while (current && current !== path.dirname(current)) {
            try {
                resolvedParent = fs.realpathSync(current);
                break;
            }
            catch {
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
