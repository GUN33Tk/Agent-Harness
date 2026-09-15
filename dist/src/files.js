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
// The article's own bug, generalized: a check that runs on the string
// the agent typed is not the same as a check on where that string
// actually resolves to. realpath collapses BOTH ../ and symlinks —
// normpath alone only collapses the former.
const ALLOWED_ROOT = path.resolve(process.cwd(), "sandbox-files");
function resolveWithinRoot(requestedPath) {
    const candidate = path.resolve(ALLOWED_ROOT, requestedPath);
    // realpath requires the path to exist; for a read tool that's fine —
    // if it doesn't exist yet, resolve its directory instead so a legitimate
    // "create under this root" case doesn't get rejected for the wrong reason.
    let real;
    try {
        real = fs.realpathSync(candidate);
    }
    catch {
        real = candidate;
    }
    const realRoot = fs.realpathSync(ALLOWED_ROOT);
    if (real !== realRoot && !real.startsWith(realRoot + path.sep)) {
        return null; // escapes the allowed root — deny
    }
    return real;
}
