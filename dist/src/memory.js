"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.remember = remember;
const conversation = [];
const disk = new Map();
const harnessConfig = new Map();
function remember(kind, key, value, derivedFromUntrusted) {
    if ((kind === "disk" || kind === "config") && derivedFromUntrusted) {
        return "DENIED: cannot persist a conclusion traced to untrusted input without review";
    }
    ({
        chat: () => conversation.push(value),
        disk: () => disk.set(key, value),
        config: () => harnessConfig.set(key, value),
    }[kind]());
}
