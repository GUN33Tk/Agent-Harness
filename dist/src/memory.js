"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.remember = remember;
exports.getMemory = getMemory;
exports.clearMemory = clearMemory;
const conversation = [];
const disk = new Map();
const harnessConfig = new Map();
function remember(kind, key, value, derivedFromUntrusted, classification = "PUBLIC") {
    if ((kind === "disk" || kind === "config") && derivedFromUntrusted) {
        return "DENIED: cannot persist a conclusion traced to untrusted input without review";
    }
    if ((kind === "disk" || kind === "config") && (classification === "SECRET" || classification === "CONFIDENTIAL")) {
        return `DENIED: cannot persist ${classification} data to persistent storage`;
    }
    ({
        chat: () => conversation.push(value),
        disk: () => disk.set(key, value),
        config: () => harnessConfig.set(key, value),
    }[kind]());
}
function getMemory(kind, key) {
    if (kind === "disk" && key)
        return disk.get(key);
    if (kind === "config" && key)
        return harnessConfig.get(key);
    if (kind === "chat")
        return conversation[conversation.length - 1];
    return undefined;
}
function clearMemory() {
    conversation.length = 0;
    disk.clear();
    harnessConfig.clear();
}
