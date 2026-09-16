"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.wrapUntrusted = wrapUntrusted;
exports.isUntrusted = isUntrusted;
const provenance_1 = require("./provenance");
function wrapUntrusted(source, content, provenance) {
    return {
        __untrusted: true,
        source,
        content,
        provenance: provenance ?? (0, provenance_1.createProvenance)("UNTRUSTED", "PUBLIC", source),
    };
}
function isUntrusted(value) {
    return typeof value === "object" && value !== null && value.__untrusted === true;
}
