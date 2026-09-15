"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.wrapUntrusted = wrapUntrusted;
exports.isUntrusted = isUntrusted;
function wrapUntrusted(source, content) {
    return { __untrusted: true, source, content };
}
function isUntrusted(value) {
    return typeof value === "object" && value !== null && value.__untrusted === true;
}
