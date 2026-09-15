"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BudgetTracker = void 0;
class BudgetTracker {
    constructor(limits) {
        this.limits = limits;
        this.spent = new Map();
    }
    spend(toolName) {
        const used = (this.spent.get(toolName) ?? 0) + 1;
        this.spent.set(toolName, used);
        return used <= (this.limits[toolName] ?? Infinity);
    }
    usage(toolName) {
        return this.spent.get(toolName) ?? 0;
    }
}
exports.BudgetTracker = BudgetTracker;
