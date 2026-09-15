"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ToolRegistry = void 0;
class ToolRegistry {
    constructor() {
        this.tools = new Map();
    }
    register(tool) {
        this.tools.set(tool.name, tool);
    }
    async call(name, args, scope) {
        const tool = this.tools.get(name);
        if (!tool)
            return { tool: name, ok: false, error: "unknown tool" };
        if (!tool.allowedInScopes.includes(scope)) {
            return { tool: name, ok: false, error: `scope '${scope}' not permitted for ${name}` };
        }
        if (!tool.schema(args))
            return { tool: name, ok: false, error: "schema validation failed" };
        try {
            const output = await tool.execute(args);
            return { tool: name, ok: true, output };
        }
        catch (err) {
            return { tool: name, ok: false, error: String(err) };
        }
    }
}
exports.ToolRegistry = ToolRegistry;
