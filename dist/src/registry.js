"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ToolRegistry = void 0;
const schema_validator_1 = require("./schema-validator");
class ToolRegistry {
    constructor() {
        this.tools = new Map();
    }
    register(tool) {
        this.tools.set(tool.name, tool);
    }
    get(name) {
        return this.tools.get(name);
    }
    has(name) {
        return this.tools.has(name);
    }
    async call(name, args, scope) {
        const tool = this.tools.get(name);
        if (!tool)
            return { tool: name, ok: false, error: "unknown tool" };
        if (!tool.allowedInScopes.includes(scope)) {
            return { tool: name, ok: false, error: `scope '${scope}' not permitted for ${name}` };
        }
        // Argument schema validation (supports both legacy predicate and full JSON Schema)
        if (typeof tool.schema === "function") {
            if (!tool.schema(args)) {
                return { tool: name, ok: false, error: "schema validation failed" };
            }
        }
        else if (typeof tool.schema === "object" && tool.schema !== null) {
            const validation = (0, schema_validator_1.validateToolArgs)(tool.schema, args, name);
            if (!validation.valid) {
                return {
                    tool: name,
                    ok: false,
                    error: `schema validation failed: ${validation.errors?.join("; ")}`,
                };
            }
        }
        if (tool.jsonSchema) {
            const validation = (0, schema_validator_1.validateToolArgs)(tool.jsonSchema, args, name);
            if (!validation.valid) {
                return {
                    tool: name,
                    ok: false,
                    error: `schema validation failed: ${validation.errors?.join("; ")}`,
                };
            }
        }
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
