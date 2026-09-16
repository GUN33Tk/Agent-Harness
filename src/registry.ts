import { validateToolArgs } from "./schema-validator";
import { Provenance } from "./provenance";

export interface ToolDefinition {
  name: string;
  allowedInScopes: string[];
  schema: ((args: unknown) => boolean) | Record<string, unknown>;
  jsonSchema?: Record<string, unknown>;
  execute: (args: Record<string, unknown>) => Promise<string>;
}

export interface ToolCallResult {
  tool: string;
  ok: boolean;
  output?: string;
  error?: string;
  provenance?: Provenance;
}

export class ToolRegistry {
  private tools = new Map<string, ToolDefinition>();

  register(tool: ToolDefinition): void {
    this.tools.set(tool.name, tool);
  }

  get(name: string): ToolDefinition | undefined {
    return this.tools.get(name);
  }

  has(name: string): boolean {
    return this.tools.has(name);
  }

  async call(name: string, args: Record<string, unknown>, scope: string): Promise<ToolCallResult> {
    const tool = this.tools.get(name);
    if (!tool) return { tool: name, ok: false, error: "unknown tool" };
    if (!tool.allowedInScopes.includes(scope)) {
      return { tool: name, ok: false, error: `scope '${scope}' not permitted for ${name}` };
    }

    // Argument schema validation (supports both legacy predicate and full JSON Schema)
    if (typeof tool.schema === "function") {
      if (!tool.schema(args)) {
        return { tool: name, ok: false, error: "schema validation failed" };
      }
    } else if (typeof tool.schema === "object" && tool.schema !== null) {
      const validation = validateToolArgs(tool.schema, args, name);
      if (!validation.valid) {
        return {
          tool: name,
          ok: false,
          error: `schema validation failed: ${validation.errors?.join("; ")}`,
        };
      }
    }

    if (tool.jsonSchema) {
      const validation = validateToolArgs(tool.jsonSchema, args, name);
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
    } catch (err) {
      return { tool: name, ok: false, error: String(err) };
    }
  }
}
