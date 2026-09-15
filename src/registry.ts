export interface ToolDefinition {
  name: string;
  allowedInScopes: string[];
  schema: (args: unknown) => boolean;
  execute: (args: Record<string, unknown>) => Promise<string>;
}

export interface ToolCallResult {
  tool: string;
  ok: boolean;
  output?: string;
  error?: string;
}

export class ToolRegistry {
  private tools = new Map<string, ToolDefinition>();

  register(tool: ToolDefinition): void {
    this.tools.set(tool.name, tool);
  }

  async call(name: string, args: Record<string, unknown>, scope: string): Promise<ToolCallResult> {
    const tool = this.tools.get(name);
    if (!tool) return { tool: name, ok: false, error: "unknown tool" };
    if (!tool.allowedInScopes.includes(scope)) {
      return { tool: name, ok: false, error: `scope '${scope}' not permitted for ${name}` };
    }
    if (!tool.schema(args)) return { tool: name, ok: false, error: "schema validation failed" };

    try {
      const output = await tool.execute(args);
      return { tool: name, ok: true, output };
    } catch (err) {
      return { tool: name, ok: false, error: String(err) };
    }
  }
}
