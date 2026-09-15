import Groq from "groq-sdk";
import { ToolCall } from "./boundary";

// Swapped from the Anthropic SDK to Groq — a free-tier, no-credit-card
// alternative (console.groq.com), OpenAI-compatible, running open models
// (Llama 3.3 70B here) with real tool-calling support. The harness code
// (boundary.ts, registry.ts, etc.) doesn't change at all — only this file,
// the one place that talks to a model, needed to change shape.

const client = new Groq({ apiKey: process.env.GROQ_API_KEY });

// CHANGED: llama-3.3-70b-versatile was decommissioned by Groq on
// Aug 16, 2026 — found this the hard way, from a real 404 on a real
// run, not from re-reading docs in advance. Model IDs on free-tier
// providers rotate; GROQ_MODEL is now an env var with a fallback to
// Groq's own recommended replacement, so the next rotation is a config
// change, not a code change. Check current options anytime with:
//   curl https://api.groq.com/openai/v1/models -H "Authorization: Bearer $GROQ_API_KEY"
const MODEL = process.env.GROQ_MODEL ?? "openai/gpt-oss-120b";

export interface ModelTool {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
  scope: string;
}

type ChatMessage = Groq.Chat.Completions.ChatCompletionMessageParam;

export class ModelDrivenCaller {
  private messages: ChatMessage[] = [];
  private lastToolCallId: string | null = null;
  private pendingUntrusted = false;
  // CHANGED: the model's final plain-text answer (no tool call attached)
  // was previously discarded entirely — next() returned null and nothing
  // ever captured what the model actually said. Found this by actually
  // running a query and noticing the printed output was just raw tool
  // dumps with no synthesized answer anywhere.
  public finalAnswer: string | null = null;

  constructor(systemPrompt: string, userQuery: string, private tools: ModelTool[]) {
    this.messages.push({ role: "system", content: systemPrompt });
    this.messages.push({ role: "user", content: userQuery });
  }

  async next(observations: string[]): Promise<ToolCall | null> {
    if (observations.length > 0 && this.lastToolCallId) {
      this.messages.push({
        role: "tool",
        tool_call_id: this.lastToolCallId,
        content: observations[observations.length - 1],
      });
    }

    const response = await client.chat.completions.create({
      model: MODEL,
      messages: this.messages,
      tools: this.tools.map((t) => ({
        type: "function",
        function: { name: t.name, description: t.description, parameters: t.input_schema },
      })),
    });

    const message = response.choices[0].message;
    this.messages.push(message);

    const toolCall = message.tool_calls?.[0];
    if (!toolCall) {
      this.finalAnswer = typeof message.content === "string" ? message.content : null;
      return null; // model is done — no further tool calls
    }

    this.lastToolCallId = toolCall.id;
    const toolDef = this.tools.find((t) => t.name === toolCall.function.name);
    const call: ToolCall = {
      name: toolCall.function.name,
      args: JSON.parse(toolCall.function.arguments) as Record<string, unknown>,
      scope: toolDef?.scope ?? "default",
      derivedFromUntrusted: this.pendingUntrusted,
    };

    // CHANGED: previously only fetch_url set this flag — meaning content
    // read via read_file got no injection protection at all, even though
    // a local file can carry the same kind of embedded instruction a
    // webpage can. Both external-content tools now set it.
    this.pendingUntrusted = toolCall.function.name === "fetch_url" || toolCall.function.name === "read_file";
    return call;
  }
}
