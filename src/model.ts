import Groq from "groq-sdk";
import { ToolCall } from "./boundary";
import { Provenance, DataClassification, createProvenance, combineProvenance, combineClassification } from "./provenance";

const client = new Groq({ apiKey: process.env.GROQ_API_KEY });
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

  // Persistent provenance & data classification state across the entire conversation
  // Fixes the single-step reset bug: once untrusted or secret data enters the context,
  // subsequent tool calls remain tainted unless explicitly cleared by verification.
  private sessionProvenance: Provenance = createProvenance("TRUSTED", "PUBLIC", "user-instruction");
  private sessionClassification: DataClassification = "PUBLIC";

  public finalAnswer: string | null = null;

  constructor(
    systemPrompt: string,
    userQuery: string,
    private tools: ModelTool[],
    initialProvenance?: Provenance
  ) {
    if (initialProvenance) {
      this.sessionProvenance = initialProvenance;
      this.sessionClassification = initialProvenance.classification;
    }
    this.messages.push({ role: "system", content: systemPrompt });
    this.messages.push({ role: "user", content: userQuery });
  }

  getProvenance(): Provenance {
    return { ...this.sessionProvenance };
  }

  getClassification(): DataClassification {
    return this.sessionClassification;
  }

  /**
   * Updates session taint from an observation or tool result provenance.
   */
  taintContext(provenance: Provenance): void {
    this.sessionProvenance = combineProvenance(this.sessionProvenance, provenance);
    this.sessionClassification = combineClassification(
      this.sessionClassification,
      provenance.classification
    );
  }

  async next(observations: string[], signal?: AbortSignal): Promise<ToolCall | null> {
    if (signal?.aborted) {
      return null;
    }

    if (observations.length > 0 && this.lastToolCallId) {
      const lastObs = observations[observations.length - 1];
      this.messages.push({
        role: "tool",
        tool_call_id: this.lastToolCallId,
        content: lastObs,
      });
    }

    const response = await client.chat.completions.create(
      {
        model: MODEL,
        messages: this.messages,
        tools: this.tools.map((t) => ({
          type: "function",
          function: { name: t.name, description: t.description, parameters: t.input_schema },
        })),
      },
      { signal }
    );

    const message = response.choices[0].message;
    this.messages.push(message);

    const toolCall = message.tool_calls?.[0];
    if (!toolCall) {
      this.finalAnswer = typeof message.content === "string" ? message.content : null;
      return null;
    }

    this.lastToolCallId = toolCall.id;
    const toolDef = this.tools.find((t) => t.name === toolCall.function.name);

    // If calling external/content-reading tools, update persistent provenance
    if (toolCall.function.name === "fetch_url") {
      this.taintContext(createProvenance("UNTRUSTED", "PUBLIC", "fetch_url"));
    } else if (toolCall.function.name === "read_file") {
      // Check if file is secret
      const args = JSON.parse(toolCall.function.arguments) as Record<string, unknown>;
      const filePath = String(args.path ?? "");
      const isSecret = filePath.toLowerCase().includes("secret");
      this.taintContext(
        createProvenance(
          "UNTRUSTED",
          isSecret ? "SECRET" : "INTERNAL",
          filePath
        )
      );
    }

    const call: ToolCall = {
      name: toolCall.function.name,
      args: JSON.parse(toolCall.function.arguments) as Record<string, unknown>,
      scope: toolDef?.scope ?? "default",
      derivedFromUntrusted: this.sessionProvenance.trust !== "TRUSTED",
      provenance: this.sessionProvenance,
      dataClassification: this.sessionClassification,
    };

    return call;
  }
}
