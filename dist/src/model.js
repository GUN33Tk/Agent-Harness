"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ModelDrivenCaller = void 0;
const groq_sdk_1 = __importDefault(require("groq-sdk"));
const provenance_1 = require("./provenance");
function getGroqClient() {
    const apiKey = process.env.GROQ_API_KEY || process.env.LLM_API_KEY;
    if (!apiKey) {
        throw new Error("GROQ_API_KEY (or LLM_API_KEY) environment variable is required to run the agent with a live LLM.");
    }
    return new groq_sdk_1.default({ apiKey });
}
const MODEL = process.env.GROQ_MODEL ?? process.env.LLM_MODEL ?? "openai/gpt-oss-120b";
class ModelDrivenCaller {
    constructor(systemPrompt, userQuery, tools, initialProvenance, sessionId = "session-default") {
        this.tools = tools;
        this.sessionId = sessionId;
        this.messages = [];
        this.lastToolCallId = null;
        // Persistent provenance & data classification state across the entire conversation.
        // Note on architecture:
        // - ModelDrivenCaller tracks local conversational context to construct informed tool-call proposals.
        // - ExecutionBoundary / SessionManager is the single deterministic enforcement authority.
        this.sessionProvenance = (0, provenance_1.createProvenance)("TRUSTED", "PUBLIC", "user-instruction");
        this.sessionClassification = "PUBLIC";
        this.finalAnswer = null;
        if (initialProvenance) {
            this.sessionProvenance = initialProvenance;
            this.sessionClassification = initialProvenance.classification;
        }
        this.messages.push({ role: "system", content: systemPrompt });
        this.messages.push({ role: "user", content: userQuery });
    }
    getProvenance() {
        return { ...this.sessionProvenance };
    }
    getClassification() {
        return this.sessionClassification;
    }
    /**
     * Updates session taint from an observation or tool result provenance.
     */
    taintContext(provenance) {
        this.sessionProvenance = (0, provenance_1.combineProvenance)(this.sessionProvenance, provenance);
        this.sessionClassification = (0, provenance_1.combineClassification)(this.sessionClassification, provenance.classification);
    }
    async next(observations, signal) {
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
        const client = getGroqClient();
        const response = await client.chat.completions.create({
            model: MODEL,
            messages: this.messages,
            tools: this.tools.map((t) => ({
                type: "function",
                function: { name: t.name, description: t.description, parameters: t.input_schema },
            })),
        }, { signal });
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
            this.taintContext((0, provenance_1.createProvenance)("UNTRUSTED", "PUBLIC", "fetch_url"));
        }
        else if (toolCall.function.name === "read_file") {
            // Check if file is secret
            const args = JSON.parse(toolCall.function.arguments);
            const filePath = String(args.path ?? "");
            const isSecret = filePath.toLowerCase().includes("secret");
            this.taintContext((0, provenance_1.createProvenance)("UNTRUSTED", isSecret ? "SECRET" : "INTERNAL", filePath));
        }
        const call = {
            name: toolCall.function.name,
            args: JSON.parse(toolCall.function.arguments),
            scope: toolDef?.scope ?? "default",
            derivedFromUntrusted: this.sessionProvenance.trust !== "TRUSTED",
            provenance: this.sessionProvenance,
            dataClassification: this.sessionClassification,
            sessionId: this.sessionId,
        };
        return call;
    }
}
exports.ModelDrivenCaller = ModelDrivenCaller;
