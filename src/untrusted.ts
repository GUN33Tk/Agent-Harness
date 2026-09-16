import { Provenance, createProvenance } from "./provenance";

/**
 * A value that entered the system from outside the trusted instruction
 * channel: tool output, fetched URLs, RAG hits, subagent responses, MCP
 * tool descriptions. It can be read and reasoned about, but it can never
 * silently become an instruction or a privileged tool argument.
 */
export interface Untrusted {
  readonly __untrusted: true;
  source: string;
  content: string;
  provenance?: Provenance;
}

export function wrapUntrusted(
  source: string,
  content: string,
  provenance?: Provenance
): Untrusted {
  return {
    __untrusted: true,
    source,
    content,
    provenance: provenance ?? createProvenance("UNTRUSTED", "PUBLIC", source),
  };
}

export function isUntrusted(value: unknown): value is Untrusted {
  return typeof value === "object" && value !== null && (value as any).__untrusted === true;
}
