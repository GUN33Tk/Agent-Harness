import { wrapUntrusted } from "./untrusted";

export async function callSubagent(
  query: string,
  runSubagent: (q: string) => Promise<string>
): Promise<string> {
  const rawResult = await runSubagent(query);
  const wrapped = wrapUntrusted("subagent", rawResult);
  // The orchestrator reads wrapped.content but any tool call it decides to
  // make as a *result* of this still goes through ExecutionBoundary marked
  // derivedFromUntrusted: true — same path as fetched web content.
  return wrapped.content;
}
