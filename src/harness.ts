import { ExecutionBoundary, ToolCall } from "./boundary";

export async function runAgent(
  boundary: ExecutionBoundary,
  nextCall: (observations: string[]) => Promise<ToolCall | null> | ToolCall | null,
  maxTurns: number = 25,
  signal?: AbortSignal
) {
  const observations: string[] = [];
  let turns = 0;

  while (turns < maxTurns) {
    if (signal?.aborted) {
      observations.push("HALTED: session cancelled via kill switch signal");
      break;
    }

    const call = await nextCall(observations);
    if (call === null) break;

    const result = await boundary.run(call);
    observations.push(result.ok ? result.output ?? "" : `ERROR: ${result.error}`);
    turns++;

    if (!result.ok && result.error?.includes("HALTED")) {
      break; // Stop agent loop immediately if halted
    }
  }
  return observations;
}
