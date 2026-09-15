import { ExecutionBoundary, ToolCall } from "./boundary";

// CHANGED (Step 2): nextCall is now async, since a real model call is a
// network request. The loop's shape is otherwise identical to the
// original six-line version — it still just repeats "ask, execute,
// observe" until there's nothing left to do or the turn cap is hit.
export async function runAgent(
  boundary: ExecutionBoundary,
  nextCall: (observations: string[]) => Promise<ToolCall | null> | ToolCall | null,
  maxTurns: number = 25
) {
  const observations: string[] = [];
  let turns = 0;

  while (turns < maxTurns) {
    const call = await nextCall(observations);
    if (call === null) break;

    const result = await boundary.run(call);
    observations.push(result.ok ? result.output ?? "" : `ERROR: ${result.error}`);
    turns++;
  }
  return observations;
}
