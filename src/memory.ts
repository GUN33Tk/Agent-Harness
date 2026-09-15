export type MemoryKind = "chat" | "disk" | "config";

const conversation: string[] = [];
const disk = new Map<string, string>();
const harnessConfig = new Map<string, string>();

export function remember(
  kind: MemoryKind,
  key: string,
  value: string,
  derivedFromUntrusted: boolean
): string | void {
  if ((kind === "disk" || kind === "config") && derivedFromUntrusted) {
    return "DENIED: cannot persist a conclusion traced to untrusted input without review";
  }
  (
    {
      chat: () => conversation.push(value),
      disk: () => disk.set(key, value),
      config: () => harnessConfig.set(key, value),
    } as Record<MemoryKind, () => void>
  )[kind]();
}
