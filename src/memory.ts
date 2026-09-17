import { DataClassification } from "./provenance";

export type MemoryKind = "chat" | "disk" | "config";

const conversation: string[] = [];
const disk = new Map<string, string>();
const harnessConfig = new Map<string, string>();

export function remember(
  kind: MemoryKind,
  key: string,
  value: string,
  derivedFromUntrusted: boolean,
  classification: DataClassification = "PUBLIC"
): string | void {
  if ((kind === "disk" || kind === "config") && derivedFromUntrusted) {
    return "DENIED: cannot persist a conclusion traced to untrusted input without review";
  }
  if ((kind === "disk" || kind === "config") && (classification === "SECRET" || classification === "CONFIDENTIAL")) {
    return `DENIED: cannot persist ${classification} data to persistent storage`;
  }
  (
    {
      chat: () => conversation.push(value),
      disk: () => disk.set(key, value),
      config: () => harnessConfig.set(key, value),
    } as Record<MemoryKind, () => void>
  )[kind]();
}

export function getMemory(kind: MemoryKind, key?: string): string | undefined {
  if (kind === "disk" && key) return disk.get(key);
  if (kind === "config" && key) return harnessConfig.get(key);
  if (kind === "chat") return conversation[conversation.length - 1];
  return undefined;
}

export function clearMemory(): void {
  conversation.length = 0;
  disk.clear();
  harnessConfig.clear();
}

