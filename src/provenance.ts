export type TrustLevel = "TRUSTED" | "UNTRUSTED" | "MIXED";

export type DataClassification = "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "SECRET";

export interface Provenance {
  trust: TrustLevel;
  sources: string[];
  classification: DataClassification;
  parents?: Provenance[];
}

const CLASSIFICATION_LEVELS: Record<DataClassification, number> = {
  PUBLIC: 0,
  INTERNAL: 1,
  CONFIDENTIAL: 2,
  SECRET: 3,
};

export function compareClassification(a: DataClassification, b: DataClassification): number {
  return CLASSIFICATION_LEVELS[a] - CLASSIFICATION_LEVELS[b];
}

export function combineClassification(
  a: DataClassification,
  b: DataClassification
): DataClassification {
  return compareClassification(a, b) >= 0 ? a : b;
}

export function combineTrust(a: TrustLevel, b: TrustLevel): TrustLevel {
  if (a === b) return a;
  if (a === "MIXED" || b === "MIXED") return "MIXED";
  if ((a === "TRUSTED" && b === "UNTRUSTED") || (a === "UNTRUSTED" && b === "TRUSTED")) {
    return "MIXED";
  }
  return "UNTRUSTED";
}

export function combineProvenance(a: Provenance, b: Provenance): Provenance {
  const sourcesSet = new Set([...a.sources, ...b.sources]);
  return {
    trust: combineTrust(a.trust, b.trust),
    classification: combineClassification(a.classification, b.classification),
    sources: Array.from(sourcesSet),
    parents: [a, b],
  };
}

export function createProvenance(
  trust: TrustLevel = "TRUSTED",
  classification: DataClassification = "PUBLIC",
  source: string = "system"
): Provenance {
  return {
    trust,
    classification,
    sources: [source],
  };
}
