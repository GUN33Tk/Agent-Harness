// A token issued for one scope must never be usable by code running
// under a different scope. This is what makes scope checks in registry.ts
// mean something beyond "which function gets called" — even if a bug let
// the wrong tool run, it still couldn't authenticate as a different
// identity than the scope it was actually granted.

const SCOPE_CREDENTIALS: Record<string, string> = {
  "customer-support": "cred-support-3f8a",
  "pricing-research": "cred-pricing-91bd",
  research: "cred-research-22e0",
};

export function getCredential(scope: string): string {
  const cred = SCOPE_CREDENTIALS[scope];
  if (!cred) throw new Error(`no credential provisioned for scope '${scope}'`);
  return cred;
}
