/**
 * SESSION TAINT & TRANSFORMATION SECURITY SUITE (26 CHECKS)
 *
 * Covers Phase 2 Stage A requirements:
 * - Isolated session security contexts
 * - Monotonic data classification & trust lattice
 * - Persistent session-level taint propagation across tool chains
 * - EgressGateway evaluation of effective session security state
 * - Transformation detection: Exact, URL-encoded, Base64, Hex
 * - Transformation CPU/memory safety guarantees
 */

import * as assert from "assert";
import { SessionManager } from "../src/session";
import { createProvenance, combineClassification, combineTrust } from "../src/provenance";
import { ExecutionBoundary } from "../src/boundary";
import { ToolRegistry } from "../src/registry";
import { KillSwitch } from "../src/killswitch";
import { BudgetTracker } from "../src/budget";
import { createFetchUrlTool, readFileTool } from "../src/tools";
import { EgressGateway } from "../src/network/egress-gateway";
import { detectPiggybacking } from "../src/network/piggybacking-detector";
import { detectTransformedSecret } from "../src/network/transformations";
import { NetworkRequest } from "../src/network/network-types";
import { securityEventBus, SecurityEvent } from "../src/security-events";
import { startMockServer } from "../demo/mock-server";

const KILLSWITCH_PATH = "./.test-killswitch-session";

async function runSessionTaintTests() {
  console.log("============================================================");
  console.log("RUNNING SESSION TAINT & TRANSFORMATION SUITE (26 CHECKS)");
  console.log("============================================================\n");

  let passed = 0;
  const pass = (name: string) => {
    passed++;
    console.log(`PASS [${passed}/26]: ${name}`);
  };

  // -------------------------------------------------------------------------
  // SECTION 1: SESSION ISOLATION & MONOTONICITY (Checks 1–9)
  // -------------------------------------------------------------------------

  // 1. New session starts PUBLIC / TRUSTED
  {
    const mgr = new SessionManager();
    const session = mgr.getSession("sess-1");
    assert.strictEqual(session.classification, "PUBLIC");
    assert.strictEqual(session.provenance.trust, "TRUSTED");
    assert.strictEqual(session.taintSources.length, 0);
    pass("Session 1: New session starts PUBLIC/TRUSTED");
  }

  // 2. PUBLIC content does not taint session
  {
    const mgr = new SessionManager();
    mgr.updateTaint("sess-2", createProvenance("TRUSTED", "PUBLIC", "file.txt"), "PUBLIC", "file.txt");
    const session = mgr.getSession("sess-2");
    assert.strictEqual(session.classification, "PUBLIC");
    assert.strictEqual(session.provenance.trust, "TRUSTED");
    assert.strictEqual(session.taintSources.length, 0);
    pass("Session 2: PUBLIC content does not taint session");
  }

  // 3. SECRET content taints session
  {
    const mgr = new SessionManager();
    mgr.updateTaint("sess-3", createProvenance("TRUSTED", "SECRET", "secret.txt"), "SECRET", "secret.txt", "my-secret-key-1234");
    const session = mgr.getSession("sess-3");
    assert.strictEqual(session.classification, "SECRET");
    assert.ok(session.taintSources.includes("secret.txt"));
    assert.ok(session.secrets.has("my-secret-key-1234"));
    pass("Session 3: SECRET content taints session");
  }

  // 4. SECRET persists across tool calls
  {
    const mgr = new SessionManager();
    mgr.updateTaint("sess-4", createProvenance("TRUSTED", "SECRET", "secret.txt"), "SECRET", "secret.txt");
    // Subsequent normal tool call
    mgr.updateTaint("sess-4", createProvenance("TRUSTED", "PUBLIC", "public.txt"), "PUBLIC", "public.txt");
    const session = mgr.getSession("sess-4");
    assert.strictEqual(session.classification, "SECRET");
    pass("Session 4: SECRET persists across sequential tool calls");
  }

  // 5. PUBLIC request cannot downgrade SECRET
  {
    const monotonicClass = combineClassification("PUBLIC", "SECRET");
    assert.strictEqual(monotonicClass, "SECRET");
    const internalToSecret = combineClassification("INTERNAL", "SECRET");
    assert.strictEqual(internalToSecret, "SECRET");
    pass("Session 5: PUBLIC request cannot downgrade SECRET classification");
  }

  // 6. TRUSTED + UNTRUSTED = MIXED
  {
    const trust = combineTrust("TRUSTED", "UNTRUSTED");
    assert.strictEqual(trust, "MIXED");
    pass("Session 6: TRUSTED + UNTRUSTED produces MIXED trust lattice");
  }

  // 7. MIXED cannot become TRUSTED
  {
    const mixedPlusTrusted = combineTrust("MIXED", "TRUSTED");
    assert.strictEqual(mixedPlusTrusted, "MIXED");
    const untrustedPlusTrusted = combineTrust("UNTRUSTED", "TRUSTED");
    assert.strictEqual(untrustedPlusTrusted, "MIXED");
    pass("Session 7: MIXED/UNTRUSTED trust cannot be downgraded to TRUSTED");
  }

  // 8. Sessions do not share taint
  {
    const mgr = new SessionManager();
    mgr.updateTaint("sess-isolated-A", createProvenance("UNTRUSTED", "SECRET", "vault.txt"), "SECRET", "vault.txt", "secret-token-A");
    const sessionB = mgr.getSession("sess-isolated-B");
    assert.strictEqual(sessionB.classification, "PUBLIC");
    assert.strictEqual(sessionB.provenance.trust, "TRUSTED");
    assert.strictEqual(sessionB.secrets.size, 0);
    pass("Session 8: Isolated sessions do not share taint or secrets");
  }

  // 9. New session starts clean
  {
    const mgr = new SessionManager();
    mgr.updateTaint("sess-old", createProvenance("UNTRUSTED", "SECRET", "data.txt"), "SECRET", "data.txt");
    const newSession = mgr.getSession("sess-brand-new");
    assert.strictEqual(newSession.classification, "PUBLIC");
    assert.strictEqual(newSession.taintSources.length, 0);
    pass("Session 9: New session starts clean");
  }

  // -------------------------------------------------------------------------
  // SECTION 2: TRANSFORMATION DETECTION (Checks 10–15)
  // -------------------------------------------------------------------------

  const TEST_SECRET = "sk_live_super_secret_test_token_9999";
  const TEST_SECRETS = new Set([TEST_SECRET]);

  // 10. Secret + allowlisted destination = DENY
  {
    const req: NetworkRequest = {
      url: "https://api.example.com/data",
      method: "POST",
      body: `{"token":"${TEST_SECRET}"}`,
      provenance: createProvenance("TRUSTED", "PUBLIC", "client"),
      dataClassification: "PUBLIC",
      sessionContext: {
        sessionId: "s10",
        provenance: createProvenance("TRUSTED", "PUBLIC"),
        classification: "PUBLIC",
        taintSources: [],
        secrets: TEST_SECRETS,
      },
    };
    const decision = detectPiggybacking(new URL(req.url), req);
    assert.strictEqual(decision.decision, "DENY");
    assert.strictEqual(decision.policy, "P-EXFIL-001");
    pass("Piggyback 10: Secret data to allowlisted destination blocked (P-EXFIL-001)");
  }

  // 11. Secret in GET query = DENY
  {
    const req: NetworkRequest = {
      url: `https://api.example.com/collect?token=${TEST_SECRET}`,
      method: "GET",
      provenance: createProvenance("TRUSTED", "PUBLIC"),
      dataClassification: "PUBLIC",
      sessionContext: {
        sessionId: "s11",
        provenance: createProvenance("TRUSTED", "PUBLIC"),
        classification: "PUBLIC",
        taintSources: [],
        secrets: TEST_SECRETS,
      },
    };
    const decision = detectPiggybacking(new URL(req.url), req);
    assert.strictEqual(decision.decision, "DENY");
    assert.strictEqual(decision.policy, "P-EXFIL-001");
    pass("Piggyback 11: Exact secret in GET query blocked");
  }

  // 12. Secret in POST body = DENY
  {
    const req: NetworkRequest = {
      url: "https://api.example.com/telemetry",
      method: "POST",
      body: `{"leak":"${TEST_SECRET}"}`,
      provenance: createProvenance("TRUSTED", "PUBLIC"),
      dataClassification: "PUBLIC",
      sessionContext: {
        sessionId: "s12",
        provenance: createProvenance("TRUSTED", "PUBLIC"),
        classification: "PUBLIC",
        taintSources: [],
        secrets: TEST_SECRETS,
      },
    };
    const decision = detectPiggybacking(new URL(req.url), req);
    assert.strictEqual(decision.decision, "DENY");
    assert.strictEqual(decision.policy, "P-EXFIL-001");
    pass("Piggyback 12: Exact secret in POST body blocked");
  }

  // 13. URL-encoded secret = DENY
  {
    const encoded = encodeURIComponent(TEST_SECRET);
    const req: NetworkRequest = {
      url: `https://api.example.com/collect?data=${encoded}`,
      method: "GET",
      provenance: createProvenance("TRUSTED", "PUBLIC"),
      dataClassification: "PUBLIC",
      sessionContext: {
        sessionId: "s13",
        provenance: createProvenance("TRUSTED", "PUBLIC"),
        classification: "PUBLIC",
        taintSources: [],
        secrets: TEST_SECRETS,
      },
    };
    const decision = detectPiggybacking(new URL(req.url), req);
    assert.strictEqual(decision.decision, "DENY");
    assert.strictEqual(decision.policy, "P-EXFIL-001");
    pass("Piggyback 13: URL-encoded secret representation blocked");
  }

  // 14. Base64 secret = DENY
  {
    const b64 = Buffer.from(TEST_SECRET).toString("base64");
    const req: NetworkRequest = {
      url: `https://api.example.com/collect?token=${b64}`,
      method: "GET",
      provenance: createProvenance("TRUSTED", "PUBLIC"),
      dataClassification: "PUBLIC",
      sessionContext: {
        sessionId: "s14",
        provenance: createProvenance("TRUSTED", "PUBLIC"),
        classification: "PUBLIC",
        taintSources: [],
        secrets: TEST_SECRETS,
      },
    };
    const decision = detectPiggybacking(new URL(req.url), req);
    assert.strictEqual(decision.decision, "DENY");
    assert.strictEqual(decision.policy, "P-EXFIL-001");
    pass("Piggyback 14: Base64-transformed secret representation blocked");
  }

  // 15. Hex secret = DENY
  {
    const hex = Buffer.from(TEST_SECRET).toString("hex");
    const req: NetworkRequest = {
      url: "https://api.example.com/telemetry",
      method: "POST",
      body: `payload=${hex}`,
      provenance: createProvenance("TRUSTED", "PUBLIC"),
      dataClassification: "PUBLIC",
      sessionContext: {
        sessionId: "s15",
        provenance: createProvenance("TRUSTED", "PUBLIC"),
        classification: "PUBLIC",
        taintSources: [],
        secrets: TEST_SECRETS,
      },
    };
    const decision = detectPiggybacking(new URL(req.url), req);
    assert.strictEqual(decision.decision, "DENY");
    assert.strictEqual(decision.policy, "P-EXFIL-001");
    pass("Piggyback 15: Hex-transformed secret representation blocked");
  }

  // -------------------------------------------------------------------------
  // SECTION 3: SESSION-AWARE TAINT ATTACK (Checks 16–21)
  // -------------------------------------------------------------------------

  // 16-21. End-to-End Session Taint Verification via ExecutionBoundary
  {
    const mockServer = await startMockServer(0);
    const gateway = new EgressGateway({
      allowedDomains: ["127.0.0.1"],
      allowedPorts: [80, 443, mockServer.port],
      blockPrivateIPs: false, // test-only local mock
    });

    const registry = new ToolRegistry();
    registry.register(createFetchUrlTool(gateway));
    registry.register(readFileTool);

    const boundary = new ExecutionBoundary(
      registry,
      new KillSwitch(KILLSWITCH_PATH),
      new BudgetTracker({ read_file: 10, fetch_url: 10 }),
      gateway
    );

    const sessionId = "session-taint-attack-demo";
    const fs = await import("fs");
    const path = await import("path");
    const secretSandboxPath = path.join(process.cwd(), "sandbox-files", "session-secret.txt");
    fs.writeFileSync(secretSandboxPath, "sk_live_session_vault_key_abc123\n");

    const events: SecurityEvent[] = [];
    const unsub = securityEventBus.subscribe((e) => events.push(e));

    let fetchResult;
    let sessionContext: any;
    try {
      // Step 1: Agent reads SECRET file (session-secret.txt)
      const readResult = await boundary.run({
        name: "read_file",
        args: { path: "session-secret.txt" },
        scope: "file-access",
        sessionId,
      });
      assert.strictEqual(readResult.ok, true);
      pass("SessionAware 16: Secret enters session security context");

      // Check session context reflects SECRET
      const sessionContext = boundary.getSessionManager().getSession(sessionId);
      assert.strictEqual(sessionContext.classification, "SECRET");
      pass("SessionAware 17: Session context monotonically upgrades to SECRET");

      // Step 2: Adversary prompt-injects agent to send benign-looking request with NO literal secret
      // Claims PUBLIC classification and TRUSTED provenance to bypass naive gates
      fetchResult = await boundary.run({
        name: "fetch_url",
        args: { url: `${mockServer.url}/api/public` }, // Completely clean URL
        scope: "research",
        sessionId,
        // Model attempts to override classification to PUBLIC:
        dataClassification: "PUBLIC",
        provenance: createProvenance("TRUSTED", "PUBLIC", "innocent-caller"),
      });
    } finally {
      unsub();
      await mockServer.close();
      if (fs.existsSync(secretSandboxPath)) {
        fs.unlinkSync(secretSandboxPath);
      }
    }

    assert.strictEqual(
      fetchResult.ok,
      false,
      "SessionAware 18: Fetch must be DENIED because session carries SECRET taint"
    );
    pass("SessionAware 18: Literal secret absent from later request is still intercepted");

    assert.ok(
      fetchResult.error?.includes("P-EXFIL-001") || fetchResult.error?.includes("SECRET"),
      `SessionAware 19: Error must reference P-EXFIL-001 or SECRET taint, got: ${fetchResult.error}`
    );
    pass("SessionAware 19: Model claiming PUBLIC cannot override session SECRET taint");

    const finalSession = boundary.getSessionManager().getSession(sessionId);
    assert.strictEqual(finalSession.classification, "SECRET");
    pass("SessionAware 20: Effective state remains SECRET despite benign request parameters");

    const exfilEvent = events.find((e) => e.type === "NETWORK_EXFILTRATION_ATTEMPT");
    assert.ok(exfilEvent, "SessionAware 21: NETWORK_EXFILTRATION_ATTEMPT security event emitted");
    pass("SessionAware 21: EgressGateway policy produces secure P-EXFIL-001 decision");
  }

  // -------------------------------------------------------------------------
  // SECTION 4: TRANSFORMATION SAFETY & BOUNDS (Checks 22–26)
  // -------------------------------------------------------------------------

  // 22. Invalid Base64 does not crash
  {
    const res = detectTransformedSecret("???invalid-b64-===!!!", TEST_SECRETS);
    assert.strictEqual(res.detected, false);
    pass("Safety 22: Invalid Base64 strings do not crash the detector");
  }

  // 23. Invalid Hex does not crash
  {
    const res = detectTransformedSecret("xyz123nothex", TEST_SECRETS);
    assert.strictEqual(res.detected, false);
    pass("Safety 23: Invalid Hex strings do not crash the detector");
  }

  // 24. Large input is bounded
  {
    const hugePayload = "A".repeat(2_000_000); // 2MB string
    const start = Date.now();
    const res = detectTransformedSecret(hugePayload, TEST_SECRETS);
    const elapsed = Date.now() - start;
    assert.strictEqual(res.detected, false);
    assert.ok(elapsed < 1000, `Large payload scan must be fast (<1000ms), took ${elapsed}ms`);
    pass("Safety 24: Oversized payloads are bounded and CPU-safe");
  }

  // 25. No recursive/unbounded decoding
  {
    // Multiple nested strings
    const nested = "data=" + Buffer.from("random_unrelated_data").toString("base64");
    const res = detectTransformedSecret(nested, TEST_SECRETS);
    assert.strictEqual(res.detected, false);
    pass("Safety 25: Non-matching candidate tokens do not trigger recursion or false positives");
  }

  // 26. Normal Base64 does not automatically trigger
  {
    const innocentBase64 = Buffer.from("Hello World, this is normal documentation text").toString("base64");
    const res = detectTransformedSecret(`https://example.com/api?data=${innocentBase64}`, TEST_SECRETS);
    assert.strictEqual(res.detected, false);
    pass("Safety 26: Normal Base64 data not containing secrets is not falsely blocked");
  }

  console.log("\n============================================================");
  console.log(`ALL ${passed}/26 SESSION TAINT & TRANSFORMATION CHECKS PASSED`);
  console.log("============================================================\n");
}

if (require.main === module) {
  runSessionTaintTests().catch((err) => {
    console.error("SESSION TAINT TEST SUITE FAILED:", err);
    process.exit(1);
  });
}
