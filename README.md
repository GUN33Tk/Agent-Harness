> **New here? Start with `RUNBOOK.md`** — it walks through every setup step from zero.

# Agent Harness — AI Security Boundary

A TypeScript + C++ security harness that wraps an LLM and enforces deterministic security policies on every tool call.

> **Core principle: The LLM is an untrusted planner. The harness is the security authority.**

The LLM produces `{ name, args }` tool-call requests. It never directly touches the network, filesystem, credentials, or external APIs. Every request is evaluated by the harness pipeline before any side-effecting action is taken.

---

## Architecture

```
┌─────────────────────────────────────┐
│          LLM (Untrusted Planner)     │
│   Generates: { name, args }          │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│                EXECUTION BOUNDARY                    │
│  1. KillSwitch / AbortSignal check                   │
│  2. Tool Authorization Policy (scope, risk, phase)   │
│  3. JSON Schema validation (AJV, strict mode)        │
│  4. Provenance & Taint tracking                      │
│  5. Data Classification enforcement                  │
│  6. Budget / Rate-limit check                        │
│  7. Human Approval binding (SHA-256 content hash)    │
│  8. Tool dispatch → EgressGateway | Sandbox | Local  │
│  9. Security event emission → harness-events.log     │
└──────────────────────┬──────────────────────────────┘
                       │
          ┌────────────┴───────────┐
          ▼                        ▼
┌──────────────────┐   ┌────────────────────────┐
│  EGRESS GATEWAY  │   │  C++ SANDBOX / LOCAL    │
│  SSRF defenses   │   │  PR_SET_NO_NEW_PRIVS    │
│  DNS rebinding   │   │  RLIMIT_* resource caps │
│  Redirect gating │   │  Seccomp syscall filter │
│  Piggybacking    │   │  Net namespace isolation│
│  Rate & byte caps│   │  Realpath traversal     │
└──────────────────┘   └────────────────────────┘
```

---

## Security Layers

### 1. SSRF Prevention (`src/network/`)

All outbound HTTP/HTTPS requests route through `EgressGateway` before any TCP connection is made.

- **Scheme validation**: only `http:` and `https:` allowed (`P-SCHEME-001`)
- **IP blocklist**: 11 IPv4 CIDRs + 4 IPv6 ranges blocked (loopback, private, link-local, cloud metadata)
- **IPv4-mapped IPv6**: `::ffff:127.0.0.1` extracted and evaluated against IPv4 blocklist
- **Port allowlist**: only configured ports accepted (`P-PORT-001`)
- **DNS rebinding defense**: hostname resolved once; `http.Agent` pins socket to validated IP — eliminates TOCTOU window
- **Redirect gating**: `redirect: "manual"`, every `Location` header fed through full validation before following

### 2. Network Piggybacking & Transformation Defense — Policy P-EXFIL-001 (`src/network/piggybacking-detector.ts`, `src/network/transformations.ts`)

Prevents an injected LLM from exfiltrating sensitive data through an *allowlisted* destination.

- `SECRET` or `CONFIDENTIAL` data classification → **DENY** regardless of destination
- `UNTRUSTED` or `MIXED` provenance with sensitive data → **DENY**
- Scans URL query parameters and POST body for registered secret tokens across representations:
  - **Exact token matching**
  - **URL-encoded variants**
  - **Base64 encoding** (standard, unpadded, and URL-safe Base64)
  - **Hex encoding** (case-insensitive)
- Evaluates both per-request metadata and persistent session security state (effective state = most restrictive).

**Demo:** `node dist/demo/run-piggyback-demo.js` demonstrates 4 scenarios:
1. Public data → **ALLOWED**
2. Direct secret token exfiltration → **BLOCKED** (`P-EXFIL-001`)
3. Base64-transformed secret exfiltration → **BLOCKED** (`P-EXFIL-001`)
4. Multi-turn session taint exfiltration → **BLOCKED** (`P-EXFIL-001`)

### 3. Session Security Context & Persistent Taint Tracking (`src/session.ts`, `src/provenance.ts`, `src/untrusted.ts`)

- **Session Security Context**: Persistent `SessionSecurityContext` per session tracking monotonic classification, provenance, and active secret tokens.
- **Monotonic lattice model**: 
  - Provenance: `TRUSTED < UNTRUSTED < MIXED` (taint never silently clears during a session)
  - Classification: `PUBLIC < INTERNAL < CONFIDENTIAL < SECRET` (escalates on reading classified resources)
- **Multi-turn taint propagation**: Tool execution updates session state; subsequent tool calls in the same session inherit taint.
- Subagent outputs wrapped as `Untrusted<T>` automatically.

### 4. Deterministic Tool Authorization (`src/policy.ts`)

- Per-tool risk levels: `LOW | MEDIUM | HIGH | CRITICAL`
- Per-tool scope allowlists: `send_email` only in `customer-support` scope
- Privileged tools denied if execution is derived from untrusted provenance

### 5. JSON Schema Validation (`src/schema-validator.ts`)

- AJV with `strict: true` and `additionalProperties: false`
- Rejects extra fields, wrong types, missing required params before execution

### 6. MCP Manifest Integrity (`src/mcp-trust.ts`)

- SHA-256 hash over canonical JSON serialization of full tool manifest
- Any change to description, inputSchema, endpoint, or permissions after approval → **DENY**
- Prevents rug-pull attacks from malicious MCP servers

### 7. Path Traversal Prevention (`src/files.ts`)

- `realpathSync` resolves symlinks before containment check
- Blocks: `../`, `%2e%2e`, `\0` null bytes, Windows `..\ `, absolute paths, UNC paths
- `resolveWithinRoot` returns `null` for any escape attempt

### 8. Human Approval Binding (`src/verification.ts`)

- SHA-256 hash computed over exact content at review time
- Pre-write hash recomputed and compared — content tampering post-approval is denied
- Single-operation approval; not a blanket write permission

### 9. Budget & Rate Limiting (`src/budget.ts`)

- Per-tool call limits, total network request cap
- Requests-per-minute sliding window rate limiter
- Request/response byte budget
- Circuit breaker: any limit exceeded → all subsequent calls denied

### 10. Emergency Kill Switch (`src/killswitch.ts`)

- `AbortController`-backed — `trigger()` immediately aborts in-flight network requests
- State transitions: `ACTIVE → HALTED → ACTIVE` (after reset)
- File-based flag for external process signalling

### 11. C++ Process Sandbox (`native/`)

- `PR_SET_NO_NEW_PRIVS` prevents privilege escalation
- `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_NPROC`, `RLIMIT_NOFILE`, `RLIMIT_FSIZE` resource caps
- Network namespace isolation (`unshare(CLONE_NEWNET)`)
- Seccomp BPF syscall allowlist (see `sandbox_filter.hpp`)

---

## Project Structure

```
src/
  boundary.ts            # Central enforcement pipeline
  session.ts             # SessionSecurityContext & SessionManager (monotonic taint & secrets)
  network/
    egress-gateway.ts    # Single outbound HTTP enforcement point
    ip-utils.ts          # IPv4/IPv6 CIDR blocklist validation
    dns.ts               # DNS resolution + IP-pinning agent
    egress-policy.ts     # Domain/port/scheme/phase policy
    piggybacking-detector.ts  # P-EXFIL-001 exfiltration defense
    transformations.ts   # Base64/Hex/URL transformation detection
    network-types.ts     # Shared types
  provenance.ts          # Taint lattice & data classification
  classification.ts      # Resource classification helpers
  policy.ts              # Tool authorization policy engine
  schema-validator.ts    # AJV JSON Schema validator
  budget.ts              # Budget tracker & circuit breaker
  killswitch.ts          # AbortController-backed kill switch
  mcp-trust.ts           # MCP manifest hash pinning
  verification.ts        # Human approval content binding
  files.ts               # Path traversal prevention
  sanitizer.ts           # Prompt injection heuristic scanner
  untrusted.ts           # Untrusted<T> wrapper
  security-events.ts     # Unified security event emitter
  tools.ts               # Tool implementations
  model.ts               # LLM driver
  harness.ts             # Top-level harness composition
  config.ts              # Config loader
  logger.ts              # Structured JSON event logger

test/
  scenarios.test.ts      # 21 integration scenario tests (all PASS)
  adversarial.test.ts    # 44 adversarial security tests (all PASS)
  integration.test.ts    # 8 full boundary pipeline integration tests (all PASS)
  session-taint.test.ts  # 26 session taint & transformation tests (all PASS)

demo/
  mock-server.ts         # Deterministic test HTTP server
  run-piggyback-demo.ts  # Piggybacking & transformation attack demo (4 scenarios)
  public-data.txt        # Demo public resource
  secret.txt             # Demo classified resource

native/
  sandbox_executor.cpp   # C++ launcher with namespace/resource isolation
  sandbox_filter.hpp     # Seccomp BPF syscall allowlist
  example_target.cpp     # Example sandboxed target process
  billing_tool.cpp       # Sandboxed billing data accessor

docs/
  THREAT_MODEL.md        # 16 attack scenarios with defense classification
```

---

## Quick Start

```bash
npm install
node node_modules/typescript/bin/tsc --noEmit   # type check
node node_modules/typescript/bin/tsc             # build

# Run all test suites (99 total tests)
npm test

# Or run individual test suites
node dist/test/scenarios.test.js      # 21 scenario tests
node dist/test/adversarial.test.js    # 44 adversarial security tests
node dist/test/integration.test.js    # 8 boundary pipeline integration tests
node dist/test/session-taint.test.js  # 26 session taint & transformation tests

# Run the piggybacking demo (4 scenarios)
node dist/demo/run-piggyback-demo.js
```

### Wire a real model

Set `GROQ_API_KEY` in your environment (or configure another provider in `src/model.ts`):

```bash
export GROQ_API_KEY=gsk_...
export HARNESS_CONFIG=./harness.config.json
node dist/run-agent.js "your query here"
```

### Configuration

`harness.config.json`:
```json
{
  "killSwitchPath": "./.kill",
  "budgetLimits": { "fetch_url": 20, "send_email": 5, "read_billing": 20 },
  "egressAllowlist": ["example.com", "api.example.com"]
}
```

### Build the C++ sandbox (Linux only)

```bash
cd native && make
sudo ./sandbox_launcher ./example_target
```

Requires `CAP_SYS_ADMIN` for `unshare(CLONE_NEWNET)`. In Docker: `--cap-add=SYS_ADMIN`.

---

## Test Results

```
scenarios.test.ts:      21/21 PASS (SSRF, injection, budget, kill switch, files, MCP, memory, subagent)
adversarial.test.ts:    44/44 PASS (SSRF ×15, piggybacking ×9, authorization ×5, MCP ×5, files ×5, kill switch ×5)
integration.test.ts:     8/8  PASS (Full boundary pipeline: policy, schema, provenance, gateway, kill switch, budget)
session-taint.test.ts:  26/26 PASS (Session lifecycle, monotonic classification/trust, multi-turn taint, Base64/Hex transforms)
-------------------------------------------------------------------------------------------------------------
Total:                  99/99 passing (98 runnable on Windows, 1 Linux sandbox test skipped on Windows)
```

---

## Honest Limitations

- **No General Semantic Exfiltration Detection**: This project does not provide general semantic exfiltration detection (e.g. natural language paraphrasing, steganography, or LLM summarization of secrets). It deterministically prevents exfiltration via exact matches, URL encoding, Base64 (standard, unpadded, URL-safe), and Hex encoding of tracked sensitive data tokens and enforces monotonic session-level classification/provenance policies.
- `sanitizer.ts` is a heuristic tripwire, not a security boundary. The real prompt-injection defense is the structural `Untrusted<T>` provenance tracking.
- The C++ sandbox demonstrates the correct architecture (seccomp + namespaces + resource limits) but lacks signal handling and cleanup on partial failure. Production workloads should use gVisor or Firecracker.
- `ModelDrivenCaller` reflects the general shape of tool-calling APIs. Verify against the exact SDK version before deploying.
- HTTPS request bodies are not inspectable at the TLS layer without a terminating proxy — P-EXFIL-001 applies to plaintext body content passed through the gateway API.
- See `docs/THREAT_MODEL.md` for the full threat model including not-fully-solved threats.
