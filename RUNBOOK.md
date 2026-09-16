# RUNBOOK — From Zero to Running Agent

This assumes you have never used a terminal, VS Code, or Node.js before. Every step says exactly
what to type and what you should see. If something doesn't match what's described, stop there —
that's the point where something needs fixing before moving on.

---

## Part 0 — Words this runbook uses

- **Terminal** — a text window where you type commands instead of clicking things. VS Code has
  one built in.
- **Terminal prompt / `$`** — when a line below starts with `$`, that's a command to type. Don't
  type the `$` itself.
- **Repo / project folder** — the folder you get from unzipping `agent-harness-project.zip`.
- **Build** — turning the TypeScript source files (`.ts`) into plain JavaScript files (`.js`) that
  Node.js can actually run. TypeScript is not directly runnable; the build step is not optional.
- **Compile** — the same idea for the C++ files: turning `.cpp` source into an actual runnable
  program.

---

## Part 1 — Install the tools you need

### 1.1 Install Node.js

- Go to https://nodejs.org
- Download the **LTS** version (not "Current") for your operating system.
- Run the installer, click through the defaults.
- Verify it worked: open a terminal (see 1.3 below if you don't know how) and type:
  ```
  $ node -v
  ```
  You should see something like `v20.11.0`. If you see "command not found," the install didn't
  complete or your terminal needs restarting — close and reopen it, then try again.

### 1.2 Install VS Code

- Go to https://code.visualstudio.com, download and install it for your OS.

### 1.3 Opening a terminal

- **Inside VS Code (recommended):** once you have the project folder open (Part 2), go to the top
  menu → **Terminal → New Terminal**. A panel opens at the bottom of the window — that's your
  terminal, already pointed at your project folder.
- Every `$` command below is meant to be typed into that panel.

### 1.4 A C++ compiler (only needed for Part 6 — the C++ sandbox)

- **This only works on Linux** (including WSL on Windows, or a Linux VM on Mac). The C++ code uses
  Linux-specific features (network namespaces, seccomp) that don't exist on macOS or Windows
  directly.
- On Ubuntu/Debian-based Linux:
  ```
  $ sudo apt-get update
  $ sudo apt-get install -y g++ libseccomp-dev
  ```
- If you're on Windows or Mac and don't want to set up WSL/a VM right now, that's fine — skip
  Part 6 entirely. Everything in Parts 1–5 (the actual agent, the TypeScript defenses) runs fine
  without it; only `read_billing`'s sandboxed execution needs the C++ side.

---

## Part 2 — Get the project into VS Code

1. Download `agent-harness-project.zip`.
2. Unzip it: on Windows, right-click → "Extract All". On Mac, double-click it. On Linux,
   `unzip agent-harness-project.zip`.
3. Open VS Code.
4. Top menu → **File → Open Folder** → select the unzipped folder (the one containing
   `package.json`, `src/`, `native/`, etc. directly inside it — not a folder above or below that).
5. You should see this in the Explorer sidebar on the left:
   ```
   demo/
   native/
   sandbox-files/
   src/
   test/
   package.json
   run-agent.ts
   tsconfig.json
   README.md
   ```
   If you see a single folder instead of these files, you opened one level too high — open the
   inner folder instead.

---

## Part 3 — Install the project's dependencies

Open the terminal inside VS Code (Part 1.3). Type:

```
$ npm install
```

What this does: reads `package.json`, downloads the libraries this project needs (TypeScript,
type definitions, `ipaddr.js` for IP validation, and `ajv` for JSON Schema validation), and puts
them in a new `node_modules` folder. This can take 10–60 seconds. You'll see a progress bar and
then a summary line like `added N packages`. That means it worked. A wall of red text means
something failed — usually a network issue; try it again.

---

## Part 4 — Build and test the TypeScript harness (no API key needed yet)

### 4.1 Type-check

```
$ npx tsc --noEmit
```
This checks every `.ts` file for errors without producing output files — it's the cheapest way to
confirm nothing is broken. **No output at all means success.** If you see red error text, something
in the code doesn't match — this shouldn't happen with the project as given, so if it does, it's
worth re-reading the exact error message; it will name the file and line.

### 4.2 Build

```
$ npx tsc
```
Same check, but this time it actually writes runnable JavaScript into a new `dist/` folder. Also
silent on success.

### 4.3 Run the scenario test suite

```
$ node dist/test/scenarios.test.js
```

Runs 21 real security scenarios against the actual harness code — no mocking, no pretending.
You should see a wall of lines starting with `PASS:`, ending in:
```
All runnable scenario tests passed.
```
If you see `SKIP: C++ sandbox not built` partway through — that's expected and fine if you
haven't done Part 6 yet.

**What this proves, concretely:**
- a request to `169.254.169.254` (cloud metadata) gets denied
- a privileged action derived from untrusted input gets denied
- a tool called past its budget gets denied
- an operator kill switch halts every subsequent call
- path traversal (`../../../../etc/passwd`) is denied; legitimate paths work
- prompt-injection phrases are flagged; clean text is not
- MCP tool rug-pull (description changed post-approval) is detected and denied
- untrusted-derived memory write is denied; trusted write is allowed
- scoped credentials are isolated — pricing scope can't use support credentials
- subagent outputs are wrapped as untrusted automatically

### 4.4 Run the adversarial security test suite (44 checks)

```
$ node dist/test/adversarial.test.js
```

Runs 44 adversarial security checks covering:
- SSRF × 15 (loopback, private CIDRs, IPv6, IPv4-mapped IPv6, redirect SSRF, non-HTTP scheme,
  unapproved port, malformed IP)
- Network Piggybacking × 9 (secret/confidential data egress, untrusted provenance, query param
  secret scan, POST body scan, oversized request, rate limit, budget exhaustion)
- Tool Authorization × 5 (scope enforcement, untrusted-derived privilege, unknown tool, schema)
- MCP Integrity × 5 (unchanged manifest, changed description, schema, endpoint, permissions)
- File/Approval × 5 (traversal, absolute path, URL-encoded, null byte, content hash tamper)
- Kill Switch × 5 (AbortSignal cancellation, domain matching, phase policy, taint propagation,
  sandbox controls)

Expected output: `ALL 44 ADVERSARIAL SECURITY CHECKS PASSED SUCCESSFULLY!`

### 4.5 Run the piggybacking demo

```
$ node dist/demo/run-piggyback-demo.js
```

Demonstrates the P-EXFIL-001 network piggybacking defense with three scenarios:
1. Agent reads `public-data.txt` → sends to allowed API → **ALLOWED** (legitimate request)
2. Agent reads `secret.txt` (SECRET) → attempts to send to allowed API → **BLOCKED** by
   P-EXFIL-001 even though the destination domain is on the allowlist
3. Agent embeds secret in POST body → **BLOCKED** by body inspection

This is the most important demo to show live — it proves the harness defends against attacks
that would completely bypass a naive domain allowlist.

---

## Part 5 — Run the real agent against a real model

This step needs a model API key. Two options:

**Free, no credit card (Groq):**
1. Go to https://console.groq.com/keys, sign up with just an email.
2. Create a key, copy it.
3. Set it:
   ```
   $ export GROQ_API_KEY=gsk_your-actual-key-here
   ```
   (Windows `cmd.exe`: `set GROQ_API_KEY=gsk_...` — PowerShell: `$env:GROQ_API_KEY="gsk_..."`)

This project's `src/model.ts` is wired to Groq's free tier by default (Llama 3.3 70B, tool-calling
supported, no cost). If you'd rather use Anthropic's API instead, see the note at the end of this
section.

4. Run the agent:
   ```
   $ node dist/run-agent.js "Summarize the pricing page at example.com"
   ```

**If you get a "model does not exist" error:** free-tier providers rotate their model lineup
fairly often — this project defaults to `openai/gpt-oss-120b` on Groq, but if that's been retired
by the time you read this, check what's currently live and override it without touching code:
```
$ curl https://api.groq.com/openai/v1/models -H "Authorization: Bearer %GROQ_API_KEY%"
$ set GROQ_MODEL=whatever-model-id-you-see-in-that-list
```
(the `curl` line above is Windows `cmd.exe` syntax for reading an env var inline; on Mac/Linux use
`$GROQ_API_KEY` instead of `%GROQ_API_KEY%`)
4. You'll see, in order:
   - `[mcp-trust]` lines — the simulated tool-poisoning check running at startup
   - `[interagent]` — the subagent boundary demo running
   - the agent's actual tool calls and reasoning, streamed from the real model
   - `--- final observations ---` followed by what it found
   - `[verification]` and `[memory]` lines — the review-then-persist step at the end

If you get an authentication error, double check the key was exported in *this* terminal window
(it doesn't carry over to a new terminal tab automatically). Free-tier rate limits are generous
but real — if you hit one, wait a minute and try again.

**Using Anthropic's API instead:** `npm install @anthropic-ai/sdk`, then swap `src/model.ts` back
to call `client.messages.create` with Anthropic's `tools`/`tool_use` shape instead of Groq's
OpenAI-style `chat.completions.create`. The rest of the harness (`boundary.ts`, `registry.ts`,
everything that actually enforces the security rules) doesn't change either way — only the one
file that talks to a model does.

---

## Part 6 — The C++ sandbox (optional, Linux only)

```
$ cd native
$ make
```
You should see three `g++` compile lines with no errors, and three new files appear:
`sandbox_launcher`, `example_target`, `billing_tool`.

Run the standalone demo:
```
$ sudo ./sandbox_launcher ./example_target
```
(`sudo` is needed because network isolation and syscall filtering require elevated privileges.)
Expected output:
```
running under seccomp: no execve, no network syscalls available
```

Now go back to the project root and re-run the full test suite — this time the sandboxed
`read_billing` test won't skip:
```
$ cd ..
$ node dist/test/scenarios.test.js
```
Look for:
```
PASS: read_billing executed inside C++ sandbox — {"account_id":"ACC123","balance_usd":0}
```
That line means `read_billing` really did run inside an isolated Linux process — not a simulation
of one — invoked from the Node.js test through `child_process`.

---

## Part 7 — Try the zero-setup browser demo (for the interview room itself)

No build needed for this one:
```
$ open demo/index.html      # Mac
$ start demo\index.html     # Windows
$ xdg-open demo/index.html  # Linux
```
Or just double-click the file. Click through the scenario buttons on the left and watch the
pipeline trace on the right — this is the fast, visual version to actually show someone live;
the terminal output from Parts 4–6 is the "here's the real code behind it" follow-up.

---

## Does this cover everything we discussed? Final honest answer.

**Yes, except one category, and one important scope limit — both worth naming yourself.**

| Incident | Covered? |
|---|---|
| Network Piggybacking / SSRF + DNS rebinding | ✅ Live, tested |
| Tool Over-Privilege | ✅ Live, tested |
| Cascading Failures / Denial of Wallet | ✅ Live, tested |
| Rogue Agents (kill switch) | ✅ Live, tested |
| Indirect Prompt Injection | ✅ Live, tested (both the sanitizer scan and the privileged-call block) |
| Identity & Privilege Abuse | ✅ Live, tested (scoped credentials) |
| Path Traversal / Sandbox Escape | ✅ Live, tested (new `read_file` tool) |
| MCP Tool Poisoning / Rug Pull | ✅ Live, tested |
| Memory & Context Poisoning | ✅ Live, tested |
| Insecure Inter-Agent Communication | ✅ Live, tested |
| Human-Agent Trust Exploitation | ✅ Wired (review step runs before persistence) |
| Unexpected Code Execution / RCE | ⚠️ Real, but scoped to one tool — see below |
| **Agentic Supply Chain Vulnerabilities** | ❌ Not implemented — see below |

**Why RCE containment is "real but scoped":** only `read_billing` actually executes inside the C++
sandbox. Extending that to *every* tool would mean running a full Node.js process tree inside the
same minimal seccomp filter — and Node itself needs dozens of syscalls (memory mapping, epoll,
file descriptor polling) that a tight filter can't allow without mostly defeating the point. This
is exactly why production systems (as discussed earlier) use gVisor or Firecracker instead of
hand-rolled seccomp for isolating an entire language runtime — seccomp alone is the right tool for
isolating one small, purpose-built binary like `billing_tool`, not a whole Node process. Naming
this trade-off yourself is a stronger answer than claiming full coverage.

**Why supply chain isn't implemented:** this category (malicious/compromised npm or MCP packages)
is fundamentally about your build and deployment pipeline — dependency pinning, provenance
verification, install-time review — not something a single harness file can meaningfully enforce
at runtime. It's a real gap, and the honest fix lives outside this project's scope, in CI/CD and
package management practices.
