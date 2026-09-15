> **New here? Start with `RUNBOOK.md`** — it assumes zero prior experience with terminals, Node, or VS Code, and walks through every step to a fully running agent.

# Agent Harness — Demo + Real Wiring

This project now has three layers, in order of how real they are:

1. `demo/index.html` — the zero-setup interactive console (open it directly, no build).
2. `src/*.ts`, `run-agent.ts`, `test/` — a real TypeScript project you can build, run, and test.
3. `native/` — the C++ sandbox, as an actual two-process launcher + target, not just a demo.

## Step 1 — Set up the project

```
npm install
npx tsc --noEmit        # confirm everything compiles clean before running anything
```

## Step 2 — Wire a real model

`src/model.ts`'s `ModelDrivenCaller` sends the conversation + tool schemas to the model and turns
its `tool_use` response into a `ToolCall`. Set `ANTHROPIC_API_KEY` in your environment. The one
thing you still have to judge yourself: `pendingUntrusted` — it's set to true right after a
`fetch_url` call, meaning "the next tool call may be influenced by content just read from
outside." Tune this if your agent has more ways of reading untrusted content (a subagent result,
a database row someone else wrote).

## Step 3 — Real tools

`src/tools.ts` has `createFetchUrlTool`, `sendEmailTool`, `readBillingTool`. Wire `send_email` and
`read_billing` to your actual providers where marked.

## Step 4 — Config-driven killswitch/budget/egress

`src/config.ts` loads from `HARNESS_CONFIG` (default `/etc/agent/harness.config.json`), e.g.:

```json
{
  "killSwitchPath": "/etc/agent/HALT",
  "budgetLimits": { "fetch_url": 20, "send_email": 5, "read_billing": 20 },
  "egressAllowlist": ["example.com"]
}
```

## Step 5 — The C++ sandbox actually executes something now

`native/sandbox_executor.cpp` is a **launcher**: it isolates the network namespace and sets
resource limits, then `execve`s into a target binary. It does *not* load a seccomp filter itself
— `native/sandbox_filter.hpp`'s `applySyscallFilter()` is meant to be called by the **target**
binary, as the first line of its own `main()` (see `native/example_target.cpp`). This two-process
split exists because seccomp filters are inherited across `execve`; loading one in the launcher
would mean either allowing `execve` (which the child then inherits too) or blocking the one
`execve` the launcher itself needs. Real container runtimes split this the same way.

## Step 6 — Build the sandbox

```
cd native && make
sudo ./sandbox_launcher ./example_target
```

`unshare(CLONE_NEWNET)` and seccomp need `CAP_SYS_ADMIN`. In Docker: `--cap-add=SYS_ADMIN` (or
`--privileged`, worse). State this trade-off yourself if asked — most production setups use
gVisor or Firecracker instead of hand-rolled seccomp for exactly this reason.

## Step 7 — Test against the live boundary

```
npm run build
node dist/test/scenarios.test.js
```

Replays SSRF, injected-privileged-call, budget-exhaustion, and kill-switch scenarios as real calls
through `ExecutionBoundary`, not just log lines in the HTML demo.

## Step 8 — Durable logging

`src/logger.ts` appends every `ALLOW`/`DENY` decision as a JSON line to `HARNESS_LOG` (default
`./harness-events.log`). `boundary.ts` calls it on every `run()`. Point your existing log
pipeline/SIEM at this file in production.

## Run it

```
npm run build
export ANTHROPIC_API_KEY=...
export HARNESS_CONFIG=/etc/agent/harness.config.json
node dist/run-agent.js "your query here"
```

## Honest limitations, worth stating yourself if asked

- `sanitizer.ts`'s pattern list is a tripwire, not the real defense — `untrusted.ts` doing the
  structural separation is the actual defense.
- `mcp-trust.ts`'s hash-pinning is an original design for the described attack class, not a
  documented industry-standard fix.
- The C++ launcher/target split is the correct *shape*, but this build has no signal handling,
  no cleanup on partial failure, and no capability drops beyond the syscall filter shown.
- `ModelDrivenCaller` reflects the general shape of tool-calling APIs, not a guaranteed-exact
  match to the current SDK version — check the docs before relying on exact method/type names.
