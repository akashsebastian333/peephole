# Integrations

Peephole is a **plugin for coding agents**. The engine is one static Go binary:
it reads a proposed tool call as JSON on stdin and returns **allow**, **ask**,
or **deny**. What differs per host is only how that decision is wired.

Install the binary first (see the root [README](../README.md)) so `peephole` is
on `PATH`, or put an absolute path in the host's `command` field. Then merge
the drop-in for your host. **Do not** `cp` a settings file over an existing
one that already has model keys, MCP servers, or other hooks — merge the
`hooks` object in.

Two facts:

1. **`peephole hook --exit2`** is the portable block. Exit code 2 plus a
   reason on stderr is what Gemini CLI, Codex, Qwen Code, Crush, Cursor, and
   OpenCode honor. Claude Code uses the richer JSON dialect
   (`permissionDecision`) without `--exit2`.
2. **A true block before the file is saved** exists only where the host has a
   pre-tool hook or an in-process plugin. MCP, LSP, and git fire later
   (advisory, or at commit). **Ask** on `--exit2` hosts is exit 0 plus a
   stderr `REVIEW` line — the write is **allowed**.

| Host | Config in this folder | When it runs | Blocks the write? |
|---|---|---|---|
| Claude Code | plugin marketplace (not a file here) | PreToolUse | **Yes** (deny); ask is a prompt |
| Grok Code | plugin marketplace (not a file here) | PreToolUse | **Yes** (deny); ask is allow |
| Gemini CLI | `gemini-cli.settings.json` | BeforeTool | **Yes** (deny only) |
| Codex CLI | `codex.hooks.json` | PreToolUse (Bash, `apply_patch`, MCP, other local tools) | **Yes** (deny only), after you **trust** the hook in `/hooks` |
| Cursor | `cursor.hooks.json` | preToolUse + beforeShellExecution + beforeMCPExecution | **Yes** on those agent tools. Tab / GUI edits are after the fact — use git |
| OpenCode | `opencode-plugin.ts` | `tool.execute.before` | **Yes** (throws on exit 2). Subagent tool calls may not fire the plugin |
| Qwen Code | `qwen-code.settings.json` | PreToolUse | **Yes** (deny only) |
| Crush | `crush.json` | PreToolUse | **Yes** (deny only) |
| Any git repo | `git-pre-commit` | commit | **Yes**, at commit (`--no-verify` skips) |
| MCP editors | `mcp.json` | model-called `scan_code` | Advisory |
| LSP editors | `peephole lsp` | document diagnostics | Advisory |

---

## Claude Code

Marketplace install registers hooks automatically. Default mode is `guided`.
That is the only host that surfaces **ask** as an approval prompt.

```
/plugin marketplace add akashsebastian333/peephole
/plugin install peephole@peephole
```

---

## Grok Code

Marketplace install registers the same `hooks/hooks.json` and `skills/`.
`--trust` is required: without it, Grok leaves hooks inactive.

Grok maps `Write`/`Edit` to `search_replace` and `Bash` to
`run_terminal_command`; native `write` is a separate tool. The engine
accepts Grok camelCase stdin (`hookEventName`, `toolName`, `toolInput`)
and, on that dialect only, emits top-level `decision` (deny blocks; ask
is allow — Grok has no ask prompt). Claude stdin stays
`permissionDecision` only, so ask is still a prompt. SessionStart /
UserPromptSubmit stdout is observe-only on Grok; the write-time deny
still stands.

```
grok plugin marketplace add akashsebastian333/peephole
grok plugin install peephole --trust
```

Restart Grok once.

---

## Gemini CLI

**File:** `gemini-cli.settings.json`  
**Merge into:** `.gemini/settings.json` (project) or `~/.gemini/settings.json`

Event is `BeforeTool`. Matcher `*` is Gemini's all-tools wildcard. `timeout`
is **milliseconds** (5000 = 5s). Exit 2 blocks the tool; the turn continues.

Copying this file wholesale will wipe other Gemini settings. Merge the
`hooks` key.

```sh
mkdir -p .gemini
# merge hooks from integrations/gemini-cli.settings.json into .gemini/settings.json
```

---

## Codex CLI

**File:** `codex.hooks.json`  
**Copy to:** `~/.codex/hooks.json` or `<repo>/.codex/hooks.json`

Codex loads every matching `hooks.json` next to a config layer. Project
hooks run only in a **trusted** `.codex/` layer. New or changed hooks are
skipped until you review them with `/hooks`.

`PreToolUse` can intercept Bash, `apply_patch` (match as `apply_patch`,
`Edit`, or `Write`), MCP tools, and other local function tools. Hosted tools
such as WebSearch are not on that path. Treat it as a guardrail, not a
complete boundary.

Timeout in this file is **seconds**. Exit 2 or
`permissionDecision: deny` both block.

```sh
mkdir -p .codex && cp integrations/codex.hooks.json .codex/hooks.json
```

Then open Codex and **trust** the hook. To turn hooks off: `[features] hooks
= false` in `config.toml` (they are on by default).

---

## Cursor

**File:** `cursor.hooks.json`  
**Copy to:** `.cursor/hooks.json` (project) or `~/.cursor/hooks.json` (user)

`timeout` is **seconds**. `failClosed: true` means a crash or timeout
**blocks** instead of failing open.

Three events:

- `preToolUse` — agent tools (Write, Shell, MCP, Task, …)
- `beforeShellExecution` — terminal commands
- `beforeMCPExecution` — MCP tools

Cursor **Tab** completions and some GUI edits use `afterFileEdit` /
`afterTabFileEdit`, which fire **after** bytes are written. Use
`git-pre-commit` as the backstop. Exit 2 is a deny.

```sh
mkdir -p .cursor && cp integrations/cursor.hooks.json .cursor/hooks.json
```

---

## OpenCode

**File:** `opencode-plugin.ts`  
**Copy to:** `.opencode/plugins/peephole.ts` (plural **plugins**)

This is an in-process plugin, not a JSON hook. On `tool.execute.before` it
sends JSON to `peephole hook --exit2` on stdin. Exit 2 throws, which
OpenCode treats as a hard abort.

The official plugin dirs are `.opencode/plugins/` and
`~/.config/opencode/plugins/`. The binary must be on `PATH` as `peephole`.
Subagent tool calls may not hit this hook — use git pre-commit.

```sh
mkdir -p .opencode/plugins
cp integrations/opencode-plugin.ts .opencode/plugins/peephole.ts
```

---

## Qwen Code

**File:** `qwen-code.settings.json`  
**Merge into:** `.qwen/settings.json` (project) or `~/.qwen/settings.json`
(user). Not a root `settings.json`.

`timeout` is **milliseconds**. Exit 2 blocks. Merge `hooks`; do not replace
a file that already has `model` / `modelProviders`.

```sh
mkdir -p .qwen
# merge hooks from integrations/qwen-code.settings.json into .qwen/settings.json
```

---

## Crush

**File:** `crush.json`  
**Merge `hooks` into:** project `crush.json` / `.crush.json`, or
`~/.config/crush/crush.json`

Charm Crush uses a flat `command` string (not a nested hooks array).
`timeout` is **seconds** (default 30). Exit 2 plus stderr is a deny.
Crush stdin names the event `event` (not `hook_event_name`); peephole
accepts both. Tool names are lowercase (`bash`, `write`, `edit`).

Copying this file wholesale will wipe providers and other Crush config.
Merge the `hooks` object.

Crush v0.67+ runs hooks through an embedded POSIX shell, including on
Windows — Git Bash is not required. `peephole` must be on `PATH`.

```sh
# merge hooks from integrations/crush.json into your crush.json
```

---

## git pre-commit (any repo, any agent)

**File:** `git-pre-commit`  
**Copy to:** `.git/hooks/pre-commit` and `chmod +x`

```sh
cp integrations/git-pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Runs `peephole scan --gate --staged`. High-confidence findings, unreadable
staged paths, or a missing `peephole` binary exit 2 and block the commit.
`--no-verify` skips the hook. This is a real block at commit time, not
write time. Useful for Aider and any agent that commits as it goes, and as
a backstop for editors that cannot veto an edit.

---

## MCP (advisory)

**File:** `mcp.json`  
**Copy the server entry into:** the host's MCP config (Claude Code
`.mcp.json`, Cursor MCP settings, etc.)

```json
{ "mcpServers": { "peephole": { "command": "peephole", "args": ["mcp"] } } }
```

`peephole mcp` is a stdio server. The model can call `scan_code` before it
writes. MCP cannot intercept the host's file tools, so this does **not**
block a write on its own. Pair it with the git pre-commit hook.

---

## LSP (advisory)

No drop-in file; point the editor at:

```
peephole lsp
```

High findings are errors, medium are warnings. Squiggles only — the editor
still saves. Use git pre-commit if you need a block.

Point any editor that takes a generic language-server command at
`peephole lsp`. Zed's `lsp.*` settings only reconfigure servers an
extension already registered, so that snippet does not start peephole.

---

## Hosts without a working pre-tool hook

These have no verified deny contract today. Use `git-pre-commit` plus MCP or
LSP; do not expect a write to be aborted.

- **Cline** — approvals are an in-process SDK callback, not exit 2.
- **Block Goose** — no external pre-tool hook.
- **Sourcegraph Amp / OpenHands** — plugin shape is not verified.

---

## How a deny looks

On `--exit2` hosts: process exits 2, stderr is the reason, the tool does not
run.

On Claude Code: stdout JSON with `permissionDecision: "deny"` and a reason
that includes the secure pattern to write instead.

`--exit2` **ask** is not a prompt: the process exits 0 and the host
continues. Guided mode on those hosts is log-plus-stderr, not a block.
Use Claude Code if the org needs a human approval dialog.
