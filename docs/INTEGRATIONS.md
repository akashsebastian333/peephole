# Using peephole with other coding agents and IDEs

Peephole's engine is a single static binary: it reads a proposed tool call (file
write / shell command) as JSON on stdin and returns a decision. Nothing about the
analysis is Claude-specific. What differs per agent is the *integration point*.

Two facts shape everything below:

1. **`exit code 2` + a reason on stderr is the universal block signal** — every
   hook-based agent honors it. Run peephole's hook with `--exit2` and one binary
   blocks all of them. (Without the flag it emits Claude Code's richer
   `permissionDecision` JSON, which the Claude-compatible agents also honor.)
2. **True pre-write blocking exists only in native pre-tool hooks and in-process
   plugins.** MCP, LSP, git, and file-watch integrations are advisory or
   reactive. This guide is honest about which is which.

## Coverage at a glance

| Integration | Blocks before write? | Agents |
|---|---|---|
| **Native pre-tool hook** (`peephole hook --exit2`) | **Yes, hard** | Claude Code, Gemini CLI, OpenAI Codex CLI, Qwen Code, Charm Crush, Block Goose, Cursor (shell + MCP paths) |
| **In-process plugin** (shells to `peephole hook`) | **Yes, hard** | OpenCode, Sourcegraph Amp, OpenHands, Cline (SDK) |
| **git pre-commit** (`peephole scan --gate --staged`) | **Yes, at commit** | Universal — any git repo (Aider auto-commits, so effectively per edit) |
| **MCP server** *(planned: `peephole mcp`)* | No — advisory | Windsurf, Trae, Tongyi Lingma, Comate, CodeGeeX, iFlyCode, Qoder, + MCP mode of every CLI agent |
| **LSP diagnostics** *(planned: `peephole lsp`)* | No — warn only | Zed, JetBrains AI, VS Code / Copilot |

Editors (VS Code/Copilot, Cursor file-edits, Windsurf, Zed) mostly cannot veto an
AI *edit* synchronously — they expose only post-hoc events or diagnostics. For
those, the honest gate is the git pre-commit hook (blocks the commit) or the
planned MCP/LSP advisory. Shell-path writes (`cat > f <<EOF`, redirects) *are*
blocked pre-write wherever a shell-execution hook exists (e.g. Cursor).

## Native pre-tool hook agents

Put the peephole binary (or the `hooks/peephole.sh` launcher) on your `PATH`, or
use an absolute path in the `command`. All use `peephole hook --exit2`.

**Gemini CLI** — `.gemini/settings.json` (project) or `~/.gemini/settings.json`:

```json
{ "hooks": { "BeforeTool": [ { "matcher": ".*",
  "hooks": [ { "type": "command", "command": "peephole hook --exit2", "timeout": 5000 } ] } ] } }
```

**OpenAI Codex CLI** — `~/.codex/hooks.json` (or repo `.codex/hooks.json`):

```json
{ "hooks": { "PreToolUse": [ { "hooks": [ { "type": "command", "command": "peephole hook --exit2" } ] } ] } }
```

**Qwen Code** — `settings.json`:

```json
{ "hooks": { "PreToolUse": [ { "matcher": ".*",
  "hooks": [ { "type": "command", "command": "peephole hook --exit2" } ] } ] } }
```

**Charm Crush** — `crush.json` (project) or `~/.config/crush/crush.json`:

```json
{ "hooks": { "PreToolUse": [ { "matcher": ".*", "command": "peephole hook --exit2", "timeout": 10 } ] } }
```

**Block Goose** — a plugin dir with `hooks/hooks.json`:

```json
{ "hooks": { "PreToolUse": [ { "matcher": ".*",
  "hooks": [ { "type": "command", "command": "peephole hook --exit2", "timeout": 10 } ] } ] } }
```

**Cursor** — `.cursor/hooks.json` (blocks shell + MCP paths pre-write; file edits
are retro-scanned):

```json
{ "version": 1, "hooks": {
  "preToolUse": [ { "command": "peephole hook --exit2", "matcher": "Write|Edit|MultiEdit", "timeout": 5000 } ],
  "beforeShellExecution": [ { "command": "peephole hook --exit2" } ] } }
```

## In-process plugin agents

**OpenCode** — `.opencode/plugin/peephole.ts` (throws to hard-abort the tool):

```ts
export const Peephole = async ({ $ }) => ({
  "tool.execute.before": async (input, output) => {
    const ev = JSON.stringify({ hook_event_name: "PreToolUse", tool_name: input.tool, tool_input: output.args });
    const p = await $`echo ${ev} | peephole hook --exit2`.quiet().nothrow();
    if (p.exitCode === 2) throw new Error(p.stderr.toString() || "blocked by peephole");
  },
});
```

**Sourcegraph Amp** — `~/.config/amp/plugins/peephole.ts`, register a `tool.call`
handler that shells to `peephole hook --exit2` and returns
`"reject-and-continue"` when the exit code is 2, else `"allow"`.

## Universal git pre-commit backstop

Works in any repo, with any agent (Aider auto-commits, so it fires per edit):

```sh
# .git/hooks/pre-commit   (chmod +x)
#!/bin/sh
peephole scan --gate --staged
```

`--gate` exits 2 (blocking the commit) when a staged file has a high-confidence
finding; `--no-verify` overrides. This is a real block, but at commit time rather
than write time.

## Ready-to-copy configs

The `integrations/` directory holds each of the above as a drop-in file.
