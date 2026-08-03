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
| **Native pre-tool hook** (`peephole hook --exit2`) | **Yes, hard** (deny) | Claude Code, Gemini CLI, OpenAI Codex CLI, Qwen Code, Charm Crush, Cursor (shell + MCP paths) |
| **In-process plugin** (shells to `peephole hook`) | **Yes, hard** | OpenCode |
| **git pre-commit** (`peephole scan --gate --staged`) | **Yes, at commit** | Universal — any git repo (Aider auto-commits, so effectively per edit) |
| **MCP server** (`peephole mcp`) | No — advisory | Windsurf, Trae, Tongyi Lingma, Comate, CodeGeeX, iFlyCode, Qoder, + MCP mode of every CLI agent |
| **LSP diagnostics** (`peephole lsp`) | No — warn only | Zed, JetBrains AI, VS Code / Copilot |
| **Unverified / no working hook** | Advisory + git backstop | Block Goose, Cline, Sourcegraph Amp, OpenHands (see caveats below) |

**Honest hook-host caveats.** A hook host hard-blocks only if it honors the block
signal. peephole emits **exit code 2** (plus the reason on stderr) under
`--exit2`, and the six native hosts above plus OpenCode's plugin honor it
(verified). But:

- **Block Goose** has no external pre-tool hook system (only in-process
  Always/Ask/Never permission modes), so a `hooks.json` is consumed by nothing —
  a config that installs cleanly and blocks nothing. Use the git pre-commit hook
  + `peephole mcp` (advisory) instead.
- **Cline** approves tools via an in-process SDK callback (`{approved:false}`),
  which an exit-2 process can't reach; a working plugin (mirroring
  `opencode-plugin.ts`, returning `{approved:false}` when peephole exits 2) is not
  yet shipped. Until it is, treat Cline as advisory + git backstop.
- **Sourcegraph Amp / OpenHands** plugins are not verified against the host's
  current deny contract — treat as unverified until a plugin is confirmed.
- **Exit-2 hosts enforce *deny* only.** A lower-confidence *ask* finding (e.g.
  `curl … | bash`, CWE-494) exits 0 (allow) on exit-code hosts; only Claude Code's
  native JSON dialect surfaces it as an approval prompt. So exit-2 hosts enforce a
  strictly smaller set (hard denies) than Claude Code.

Editors (VS Code/Copilot, Cursor file-edits, Windsurf, Zed) mostly cannot veto an
AI *edit* synchronously — they expose only post-hoc events or diagnostics. For
those, the honest gate is the git pre-commit hook (blocks the commit) or the
MCP/LSP advisory below. Shell-path writes (`cat > f <<EOF`, redirects) *are*
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

**Sourcegraph Amp** (unverified) — the sketch is a `~/.config/amp/plugins/peephole.ts`
`tool.call` handler that shells to `peephole hook --exit2` and rejects when the
exit code is 2, but the exact deny return value has not been verified against
Amp's current plugin API. Confirm it against Amp's docs before relying on it; use
the git pre-commit backstop meanwhile.

## MCP server (advisory — for editors that can't block)

Editors that consume MCP (Windsurf, Trae, Tongyi Lingma, Comate, CodeGeeX,
iFlyCode, Qoder, Cursor, and the MCP mode of any CLI agent) can call peephole's
`scan_code` tool to check code before writing it. This is **advisory** — the
model chooses to call it; MCP servers cannot intercept the host's file writes.
Pair it with the git pre-commit backstop for an actual block.

`peephole mcp` is a stdio MCP server. Register it (config shape varies slightly
per host; this is the common one, e.g. `~/.codeium/windsurf/mcp_config.json`,
`.cursor/mcp.json`):

```json
{ "mcpServers": { "peephole": { "command": "peephole", "args": ["mcp"] } } }
```

## LSP diagnostics (warn-only — inline findings in editors)

`peephole lsp` is a stdio language server that publishes each document's findings
as diagnostics (high = error, medium = warning), giving inline squiggles in Zed,
JetBrains, VS Code, and any LSP-capable editor. It annotates; it cannot block an
edit. Register it per the editor's "custom language server" setting, e.g. Zed:

```json
{ "lsp": { "peephole": { "binary": { "path": "peephole", "arguments": ["lsp"] } } } }
```

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
