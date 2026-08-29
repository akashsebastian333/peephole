# Changelog

All notable changes are listed here. The project follows
[Semantic Versioning](https://semver.org/).

## [0.5.1] - 2026-08

Plugin for coding agents: steers the write, can ask or deny before a file is
saved, so they ship secure code.

### Added

- Claude Code plugin (`guided` default) and a standalone Go binary for Gemini
  CLI, Codex, Cursor, OpenCode, Qwen Code, Crush, git pre-commit, MCP, and LSP.
  Crush stdin `event` is accepted (official Crush payload; not only
  `hook_event_name`).
- Grok Code marketplace plugin: `grok plugin marketplace add
  akashsebastian333/peephole` then `grok plugin install peephole --trust`.
  Deny blocks at PreToolUse; Grok has no ask prompt.
- Write-time presence scan plus Python/JS/Go/Rust cross-line taint (SQLi,
  command injection, eval/exec, XSS, pickle/yaml, path traversal, secrets, weak
  crypto, SSTI, JWT verify-off, SSRF, exfil).
- Modes: `guided`, `audit`, `strict`, `hardened`, `off`. Org policy can only
  raise the floor.
- Missing-guard review (IDOR, CSRF, races, business logic, rate-limit) at Stop
  and on commit, using the host agent.
- Tamper-evident decision log, 30-day retention, 10MB + one archive cap.
- Fleet installers in `deploy/`, org policy and custom rules
  ([docs/ENTERPRISE.md](docs/ENTERPRISE.md)), threat model and architecture
  docs.

### Detection

- Shared slice: peephole 45/45, 0/40 false positives. SAST slice 28/28.
- Live Haiku n=20: 0% requested vulns landed. Sonnet 0%, Kimi 0%, GLM 10%
  (two saved artifacts; current detector flags both as high).

### Security

- Binaries built on go1.26.6. Release is gated on tests, KB freshness, version
  consistency, govulncheck on an unstripped build, and a toolchain pin check.
- `peephole selfcheck` verifies the binary and the pinned hook/skill files.
- Plugin manifest is metadata only. Claude Code auto-loads `hooks/hooks.json`
  and `skills/`.

[0.5.1]: https://github.com/akashsebastian333/peephole/releases/tag/v0.5.1
