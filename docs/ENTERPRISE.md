# Organization deployment and customization

How to roll peephole out to a team or company, raise the enforcement floor,
add your own rules, pin a version, and ship it through MDM. This is the
operator guide. Fleet installers live in [`deploy/`](../deploy/). Host wiring
lives in [`integrations/README.md`](../integrations/README.md).

Peephole is a **plugin for coding agents**. It shows the model the secure
pattern, then can ask or deny before a file is saved. It is not a whole-repo
SAST and not a compliance control. The audit log is tamper-*evident*, not
tamper-proof. Same-user processes (including the agent) can disable it.

---

## 1. Choose a mode for the org

| Mode | What happens | When to use it |
|---|---|---|
| `guided` | **Default.** Findings are asks. The developer sees the issue and decides. Self-protection and org-mandated CWEs still deny. | First rollout. Precision is not 100%; a wrong hard block is how security tools get uninstalled. |
| `audit` | Log only. Org-`enforce` CWEs and self-protection still deny. | Measure interruption rate before enforcing. |
| `strict` | Deny high-confidence CWEs. Ask on lower-confidence. The 3rd **consecutive** deny of the same CWE, or the 6th deny of any kind in the session, becomes ask; org-`enforce` and self-protect skip that budget. | Teams that already ran `guided` and accept the remaining false-positive rate. |
| `hardened` | Deny-by-default, including unreachable registries. Same deny budget as `strict` unless the CWE is org-`enforce`. | High-assurance repos, after `strict` is proven. |
| `off` | CWE scanning off. Self-protection still denies. Org-`enforce` does **not** fire unless `min_mode` is also set. | Incident response / explicit local waiver. |

Mode is **per project** (`.peephole/mode`), not a machine-wide setting. MDM
cannot set it. A developer can lower the local mode with `/peephole audit` or
`/peephole off` (human-typed). An org policy **committed in that repo** can
raise the floor (`min_mode`) so the effective mode is never weaker than
`strict` or `hardened`. It cannot lower a local mode that is already
stricter. The file is git and deletable — it is not fleet enforcement.

On path B the binary lives under `/usr/local/bin` or `C:\Program Files\peephole`,
so self-protect treats the grandparent directory (`/usr/local` or
`C:\Program Files`) as the plugin root and denies writes anywhere under it.

Recommended path: `guided` as the per-project default for two weeks → read
`peephole audit` (or `/sec-audit` if the plugin is installed) and developer
reports → `min_mode: strict` on the repos that can take it.

---

## 2. Two install paths — do not mix them

| Path | Who it is for | What MDM can do |
|---|---|---|
| **A. Claude Code plugin** | A developer machine | Almost nothing. `/plugin marketplace add` is a person in Claude Code, not an MDM payload. |
| **B. Fleet binary + managed hooks** | Org laptops | This is the MDM path. Install the pinned binary and point Claude Code's **managed** hooks at it. |

The binary is the same either way. The plugin is convenience for one human.
Fleet rollout is path B. **Pick one per machine.** If you move a laptop to
path B, uninstall the marketplace plugin
(`/plugin uninstall peephole@peephole`) so two hook processes do not run
on every write. Managed `enabledPlugins` can force-enable a plugin, but
the public marketplace is not a version pin — do not use that as the
fleet path.

### A. Developer plugin (not MDM)

```
/plugin marketplace add akashsebastian333/peephole
/plugin install peephole@peephole
```

Grok Code (hooks stay off until trusted):

```
grok plugin marketplace add akashsebastian333/peephole
grok plugin install peephole --trust
```

Restart Claude Code or Grok Code once. Marketplace tracks the public repo; it is not a
version pin. For a pin, use path B or vendor the plugin directory.

Do **not** set `allowManagedHooksOnly: true` on this path. That setting
blocks plugin hooks unless the plugin is also force-enabled in managed
`enabledPlugins`. You would install peephole and then silently disable it.

### B. Fleet binary (MDM)

Pin a tag. Do not float `latest`.

1. Pin a GitHub release. The installer downloads from
   `https://github.com/akashsebastian333/peephole/releases/download/v0.5.1/`
   with no token. You do **not** need `PEEPHOLE_BASE_URL`. Set that only if
   you already host a copy of that directory yourself.
2. Run [`deploy/install-unix.sh`](../deploy/install-unix.sh) as **root** or
   [`deploy/install-windows.ps1`](../deploy/install-windows.ps1) as **SYSTEM**.
   Both are idempotent — schedule them on every check-in.
3. Verify: `peephole version && peephole selfcheck`. Expect
   `peephole 0.5.1`, `181 rules, 605 patterns, 13 cross-line taint specs`,
   `integrity: OK`. `selfcheck` is binary integrity, and in a plugin tree
   also the pinned hook/skill files. Until `/status` shows the source you
   intended **and** a Write of known SQLi is gated, peephole is not
   deployed — MDM can still be green.

```sh
export PEEPHOLE_VERSION=v0.5.1
# macOS / Linux, as root:
sudo -E sh deploy/install-unix.sh
```

```powershell
$env:PEEPHOLE_VERSION = 'v0.5.1'
# Windows, as SYSTEM:
# contents of deploy/install-windows.ps1
```

The installer downloads the matching asset (`peephole-darwin-arm64`,
`peephole-linux-amd64`, `peephole-windows-amd64.exe`, …) **and**
`SHA256SUMS`, refuses to install on checksum mismatch, writes the binary to
`/usr/local/bin/peephole` or `%ProgramFiles%\peephole\peephole.exe`, and
drops Claude Code hook config in the **file-based** managed-settings
directory. Public GitHub needs no token. For a **private fork**, set
`PEEPHOLE_REPO` and `GH_TOKEN` (GitHub assets API), or host the tag
directory yourself and set `PEEPHOLE_BASE_URL`. Do not put a GitHub token
in an MDM payload if you can avoid it.

| OS | Directory (official; ignored if `/status` is `(remote)`, `(plist)`, or `(HKLM)` — see §3) |
|---|---|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.d/` |
| Linux | `/etc/claude-code/managed-settings.d/` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.d\` |

The installer checksums the download against `SHA256SUMS`, then writes a
small `manifest.sha256` next to the binary so `peephole selfcheck` can
confirm that file has not been replaced. A **running** hook treats a mismatch
as an integrity alarm and keeps enforcing. The **installer** exits non-zero
if `selfcheck` fails, so MDM reports the device as failed.

On fleet-only machines there is no `/sec-audit` skill; use `peephole audit`.

---

## 3. Deploy through MDM (Jamf, Iru / Kandji, Intune)

Peephole is a binary plus a Claude Code hook. MDM does **two jobs**, and they
are different payloads:

1. **Put the binary on disk** — the scripts in [`deploy/`](../deploy/).
2. **Make Claude Code call it** — managed `hooks`. That only works if those
   hooks live in the managed source Claude Code actually reads.

There is no peephole daemon, LaunchAgent, or Windows service. Rollback is
delete the binary and the hook file.

### Which Claude Code source wins

Claude Code uses **one** managed source and **ignores the others with no
warning** ([docs](https://code.claude.com/docs/en/managed-settings)). First
source that contains at least one policy key wins:

| Rank | Source | `/status` says | How it gets there |
|---|---|---|---|
| 1 | Server-managed | `(remote)` | claude.ai admin console, or a Claude apps gateway |
| 2 | MDM / OS policy | `(plist)` or `(HKLM)` | macOS `com.anthropic.claudecode` profile; Windows `HKLM\SOFTWARE\Policies\ClaudeCode` value **`Settings`** (REG_SZ JSON) |
| 3 | Files | `(file)`, `(drop-ins)`, or `(file + drop-ins)` | `managed-settings.json` **merged with** `managed-settings.d/*.json` |
| 4 | Windows HKCU | `(HKCU)` | User-writable fallback. Not an enforcement channel. |

**Inside the file source only**, `managed-settings.json` and every
`managed-settings.d/*.json` **merge** (later files win on scalar keys; lists
combine). That is why the installer drop-in still applies if you also deploy
Anthropic's Intune script that writes `managed-settings.json` — both are files.
A plist, HKLM policy, or server-managed payload is a *different* source and
**replaces** the files, including the installer drop-in.

Cloud / Anthropic-hosted Claude Code sessions **do not read** the laptop's
MDM profile or files. Policy for those sessions has to be server-managed.

Starter templates for Claude Code locks (not peephole) live in
[anthropics/claude-code examples/mdm](https://github.com/anthropics/claude-code/tree/main/examples/mdm)
(Jamf / Iru Custom Settings plist, Intune platform script, ADMX/GPO). They
are Anthropic's. Add peephole `hooks` to whichever of those sources `/status`
shows.

### Hook payload to paste into the winning source

Unix (`/usr/local/bin/peephole`). The installer writes this as
`10-peephole.json`. If `/status` is `(plist)` or `(HKLM)`, put this
`hooks` object in **that** payload (JSON for HKLM `Settings`; convert to
plist dicts/arrays for Jamf/Iru Custom Settings — do not paste JSON into
a `.plist` unchanged). If `/status` is `(remote)`, do **not** paste the
Unix laptop path into the org-wide console policy (Windows and
Anthropic-hosted cloud would get a path with no binary). Clear
server-managed keys so file/plist can win, or ship an OS-correct
`command`+`args` per OS cohort and expect the hook-approval dialog.

```json
{
  "hooks": {
    "SessionStart":       [{ "hooks": [{ "type": "command", "command": "/usr/local/bin/peephole", "args": ["hook"], "timeout": 10 }] }],
    "SubagentStart":      [{ "hooks": [{ "type": "command", "command": "/usr/local/bin/peephole", "args": ["hook"], "timeout": 10 }] }],
    "UserPromptSubmit":   [{ "hooks": [{ "type": "command", "command": "/usr/local/bin/peephole", "args": ["hook"], "timeout": 10 }] }],
    "PreToolUse":         [{ "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash|mcp__.*",
                             "hooks": [{ "type": "command", "command": "/usr/local/bin/peephole", "args": ["hook"], "timeout": 10 }] }],
    "PostToolUse":        [{ "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash",
                             "hooks": [{ "type": "command", "command": "/usr/local/bin/peephole", "args": ["hook"], "timeout": 10 }] }],
    "Stop":               [{ "hooks": [{ "type": "command", "command": "/usr/local/bin/peephole", "args": ["hook"], "timeout": 10 }] }],
    "ConfigChange":       [{ "hooks": [{ "type": "command", "command": "/usr/local/bin/peephole", "args": ["hook"], "timeout": 10 }] }],
    "InstructionsLoaded": [{ "hooks": [{ "type": "command", "command": "/usr/local/bin/peephole", "args": ["hook"], "timeout": 10 }] }]
  }
}
```

Windows: same object, **exec form** (do not put `Program Files` and `hook`
in one shell string — Claude Code will split on the space). Every
`"command"` field is:

```json
"command": "C:\\Program Files\\peephole\\peephole.exe",
"args": ["hook"],
"timeout": 10
```

Do not paste the same `hooks` object into both `managed-settings.json` and
`10-peephole.json` — file-source lists combine, so the hook would run twice.

This is the **write-time** path. It does not include the plugin's git
commit/push rewake. Use [`integrations/git-pre-commit`](../integrations/git-pre-commit)
if you need a commit gate. The matcher covers Claude Code `Bash`, not the
Windows `PowerShell` tool — those calls are not scanned.

### What every MDM does

| Step | What | Notes |
|---|---|---|
| 1 | Allowlist the binary by SHA-256 from `SHA256SUMS` | macOS: not notarized (ad-hoc / linker-signed). Windows: no Authenticode. Santa, Jamf allowlisting, WDAC, AppLocker, Defender ASR block it until you allowlist the hash. |
| 2 | Run the installer on a schedule as root / SYSTEM | [`deploy/install-unix.sh`](../deploy/install-unix.sh) / [`install-windows.ps1`](../deploy/install-windows.ps1). Set `PEEPHOLE_VERSION`. Never `latest`. GitHub is the default download. |
| 3 | Put `hooks` in the **winning** Claude Code source | Installer drop-in is enough only when `/status` shows a **file** source. If it shows `(remote)`, `(plist)`, or `(HKLM)`, paste the payload above into *that* source. |
| 4 | Exclude `**/.peephole/` from on-access AV | ~5–7 file ops per gated event; AV turns ~4ms into ~15–50ms. |
| 5 | Commit `.peephole-policy.json` in **repos** | MDM cannot set peephole's mode. The floor is git, per repo. |

### Prove it on a pilot device

`peephole scan` only tests the binary. It does **not** prove Claude Code
calls the hook.

1. `peephole version && peephole selfcheck` — expect `0.5.1`,
   `181 rules, 605 patterns, 13 cross-line taint specs`, `integrity: OK`.
2. In Claude Code, `/status` → **Setting sources** lists
   `Enterprise managed settings` with the source you intended
   (`(remote)` / `(plist)` / `(HKLM)` / `(file)` / `(drop-ins)` /
   `(file + drop-ins)` / `(helper)`). If it names a source you did not
   mean, a higher one is present and your drop-in is ignored.
3. In a throwaway project, `peephole mode strict`, then ask the agent to
   write `cur.execute(f"SELECT * FROM t WHERE id={x}")` to a `.py` file.
   Expect a **deny** (or an ask in `guided`). If the write lands with no
   prompt, the hook is not in the winning source.

### Jamf (macOS)

1. **Allowlist** `peephole-darwin-arm64` and `peephole-darwin-amd64` by
   SHA-256 (Jamf allow-list / Santa). Without this, Gatekeeper and
   allowlisting kill the binary after a clean installer run.
2. **Policy → Scripts**, run as **root**, trigger recurring (every check-in
   or daily). Jamf has no env-var field — export at the top of the script:

   ```sh
   export PEEPHOLE_VERSION=v0.5.1
   # paste deploy/install-unix.sh below
   ```

   Scope to Macs that run Claude Code. Recurring is required: a one-shot
   policy will not refresh hooks after you bump the pin.
3. **Claude Code hooks — pick one:**
   - **No existing Claude Code MDM, and `/status` is not `(remote)`:** leave
     `/Library/Application Support/ClaudeCode/managed-settings.d/10-peephole.json`.
     `/status` should show `(drop-ins)` or `(file + drop-ins)`.
   - **You already push Custom Settings** for preference domain
     `com.anthropic.claudecode`, or a `.mobileconfig` for that domain: files
     are ignored. Convert the `hooks` object to plist (nested dicts/arrays,
     `timeout` as integer) and merge it into **that** profile. `/status`
     must show `(plist)`.
   - **`/status` shows `(remote)`:** the laptop drop-in will never run.
     Prefer clearing server-managed keys for this cohort so files or
     plist can win. Do not paste the Unix `command` into a mixed-OS org
     policy.
4. Optional Claude Code locks (`allowManagedPermissionRulesOnly`, login org)
   go in the same winning source as the hooks. Adding a new Custom Settings
   profile for those locks **moves you onto the plist path** — take the
   peephole hooks with you.
5. Pilot one Mac through “Prove it” above, then widen scope.

### Iru (Kandji) (macOS)

Kandji is now **Iru**. Same two jobs as Jamf: Custom Script for the binary,
Custom Settings only if Iru should own Claude Code policy.

1. Allowlist the darwin hashes (Iru Library / Blocking).
2. **Custom Script**, execute as root, assigned to a Blueprint that
   re-applies. Same unix installer with `PEEPHOLE_VERSION=v0.5.1` at the
   top. GitHub is the default download.
3. **Custom Settings**, preference domain `com.anthropic.claudecode`,
   **only if** you already (or now) manage Claude Code from Iru. Then the
   drop-in file is ignored — convert peephole `hooks` to plist and put
   them in that payload. Otherwise skip Custom Settings and use the
   installer drop-in.
4. Pilot `/status` and a denied write. Iru “enforcement” of a Custom Script
   is not the same as Claude Code loading the hook.

### Intune (Windows)

1. Allowlist `peephole-windows-amd64.exe` by hash (WDAC / AppLocker /
   Defender ASR). Unsigned `.exe`; `Unblock-File` is already in the
   installer for Mark-of-the-Web.
2. **Platform script** or **remediation script**. Intune defaults are the
   opposite of what this script needs — set them explicitly:

   | Setting | Intune default | Required |
   |---|---|---|
   | Run using logged-on credentials | Yes | **No** (SYSTEM) |
   | Run script in 64-bit PowerShell host | No | **Yes** |
   | Enforce script signature check | Yes | **No** (the `.ps1` is unsigned) |

   32-bit SYSTEM writes under `Program Files (x86)` / WOW64 while
   64-bit Claude Code reads `C:\Program Files\ClaudeCode\` only — MDM
   can be green and the hook never loads. Prepend:

   ```powershell
   $env:PEEPHOLE_VERSION = 'v0.5.1'
   # then the body of deploy/install-windows.ps1
   ```

   Assign to the Windows devices that run Claude Code. 64-bit PowerShell
   host, 64-bit binary only (`peephole-windows-amd64.exe`). Run as SYSTEM,
   not the logged-on user (user context cannot write `Program Files`).
   The installer writes `%ProgramFiles%\peephole\peephole.exe` and adds
   that directory to the **machine** PATH (new logons only). The hook
   command uses the full path, so PATH is for humans and other hosts, not
   for Claude Code. WSL is a **Linux** install: run `install-unix.sh` as
   root inside the distro. Do not point WSL hooks at
   `peephole.exe`. Check `/status` inside WSL separately.
3. **Claude Code hooks — pick one:**
   - **File-only, or Anthropic's `Set-ClaudeCodePolicy.ps1`:** both write
     under `C:\Program Files\ClaudeCode\`. The installer drop-in
     `managed-settings.d\10-peephole.json` **merges** with
     `managed-settings.json`. Claude Code does **not** read
     `C:\ProgramData\ClaudeCode\`. `/status` should show `(drop-ins)` or
     `(file + drop-ins)`.
   - **ADMX / GPO / `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`:** HKLM
     wins; the drop-in is ignored. Put peephole `hooks` in that REG_SZ
     JSON. `/status` must show `(HKLM)`.
   - **`(remote)`:** same as macOS — the drop-in never runs. Clear
     server-managed keys, or put an **OS-correct** Windows `command`+`args`
     in the console payload (not the Unix path).
4. Pilot one PC. A user-context script will not write
   `C:\Program Files\…`. GPO is the same as the HKLM bullet: Computer
   Configuration startup script = the installer as SYSTEM; ADMX writes
   `Settings` REG_SZ, so hooks go in that JSON, not the drop-in.

### Linux

No Jamf/Intune equivalent in most orgs. Run `install-unix.sh` as root from
Chef, Ansible, JumpCloud Command, or the image. The drop-in is
`/etc/claude-code/managed-settings.d/10-peephole.json` (official directory
`/etc/claude-code/`). If you also ship `/etc/claude-code/managed-settings.json`,
they merge. If you have no MDM plist on Linux, files are the usual winning
source unless server-managed is on.

### `allowManagedHooksOnly`

Set this **only** on path B, and **only** in the managed source that
actually wins (server / plist / HKLM / file — not a user `settings.json`).

When `true`, Claude Code runs managed hooks, Agent SDK hooks, and hooks
from plugins **force-enabled** in managed `enabledPlugins` (matched as
`plugin@marketplace`). User, project, local, and other plugin hooks are
blocked. The installer-written hook is a managed hook **only if** the
file source won (`(file)` / `(drop-ins)` / `(file + drop-ins)`), or you
copied those `hooks` into the winning plist/HKLM/remote payload. If a
higher source has `allowManagedHooksOnly: true` **without** peephole
`hooks`, the drop-in is ignored and the product is silently off.

Invalid `allowManagedHooksOnly` fails closed to `true`. Do not experiment
with this on a plugin-only install.

---

## 4. Org policy (escalation only)

Commit `.peephole-policy.json` at the repo root (or
`.claude/peephole-policy.json`). While the file is valid JSON, extra
`enforce` entries and a higher `min_mode` can only raise the gate.
`min_mode` values other than `strict`/`hardened` are ignored. The file is
**not** self-protected — the agent can Write or delete it. Deleting it,
replacing it with `{}`, or breaking the JSON drops the floor to the local
mode. Protect it with CODEOWNERS / branch rules. If a CWE must still deny
under `/peephole off`, set `min_mode` as well as `enforce`. MDM does not
distribute this file — it is git, per repo.

```json
{
  "min_mode": "strict",
  "enforce": ["CWE-89", "CWE-78", "CWE-798", "CWE-94"],
  "global": [
    "Do not log request bodies that may contain credentials.",
    "All SQL against customers or orders goes through the replica, never primary."
  ],
  "CWE-89": [
    "Use the shared db.Query helper; do not call database/sql directly in handlers."
  ]
}
```

| Field | Effect |
|---|---|
| `min_mode` | `"strict"` or `"hardened"` only. Effective mode is `max(local, min_mode)`. |
| `enforce` | Named CWEs (`CWE-` plus 1–4 digits) are a hard **deny** in `guided`, `audit`, `strict`, and `hardened`. A `sec-debt` marker cannot waive them. They do not fire in `off` unless `min_mode` raises the floor. |
| `global` | Extra instructions injected at prompt time (max 3 used). |
| `CWE-NNN` | Extra instructions for that class (max 2 used). |

Limits: 50 entries, 240 characters each. Unicode/bidi/injection phrases are
dropped. Policy is not a programming language.

`min_mode` does not accept `guided` or `off` — those would be a weaken, and
weaken is rejected.

---

## 5. Custom rules (additive)

You do not need a fork to add a rule. Commit `.peephole-rules.json` at the
repo root (or `.claude/peephole-rules.json`). Rules **add** findings. They
cannot disable a built-in rule.

Schema is the same as `rules/*.json`. One object or an array. RE2 regex
(linear time — a custom pattern cannot ReDoS the hook). Cap: 200 user rules,
1 MiB file.

```json
[
  {
    "cwe_id": "CWE-89",
    "name": "Acme: raw SQL in services",
    "severity": "high",
    "task_triggers": ["sql", "query", "customer"],
    "patterns": [
      {
        "lang": "python",
        "confidence": "high",
        "re": "acme\\.db\\.execute\\(\\s*f[\"']",
        "reject_re": "execute\\(\\s*[\"'][^\"']*[\"']\\s*,"
      }
    ],
    "attack_scenario": "an f-string into acme.db.execute is SQL injection on customer data",
    "negative_test_hint": ["submit username \"' OR 1=1--\" and assert the query is parameterized"],
    "exemplar": {
      "noncompliant": "acme.db.execute(f\"SELECT * FROM customers WHERE name={name}\")",
      "compliant": "acme.db.execute(\"SELECT * FROM customers WHERE name=?\", (name,))",
      "explanation": "use the shared helper with bound parameters"
    }
  }
]
```

| Field | Required | Notes |
|---|---|---|
| `cwe_id` | yes | Non-empty. Org `enforce` only matches `CWE-` plus 1–4 digits |
| `name` | recommended | Shown in deny/ask text |
| `severity` | no | Informational in the schema; deny vs ask follows `patterns[].confidence` |
| `patterns[].re` | yes | RE2. Invalid patterns are skipped and listed as disabled |
| `patterns[].lang` | no | `python`, `javascript`, `go`, `rust`, … Empty = all languages |
| `patterns[].confidence` | yes for enforcement | `high` is deny in `strict`; anything else is ask (or deny in `hardened`) |
| `patterns[].reject_re` | no | If this matches the same line, the hit is dropped |
| `patterns[].require_re` | no | Hit kept only if this also matches the same line |
| `task_triggers` | recommended | Keywords that inject this rule at the prompt |
| `attack_scenario` / `exemplar` | recommended | What the model sees on deny |

Invisible Unicode, bidi, and injection phrases in a user rule are rejected at
load. SessionStart reports how many user patterns failed to compile.

**Do not** copy peephole's own `.gitignore` into an application repo if it
ignores `.peephole-rules.json`. That ignore is for this project's sandbox, not
for yours. Application repos should **commit** policy and custom rules.

### Shipping a rule in the product

To change the embedded KB (every install, not one repo):

1. Add `rules/cwe-NNN-short-name.json` (and taint spec under `taint/` if needed).
2. `go run ./cmd/kbgen`
3. Add a true and a false case to `corpus_test.go`.
4. `go test ./...` then `./build.sh`.
5. Commit `rules_gen.go` and `bin/manifest.sha256`.

Two-signal rules only: a pattern plus `reject_re` / `require_re` so everyday
correct code stays clean. A high-confidence false positive is worse than a
miss.

---

## 6. Other hosts at org scale

The binary is the same. Copy the drop-in from [`integrations/`](../integrations/):

| Host | Block before write? |
|---|---|
| Claude Code | Yes (deny and ask) |
| Gemini CLI, Qwen Code, Crush | Yes (deny only) |
| Codex CLI | Yes (deny only) on Bash, `apply_patch`, MCP, other local tools; trust the hook in `/hooks` |
| OpenCode plugin | Yes (deny). Subagent calls may skip the plugin |
| Cursor | Yes on agent Write/Shell/MCP. Tab/GUI edits need git |
| `git pre-commit` | Yes, at commit |
| MCP / LSP | Advisory |

Exit-2 hosts do not surface **ask** — `ask` is allow plus a stderr line.
Default `guided` therefore blocks nothing on those hosts except
self-protection and org-`enforce`. If the org needs a human approval
dialog on medium findings, use Claude Code.

MDM still only installs the binary. Gemini / Codex / Cursor / Qwen /
Crush / OpenCode hook files are per-user or per-project — put them in the
image or a dotfiles repo; there is no Claude-style managed-settings
directory for those hosts. Codex skips new hooks until a person **trusts**
them in `/hooks`. Cursor Tab / GUI edits write first; use git pre-commit.

---

## 7. Audit log

Per project, under `.peephole/`:

- `log.jsonl` — hash-chained decisions, last 30 days
- `log.head` — running hash
- rotated `log.jsonl.1` — previous 10MB, deleted when older than 30 days

Mode `audit` plus `peephole audit` is how you measure before tightening
`min_mode` (`/sec-audit` only if the plugin is installed). Do not treat `.peephole/log.jsonl` as a security or compliance
control, including in a SIEM. It never leaves the laptop, has no user
identity, is unkeyed SHA-256, and any same-user process (including the
agent) can rewrite or delete it.

---

## 8. Version pins and forks

| What | How |
|---|---|
| Fleet binary | Pin `v0.5.1` (or your tag) in the MDM script, not `latest` |
| Plugin | Not a pin. Vendor the directory, or do not use the plugin on the fleet |
| Your fork | Set `PEEPHOLE_REPO=you/peephole`. Public GitHub `releases/download` needs no token. `GH_TOKEN` only for a private GitHub assets API. `PEEPHOLE_BASE_URL` only if you host the files yourself. Then `./build.sh`, tag, let `.github/workflows/release.yml` gate the cut |

The binary does not phone home. The only optional outbound call is a short
`curl` to PyPI / npmjs when the agent is installing a package (existence /
freshness / typosquat). If egress blocks it the verdict is `unknown`: Bash **install** is ask in
`guided`/`strict`, deny in `hardened`, log-only in `audit`. Manifest
**edits** stay ask even in `hardened`. Allowlist `pypi.org` and
`registry.npmjs.org` if you run `hardened`.

---

## 9. What not to do

- Do not set `min_mode` to `strict` on day one across every repo.
- Do not present the audit log as a SOX/ISO control, or as any control.
- Do not treat peephole as a replacement for other SAST tools in CI.
  Cross-file taint and whole-repo review stay there.
- Do not put secrets in `.peephole-policy.json` — policy text is injected
  into the model context.
- Do not expect a motivated agent or user, running as the same OS user, to
  be unable to turn it off.
- Do not set `allowManagedHooksOnly` on a marketplace-plugin install.
- Do not deploy both an MDM plist/HKLM **and** rely on the installer
  drop-in. One source wins; the other is ignored with no warning.
- Do not rely on the installer drop-in if `/status` shows `(remote)`.
  Server-managed settings outrank files and the plist. Put `hooks` in the
  console / gateway policy, or stop delivering server-managed keys.
- Do not treat `enforce` as undeleteable. The policy file is git; deleting
  it removes the floor.
- Do not put `"command": "C:\\Program Files\\peephole\\peephole.exe hook"`
  as one shell string. Use `command` + `args` (exec form).

---

## 10. Quick checklist

1. Pin `v0.5.1`. GitHub releases are the default download. Allowlist hashes.
2. Schedule `deploy/install-unix.sh` / `install-windows.ps1` from Jamf,
   Iru, Intune, or your existing root channel. `peephole selfcheck` succeeds.
3. Confirm Claude Code `/status` shows the managed source you intended
   (`(remote)` / `(plist)` / `(HKLM)` / `(file)` / `(drop-ins)`). Then
   prove the **hook** with a denied write in `strict` — `peephole scan`
   only tests the binary.
4. Exclude `**/.peephole/` from EDR on-access scan.
5. Wire other hosts from [`integrations/README.md`](../integrations/README.md)
   if the fleet is not Claude Code-only.
6. Run two weeks in `guided`. Read `peephole audit` (`/sec-audit` only if
   the plugin is installed).
7. Commit `.peephole-policy.json` with `enforce` for the CWEs you will never
   allow (and `min_mode` if they must still deny under `/peephole off`).
8. Add `.peephole-rules.json` for house style. Keep them high-precision.
9. Keep other SAST tools in CI.
