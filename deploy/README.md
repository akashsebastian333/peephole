# Fleet deployment — JumpCloud (macOS · Windows · Linux)

Deploys peephole to employee laptops in **`guided`** mode: findings surface as
prompts, nothing is hard-blocked. Scripts in this directory are idempotent and safe
to run on every device check-in.

Read [../docs/SECURITY_ASSESSMENT.md §7](../docs/SECURITY_ASSESSMENT.md) first — it
lists the conditions this runbook implements and why.

---

## 0. Decide the artifact source first

**The upstream repo is private.** An unauthenticated download returns HTTP 404, and
a JumpCloud Command has no GitHub credential:

```
$ curl -s -o /dev/null -w '%{http_code}' \
    https://github.com/<owner>/peephole/releases/download/v0.5.1/SHA256SUMS
404
```

| Option | Verdict |
|---|---|
| **Mirror to internal storage** (Artifactory, S3+CloudFront, JumpCloud file distribution) | **Recommended.** Change control, no GitHub dependency, no credential on endpoints |
| `GH_TOKEN` in the JumpCloud Command | Pilot only. Puts a GitHub credential in an MDM payload and on every endpoint |
| Make the repo public | Removes the problem; a separate decision |

**Mirror procedure** — do this once per release, on a trusted host, and verify
before publishing:

```sh
VER=v0.5.1
gh release download "$VER" --repo <owner>/peephole -D "$VER"
cd "$VER" && shasum -a 256 -c SHA256SUMS --ignore-missing   # must print OK for every asset
# then upload this directory verbatim, SHA256SUMS included
```

Point `PEEPHOLE_BASE_URL` at that directory. The installers re-verify the checksum
on every endpoint, so a mirror compromise is still caught.

## 1. JumpCloud Commands

Create three Commands. Each is idempotent — schedule them (e.g. daily) rather than
running once, so drift self-heals and new devices pick it up automatically.

### macOS and Linux

- **Type:** `mac` / `linux`, run as **root**
- **Body:** contents of [`install-unix.sh`](install-unix.sh)
- **Env:** JumpCloud has no env-var field, so prepend:

```sh
PEEPHOLE_VERSION=v0.5.1
PEEPHOLE_BASE_URL=https://artifacts.corp/peephole/v0.5.1
export PEEPHOLE_VERSION PEEPHOLE_BASE_URL
```

### Windows

- **Type:** `windows`, PowerShell, runs as **SYSTEM**
- **Body:** contents of [`install-windows.ps1`](install-windows.ps1)
- **Env:** prepend

```powershell
$env:PEEPHOLE_VERSION  = 'v0.5.1'
$env:PEEPHOLE_BASE_URL = 'https://artifacts.corp/peephole/v0.5.1'
```

### What the installers do

1. Detect OS/arch; refuse unsupported targets rather than installing nothing.
2. Exit 0 immediately if already at the pinned version (after a `selfcheck`).
3. Download the asset **and `SHA256SUMS`**, verify, and **refuse to install on
   mismatch**.
4. Install to `/usr/local/bin/peephole` or `%ProgramFiles%\peephole\peephole.exe`,
   atomically on Unix so a concurrent hook never sees a partial binary.
5. Write admin-owned hook config to the **`managed-settings.d` drop-in directory**
   as `10-peephole.json`.
6. Re-verify: `version` executes, `selfcheck` passes, version matches the pin.
   Any failure is a non-zero exit, so JumpCloud reports the device as failed.

**Why `managed-settings.d` and not `~/.claude/settings.json`:** a per-user file is
user-editable and would have to be merged, not written — engineers commonly already
have hooks there (a clobbering installer would break their other tooling). The
drop-in directory is admin-owned, needs no merge, and pairs with
`allowManagedHooksOnly` if you later want to prevent repo-supplied hooks.

Confirmed paths:

| OS | Path |
|---|---|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.d/` |
| Linux | `/etc/claude-code/managed-settings.d/` |
| Windows | `%ProgramData%\ClaudeCode\managed-settings.d\` — **verify on a pilot host**, see §5 |

## 2. Endpoint-agent exclusion — do not skip this

Peephole performs ~5–7 file operations per gated event to append its audit entry.
On a laptop whose EDR inspects every file operation those cost **~3–5 ms each
instead of ~0.05 ms**, which is the entire difference between a ~4 ms and a
~15–50 ms hook. Rule evaluation itself is ~0.33 ms.

Add an on-access-scanning exclusion for the state directory:

| Platform | Pattern |
|---|---|
| macOS / Linux | `**/.peephole/` |
| Windows | `**\.peephole\` |

Nothing sensitive lives there — mode, a decision log, and per-session counters —
and it is already `0600` inside a `0700` directory.

## 3. Verify the rollout

Inventory command (safe, read-only, run as any user):

```sh
peephole version && peephole selfcheck
```

```
peephole 0.5.1 (darwin/arm64, go1.26.6)
181 rules, 584 patterns, 12 cross-line taint specs
peephole integrity: OK
```

Treat as a failed install: a version that is not the pin, a `selfcheck` that is not
`OK`, or a missing `10-peephole.json`. Then confirm the hooks actually fire — in any
git repo, as the engineer:

```sh
cd /tmp && mkdir -p ph-smoke && cd ph-smoke
printf 'cur.execute(f"SELECT * FROM t WHERE id={x}")\n' > v.py
peephole scan v.py          # expect: CWE-89 SQL Injection (high)
peephole audit              # expect: mode: guided, and a decision count
```

## 4. Staged rollout

| Stage | Scope | Gate to proceed |
|---|---|---|
| 1 | 1 device per OS, hand-held | `version` + `selfcheck` OK; hooks fire; Windows managed-settings path confirmed |
| 2 | One volunteer team (~10) for 2 weeks | zero developer-blocking reports; `peephole audit` shows a sane interruption rate |
| 3 | One engineering org | security-finding trend on their PRs vs their own 3-month baseline |
| 4 | Fleet | — |

Keep `guided` at every stage. Do not enable `strict` without re-running the
false-positive triage in `docs/SECURITY_ASSESSMENT.md` on *your* codebases.

## 5. Known constraints

**macOS — not notarized.** The binaries are ad-hoc/linker-signed only:
`TeamIdentifier=not set`, and `spctl -a` reports `rejected`. Measured: it
nevertheless **executes normally** from a shell, including with a
`com.apple.quarantine` xattr set, because Apple Silicon requires only *a*
signature and Gatekeeper's assessment gates GUI/LaunchServices launches. But if you
run a binary-authorization tool — **Santa, Jamf allowlisting, WDAC-equivalent** — it
*will* be blocked and needs explicit allowlisting. Allowlist by SHA-256 from
`SHA256SUMS`; builds are reproducible for a fixed toolchain, so the hash is stable.

**Windows — unsigned `.exe`.** No Authenticode signature. SYSTEM-invoked execution
is normally fine, but Defender ASR, WDAC or AppLocker may block it; allowlist by
hash. `Unblock-File` in the installer clears Mark-of-the-Web.

**Windows managed-settings path is unconfirmed.** The macOS and Linux paths were
verified against the Claude Code binary; the Windows path follows the `ProgramData`
convention but was not observed directly. **Confirm on the stage-1 Windows host**
before fleet rollout — if hooks do not fire, check where that build reads managed
settings from and adjust the installer.

**No central telemetry.** There is no egress path in peephole. Each endpoint keeps a
local log with no file paths, no user identity, and no repo identity. If you need
fleet reporting, build a collector; do not expect one. And per
`docs/THREAT_MODEL.md` §5.3 the log is unkeyed and same-user writable — it is
evidence of record, **not** compliance evidence.

**Per-project mode.** Mode is stored per project in `.peephole/mode`, not globally.
A fleet-wide floor needs `.peephole-policy.json` with `min_mode` committed to each
repo (escalation-only, and deletable — see `docs/THREAT_MODEL.md` §5.1 E6).

## 6. Rollback

```sh
# macOS / Linux
rm -f /usr/local/bin/peephole
rm -f "/Library/Application Support/ClaudeCode/managed-settings.d/10-peephole.json"   # macOS
rm -f /etc/claude-code/managed-settings.d/10-peephole.json                            # Linux
```

```powershell
Remove-Item "$env:ProgramFiles\peephole" -Recurse -Force
Remove-Item "$env:ProgramData\ClaudeCode\managed-settings.d\10-peephole.json" -Force
```

Removing the hook file disables peephole completely and immediately for new
sessions. Nothing else on the host is touched: no daemon, no LaunchAgent, no
service, no registry keys beyond the machine `PATH` entry on Windows. Project
`.peephole/` directories are harmless leftovers and are gitignored.

An engineer can also disable it per project at any time with `peephole mode off` —
by design, and the reason this is a guidance control rather than an enforcement one.
