# Fleet installers

Scripts in this directory install a **pinned** peephole binary and write Claude
Code managed hooks. They are idempotent — schedule them on every device
check-in.

Org policy, custom rules, and **Jamf / Iru (Kandji) / Intune** rollout:
[docs/ENTERPRISE.md](../docs/ENTERPRISE.md). Threat model:
[docs/THREAT_MODEL.md](../docs/THREAT_MODEL.md).

---

## 0. If you forked this into your own org

| What | Where |
|---|---|
| Installer default repo | `install-unix.sh` `REPO=`, `install-windows.ps1` `$Repo =` — or set `PEEPHOLE_REPO`. `PEEPHOLE_BASE_URL` only if you host the files yourself |
| Install URLs | `../README.md` |
| Plugin marketplace | `../README.md` `/plugin marketplace add <owner>/peephole` |

```sh
git grep -l 'akashsebastian333/peephole'
./build.sh
go test ./... && ./bin/peephole-$(uname -s|tr '[:upper:]' '[:lower:]')-$(uname -m|sed 's/x86_64/amd64/;s/aarch64/arm64/') selfcheck
git tag -a v0.5.1 -m v0.5.1 && git push origin v0.5.1
```

The tag triggers `.github/workflows/release.yml` (KB freshness, tests, version
consistency, govulncheck, toolchain pin). Confirm the run is green before
pointing MDM at it.

The binary does not phone home. The only optional outbound call is a short
`curl` to PyPI / npmjs on the dependency-install path. If egress blocks it,
that check degrades to ask.

---

## 1. Artifact source

Public GitHub releases download unauthenticated:

`https://github.com/akashsebastian333/peephole/releases/download/v0.5.1/`

That is the default. `PEEPHOLE_BASE_URL` is only if you already host a copy
of that directory (the installer still re-verifies `SHA256SUMS`).

`GH_TOKEN` is only for a **private fork** (GitHub assets API). Do not put a
GitHub credential in an MDM payload if you can avoid it.

```sh
# optional — only if you host a copy yourself, then set PEEPHOLE_BASE_URL
VER=v0.5.1
gh release download "$VER" --repo akashsebastian333/peephole -D "$VER"
cd "$VER" && shasum -a 256 -c SHA256SUMS --ignore-missing
```

---

## 2. What the installers do

[`install-unix.sh`](install-unix.sh) — root, macOS and Linux.
[`install-windows.ps1`](install-windows.ps1) — SYSTEM, Windows.

Required env: `PEEPHOLE_VERSION=v0.5.1`. Default download is GitHub. `PEEPHOLE_BASE_URL` is optional.

1. Detect OS/arch; refuse unsupported targets.
2. Exit 0 if already at the pinned version **and** `selfcheck` passes.
   `selfcheck` failure is a failed MDM run (exit 4).
3. Download the asset and `SHA256SUMS`, refuse to install on mismatch.
4. Install to `/usr/local/bin/peephole` or
   `%ProgramFiles%\peephole\peephole.exe`.
5. Write `10-peephole.json` in the **file-based** Claude Code managed-settings
   directory:

| OS | Path |
|---|---|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.d/` |
| Linux | `/etc/claude-code/managed-settings.d/` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.d\` |

   Claude Code does **not** read `C:\ProgramData\ClaudeCode\`. If a
   **server-managed**, **plist**, or **HKLM** policy already delivers any
   Claude Code key, this drop-in is ignored — put peephole hooks in that
   winning source instead ([docs/ENTERPRISE.md](../docs/ENTERPRISE.md) §3).
   A `managed-settings.json` next to the drop-in **merges** with it.

6. Re-verify `version` and `selfcheck`.

Mode is per-project. The installer does not set a global mode. The org floor
is `.peephole-policy.json` committed in each repo.

---

## 3. MDM in one paragraph

Jamf / Iru (Kandji): root **script** = unix installer, scheduled. Intune:
SYSTEM **platform script** = Windows installer. JumpCloud: Commands, same
scripts. Allowlist the SHA-256 from `SHA256SUMS` (binaries are not notarized
and not Authenticode-signed). Exclude `**/.peephole/` from on-access AV.
Details, precedence, and `allowManagedHooksOnly`: [docs/ENTERPRISE.md](../docs/ENTERPRISE.md).

---

## 4. Verify

```sh
peephole version && peephole selfcheck
```

```
peephole 0.5.1 (darwin/arm64, go1.26.6)
181 rules, 605 patterns, 13 cross-line taint specs
peephole integrity: OK
```

Then:

```sh
printf 'cur.execute(f"SELECT * FROM t WHERE id={x}")\n' > /tmp/v.py
peephole scan /tmp/v.py          # expect CWE-89
```

In Claude Code, `/status` must list **Enterprise managed settings** with the
source you intended (`file` / `drop-ins` vs `plist` vs `HKLM`).

---

## 5. Staged rollout

| Stage | Scope | Gate |
|---|---|---|
| 1 | 1 device per OS | `version` + `selfcheck`; `/status` source is the one you meant; hooks fire |
| 2 | One volunteer team (~10) for 2 weeks | no developer-blocking pile-up; `peephole audit` looks sane |
| 3 | One engineering org | PR security-finding trend vs their own baseline |
| 4 | Fleet | — |

Keep `guided` at every stage. Do not enable `strict` without triaging
false positives on *your* codebases.

---

## 6. Constraints

**macOS — not notarized.** Ad-hoc/linker-signed only. It runs from a shell;
Santa / Jamf allowlisting will still block it until you allowlist the hash.

**Windows — unsigned `.exe`.** SYSTEM execution is usually fine; WDAC,
AppLocker, Defender ASR may block it. Allowlist by hash. `Unblock-File`
clears Mark-of-the-Web.

**No central telemetry.** Local log only; not compliance evidence
(`docs/THREAT_MODEL.md` §5.3).

**Per-project mode.** Fleet floor = `.peephole-policy.json` `min_mode` in
each repo (escalation-only, and deletable).

---

## 7. Rollback

```sh
# macOS / Linux
rm -f /usr/local/bin/peephole
rm -f "/Library/Application Support/ClaudeCode/managed-settings.d/10-peephole.json"   # macOS
rm -f /etc/claude-code/managed-settings.d/10-peephole.json                            # Linux
```

```powershell
Remove-Item "$env:ProgramFiles\peephole" -Recurse -Force
Remove-Item "C:\Program Files\ClaudeCode\managed-settings.d\10-peephole.json" -Force
```

Removing the hook file disables peephole for new Claude Code sessions. No
daemon, LaunchAgent, or service. Project `.peephole/` directories are
harmless leftovers and are gitignored.

An engineer can also disable it per project with `peephole mode off` — by
design, and the reason this is a guidance control rather than an enforcement
one.
