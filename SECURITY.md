# Security Policy

Peephole is a security tool, so its own attack surface matters. We take reports
seriously.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub's **"Report a
vulnerability"** private security advisory flow on this repository. Do not open
a public issue for a security report.

Include: a description, affected version/commit, and a reproduction (a hook
event JSON and the observed decision is ideal). We aim to acknowledge within a
few business days.

## Scope

In scope — bypasses of the enforcement or self-protection model, for example:
- insecure code that reaches disk despite `strict`/`hardened` mode;
- disabling or tampering with enforcement, the mode file, or the audit log;
- a rule that silently fails to compile (a disabled detection);
- a false-negative or false-positive in a shipped rule.

Explicitly out of scope (documented honest boundaries, see `docs/REVIEW.md`):
- host-level tampering by a same-user process (mode 0600 stops other users, not
  the same-user agent — peephole provides tamper-*evidence*, not an OS-level
  integrity guarantee);
- a same-user process that reads the mode signing key and forges a signature;
- detection of race conditions / business-logic flaws by pattern (these are
  handled by guidance + review, never claimed as machine-enforced).

## Trust model

Rules are inert JSON data embedded in the binary and compiled with RE2
(linear-time, no catastrophic backtracking). The binary and its hook wiring are
pinned by a SHA-256 manifest verified at SessionStart. See `docs/DESIGN.md` and
`docs/REVIEW.md` for the full model.
