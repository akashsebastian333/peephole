---
name: sec-review
description: Review the current changes for the CWE classes Peephole enforces, as a checklist including the absence-of-guard classes regexes cannot catch. Use when the user says /sec-review or asks for a security review of recent code before committing.
---

# Peephole security review

Peephole's write-time gate catches *present* insecure patterns. This review adds the
part a regex cannot prove: **missing** guards. Review the current diff against this
checklist and report concrete findings with file:line.

Present (Peephole enforces these at write time — verify none slipped through in audit mode):
- CWE-89 SQL injection — string-built queries instead of parameters
- CWE-94 code injection — eval/exec/new Function on dynamic input
- CWE-502 unsafe deserialization — pickle/yaml.load/node-serialize on untrusted data
- CWE-79 XSS — unescaped output, dangerouslySetInnerHTML, `| safe`
- CWE-78 command injection — shell=True / exec with interpolation
- CWE-22 path traversal — join(base, user_input) without containment check
- CWE-798 hardcoded secrets
- CWE-327 weak crypto — fast/unsalted password hashes, ECB, non-CSPRNG for secrets
- CWE-1188 disabled controls — verify=False, DEBUG=True, csrf_exempt, wildcard CORS+credentials

Absence — cannot be regex-proven; check by reading (this is where real bugs hide):
- CWE-862/863 missing/incorrect authorization on state-changing or cross-user routes
- CWE-639 IDOR — object lookups keyed on a client-supplied id without ownership scoping
- CWE-352 CSRF on state-changing endpoints
- CWE-306 missing authentication on a sensitive endpoint
- CWE-770 missing rate limiting on expensive or auth endpoints

For each finding: state the CWE, the file:line, the exploit in one sentence, and the fix.

## Challenge every finding before reporting it (3 lenses)

A finding survives only if you *fail* to disprove it. Before reporting each one, try
to refute it from all three angles — report only the ones that survive:

- **REACHABILITY** — can an attacker actually reach the sink? Is the source genuinely
  attacker-controlled? Is the path reachable in a default deployment, or is there a guard
  on *every* route (not just the one you first looked at)?
- **IMPACT** — if they reach it, does it matter? Is the claimed consequence the real one?
  Is the data actually sensitive, the write actually dangerous?
- **DEFENSES** — is something already stopping it — a framework default, middleware, a
  type, an escape, a prepared statement, a check one frame up?

Report a confirmed, complete attack path — not a pattern that merely looks suspicious.

Then run `/sec-audit` to cross-check against what Peephole logged this session.
