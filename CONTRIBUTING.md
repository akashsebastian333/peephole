# Contributing to Peephole

Thanks for helping make AI-generated code born secure.

## Development

- Requires Go 1.26+. No third-party dependencies (standard library only).
- `go test ./...` runs the full suite (contract tests, KB self-consistency, the
  edge-case corpus, and tamper/log tests). Use `-race` before sending a PR.
- `./build.sh` cross-compiles every platform binary and regenerates the
  integrity manifest (`bin/manifest.sha256`). Run it whenever you change any
  `.go` file or `rules/*.json` — the rules are embedded into the binary.
- Keep it gofmt-clean and `go vet`-clean. CI enforces both.

## Adding or changing a detection rule

Rules live in `rules/*.json` (one rule record per file; several files may share
a CWE for different language/variant classes). A rule is inert data:

```json
{
  "cwe_id": "CWE-89",
  "name": "SQL Injection",
  "severity": "critical",
  "kev": true,
  "task_triggers": ["database", "query", "login"],
  "patterns": [
    { "lang": "python", "confidence": "high", "re": "\\.execute\\(\\s*f[\"'][^)]*\\{", "require_re": "(?i:SELECT|INSERT)" }
  ],
  "attack_scenario": "one sentence on how it is exploited",
  "negative_test_hint": ["the adversarial input a test should feed"],
  "exemplar": { "noncompliant": "...", "compliant": "...", "explanation": "..." }
}
```

Rules for a rule:

- **RE2 only** — Go's `regexp` has no lookaround or backreferences. Use the
  declarative refinements instead of lookaround: `prev_not` (reject a match whose
  preceding char is in a class), `reject_re` (skip if this matches the same
  line), `require_re` (only fire if this matches the same line).
- **`lang`** scopes the pattern to a language bucket (see `extToLang` in
  `kb.go`); `""` runs on every file. Prefer high precision — a false block is
  worse than a miss.
- **`confidence`**: `high` denies in strict/hardened; `medium` asks in strict.
- Every rule with patterns is tested against its own exemplars: the
  `noncompliant` example must match and the `compliant` example must not
  (`TestKBExemplarConsistency`). Add true-positive and false-positive cases to
  `corpus_test.go` for anything non-trivial.
- Absence classes (missing authz, race conditions) that a single hunk cannot
  prove get `absence_requirements` (advisory guidance), not enforced patterns.

Run `go test ./...`, then `./build.sh`, then include the regenerated
`bin/manifest.sha256` in your change.

## Custom / org rules without a PR

You don't need to fork to add project-specific rules: drop a
`.peephole-rules.json` (same schema) in your repo. They are additive and cannot
disable a built-in rule.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — do not open a public issue for a vulnerability.
