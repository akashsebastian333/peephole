<!-- Thanks for contributing to Peephole. -->

## What this changes

<!-- One or two sentences. Link any related issue: Closes #123 -->

## Checklist

- [ ] `go test ./...` passes (ran `-race` locally).
- [ ] `gofmt -l *.go cmd internal` is empty and `go vet ./...` is clean.
- [ ] If I changed any `.go` file or `rules/*.json`, I ran `./build.sh` and
      included the regenerated `bin/manifest.sha256`.
- [ ] New/changed rules have a `compliant` and `noncompliant` exemplar, and
      (for non-trivial ones) true-positive + false-positive cases in
      `corpus_test.go`.
- [ ] Regexes are RE2-safe (no lookaround/backreferences).

## Security

- [ ] This is **not** an enforcement/self-protection bypass (those go to
      [SECURITY.md](../SECURITY.md), privately — not a public PR).
