package main

import "embed"

// Rules are embedded into the binary at compile time. This is the running
// source of truth: a local attacker editing loose rules/*.json cannot change
// enforcement (the binary ignores the files on disk), and there is no file I/O
// on the hot path to load them. Poisoning the KB requires replacing the binary,
// which the self-integrity check (integrity.go) detects.
//
//go:embed rules/*.json
var rulesFS embed.FS
