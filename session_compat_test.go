package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The append-only rewrite must still read a set file written by the previous
// implementation, so a session already in flight when the binary is upgraded does
// not silently lose its recorded classes.
func TestReadSessionSetLegacyFormat(t *testing.T) {
	sd := t.TempDir()
	dir := filepath.Join(sd, "session")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Pre-append-only format: one line, comma-joined, no trailing newline.
	if err := os.WriteFile(filepath.Join(dir, "s1.semreview"), []byte("csrf,idor,race"), 0o600); err != nil {
		t.Fatal(err)
	}
	if g := readSessionSet(sd, "s1", "semreview"); len(g) != 3 {
		t.Fatalf("legacy format: got %v, want 3 keys", g)
	}
	// Legacy line followed by new appended records (upgrade mid-session).
	if err := os.WriteFile(filepath.Join(dir, "s2.semreview"), []byte("csrf,idor\nrace\nbizlogic,ratelimit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if g := readSessionSet(sd, "s2", "semreview"); len(g) != 5 {
		t.Fatalf("mixed format: got %v, want 5 keys", g)
	}
	// Duplicates across records collapse.
	if err := os.WriteFile(filepath.Join(dir, "s3.semreview"), []byte("idor\nidor\nidor,csrf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if g := readSessionSet(sd, "s3", "semreview"); len(g) != 2 {
		t.Fatalf("dedupe: got %v, want 2 keys", g)
	}
}
