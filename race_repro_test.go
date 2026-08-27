package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Deterministic demonstration that addSessionSet loses keys.
//
// withLock spins ~400 x 1ms and then, by design, runs the callback WITHOUT the
// lock ("logging must never block enforcement"). That is correct for the
// append-only audit chain it was written for. addSessionSet, however, does a
// read-modify-write, so two callbacks running unlocked each compute a union that
// omits the other's keys and the last os.Rename wins.
//
// TestAddSessionSetConcurrent only exposes this when the machine is loaded enough
// for contention to exceed the ~400ms budget. This test creates the contention
// deterministically by holding the lockfile for longer than the budget, with a
// fresh mtime so the 3s stale-lock steal does not fire.
func TestAddSessionSetLosesKeysWhenLockAbandoned(t *testing.T) {
	sd := t.TempDir()
	if err := os.MkdirAll(sd, 0o700); err != nil {
		t.Fatal(err)
	}
	lp := filepath.Join(sd, "log.lock")
	if err := os.WriteFile(lp, []byte("held"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Keep the lock "fresh" so withLock never steals it as stale, and hold it
	// past the ~400ms give-up budget.
	stop := make(chan struct{})
	var toucher sync.WaitGroup
	toucher.Add(1)
	go func() {
		defer toucher.Done()
		for {
			select {
			case <-stop:
				return
			default:
				now := time.Now()
				_ = os.Chtimes(lp, now, now)
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()

	var wg sync.WaitGroup
	for _, c := range []string{"idor", "race", "csrf", "bizlogic"} {
		wg.Add(1)
		go func(c string) { defer wg.Done(); markSemReview(sd, "s1", []string{c}) }(c)
	}
	wg.Wait()
	close(stop)
	toucher.Wait()
	_ = os.Remove(lp)

	got := map[string]bool{}
	for _, k := range sessionSemReview(sd, "s1") {
		got[k] = true
	}
	missing := []string{}
	for _, c := range []string{"idor", "race", "csrf", "bizlogic"} {
		if !got[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("lost %d of 4 classes: %v (kept %v)", len(missing), missing, got)
	}
}
