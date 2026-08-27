package main

import (
	"fmt"
	"runtime"
)

const version = "0.5.1"

func cliVersion() {
	kb := loadKB()
	pats := 0
	for i := range kb.Rules {
		pats += len(kb.Rules[i].Patterns)
	}
	fmt.Printf("peephole %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	fmt.Printf("%d rules, %d patterns, %d cross-line taint specs\n", len(kb.Rules), pats, len(generatedTaintSpecs))
}
