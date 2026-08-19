package main

import (
	"fmt"
	"runtime"
)

// version is the single source of truth for the shipped version. Everything that
// reports a version reads it from here: the `version` subcommand, the MCP and LSP
// serverInfo handshakes, and the SARIF tool driver. Previously each of those
// carried its own literal and they had drifted to 0.3.0, 0.3.0 and 0.2.0 while
// the plugin manifest said 0.4.0, so a consumer could not tell what it was
// running. Bump this, .claude-plugin/plugin.json and
// .claude-plugin/marketplace.json together, then tag.
const version = "0.5.0"

// cliVersion prints the version, the target it was built for, and the rule
// counts, so an operator can confirm what a deployed binary actually is.
func cliVersion() {
	kb := loadKB()
	pats := 0
	for i := range kb.Rules {
		pats += len(kb.Rules[i].Patterns)
	}
	fmt.Printf("peephole %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	fmt.Printf("%d rules, %d patterns, %d cross-line taint specs\n", len(kb.Rules), pats, len(generatedTaintSpecs))
}
