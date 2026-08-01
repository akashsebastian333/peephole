//go:build race

package main

// raceEnabled reports whether the binary was built with the race detector, so
// latency assertions can scale their budget (instrumentation is ~20x on the
// regex-heavy scan path; the §7.4 budget applies to the shipped native binary).
const raceEnabled = true
