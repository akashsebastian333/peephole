package main

import (
	"strings"
	"testing"
)

// KB schema contract (blueprint §4.1): every rule ships the full record -
// CWE key, triggers, attack scenario, an exemplar pair, and a negative-test
// hint carrying an extractable adversarial payload (what N6's hint-literal
// match verifies). A rule missing any of these silently weakens the gate and
// the Stop-time test mandate. This test is the CI enforcement of the rule
// governance the blueprint requires.
func TestKBSchemaComplete(t *testing.T) {
	kb := loadKB()
	if len(kb.Rules) == 0 {
		t.Fatal("no rules loaded")
	}
	for i := range kb.Rules {
		r := &kb.Rules[i]
		if r.CWE == "" || !strings.HasPrefix(r.CWE, "CWE-") {
			t.Errorf("rule %q: bad cwe_id %q", r.Name, r.CWE)
		}
		if r.Name == "" {
			t.Errorf("%s: missing name", r.CWE)
		}
		if len(r.TaskTriggers) == 0 {
			t.Errorf("%s (%s): missing task_triggers", r.CWE, r.Name)
		}
		if r.AttackScenario == "" {
			t.Errorf("%s (%s): missing attack_scenario", r.CWE, r.Name)
		}
		if len(r.NegativeHints) != 1 {
			t.Errorf("%s (%s): negative_test_hint must be exactly one hint", r.CWE, r.Name)
		} else if payloadOf(r.NegativeHints[0]) == "" {
			t.Errorf("%s (%s): hint carries no extractable adversarial payload (need a quoted literal >= 5 chars): %q",
				r.CWE, r.Name, r.NegativeHints[0])
		}
		if len(r.Patterns) > 0 {
			// enforced rules need the exemplar pair (few-shot + regression fixture)
			if r.Exemplar.Noncompliant == "" || r.Exemplar.Compliant == "" {
				t.Errorf("%s (%s): enforced rule missing exemplar pair", r.CWE, r.Name)
			}
			if r.Exemplar.Explanation == "" {
				t.Errorf("%s (%s): missing exemplar explanation", r.CWE, r.Name)
			}
		}
		for _, p := range r.Patterns {
			if p.Confidence != "high" && p.Confidence != "medium" {
				t.Errorf("%s: pattern with bad confidence %q", r.CWE, p.Confidence)
			}
		}
	}
}
