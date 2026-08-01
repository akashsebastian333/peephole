package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// cweToOWASP maps each CWE we ship to its OWASP Top-10 2025 category, so findings
// can be rolled up for compliance reporting (the blueprint's rollup target -
// A03:2025 is Software Supply Chain Failures; SSRF merged into A01). Rules may
// override via the JSON "owasp" field; this table fills the gap for the rest.
var cweToOWASP = map[string]string{
	// A01 Broken Access Control (incl. SSRF, merged in 2025)
	"CWE-22": "A01", "CWE-73": "A01", "CWE-200": "A01", "CWE-276": "A01", "CWE-284": "A01",
	"CWE-285": "A01", "CWE-352": "A01", "CWE-377": "A01", "CWE-538": "A01", "CWE-598": "A01",
	"CWE-601": "A01", "CWE-639": "A01", "CWE-668": "A01", "CWE-862": "A01", "CWE-863": "A01",
	"CWE-918": "A01",
	// A02 Security Misconfiguration
	"CWE-250": "A02", "CWE-269": "A02", "CWE-489": "A02", "CWE-548": "A02", "CWE-611": "A02",
	"CWE-614": "A02", "CWE-653": "A02", "CWE-693": "A02", "CWE-732": "A02", "CWE-749": "A02",
	"CWE-942": "A02", "CWE-1188": "A02",
	// A03 Software Supply Chain Failures
	"CWE-494": "A03", "CWE-829": "A03", "CWE-1104": "A03", "CWE-1357": "A03",
	// A04 Cryptographic Failures
	"CWE-261": "A04", "CWE-295": "A04", "CWE-311": "A04", "CWE-319": "A04", "CWE-321": "A04",
	"CWE-323": "A04", "CWE-326": "A04", "CWE-327": "A04", "CWE-328": "A04", "CWE-329": "A04",
	"CWE-330": "A04", "CWE-338": "A04", "CWE-347": "A04", "CWE-916": "A04",
	// A05 Injection
	"CWE-74": "A05", "CWE-78": "A05", "CWE-79": "A05", "CWE-89": "A05", "CWE-90": "A05",
	"CWE-94": "A05", "CWE-95": "A05", "CWE-98": "A05", "CWE-113": "A05", "CWE-470": "A05",
	"CWE-643": "A05", "CWE-917": "A05", "CWE-943": "A05", "CWE-1236": "A05", "CWE-1321": "A05",
	"CWE-1336": "A05",
	// A06 Insecure Design
	"CWE-190": "A06", "CWE-362": "A06", "CWE-400": "A06", "CWE-409": "A06", "CWE-522": "A06",
	"CWE-546": "A06", "CWE-664": "A06", "CWE-676": "A06", "CWE-691": "A06", "CWE-770": "A06",
	"CWE-840": "A06", "CWE-841": "A06", "CWE-927": "A06", "CWE-1333": "A06",
	// A07 Identification & Authentication Failures
	"CWE-258": "A07", "CWE-306": "A07", "CWE-521": "A07", "CWE-798": "A07",
	// A08 Software & Data Integrity Failures
	"CWE-426": "A08", "CWE-502": "A08", "CWE-915": "A08",
	// A09 Logging & Alerting Failures
	"CWE-117": "A09", "CWE-359": "A09", "CWE-532": "A09",
	// A10 Mishandling of Exceptional Conditions
	"CWE-209": "A10", "CWE-703": "A10",
}

var owaspName = map[string]string{
	"A01": "Broken Access Control", "A02": "Security Misconfiguration",
	"A03": "Software Supply Chain Failures", "A04": "Cryptographic Failures",
	"A05": "Injection", "A06": "Insecure Design",
	"A07": "Identification & Authentication Failures", "A08": "Software & Data Integrity Failures",
	"A09": "Logging & Alerting Failures", "A10": "Mishandling of Exceptional Conditions",
}

// owaspOf returns the rule's OWASP categories: its declared ones, else the
// CWE-derived one, else "A00" (uncategorized).
func owaspOf(r *Rule) []string {
	if len(r.OWASP) > 0 {
		return r.OWASP
	}
	if c, ok := cweToOWASP[r.CWE]; ok {
		return []string{c}
	}
	return []string{"A00"}
}

// ruleSeverity derives a severity when the rule doesn't declare one: KEV or an
// RCE-class CWE is critical, otherwise from the strongest pattern confidence.
func ruleSeverity(r *Rule) string {
	if r.Severity != "" {
		return r.Severity
	}
	if r.KEV {
		return "critical"
	}
	switch r.CWE {
	case "CWE-78", "CWE-89", "CWE-94", "CWE-95", "CWE-502", "CWE-611", "CWE-1336", "CWE-829", "CWE-841":
		return "critical"
	}
	for _, p := range r.Patterns {
		if p.Confidence == "high" {
			return "high"
		}
	}
	return "medium"
}

// securityScore maps severity to a GitHub code-scanning security-severity number.
func securityScore(sev string) string {
	switch sev {
	case "critical":
		return "9.3"
	case "high":
		return "7.5"
	default:
		return "5.0"
	}
}

func sarifLevel(sev string) string {
	if sev == "medium" {
		return "warning"
	}
	return "error"
}

// firstMatchLine returns the 1-based line of the rule's first matching pattern in
// content (for a SARIF region), or 1 if it can't be localized.
func firstMatchLine(r *Rule, lang, content string) int {
	for j := range r.Patterns {
		p := &r.Patterns[j]
		if p.Lang != "" && lang != "" && p.Lang != lang {
			continue
		}
		if p.compile() != nil || p.re == nil {
			continue
		}
		if loc := p.re.FindStringIndex(content); loc != nil {
			return strings.Count(content[:loc[0]], "\n") + 1
		}
	}
	return 1
}

// cliSarif scans the given files and writes a SARIF 2.1.0 report to stdout -
// SARIF is the standard code-scanning interchange format (GitHub, Azure DevOps,
// most SAST dashboards), giving regulated teams machine-readable evidence.
func cliSarif(paths []string) {
	kb := loadKB()
	type sarifRule struct {
		ID               string                 `json:"id"`
		Name             string                 `json:"name"`
		ShortDescription map[string]string      `json:"shortDescription"`
		Properties       map[string]interface{} `json:"properties"`
	}
	type result struct {
		RuleID    string                   `json:"ruleId"`
		Level     string                   `json:"level"`
		Message   map[string]string        `json:"message"`
		Locations []map[string]interface{} `json:"locations"`
	}
	seen := map[string]bool{}
	var rules []sarifRule
	var results []result
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		content := string(b)
		lang := langOf(p)
		for _, f := range kb.scan(p, content) {
			r := f.Rule
			sev := ruleSeverity(r)
			if !seen[r.CWE] {
				seen[r.CWE] = true
				tags := []string{"security", "external/cwe/" + strings.ToLower(r.CWE)}
				for _, o := range owaspOf(r) {
					tags = append(tags, "OWASP-2025/"+o)
				}
				rules = append(rules, sarifRule{
					ID: r.CWE, Name: r.Name,
					ShortDescription: map[string]string{"text": r.Name},
					Properties: map[string]interface{}{
						"security-severity": securityScore(sev), "tags": tags,
					},
				})
			}
			results = append(results, result{
				RuleID: r.CWE, Level: sarifLevel(sev),
				Message: map[string]string{"text": fmt.Sprintf("%s (%s, %s confidence) - %s", r.Name, r.CWE, f.Confidence, r.AttackScenario)},
				Locations: []map[string]interface{}{{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{"uri": p},
						"region":           map[string]int{"startLine": firstMatchLine(r, lang, content)},
					},
				}},
			})
		}
	}
	if rules == nil {
		rules = []sarifRule{}
	}
	if results == nil {
		results = []result{}
	}
	doc := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{{
			"tool": map[string]interface{}{"driver": map[string]interface{}{
				"name": "peephole", "version": "0.2.0",
				"rules": rules,
			}},
			"results": results,
		}},
	}
	out, _ := json.MarshalIndent(doc, "", "  ")
	fmt.Println(string(out))
}
