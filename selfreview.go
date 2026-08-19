package main

import (
	"regexp"
	"strings"
)

// The Stop-time adversarial self-review is the expensive half of "born-secure":
// it forces a model continuation. Running it on every security-relevant session
// is the bulk of the wall-time overhead, yet it only helps the absence-of-guard
// classes (IDOR / race / CSRF / business-logic / rate-limit) that the LANDED code
// actually touches. So we classify the written code cheaply (regex, sub-ms, at
// write time) and fire the review ONLY for the classes present, scoped to those
// classes - skipping it entirely for the common pattern-tier code that touches
// none. This is the cascade principle (cheap deterministic first stage, heavy
// model review only for the risky minority) shared by FrugalGPT / AutoMix and the
// Chinese guardrail-engineering practice (低延迟护栏: heavy self-inspection only
// for high-risk requests).

const selfReviewHeader = `Before you finish, RED-TEAM the code you wrote THIS session. You hold a VALID but
LOW-PRIVILEGE account. For each class below, QUOTE the exact line(s) that enforce the guard,
or write "ABSENT" and FIX it now before stopping. "Looks fine" is not allowed.`

type semReviewBlock struct {
	key    string
	detect *regexp.Regexp // the landed code touches this class
	text   string         // the adversarial review block for it
}

// Detectors lean toward firing (a missed semantic class silently loses the
// guard), but "over-firing only costs a continuation the review would have run
// anyway" is false once a class fires SPURIOUSLY: each extra class adds a block
// the model must answer, and a plain GET read endpoint measured 274s vs 27s
// because three classes fired on it - `ratelimit` on the word "authenticated"
// inside an error string, `csrf` on a bare session read, `race` on any `+=`.
// So each detector requires evidence that the class actually applies: a
// state-changing route for CSRF, an auth route (not the word) for rate limiting,
// and a shared-state noun near the mutation for the race class.
var semReviewBlocks = []semReviewBlock{
	{"idor", regexp.MustCompile(`(?i)<int:\w*id|<\w*id>|get_object_or_404|\.get\(\s*(?:pk|id)\s*=|\binvoice\b|\.query\.get\(|find_by_id|findbyid|findbypk|findunique|req\.params\.\w*id|/:\w*id\b|/(?:user|account|order|invoice|document|record)/[<:]|WHERE\s+id\s*=`),
		`- IDOR / object authorization: every fetch or mutation of a record by a client-supplied id
  MUST filter by the authenticated owner in the SAME query (WHERE id=? AND owner_id=?), not
  fetch-then-maybe-check; return 404 on mismatch. Quote the ownership check or add it.
  (Exploit: replay the request with account B's session and read account A's object.)`},
	{"race", regexp.MustCompile(`(?i)\bwithdraw\b|\bdeduct\b|\b(?:balance|in_stock|stock|quota|inventory|credits?|points?|seats?|tickets?)\b[^\n]{0,80}(?:[-+]=|=\s*[\w.]*\b(?:balance|stock|quota|inventory|credits?)\b|\bUPDATE\b|\bSET\b)|(?:[-+]=|\bSET\b)[^\n]{0,40}\b(?:balance|in_stock|stock|quota|inventory|credits?)\b`),
		`- Race / atomicity (TOCTOU): any read-check-write on shared state (balance, stock, counter,
  quota) MUST be ONE atomic operation - UPDATE ... SET x=x-? WHERE x>=? (check rows-affected),
  SELECT ... FOR UPDATE in a transaction, or compare-and-set - never compute the new value in
  app code from a separately-read value. Quote the atomic op or add it. (Exploit: two
  concurrent requests drive the balance below zero.)`},
	{"csrf", regexp.MustCompile(`(?i)methods\s*=\s*\[[^]]*(?:POST|PUT|DELETE|PATCH)|@\w+\.(?:post|put|delete|patch)\b|\b(?:router|app)\.(?:post|put|delete|patch)\s*\(|\btransfer\b|\bset_cookie\b|\blogin_user\b|\bsession\[[^\]]+\]\s*=`),
		`- CSRF: every state-changing, cookie-authenticated endpoint MUST enforce an anti-CSRF token
  and SameSite cookies (a token-in-Authorization-header API is exempt - say which applies).
  Quote it or add it.`},
	{"bizlogic", regexp.MustCompile(`(?i)(?:price|total|amount|qty|quantity|discount|cost|subtotal)\b[^\n]{0,60}(?:request\.(?:form|json|args|values|data)|\bform\[|\bjson\[)|(?:request\.(?:form|json|args|values)|\bform\[|\bjson\[)[^\n]{0,40}(?:price|total|amount|qty|quantity)`),
		`- Business logic / trust: never trust a client-supplied price, total, quantity, role, or
  status. Re-derive prices/totals from server data at request time, validate quantity ranges
  (reject negative/zero), authorize role/status changes. Quote the server-side derivation or add it.`},
	{"ratelimit", regexp.MustCompile(`(?i)/login\b|/signin\b|/otp\b|/password[-_]?reset\b|def\s+(?:login|signin|authenticate|verify_otp|reset_password)\b|\bcheck_password\b|\bverify_password\b|\bpassword_reset\b|\bverify_otp\b`),
		`- Rate limiting: auth / login / OTP / password-reset / token endpoints MUST have per-account
  AND per-IP rate limiting or lockout/backoff. Quote it or add it.`},
}

// semReviewKeys returns the semantic-class keys the code touches (nil = none, so
// the Stop self-review is skipped entirely).
func semReviewKeys(content string) []string {
	var out []string
	for i := range semReviewBlocks {
		if semReviewBlocks[i].detect.MatchString(content) {
			out = append(out, semReviewBlocks[i].key)
		}
	}
	return out
}

// buildSelfReview assembles the adversarial review for the touched classes only,
// appending the session diff when one is available.
func buildSelfReview(keys []string, diff string) string {
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	var b strings.Builder
	b.WriteString(selfReviewHeader)
	for i := range semReviewBlocks {
		if want[semReviewBlocks[i].key] {
			b.WriteString("\n\n")
			b.WriteString(semReviewBlocks[i].text)
		}
	}
	// Terse output contract: the review exists to make the model LOOK, not to
	// produce a report. One line per class keeps the continuation short - the
	// verbose "output the class, the guard and the fix" form turned a single
	// endpoint into a multi-page audit write-up.
	b.WriteString("\n\nAnswer in ONE line per class, nothing else: `<class>: <quoted guard line>` or `<class>: FIXED <what you changed>`. No preamble, no summary, no restating the code.")
	if diff != "" {
		b.WriteString("\n\nThe code you wrote this session:\n```diff\n" + diff + "\n```")
	}
	return b.String()
}
