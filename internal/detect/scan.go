package detect

import "strings"

// textDetectors are the detectors ScanText runs, in order. Read-only.
var textDetectors = [...]func(string) (Hit, bool){
	SQLi, XSS, CmdI, CodeI, LDAP, SSTI, JNDI, CRLF, LFI, RFI, SSRF,
}

// queryTextDetectors are the detectors ScanQueryText runs: textDetectors
// with CmdI's query form. Read-only.
var queryTextDetectors = [...]func(string) (Hit, bool){
	SQLi, XSS, cmdIQuery, CodeI, LDAP, SSTI, JNDI, CRLF, LFI, RFI, SSRF,
}

// ScanText runs every text detector on v (SQLi, XSS, CmdI, CodeI, LDAP,
// SSTI, JNDI, CRLF, LFI, RFI, SSRF, in that order) and returns their hits,
// each rule ID at most once, or nil when there are none.
//
// A cheap prefilter (mayContainAttack) comes first. When it finds none of
// the bytes and markers the detectors need, which is most real customer
// text, only SQLi runs: a quote-free SQL injection such as "1 OR 1" or
// "1 UNION SELECT 1" is made of words alone, and whether a word is one of
// the thousands of keywords and functions libinjection knows is decided by
// libinjection's own tokenizer, not by a copy of its dictionary here.
//
// Every detector is linear in len(v), so ScanText is too. Fields typed as
// URLs are not passed here; the engine runs only SSRF on them.
func ScanText(v string) []Hit { return scanText(v, &textDetectors) }

// ScanQueryText is ScanText for a URL query value the engine has already
// percent-decoded once. The only difference is in CmdI: a query string
// cannot carry a raw line break, so a line break in the value arrived
// percent-encoded ("q=x%0aid"), and a bare command after it is not read as
// a line of prose the way "Notes:\nls" in a JSON note or a form textarea
// is.
func ScanQueryText(v string) []Hit { return scanText(v, &queryTextDetectors) }

func scanText(v string, detectors *[len(textDetectors)]func(string) (Hit, bool)) []Hit {
	if !mayContainAttack(v) {
		if h, ok := SQLi(v); ok {
			return []Hit{h}
		}
		return nil
	}
	var hits []Hit
	for _, detect := range detectors {
		h, ok := detect(v)
		if !ok || containsRule(hits, h.RuleID) {
			continue
		}
		hits = append(hits, h)
	}
	return hits
}

func containsRule(hits []Hit, id string) bool {
	for _, h := range hits {
		if h.RuleID == id {
			return true
		}
	}
	return false
}

// mayContainAttack is ScanText's prefilter. It reports false only when v
// has none of the following, so that no detector but SQLi can match:
//
//   - a byte from ' " < > ; | & $ ( ) { } % \ / * : or a backtick, CR, LF,
//     NUL or '='. Between them these are every shell operator (CmdI), the
//     PHP/ERB tag and call syntax (CodeI), filter parentheses (LDAP),
//     template delimiters (SSTI), "${" (JNDI), line breaks (CRLF), path
//     separators, percent escapes and NUL (LFI), and the scheme colon
//     (RFI, SSRF, javascript: URLs). libinjection's XSS check needs '<' for
//     a tag, or '=', a quote or a backtick before an attribute value.
//   - a '-' at the start or after a blank: the flag in the CmdI markers
//     bash -i, nc -e and powershell -e.
//   - the CodeI markers that need none of the bytes above: mainModule,
//     child_process (then .exec or .spawn), and the Java serialization
//     headers rO0AB and aced0005.
//
// TestScanTextPrefilterSafe runs every detector positive through ScanText,
// and TestScanTextPrefilterSound checks random values the prefilter skips
// against every detector. The scan is one pass plus four substring
// searches, all linear.
func mayContainAttack(v string) bool {
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\'', '"', '<', '>', ';', '|', '&', '$', '(', ')', '{', '}', '%', '\\', '/', '*', ':',
			'`', '\r', '\n', 0, '=':
			return true
		case '-':
			if i == 0 || v[i-1] == ' ' || v[i-1] == '\t' {
				return true
			}
		}
	}
	return strings.Contains(v, "rO0AB") || indexFold(v, "aced0005") >= 0 ||
		indexFold(v, "mainmodule") >= 0 || indexFold(v, "child_process") >= 0
}
