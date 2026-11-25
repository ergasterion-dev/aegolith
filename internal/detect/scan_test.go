package detect

import (
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

// scanTextPositives is every positive value of the text detectors (Tasks 4
// to 6). Each must still produce at least one hit through ScanText, which
// proves the prefilter never drops them.
func scanTextPositives() []string {
	var all []string
	for _, tbl := range [][]string{
		sqliPositives, xssPositives, decodedOnlyPositives, copyProgramPositives, scriptURLPositives,
		cmdIPositives, codeIPositives, codeISerializedPositives, ldapPositives, sstiPositives,
		jndiPositives, crlfPositives,
		lfiTraversalPositives, lfiFilePositives, rfiPositives, ssrfMetadataPositives, ssrfPrivatePositives,
	} {
		all = append(all, tbl...)
	}
	return all
}

// scanTextNegatives is every negative value of the text detectors plus the
// legitimate user agents and paths. None may produce a hit through ScanText.
func scanTextNegatives() []string {
	var all []string
	for _, tbl := range [][]string{
		legitNegatives, xssNegatives, copyProgramNegatives, scriptURLNegatives,
		injectionLegit, cmdINegatives, codeINegatives, ldapNegatives, sstiNegatives, jndiNegatives, crlfNegatives,
		lfiNegatives, rfiNegatives, ssrfNegatives,
		legitUserAgents, legitPaths,
	} {
		all = append(all, tbl...)
	}
	return all
}

func TestScanTextPrefilterSafe(t *testing.T) {
	for _, v := range scanTextPositives() {
		if hits := ScanText(v); len(hits) == 0 {
			t.Errorf("ScanText(%q) = no hits, want at least one (prefilter=%v)", v, mayContainAttack(v))
		}
	}
}

func TestScanTextLegit(t *testing.T) {
	for _, v := range scanTextNegatives() {
		if hits := ScanText(v); len(hits) != 0 {
			t.Errorf("ScanText(%q) = %+v, want no hits", v, hits)
		}
	}
}

// TestScanTextPrefilterSound generates random values the prefilter lets
// through (mayContainAttack returns false) and checks that no detector but
// SQLi, which ScanText still runs on them, hits any of them. The alphabet
// mixes command, file, scheme, code-injection and SQL words, numbers in
// several notations, and every byte outside the prefilter's set.
func TestScanTextPrefilterSound(t *testing.T) {
	pieces := strings.Fields("a x id ls cat sh bash nc ncat rm type dir cmd powershell whoami uname ping curl wget " +
		"admin root user name version sleep benchmark char concat current_user group_concat union select or and " +
		"rO0A ace d0005 process mainModul child require exec spawn eval assert base64_decode jndi ldap lower upper " +
		"file php gopher dict jar expect data text html http https localhost metadata google internal " +
		"etc passwd shadow proc self serviceaccount token win ini boot Set Cookie Location Content Type config " +
		"__class__ T javascript vbscript alert onerror onload svg script img src " +
		"0 1 7 42 127 169 254 0x7f 0x41 1e5 1.5 .5 0b1 0177 2130706433")
	pieces = append(pieces, " ", "  ", "\t", "\v", "\f", ",", ".", "..", "-", "--", "_", "@", "@@", "#", "+",
		"!", "?", "^", "~", "[", "]", "é", "دودھ", "😋", " -", "1 ", " 1")
	others := []struct {
		name string
		fn   func(string) (Hit, bool)
	}{
		{"XSS", XSS}, {"CmdI", CmdI}, {"CodeI", CodeI}, {"LDAP", LDAP}, {"SSTI", SSTI},
		{"JNDI", JNDI}, {"CRLF", CRLF}, {"LFI", LFI}, {"RFI", RFI}, {"SSRF", SSRF},
	}
	rng := rand.New(rand.NewPCG(1, 2))
	var b strings.Builder
	checked := 0
	for n := 0; n < 300000; n++ {
		b.Reset()
		for k := 1 + rng.IntN(10); k > 0; k-- {
			b.WriteString(pieces[rng.IntN(len(pieces))])
		}
		v := b.String()
		if mayContainAttack(v) {
			continue
		}
		checked++
		for _, f := range others {
			if hit, ok := f.fn(v); ok {
				t.Fatalf("prefilter skips %q but %s hits it: %+v", v, f.name, hit)
			}
		}
	}
	if checked < 100000 {
		t.Fatalf("only %d generated values passed the prefilter; the test is not exercising it", checked)
	}
}

// TestScanTextSkippedStillRunsSQLi checks the prefilter's clean path: a
// quote-free injection made of words and numbers alone is still caught.
func TestScanTextSkippedStillRunsSQLi(t *testing.T) {
	for _, v := range []string{"1 UNION SELECT 1", "1#current_user", "0x41-^^current_user"} {
		if mayContainAttack(v) {
			t.Fatalf("mayContainAttack(%q) = true; pick a value the prefilter skips", v)
		}
		hits := ScanText(v)
		if len(hits) != 1 || hits[0].RuleID != "AEG-SQLI-001" {
			t.Errorf("ScanText(%q) = %+v, want [AEG-SQLI-001]", v, hits)
		}
	}
}

func TestScanTextOrderAndDedup(t *testing.T) {
	// gopher to a loopback host is both RFI and SSRF; RFI runs first.
	hits := ScanText("gopher://127.0.0.1:6379/_FLUSHALL")
	if len(hits) != 2 || hits[0].RuleID != "AEG-RFI-001" || hits[1].RuleID != "AEG-SSRF-002" {
		t.Fatalf("ScanText(gopher) = %+v, want [AEG-RFI-001 AEG-SSRF-002]", hits)
	}
	// A value hitting many detectors lists each rule once, in ScanText order.
	hits = ScanText("'; cat /etc/passwd; ../../etc/passwd <script>alert(1)</script>")
	seen := map[string]bool{}
	order := map[string]int{
		"AEG-SQLI-001": 0, "AEG-XSS-001": 1, "AEG-CMDI-001": 2, "AEG-CODEI-001": 3, "AEG-CODEI-002": 3,
		"AEG-LDAP-001": 4, "AEG-SSTI-001": 5, "AEG-JNDI-001": 6, "AEG-CRLF-001": 7, "AEG-LFI-001": 8,
		"AEG-LFI-002": 8, "AEG-RFI-001": 9, "AEG-SSRF-001": 10, "AEG-SSRF-002": 10,
	}
	last := -1
	for _, h := range hits {
		if seen[h.RuleID] {
			t.Errorf("rule %s reported twice: %+v", h.RuleID, hits)
		}
		seen[h.RuleID] = true
		if order[h.RuleID] < last {
			t.Errorf("hits out of order: %+v", hits)
		}
		last = order[h.RuleID]
	}
	for _, id := range []string{"AEG-XSS-001", "AEG-CMDI-001", "AEG-LFI-001"} {
		if !seen[id] {
			t.Errorf("ScanText missing %s: %+v", id, hits)
		}
	}
	if hits := ScanText("milk"); hits != nil {
		t.Errorf("ScanText(milk) = %+v, want nil", hits)
	}
}

// TestScanTextLinear runs ScanText on adversarial values (long repetitions
// of every detector's trigger). The growth check compares 64 KiB with
// 256 KiB, sizes that stay in cache, and allows eight times the time for
// four times the input (quadratic growth would be sixteen). Past the CPU
// caches timings jump for reasons that have nothing to do with the
// algorithm, so at 1 MiB only an absolute bound is checked.
func TestScanTextLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("wall-clock bound; skipped under -short")
	}
	units := map[string]string{
		"traversal":           "../",
		"enc-dots":            "%2e%2e",
		"dots":                "..",
		"url":                 "http://",
		"scheme-sep":          "://",
		"loopback":            "http://127.0.0.1",
		"userinfo":            "a://@",
		"ipv6":                "x://[",
		"nul":                 "%00",
		"percent":             "%",
		"jndi":                "${",
		"cmdi":                "; id x",
		"ssti":                "{{",
		"ldap":                ")(",
		"crlf":                "\r\n",
		"sqli":                "' or 1=1 --",
		"keyword":             "union ",
		"rfi":                 "file:",
		"mixed":               "../%2e{{${;|&<>'\"://",
		"etc":                 "/etc/",
		"java":                "rO0AB",
		"backslashes":         "..\\",
		"union-comment":       "union /* ",
		"union-paren-comment": "and union (/* note ",
		"comment-backtick":    "<!-- `x` -->",
		"open-comment":        "<!--`onx -",
		"placeholder-tag":     "<link>",
		"doctype-mention":     "<!doctype ",
	}
	const small, medium, large = 64 << 10, 256 << 10, 1 << 20
	limit := wallLimit(2*time.Second, 20*time.Second)
	for name, unit := range units {
		s := strings.Repeat(unit, small/len(unit))
		m := strings.Repeat(unit, medium/len(unit))
		l := strings.Repeat(unit, large/len(unit))
		// The race detector's instrumentation and GC pauses make ratios
		// noisy, so the growth check runs only without -race, and a ratio
		// over the limit must repeat three times in a row to count.
		if raceSlowdown == 1 && superLinear(s, m) && superLinear(s, m) && superLinear(s, m) {
			t.Errorf("%s: ScanText on %d bytes took over 8x its time on %d bytes: super-linear", name, len(m), len(s))
		}
		if dl := bestOf(3, func() { ScanText(l) }); dl > limit {
			t.Errorf("%s: ScanText on %d bytes took %v, want under %v", name, len(l), dl, limit)
		}
	}
}

// superLinear reports whether ScanText on m (four times the length of s)
// took more than eight times as long as on s, best of five runs each.
// Runs on s under 500µs are too fast to time reliably and never count.
func superLinear(s, m string) bool {
	ds := bestOf(5, func() { ScanText(s) })
	dm := bestOf(5, func() { ScanText(m) })
	return ds > 500*time.Microsecond && dm > 8*ds
}
