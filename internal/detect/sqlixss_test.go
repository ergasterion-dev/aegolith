package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

// legitNegatives is realistic customer input that must never be flagged by
// either detector.
var legitNegatives = []string{
	"milk",
	"milk & bread",
	"kid's snacks",
	"O'Brien",
	"select fresh vegetables",
	"union bank atm near me",
	"drop off at gate 2",
	"price<500",
	"House #12, Lal Chowk, Srinagar 190001",
	"50% off",
	"+91 9000012345",
	"Please ring the bell, don't knock. Gate code 1234 & leave at door",
	"دودھ اور روٹی",
	"दूध और ब्रेड",
	// Task 9 corpus: a number, prose, then a comment token (fingerprint 1c).
	"10% off -- limited",
	"Pack of 2 -- fresh",
}

// The positive and negative tables are package-level so that ScanText's
// tests (scan_test.go) can run every one of them through the combined scan.
var (
	sqliPositives = []string{
		"1' OR '1'='1",
		"admin'--",
		"1 OR 1=1",
		"1 UNION SELECT username, password FROM users--",
		"1' AND (SELECT 1 FROM pg_sleep(5))--",
		"1'/**/UNION/**/SELECT/**/1,2--",
		"1' uNiOn SeLeCt 1,2--",
		"'; COPY (SELECT '') TO PROGRAM 'id'--",
		"1%27%20OR%20%271%27=%271",
		// Task 9: the 1c guard needs a letter before the comment.
		"1--",
		"5-- ",
		"10 -- limited",
		"100 /* see note */",
	}
	xssPositives = []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg/onload=alert(document.cookie)>",
		"javascript:alert(1)",
		`" onmouseover="alert(1)`,
		"<ScRiPt >alert(1)</sCrIpT >",
		`<a href="&#106;avascript:alert(1)">x</a>`,
	}
	xssNegatives = []string{
		"Fresh & tasty 😋 – 5/5! Will order again :)",
		"price<500",
		"I <3 this shop",
	}
	decodedOnlyPositives = []string{
		"%3Cscript%3Ealert(1)%3C%2Fscript%3E",
		"admin%27--",
	}
	copyProgramPositives = []string{
		"'; COPY (SELECT '') TO PROGRAM 'id'--",
		"1;copy users to program 'id'",
		"x';/**/COPY/**/t(a)/**/FROM/**/PROGRAM/**/'id'--",
		"'; copy public.t to program E'id'--",
		"'; COPY(SELECT 1) TO PROGRAM $$id$$--",
		"x'; copy (select 1); copy (select '') to program 'id'--",
		"x'; copy t; copy t to program 'id'--",
	}
	copyProgramNegatives = []string{
		"Meet at 5; copy the list to program 'abc'",
		"don't; copy that",
		"Copy to program 'x' please",
		"Room 12; copy notes to programme 'abc'",
		"pick up; copy t to program everything",
	}
	scriptURLPositives = []string{
		"javascript:alert(1)",
		"  JavaScript:alert(1)",
		"java\tscript:alert(1)",
		"javascript: window.location='https://evil.example'",
		"javascript://%0Aalert(1)",
		"javascript:alert`1`",
		"vbscript:msgbox(1)",
		"javascript%3Aalert(1)",
		"javascript:location=name",
		"javascript: document.cookie=1",
		// Fix round 1: the key=value prose guard must not cover these.
		"javascript: location=name",
		"javascript:\tlocation=name",
		"javascript:\nlocation=name",
		"javascript: a=1;alert(1)",
		"javascript: top=1;alert(1)",
		"javascript: x=alert,x(1)",
		// HTML whitespace references decoded like the whitespace itself.
		"javascript:&#9;location=name",
		"javascript:&Tab;location=name",
		"java&#x09;script:alert(1)",
		"java&#10script:alert(1)",
		"javascript:&#X0A;alert(1)",
		"&#13;javascript:alert(1)",
		// a call after ')' and a global assigned a global
		"javascript: x=(alert)(1)",
		"javascript: top=self",
	}
	scriptURLNegatives = []string{
		"JavaScript: The Good Parts",
		"javascript: is it hard to learn?",
		"Learn javascript:alert(1) is a famous payload",
		"javascript:",
		"JavaScript: version=ES6",
		"JavaScript: Name=Ali",
		// key=value prose with ';', '(' or a browser-global key
		"javascript: a=1; b=2",
		"JavaScript: level=beginner (2 weeks)",
		"javascript: name=Ali",
		"javascript: top=10 tips",
		"JavaScript: yes=no; maybe",
		"javascript: &#9; is a tab",
		"javascript:&amp;",
		"javascript: version=&#9;ES6",
	}
)

func TestSQLiPositives(t *testing.T) {
	for _, v := range sqliPositives {
		hit, ok := SQLi(v)
		if !ok {
			t.Errorf("SQLi(%q) = no hit, want hit", v)
			continue
		}
		want := Hit{RuleID: "AEG-SQLI-001", Category: model.CatSQLi, Severity: model.SeverityCritical}
		if hit != want {
			t.Errorf("SQLi(%q) = %+v, want %+v", v, hit, want)
		}
	}
}

func TestSQLiNegatives(t *testing.T) {
	for _, v := range legitNegatives {
		if hit, ok := SQLi(v); ok {
			t.Errorf("SQLi(%q) = %+v, want no hit", v, hit)
		}
	}
}

func TestXSSPositives(t *testing.T) {
	for _, v := range xssPositives {
		hit, ok := XSS(v)
		if !ok {
			t.Errorf("XSS(%q) = no hit, want hit", v)
			continue
		}
		want := Hit{RuleID: "AEG-XSS-001", Category: model.CatXSS, Severity: model.SeverityHigh}
		if hit != want {
			t.Errorf("XSS(%q) = %+v, want %+v", v, hit, want)
		}
	}
}

func TestXSSNegatives(t *testing.T) {
	for _, v := range append(append([]string(nil), xssNegatives...), legitNegatives...) {
		if hit, ok := XSS(v); ok {
			t.Errorf("XSS(%q) = %+v, want no hit", v, hit)
		}
	}
}

// TestDecodedOnly checks that a payload visible only after percent-decoding
// is still caught.
func TestDecodedOnly(t *testing.T) {
	if _, ok := XSS(decodedOnlyPositives[0]); !ok {
		t.Error("XSS on percent-encoded <script> = no hit, want hit")
	}
	if _, ok := SQLi(decodedOnlyPositives[1]); !ok {
		t.Error("SQLi on percent-encoded admin'-- = no hit, want hit")
	}
}

// TestCopyProgram covers the stacked PostgreSQL COPY ... PROGRAM rule that
// supplements libinjection, and the prose it must not match.
func TestCopyProgram(t *testing.T) {
	for _, v := range copyProgramPositives {
		if _, ok := SQLi(v); !ok {
			t.Errorf("SQLi(%q) = no hit, want hit", v)
		}
	}
	for _, v := range copyProgramNegatives {
		if hit, ok := SQLi(v); ok {
			t.Errorf("SQLi(%q) = %+v, want no hit", v, hit)
		}
	}
}

// TestScriptURL covers the bare javascript:/vbscript: URL rule that
// supplements libinjection, and the prose it must not match.
func TestScriptURL(t *testing.T) {
	for _, v := range scriptURLPositives {
		if _, ok := XSS(v); !ok {
			t.Errorf("XSS(%q) = no hit, want hit", v)
		}
	}
	for _, v := range scriptURLNegatives {
		if hit, ok := XSS(v); ok {
			t.Errorf("XSS(%q) = %+v, want no hit", v, hit)
		}
	}
}

// TestCopyProgramLinear checks the COPY scan stays linear on adversarial
// repetitions that used to make every ';' rescan to the end of the value.
func TestCopyProgramLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("wall-clock bound; skipped under -short")
	}
	const size = 8 << 10
	lim := wallLimit(time.Millisecond, 20*time.Millisecond)
	for name, in := range map[string]string{
		"unclosed parens":  strings.Repeat(";copy(", size/6),
		"balanced parens":  strings.Repeat(";copy(", size/12) + strings.Repeat(")", size/12),
		"unclosed comment": strings.Repeat(";copy/*", size/7),
		"quotes":           strings.Repeat(";copy('", size/7),
	} {
		if d := bestOf(3, func() { hasStackedCopyProgram(in) }); d > lim {
			t.Errorf("%s: hasStackedCopyProgram took %v on %d bytes, want under %v", name, d, len(in), lim)
		}
	}
}

// TestCopyProgramAfterEarlierStatement checks that skipping past a parsed
// COPY group still finds a later stacked statement.
func TestCopyProgramAfterEarlierStatement(t *testing.T) {
	for _, v := range copyProgramPositives[5:] {
		if _, ok := SQLi(v); !ok {
			t.Errorf("SQLi(%q) = no hit, want hit", v)
		}
	}
}
