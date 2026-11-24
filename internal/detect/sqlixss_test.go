package detect

import (
	"testing"

	"github.com/ergasterion-dev/pylolith/internal/model"
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
	"+91 9000000000",
	"Please ring the bell, don't knock. Gate code 1234 & leave at door",
	"دودھ اور روٹی",
	"दूध और ब्रेड",
}

func TestSQLiPositives(t *testing.T) {
	for _, v := range []string{
		"1' OR '1'='1",
		"admin'--",
		"1 OR 1=1",
		"1 UNION SELECT username, password FROM users--",
		"1' AND (SELECT 1 FROM pg_sleep(5))--",
		"1'/**/UNION/**/SELECT/**/1,2--",
		"1' uNiOn SeLeCt 1,2--",
		"'; COPY (SELECT '') TO PROGRAM 'id'--",
		"1%27%20OR%20%271%27=%271",
	} {
		hit, ok := SQLi(v)
		if !ok {
			t.Errorf("SQLi(%q) = no hit, want hit", v)
			continue
		}
		want := Hit{RuleID: "PYL-SQLI-001", Category: model.CatSQLi, Severity: model.SeverityCritical}
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
	for _, v := range []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg/onload=alert(document.cookie)>",
		"javascript:alert(1)",
		`" onmouseover="alert(1)`,
		"<ScRiPt >alert(1)</sCrIpT >",
		`<a href="&#106;avascript:alert(1)">x</a>`,
	} {
		hit, ok := XSS(v)
		if !ok {
			t.Errorf("XSS(%q) = no hit, want hit", v)
			continue
		}
		want := Hit{RuleID: "PYL-XSS-001", Category: model.CatXSS, Severity: model.SeverityHigh}
		if hit != want {
			t.Errorf("XSS(%q) = %+v, want %+v", v, hit, want)
		}
	}
}

func TestXSSNegatives(t *testing.T) {
	vals := append([]string{
		"Fresh & tasty 😋 – 5/5! Will order again :)",
		"price<500",
		"I <3 this shop",
	}, legitNegatives...)
	for _, v := range vals {
		if hit, ok := XSS(v); ok {
			t.Errorf("XSS(%q) = %+v, want no hit", v, hit)
		}
	}
}

// TestDecodedOnly checks that a payload visible only after percent-decoding
// is still caught.
func TestDecodedOnly(t *testing.T) {
	if _, ok := XSS("%3Cscript%3Ealert(1)%3C%2Fscript%3E"); !ok {
		t.Error("XSS on percent-encoded <script> = no hit, want hit")
	}
	if _, ok := SQLi("admin%27--"); !ok {
		t.Error("SQLi on percent-encoded admin'-- = no hit, want hit")
	}
}

// TestCopyProgram covers the stacked PostgreSQL COPY ... PROGRAM rule that
// supplements libinjection, and the prose it must not match.
func TestCopyProgram(t *testing.T) {
	for _, v := range []string{
		"'; COPY (SELECT '') TO PROGRAM 'id'--",
		"1;copy users to program 'id'",
		"x';/**/COPY/**/t(a)/**/FROM/**/PROGRAM/**/'id'--",
		"'; copy public.t to program E'id'--",
		"'; COPY(SELECT 1) TO PROGRAM $$id$$--",
	} {
		if _, ok := SQLi(v); !ok {
			t.Errorf("SQLi(%q) = no hit, want hit", v)
		}
	}
	for _, v := range []string{
		"Meet at 5; copy the list to program 'abc'",
		"don't; copy that",
		"Copy to program 'x' please",
		"Room 12; copy notes to programme 'abc'",
		"pick up; copy t to program everything",
	} {
		if hit, ok := SQLi(v); ok {
			t.Errorf("SQLi(%q) = %+v, want no hit", v, hit)
		}
	}
}

// TestScriptURL covers the bare javascript:/vbscript: URL rule that
// supplements libinjection, and the prose it must not match.
func TestScriptURL(t *testing.T) {
	for _, v := range []string{
		"javascript:alert(1)",
		"  JavaScript:alert(1)",
		"java\tscript:alert(1)",
		"javascript: window.location='https://evil.example'",
		"javascript://%0Aalert(1)",
		"javascript:alert`1`",
		"vbscript:msgbox(1)",
		"javascript%3Aalert(1)",
	} {
		if _, ok := XSS(v); !ok {
			t.Errorf("XSS(%q) = no hit, want hit", v)
		}
	}
	for _, v := range []string{
		"JavaScript: The Good Parts",
		"javascript: is it hard to learn?",
		"Learn javascript:alert(1) is a famous payload",
		"javascript:",
	} {
		if hit, ok := XSS(v); ok {
			t.Errorf("XSS(%q) = %+v, want no hit", v, hit)
		}
	}
}
