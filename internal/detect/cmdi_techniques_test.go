package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

// assertCmdI runs vals through both CmdI entry points (body and query) and
// ScanText, and expects an AEG-CMDI-001 hit from each, or from none.
func assertCmdI(t *testing.T, want bool, vals []string) {
	t.Helper()
	cmdi := Hit{RuleID: "AEG-CMDI-001", Category: model.CatCmdi, Severity: model.SeverityCritical}
	if want {
		assertHits(t, "CmdI", CmdI, cmdi, vals)
		assertHits(t, "cmdIQuery", cmdIQuery, cmdi, vals)
	}
	for _, v := range vals {
		if !want {
			for name, fn := range map[string]func(string) (Hit, bool){"CmdI": CmdI, "cmdIQuery": cmdIQuery} {
				if hit, ok := fn(v); ok {
					t.Errorf("%s(%q) = %+v, want no hit", name, v, hit)
				}
			}
		}
		for name, scan := range map[string]func(string) []Hit{"ScanText": ScanText, "ScanQueryText": ScanQueryText} {
			if got := containsRule(scan(v), cmdi.RuleID); got != want {
				t.Errorf("%s(%q): %s reported = %v, want %v", name, v, cmdi.RuleID, got, want)
			}
		}
	}
}

// TestCmdIHereString: a word glued to "<<<" and a word is a Bash
// here-string.
func TestCmdIHereString(t *testing.T) {
	assertCmdI(t, true, []string{
		"cat<<<uname",
		";tac<<<id",
		"rev<<< 'olleh'",
		`base64<<<"hello"`,
		"x9<<<\t_v",
		"y_<<<_y",
		"a<<<b",
		"<<<<x rev<<<abc",
		"cat%3C%3C%3Cuname",
	})
	assertCmdI(t, false, []string{
		"miss you<<<3",
		"x = <<<EOT",
		"<<<<<<< HEAD",
		"main<<<<<<< HEAD",
		"=======\n>>>>>>> feature/login",
		"$sql=<<<SQL",
		"$html = <<<'HTML'",
		"scroll down <<< here",
		"love<<<3 forever",
		"a<<<$b",
		`a<<<"$HOME"`,
		"a<<<''x",
		"abc<<<",
		"abc<<<   ",
		"word<<<(see)",
		"friend std::ostream& operator<<<>(std::ostream&, const Box<T>&);",
		"P4ss<<<!word",
		"cat<<EOF",
		`std::cout<<"total"<<count;`,
		"hi<<<<<<<<there",
		"caf\u00e9<<<noir",
	})
}

// TestCmdISystemGlob: a rooted glob that matches a well-known system file or
// program is a way to name it without spelling it.
func TestCmdISystemGlob(t *testing.T) {
	assertCmdI(t, true, []string{
		"/???/?a?h",
		"/e?c/pa[s]swd",
		"cat /e??/passwd",
		";/???/c?t /e?c/p?ss??",
		"x|/bin/c[a]t",
		"x&/usr/bin/wh?am?",
		"`/usr/bin/i?`",
		"(/bin/[b]ash)",
		"{/bin/l?,-a}",
		"a,/proc/se?f/environ",
		"a=/et?/hosts",
		`p="/etc/sh*dow"`,
		"'/etc/iss[!a]e'",
		"'/etc/iss[^a]e'",
		"x </e?c/gr?up",
		"x >/d?v/tcp",
		"cat+/e?c/passwd",
		"/usr/sbin/ba?h -c",
		"/usr/bin/w?et",
		"/usr/bin/cu[r]l",
		"/usr/bin/n?",
		"/usr/bin/ba*h",
		"/usr/bin/?h",
		"/bin/n[c]",
		"/e*c",
		"/e[t/]c",
		"/etc/pass[v-x]d",
		"/???/??[t]",
		"/etc/pa**wd",
		"cat\t/etc/h?sts",
		"%2F%3F%3F%3F%2F%3Fa%3Fh",
	})
	assertCmdI(t, false, []string{
		"The redirect went to /???",
		"ls /usr/bin/py*",
		"/usr/bin/*",
		"/etc/*",
		"/*",
		"/???/??",
		"Accept: text/html,*/*;q=0.8",
		"image/*, /*",
		"*/5 * * * * /usr/local/bin/backup",
		"/* a comment */",
		"/*etc*/",
		"SELECT /*c*/ name",
		"src/**/*.ts",
		"Disallow: /*.pdf",
		`{"path":"/api/*"}`,
		"location /static/* { expires 1d; }",
		"/[a-z]*",
		`pattern: "/[a-z0-9_]*"`,
		"route '/[^/]*' matches one segment",
		"See /users/[id] and /blog/[...slug]",
		"/[locale]/about",
		"/[slug]",
		"/bin/[id]",
		`name.replace(/\s*/g, "")`,
		"(/colou?r/i)",
		"=/https?/",
		"match(/e?tc/)",
		"/e?c/",
		"/?q=shoes",
		"redirect=/?page=2&sort=asc",
		"https://example.com/e?c",
		"https://example.com/search?etc=1",
		"Did you open /etc?",
		"Is it in /etc/passwd?",
		"Edit **/etc/hosts** today",
		"path=/e?c/passwd/extra",
		"/e?c//passwd",
		"/etc/[!p]asswd",
		"/[!e]tc",
		"/E?C/passwd",
		"/etc/pass[wd",
		"/home/*/notes",
		"/usr/bin/c?",
		"10/??/2024",
		"dir /?",
		"/a?c/def",
		"/??/?? /???/????",
		"</p>*",
		"price /[kg]?",
	})
}

// TestCmdIChainedFor: a Windows FOR loop chained to another command with an
// operator.
func TestCmdIChainedFor(t *testing.T) {
	loop := "for %q in (x) do y"
	assertCmdI(t, true, []string{
		"& " + loop,
		"&" + loop,
		"| for %%a in (1) do whoami",
		"; FOR /L %i in (1,1,3) DO echo %i",
		`&& for /f "tokens=*" %i in ('whoami') do echo %i`,
		"|| For /F \"usebackq delims=\" %%G IN (`hostname`) Do @echo %%G",
		`& for /r C:\temp %f in (*.txt) do type %f`,
		`& for /d /r "C:\a b" %d in (*) do rd %d`,
		"& for /r %SystemRoot% %f in (*) do type %f",
		`& for /f"delims=" %i in ('ver') do %i`,
		"& for %@a in (x) do y",
		"& for %~[1]_ in (x) do y",
		"& for %abcdefghijklmnop in (x) do y",
		"& for %q in(x)do(y)",
		"& for /f %i in ('cmd /c (echo x)') do %i",
		"x |\tfor\t%q\tin\t(x)\tdo\ty",
		"%26%20for%20%25q%20in%20(x)%20do%20y",
	})
	assertCmdI(t, false, []string{
		loop,
		`FOR /F "tokens=1" %%a IN ('ver') DO echo %%a`,
		"@echo off\nfor %%i in (*.log) do del %%i",
		"Batch tip: for %i in (*) do echo %i",
		"Save 20% & for members (online) do nothing",
		"R&D; for %d percent in (all) cases do check",
		"Q&A for %name% in (template) do replace it",
		"Q&A; for %name% in (template) do replace it",
		"Use it; for %s in (list) done",
		"A & for %s in the list (see below) do ask",
		"A & for %s in (list) does it work?",
		"A & format %q in (x) do y",
		"A & forward %q in (x) do y",
		"A & for % in (x) do y",
		"A & for %q (x) do y",
		"A & for %qin (x) do y",
		"A & for %q in x do y",
		"A & for %q in (x) y",
		"A & for /q %q in (x) do y",
		"A & for %abcdefghijklmnopq in (x) do y",
		"A & for each item (50% off) do ask",
		"item=1&for=%20in(x)do",
		"Terms & for 100% in (store) purchases we do refunds",
	})
}

// TestCmdIChainedForSharedSet: several loops whose sets share bytes are
// each judged by their own bounds, also after an earlier loop in the value
// found no close, and when a quoted option makes an earlier operator read
// further than a later one.
func TestCmdIChainedForSharedSet(t *testing.T) {
	pad := strings.Repeat("a", 500)
	assertCmdI(t, true, []string{
		// The second loop's set reaches past the first one's bound.
		"&for %a in(" + pad + " &for %b in(" + pad + ") do y",
		// The first set holds no close; a later one, far away, does.
		"&for %a in(x) y " + pad + pad + " &for %b in(z) do y",
		// A short loop inside the quoted option of a longer one.
		`&for /f "&for %b in(z) do y" %a in(x) y`,
		`&for /f "&for %b in(z) y" %a in(x) do y`,
		`&for /f "&for %b in(" %a in(x) y &for %c in(z) do y`,
	})
	assertCmdI(t, false, []string{
		"&for %a in(" + pad + " &for %b in(" + pad + pad + ") do y",
		`&for /f "&for %b in(z) y" %a in(x) y`,
	})
}

// TestCmdITechniquesAcceptedFalsePositives pins the legitimate shapes the
// here-string, system glob and chained FOR checks flag (threat model,
// "Command injection techniques added in alpha.7"). If one stops matching,
// update that section.
func TestCmdITechniquesAcceptedFalsePositives(t *testing.T) {
	assertCmdI(t, true, []string{
		// A word glued to "<<<" and a word.
		"Back<<<Home",
		"great<<< see more",
		"echo<<<EOT",
		"operator<<<T>",
		// A rooted glob that matches a listed file.
		"ls /usr/bin/c*",
		"ls /usr/bin/*sh",
		"Add the entry to /etc/hosts* (see note)",
		"Disallow: /*/id",
		"the short pattern /e* matches it",
		"Disallow: /*c",
		`regex = "/[a-z]tc*"`,
		"redirect=/?tc=accepted",
		// A chained loop in a batch snippet.
		`@echo off & for %%i in (*.log) do del %%i`,
		"Run cd logs && for %f in (*.log) do type %f",
		"In HTML text &lt; for %s in (list) do nothing",
	})
}

// TestCmdITechniquesAcceptedMisses pins the attack shapes the three checks
// let through (threat model, same section). If one starts to hit, update it.
func TestCmdITechniquesAcceptedMisses(t *testing.T) {
	assertCmdI(t, false, []string{
		// Here-string: a blank or a quote before "<<<", or a variable or
		// substitution after it.
		"cat <<<uname",
		"'cat'<<<uname",
		"cat<<<$HOME",
		"cat<<</tmp/x",
		// Glob: no letter in the last segment, or letters only in a range
		// or a negated class.
		"/???/??",
		"/???/??[a-z]",
		"/???/??[!x]",
		// Doubled slash, escaped byte, POSIX class, more than one leading
		// character outside the list, a token that goes on past the file.
		"/e?c//passwd",
		`/e?c/p\asswd`,
		"/etc/[[:lower:]]asswd",
		"cat${IFS}/e?c/passwd",
		"x\n/e?c/passwd",
		"x:/e?c/passwd",
		"/e?c/passwd$x",
		"/d?v/t?p/192.0.2.1/4444",
		// A file that is not listed, and a token over 64 bytes.
		"/e?c/crontab",
		"/usr/local/bin/b?sh",
		"/e" + strings.Repeat("*", 64) + "c",
		// FOR: no operator, a line break or "(" before it, "@", a path with
		// blanks, and the length bounds.
		"x\nfor %q in (x) do y",
		"A & (for %q in (x) do y)",
		"A & @for %q in (x) do y",
		`A & for /r C:\a b %f in (*) do y`,
		"A & for %q in (" + strings.Repeat("a", 600) + ") do y",
		`A & for /f "` + strings.Repeat("a", 300) + `" %q in (x) do y`,
		"A & for" + strings.Repeat(" ", 300) + "%q in (x) do y",
	})
}

// TestNewCmdIChecksLinear: the here-string, system glob and chained FOR
// checks stay linear on 1 MiB hostile values, and still find an attack at
// the end of one.
func TestNewCmdIChecksLinear(t *testing.T) {
	units := map[string]string{
		"here":           "a<<<$",
		"here-quote":     "a<<<' ",
		"here-run":       "<",
		"here-blanks":    "a<<<" + strings.Repeat(" ", 200) + "1 ",
		"here-digits":    "a<<<1 ",
		"glob-slashes":   " /",
		"glob-short":     " /?",
		"glob-nomatch":   " /e?x",
		"glob-stars":     " /" + strings.Repeat("*", 62) + "x",
		"glob-segments":  " /*/*/*x",
		"glob-deep":      "/*",
		"glob-open":      " /" + strings.Repeat("[", 62) + "x",
		"glob-bracket":   " /*[" + strings.Repeat("a", 56) + "]x",
		"glob-bracket3":  " /*[" + strings.Repeat("a", 15) + "]/*[" + strings.Repeat("a", 15) + "]/*[" + strings.Repeat("a", 15) + "]x",
		"glob-brackets":  " /*" + strings.Repeat("[a]", 19) + "x",
		"glob-long":      "/e*",
		"for-set":        "&for %a in(",
		"for-parens":     "&for %a in())))",
		"for-parens-gap": "&for %a in()" + strings.Repeat(" ", 200),
		"for-quote":      `&for/f"`,
		"for-switches":   "&for/d/d/d/d ",
		"for-switch-gap": "& for /d " + strings.Repeat(" ", 200),
		"for-path":       "&for /r %a ",
		"for-blanks":     "&" + strings.Repeat(" ", 200) + "for ",
		"for-operators":  ";%(",
		"for-var":        "&for %" + strings.Repeat("a", 20),
		"for-no-do":      "&for %a in(x)dx ",
	}
	tails := []string{" cat<<<uname", " /???/?a?h", " & for %q in (x) do y"}
	const small, medium, large = 64 << 10, 256 << 10, 1 << 20
	// A quadratic scan of 1 MiB takes tens of seconds.
	lim := wallLimit(250*time.Millisecond, 5*time.Second)
	for name, unit := range units {
		s := strings.Repeat(unit, small/len(unit))
		m := strings.Repeat(unit, medium/len(unit))
		l := strings.Repeat(unit, large/len(unit))
		if hasCmdTechnique(l) {
			t.Errorf("%s: hit on the hostile value, want none", name)
		}
		for _, end := range tails {
			if !hasCmdTechnique(l + "\n" + end) {
				t.Errorf("%s: no hit with %q at the end", name, end)
			}
		}
		if testing.Short() {
			continue
		}
		// The growth ratio is measured on the smaller sizes: their runs
		// are short enough to finish undisturbed on a loaded machine.
		if raceSlowdown == 1 && techniqueSuperLinear(s, m) && techniqueSuperLinear(s, m) && techniqueSuperLinear(s, m) {
			t.Errorf("%s: %d bytes took over 8x the time of %d bytes three times: super-linear", name, len(m), len(s))
		}
		if d := bestOf(3, func() { hasCmdTechnique(l) }); d > lim {
			t.Errorf("%s: %v on %d bytes, want under %v", name, d, len(l), lim)
		}
	}
	// One long run of each kind: no unit repeats.
	for name, l := range map[string]string{
		"one-here-blanks": "a<<<" + strings.Repeat(" ", large),
		"one-glob":        "/" + strings.Repeat("*", large),
		"one-glob-open":   "/" + strings.Repeat("[", large),
		"one-for-blanks":  "%(&" + strings.Repeat(" ", large),
		"shared-gap":      strings.Repeat("&for %a in(", 100) + ")" + strings.Repeat(" ", large),
	} {
		if hasCmdTechnique(l) {
			t.Errorf("%s: hit on the hostile value, want none", name)
		}
		if d := bestOf(3, func() { hasCmdTechnique(l) }); !testing.Short() && d > lim {
			t.Errorf("%s: %v on %d bytes, want under %v", name, d, len(l), lim)
		}
	}
}

// techniqueSuperLinear reports whether hasCmdTechnique on m (four times the
// length of s) took more than eight times as long as on s, best of five runs
// each. Runs on s under 200µs are too fast to time reliably and never count.
func techniqueSuperLinear(s, m string) bool {
	ds := bestOf(5, func() { hasCmdTechnique(s) })
	dm := bestOf(5, func() { hasCmdTechnique(m) })
	return ds > 200*time.Microsecond && dm > 8*ds
}

// cmdTechniqueWorst are 8 KiB inputs that make the three checks do the most
// work without matching.
var cmdTechniqueWorst = []struct{ name, v string }{
	{"here", strings.Repeat("a<<<$", 8<<10/5)},
	{"glob-short", strings.Repeat(" /?", 8<<10/3)},
	{"glob-bracket", strings.Repeat(" /*["+strings.Repeat("a", 56)+"]x", 8<<10/62)},
	{"glob-brackets", strings.Repeat(" /*"+strings.Repeat("[a]", 19)+"x", 8<<10/61)},
	{"glob-segments", strings.Repeat(" /*/*/*x", 8<<10/8)},
	{"for-set", strings.Repeat("&for %a in(", 8<<10/11)},
	{"for-parens", strings.Repeat("&for %a in())))", 8<<10/15)},
}

func BenchmarkCmdTechnique(b *testing.B) {
	for _, in := range cmdTechniqueWorst {
		b.Run(in.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(in.v)))
			if hasCmdTechnique(in.v) {
				b.Fatal("the input matches, want a worst case without a match")
			}
			for b.Loop() {
				hasCmdTechnique(in.v)
			}
		})
	}
}
