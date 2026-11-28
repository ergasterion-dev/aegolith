package detect

import (
	"testing"
)

// checkSSRF asserts that SSRF reports rule ("" for no hit) on every value and
// that ScanText agrees.
func checkSSRF(t *testing.T, rule string, values ...string) {
	t.Helper()
	for _, v := range values {
		h, ok := SSRF(v)
		if ok != (rule != "") || ok && h.RuleID != rule {
			t.Errorf("SSRF(%q) = %q %v, want %q", v, h.RuleID, ok, rule)
		}
		for _, id := range []string{"AEG-SSRF-001", "AEG-SSRF-002"} {
			if got := containsRule(ScanText(v), id); got != (id == rule) {
				t.Errorf("ScanText(%q) has %s = %v, want %v", v, id, got, id == rule)
			}
		}
	}
}

// "http:host" and "http:/host" are read as "http://host/".
func TestSSRFSlashless(t *testing.T) {
	checkSSRF(t, "AEG-SSRF-001",
		"http:169.254.169.254/latest/meta-data/", "http:/169.254.169.254/latest/meta-data/",
		"HTTP:169.254.169.254", "Http:/metadata.google.internal/computeMetadata/v1/",
		"http:metadata.google.internal.", "http:100.100.100.200", "http:/[fd00:ec2::254]/",
		"http:2852039166", "http:/0xa9fea9fe/", "http:user@169.254.169.254:80/",
		"http%3A169.254.169.254%2F", "http%3A%2F169.254.169.254",
		"url=http:169.254.169.254", "next=//x,http:/169.254.169.254",
		"http://ok.example/?u=http:169.254.169.254", "http:127.0.0.1,http:169.254.169.254",
		"http:127.0.0.1 http:/169.254.169.254",
	)
	checkSSRF(t, "AEG-SSRF-002",
		"http:127.0.0.1", "http:/127.0.0.1/admin", "http:127.1", "http:/127.1:8080/", "http:2130706433",
		"http:0x7f000001", "http:/0177.0.0.1/", "http:017700000001",
		"http:10.0.0.5/internal", "http:/172.16.0.1", "http:192.168.1.1:80", "http:169.254.10.1",
		"http:0.0.0.0:8080", "http:/0.0.0.0/", "http:localhost", "http:/localhost:9000/x", "http:LOCALHOST",
		"http:api.localhost/", "http:localhost.", "http:[::1]:8080/", "http:/[::ffff:127.0.0.1]/",
		"http:user:pw@127.0.0.1/", "http:a@b@localhost", "fetch http:localhost please",
		`{"u":"http:127.0.0.1"}`, "<http:/127.0.0.1>", "(http:127.0.0.1", "http:127.0.0.1?x=1",
		"http:127.0.0.1#a", `http:127.0.0.1\x`, "http:example.com,http:localhost",
		"http%3Alocalhost",
	)
}

// Ordinary text, public hosts and other schemes stay clear.
func TestSSRFSlashlessClear(t *testing.T) {
	checkSSRF(t, "",
		// The brief's strings.
		"the http:status header", "http:error codes",
		// "http:" followed by a word or a name.
		"http:", "http:/", "http: localhost", "http :localhost", "http:status", "{http:true}",
		"logging.level.org.springframework.web.client.http:DEBUG", "http:Get(url)", "use the http: prefix",
		"http:example.com", "http:/example.com/path", "http:www.example.org:8080", "http:/etc/hosts",
		"http:localhost.example.com", "http:localhost-only mode", "http:localhosts",
		// Public addresses.
		"http:8.8.8.8", "http:/203.0.113.7/", "http:3405803783", "http:0x08080808", "http:[2001:db8::1]/",
		"http:user@example.com", "http:127.0.0.1@example.com", "http:172.32.0.1",
		// Small numbers are statuses, versions, ports and tags.
		"http:404", "HTTP:200 OK", "the http:2 protocol", "http:10", "http:127", "http:80", "http:/404",
		"http:0", "http:0.9", "http:10.1.example", "http:1.1", "http:2.0", "http:0x1f",
		"FROM example/http:1.25", "image: http:2.4", "{{ http:500 }}", "http:16777215",
		// Another scheme or a longer name before the colon.
		"xhttp:127.0.0.1", "okhttp:127.0.0.1", "git+http:127.0.0.1", "my-http:127.0.0.1",
		"svc.http:127.0.0.1", "my_http:127.0.0.1", "io.ktor:ktor-client-http:10.0.0",
		"org.example:http:10.0.0.1", "urn:http:localhost", "/http:127.0.0.1", "@http:localhost",
		"https:127.0.0.1", "ftp:localhost", "httpx:127.0.0.1",
		// XML namespaces and URL schemes inside identifiers.
		`xmlns:http="http://schemas.example.org/http/"`, "xsi:schemaLocation http://www.example.org/",
		// More than two slashes is read as before.
		"http:///127.0.0.1", "http:////localhost", `http:\\localhost`, "http:/ localhost",
	)
}

// U+3002, U+FF0E and U+FF61 are read as "." in a host.
func TestSSRFUnicodeDots(t *testing.T) {
	for _, dot := range []string{"\u3002", "\uff0e", "\uff61"} {
		checkSSRF(t, "AEG-SSRF-001",
			"http://169"+dot+"254"+dot+"169"+dot+"254/", "http://169"+dot+"254.169"+dot+"254",
			"http://metadata"+dot+"google"+dot+"internal/", "http:169"+dot+"254"+dot+"169"+dot+"254",
			"http://metadata.google.internal"+dot,
		)
		checkSSRF(t, "AEG-SSRF-002",
			"http://127"+dot+"0"+dot+"0"+dot+"1/", "http://127"+dot+"1", "http://127.0.0.1"+dot,
			"http://10"+dot+"0.0"+dot+"5:80/x", "http://api"+dot+"localhost/", "http://localhost"+dot,
			"http://user@192"+dot+"168"+dot+"1"+dot+"1", "http:/127"+dot+"0"+dot+"0"+dot+"1",
			"gopher://127"+dot+"0.0.1:6379/", "http://[::ffff:127"+dot+"0"+dot+"0"+dot+"1]/",
		)
		checkSSRF(t, "",
			"http://example"+dot+"com/", "http://8"+dot+"8"+dot+"8"+dot+"8/", "http:example"+dot+"com",
			"127"+dot+"0"+dot+"0"+dot+"1", "http://localhost"+dot+"example"+dot+"com/",
			// Text that runs on after the host with no blank is part of the
			// host, as before.
			"http://localhost"+dot+"more", "http://127.0.0.1"+dot+"more", "http:"+dot,
			"http://"+dot, "http://127"+dot+dot+"1",
		)
	}
	// Encoded dots are read after the percent-decoding pass.
	checkSSRF(t, "AEG-SSRF-002", "http://127%E3%80%820%EF%BC%8E0%EF%BD%A11/")
	// CJK prose around ASCII words.
	checkSSRF(t, "",
		"\u8bf7\u8bbf\u95ee http://www.example.com\u3002\u7136\u540e\u767b\u5f55\u3002",
		"\u534f\u8bae\u662f http:\u72b6\u6001\u3002", "\u8fd4\u56de http:404\u3002",
		"\u7248\u672c http:1\u30025", "\u8bbe\u7f6e localhost\u3002127.0.0.1\u3002",
		"API\u3002localhost\u3002",
	)
}

// Accepted false positives, listed in docs/threat-model.md.
func TestSSRFSpellingAcceptedFalsePositives(t *testing.T) {
	checkSSRF(t, "AEG-SSRF-002",
		"our client sends http:localhost by default", "docker pull http:10.0.1", "http:127.1 is odd",
		"PROXY HTTP:10.0.0.1:8080", "Serving HTTP:0.0.0.0", "\u8bbf\u95ee http://127.0.0.1\u3002",
	)
}

// Accepted misses, listed in docs/threat-model.md.
func TestSSRFSpellingAcceptedMisses(t *testing.T) {
	checkSSRF(t, "",
		// Only "http" is read without its slashes.
		"https:127.0.0.1", "ws:localhost", "ftp:/127.0.0.1",
		// A small number as the whole host.
		"http:0", "http:/0/", "http:1", "http:0.1",
		// A byte before the scheme that other names use.
		"x:http:127.0.0.1", "/http:127.0.0.1", "u@http:localhost", "-http:localhost",
		// Three or more slashes, or backslashes.
		"http:///localhost", `http:\localhost`, `http:/\localhost`,
		// A host that runs into other text.
		"http:localhost,", "http:127.0.0.1;x",
		// Other look-alikes of "." and of the scheme.
		"http://127\u20240\u20240\u20241/", "http\uff1alocalhost", "http://\uff11\uff12\uff17.0.0.1/",
	)
}
