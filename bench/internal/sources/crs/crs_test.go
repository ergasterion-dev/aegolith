package crs

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

const fixtureTree = "testdata/tree"

// importFixtures imports the hand-written tree and indexes the result by
// case ID.
func importFixtures(t *testing.T) (map[string]cases.Line, map[string]string) {
	t.Helper()
	lines, skipped, err := Import(fixtureTree)
	if err != nil {
		t.Fatal(err)
	}
	return index(t, lines, skipped)
}

func index(t *testing.T, lines []cases.Line, skipped []cases.Skip) (map[string]cases.Line, map[string]string) {
	t.Helper()
	byID := map[string]cases.Line{}
	for _, l := range lines {
		if _, ok := byID[l.SourceCaseID]; ok {
			t.Errorf("case ID %q is used twice", l.SourceCaseID)
		}
		byID[l.SourceCaseID] = l
	}
	reasons := map[string]string{}
	for _, s := range skipped {
		if s.CaseID == "" || s.Reason == "" {
			t.Errorf("skip %+v has an empty field", s)
		}
		if _, ok := reasons[s.CaseID]; ok {
			t.Errorf("case ID %q is skipped twice", s.CaseID)
		}
		if _, ok := byID[s.CaseID]; ok {
			t.Errorf("case ID %q is both imported and skipped", s.CaseID)
		}
		reasons[s.CaseID] = s.Reason
	}
	return byID, reasons
}

func TestImportFixtureTree(t *testing.T) {
	t.Parallel()
	lines, skipped, err := Import(fixtureTree)
	if err != nil {
		t.Fatal(err)
	}
	byID, reasons := index(t, lines, skipped)

	wantLines := map[string]cases.Expected{
		"942100-1": cases.Attack,
		"942100-2": cases.NearMiss,
		"931100-1": cases.Attack,
		"920100-1": cases.NearMiss,
	}
	if len(byID) != len(wantLines) {
		t.Errorf("%d lines, want %d", len(byID), len(wantLines))
	}
	for id, want := range wantLines {
		l, ok := byID[id]
		if !ok {
			t.Errorf("case %s was not imported (skip reason %q)", id, reasons[id])
			continue
		}
		if l.Expected != want {
			t.Errorf("case %s: expected %q, want %q", id, l.Expected, want)
		}
		if l.Source != Source || l.Name == "" {
			t.Errorf("case %s: source %q, name %q", id, l.Source, l.Name)
		}
	}
	for _, l := range lines {
		if _, err := cases.FromLine(l); err != nil {
			t.Errorf("FromLine: %v", err)
		}
	}

	wantSkips := map[string]string{
		"942100-3": "raw",
		"942100-4": "stages",
		"951100-1": "response",
		"920100-2": "version",
		"920100-3": "rule IDs",
		"REQUEST-920-PROTOCOL-ENFORCEMENT/920200.yaml": "YAML",
		"REQUEST-920-PROTOCOL-ENFORCEMENT/920300.yaml": "no tests",
	}
	if len(reasons) != len(wantSkips) {
		t.Errorf("%d skips, want %d: %v", len(reasons), len(wantSkips), reasons)
	}
	for id, want := range wantSkips {
		if got := reasons[id]; !strings.Contains(got, want) {
			t.Errorf("skip %s: reason %q, want it to mention %q", id, got, want)
		}
	}
}

func TestAttackStage(t *testing.T) {
	t.Parallel()
	byID, _ := importFixtures(t)
	got := byID["942100-1"]
	want := cases.Line{
		Name:         "crs-942100-1",
		Category:     "sqli",
		Kind:         "attack",
		Method:       "POST",
		Path:         "/post",
		Headers:      map[string]string{"Host": "localhost", "User-Agent": "OWASP CRS test agent", "Accept": "*/*"},
		ContentType:  "application/x-www-form-urlencoded",
		Body:         "id=7%27+OR+%271%27%3D%271",
		Source:       "crs",
		SourceCaseID: "942100-1",
		Expected:     cases.Attack,
		Payload:      "7' OR '1'='1",
		Placement:    "body",
	}
	if g, w := toJSON(t, got), toJSON(t, want); g != w {
		t.Errorf("line:\n got %s\nwant %s", g, w)
	}
}

func TestNearMissStage(t *testing.T) {
	t.Parallel()
	byID, _ := importFixtures(t)
	got := byID["942100-2"]
	if got.Expected != cases.NearMiss || got.Kind != "near-miss" {
		t.Errorf("expected %q, kind %q; want near-miss", got.Expected, got.Kind)
	}
	if got.Method != "GET" || got.Path != "/get" || got.RawQuery != "note=union%20station" {
		t.Errorf("request %s %s?%s", got.Method, got.Path, got.RawQuery)
	}
	if got.Payload != "union station" || got.Placement != "query" {
		t.Errorf("payload %q in %q", got.Payload, got.Placement)
	}
	if got.Body != "" || got.ContentType != "" {
		t.Errorf("body %q, content type %q; want none", got.Body, got.ContentType)
	}
}

func TestDefaultsAndScalarHeaders(t *testing.T) {
	t.Parallel()
	byID, _ := importFixtures(t)
	got := byID["920100-1"]
	if got.Method != "GET" || got.Path != "/" || got.RawQuery != "" {
		t.Errorf("request %q %q?%q, want GET /", got.Method, got.Path, got.RawQuery)
	}
	if got.Headers["Keep-Alive"] != "300" {
		t.Errorf("Keep-Alive = %q, want the number as written", got.Headers["Keep-Alive"])
	}
	if got.Category != "protocol" {
		t.Errorf("category %q", got.Category)
	}
	if got.Payload != "" || got.Placement != "" {
		t.Errorf("payload %q in %q, want none", got.Payload, got.Placement)
	}
}

func TestCallbacksRewritten(t *testing.T) {
	t.Parallel()
	byID, _ := importFixtures(t)
	got := byID["931100-1"]
	if text := toJSON(t, got); strings.Contains(text, "attacker.example") {
		t.Errorf("a public host survived: %s", text)
	}
	if got.RawQuery != "page=http%3A%2F%2Fcallback.invalid%2Fshell.txt" {
		t.Errorf("raw query %q", got.RawQuery)
	}
	if got.Headers["Referer"] != "https://callback.invalid/start" {
		t.Errorf("Referer %q", got.Headers["Referer"])
	}
	if got.Body != "next=http://callback.invalid/a" {
		t.Errorf("body %q", got.Body)
	}
	// Three parts could carry the attack, so none is named.
	if got.Payload != "" || got.Placement != "" {
		t.Errorf("payload %q in %q, want none", got.Payload, got.Placement)
	}
}

func TestCategory(t *testing.T) {
	t.Parallel()
	for group, want := range map[string]string{
		"REQUEST-911-METHOD-ENFORCEMENT":                  "protocol",
		"REQUEST-913-SCANNER-DETECTION":                   "scanner",
		"REQUEST-920-PROTOCOL-ENFORCEMENT":                "protocol",
		"REQUEST-921-PROTOCOL-ATTACK":                     "protocol",
		"REQUEST-922-MULTIPART-ATTACK":                    "protocol",
		"REQUEST-930-APPLICATION-ATTACK-LFI":              "lfi",
		"REQUEST-931-APPLICATION-ATTACK-RFI":              "rfi",
		"REQUEST-932-APPLICATION-ATTACK-RCE":              "cmdi",
		"REQUEST-933-APPLICATION-ATTACK-PHP":              "codei",
		"REQUEST-941-APPLICATION-ATTACK-XSS":              "xss",
		"REQUEST-942-APPLICATION-ATTACK-SQLI":             "sqli",
		"REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION": "session",
		"REQUEST-944-APPLICATION-ATTACK-JAVA":             "java",
		"REQUEST-934-APPLICATION-ATTACK-GENERIC":          "other",
		"REQUEST-949-BLOCKING-EVALUATION":                 "other",
		"REQUEST-942":                                     "sqli",
		"REQUEST-9420-SOMETHING":                          "other",
		"something-else":                                  "other",
		"":                                                "other",
	} {
		if got := category(group); got != want {
			t.Errorf("category(%q) = %q, want %q", group, got, want)
		}
	}
}

// stage is one upstream stage for importStage: the lines of its input and of
// its output mapping, indented by the helper.
type stage struct {
	group  string // rule file group; REQUEST-942-APPLICATION-ATTACK-SQLI if empty
	input  string
	output string // an expect_ids log if empty
}

const (
	plainHeaders = "headers:\n  Host: localhost\n"
	caseID       = "942999-1"
)

// importStage imports a tree holding one test with the one stage s. Exactly
// one of the returned line and skip reason is set.
func importStage(t *testing.T, s stage) (line *cases.Line, reason string) {
	t.Helper()
	if s.group == "" {
		s.group = "REQUEST-942-APPLICATION-ATTACK-SQLI"
	}
	if s.output == "" {
		s.output = "log:\n  expect_ids: [942999]\n"
	}
	indent := func(text string) string {
		return "          " + strings.ReplaceAll(strings.TrimRight(text, "\n"), "\n", "\n          ") + "\n"
	}
	doc := "---\nrule_id: 942999\ntests:\n  - test_id: 1\n    stages:\n      - input:\n" +
		indent(s.input) + "        output:\n" + indent(s.output)
	root := t.TempDir()
	dir := filepath.Join(root, "tests", "regression", "tests", s.group)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "942999.yaml"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, skipped, err := Import(root)
	if err != nil {
		t.Fatal(err)
	}
	byID, reasons := index(t, lines, skipped)
	if len(byID)+len(reasons) != 1 {
		t.Fatalf("%d lines and %d skips, want one result:\n%s", len(byID), len(reasons), doc)
	}
	if l, ok := byID[caseID]; ok {
		if _, err := cases.FromLine(l); err != nil {
			t.Fatalf("FromLine: %v", err)
		}
		return &l, ""
	}
	reason, ok := reasons[caseID]
	if !ok {
		t.Fatalf("the result is not for case %s: %v", caseID, reasons)
	}
	return nil, reason
}

func mustImport(t *testing.T, s stage) cases.Line {
	t.Helper()
	l, reason := importStage(t, s)
	if l == nil {
		t.Fatalf("skipped: %s", reason)
	}
	return *l
}

func TestSkippedStages(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		stage  stage
		reason string // a part of the wanted reason
	}{
		{"encoded request", stage{input: "encoded_request: R0VUIC8gSFRUUC8xLjENCg0K\n"}, "raw"},
		{"raw request", stage{input: "raw_request: \"GET / HTTP/1.1\\r\\n\\r\\n\"\n"}, "raw"},
		{"response rule", stage{group: "RESPONSE-953-DATA-LEAKAGES-PHP", input: plainHeaders}, "response"},
		{"version", stage{input: plainHeaders + "version: HTTP/2.0\n"}, "version"},
		{"empty version", stage{input: plainHeaders + "version: \"\"\n"}, "version"},
		{"unknown input field", stage{input: plainHeaders + "follow_redirect: true\n"}, "follow_redirect"},
		{"encoded data", stage{input: plainHeaders + "encoded_data: aWQ9MQ==\n"}, "encoded_data"},
		{"repeated input field", stage{input: plainHeaders + "uri: /a\nuri: /b\n"}, "twice"},
		{"input is not a mapping", stage{input: "- a\n- b\n"}, "input"},
		{"uri is not a scalar", stage{input: plainHeaders + "uri: [a]\n"}, "uri"},
		{"template in data", stage{input: plainHeaders + "data: 'a={{ \"1\" | repeat 9 }}'\n"}, "template"},
		{"no Host header", stage{input: "headers:\n  Accept: \"*/*\"\n"}, "Host"},
		{"no headers", stage{input: "uri: /\n"}, "Host"},
		{"repeated header", stage{input: "headers:\n  Host: localhost\n  Cookie: a=1\n  cookie: b=2\n"}, "header name"},
		{"header value is not UTF-8", stage{input: "headers:\n  Host: localhost\n  Cookie: !!binary /w==\n"}, "UTF-8"},
		{"header value is not a scalar", stage{input: "headers:\n  Host: localhost\n  Cookie: [a]\n"}, "header"},
		{"Transfer-Encoding", stage{input: "headers:\n  Host: localhost\n  transfer-encoding: chunked\ndata: \"a=1\"\n"}, "Transfer-Encoding"},
		{"authority target", stage{input: plainHeaders + "method: CONNECT\nuri: \"localhost:80\"\n"}, "target"},
		{"asterisk target", stage{input: plainHeaders + "method: OPTIONS\nuri: \"*\"\n"}, "target"},
		{"absolute target", stage{input: plainHeaders + "uri: \"http://localhost/a\"\n"}, "target"},
		{"empty query", stage{input: plainHeaders + "uri: \"/a?\"\n"}, "query"},
		{"empty method", stage{input: plainHeaders + "method: \"\"\n"}, "method"},
		{"method is not UTF-8", stage{input: plainHeaders + "method: !!binary /w==\n"}, "UTF-8"},
		{"no rule IDs", stage{input: plainHeaders, output: "status: 200\n"}, "rule IDs"},
		{"only a log pattern", stage{input: plainHeaders, output: "log:\n  match_regex: 'id \"942999\"'\n"}, "rule IDs"},
		{"empty ID lists", stage{input: plainHeaders, output: "log:\n  expect_ids: []\n  no_expect_ids: []\n"}, "rule IDs"},
		{"error expected", stage{input: plainHeaders, output: "expect_error: true\nlog:\n  no_expect_ids: [942999]\n"}, "fail"},
		{"output is not a mapping", stage{input: plainHeaders, output: "- a\n"}, "output"},
		{
			"body without completion or length",
			stage{input: plainHeaders + "method: POST\nautocomplete_headers: false\ndata: \"a=1\"\n"},
			"Content-Length",
		},
		{
			"POST without completion or length",
			stage{input: plainHeaders + "method: POST\nautocomplete_headers: false\n"},
			"Content-Length",
		},
		{
			"multipart without completion",
			stage{input: "headers:\n  Host: localhost\n  Content-Type: \"multipart/form-data; boundary=b\"\n  Content-Length: 3\n" +
				"autocomplete_headers: false\ndata: \"a\\nb\"\n"},
			"multipart",
		},
		{
			"multipart with CRLF",
			stage{input: "headers:\n  Host: localhost\n  Content-Type: \"multipart/form-data; boundary=b\"\n" +
				"data: \"--b\\r\\nx\\n--b--\"\n"},
			"multipart",
		},
		{
			"rewrite changes a stated length",
			stage{input: "headers:\n  Host: localhost\n  Content-Length: 24\ndata: \"u=http://a.example.com/x\"\n"},
			"Content-Length",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			l, reason := importStage(t, tt.stage)
			if l != nil {
				t.Fatalf("imported as %s, want a skip", toJSON(t, *l))
			}
			if !strings.Contains(reason, tt.reason) {
				t.Errorf("reason %q, want it to mention %q", reason, tt.reason)
			}
		})
	}
}

func TestSkipReasonsNeverRepeatValues(t *testing.T) {
	t.Parallel()
	const secret = "s3cr3t-value"
	for _, input := range []string{
		plainHeaders + secret + ": 1\n",
		plainHeaders + "\"" + secret + " with spaces\": 1\n",
		plainHeaders + "version: " + secret + "\n",
		plainHeaders + "uri: " + secret + "\n",
		"headers:\n  Host: localhost\n  A: " + secret + "\n  a: " + secret + "\n",
	} {
		_, reason := importStage(t, stage{input: input})
		if reason == "" || strings.Contains(reason, "s3cr3t") {
			t.Errorf("reason %q for input %q", reason, input)
		}
	}
}

func TestExpectedFromOutput(t *testing.T) {
	t.Parallel()
	for output, want := range map[string]cases.Expected{
		"log:\n  expect_ids: [942999]\n":                              cases.Attack,
		"log:\n  no_expect_ids: [942999]\n":                           cases.NearMiss,
		"log:\n  expect_ids: [942999]\n  no_expect_ids: [942100]\n":   cases.Attack,
		"status: 200\nlog:\n  no_expect_ids: [942999]\n":              cases.NearMiss,
		"retry_once: true\nlog:\n  expect_ids: [942999, 949110]\n":    cases.Attack,
		"expect_error: false\nlog:\n  no_expect_ids: [942999]\n":      cases.NearMiss,
		"log:\n  no_expect_ids: [942999]\n  match_regex: 'x'\n":       cases.NearMiss,
		"log:\n  expect_ids: []\n  no_expect_ids: [942999, 942100]\n": cases.NearMiss,
	} {
		l := mustImport(t, stage{input: plainHeaders, output: output})
		if l.Expected != want || l.Kind != string(want) {
			t.Errorf("output %q: expected %q, kind %q; want %q", output, l.Expected, l.Kind, want)
		}
	}
}

func TestNothingIsImportedAsLegit(t *testing.T) {
	t.Parallel()
	lines, _, err := Import(fixtureTree)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if l.Expected != cases.Attack && l.Expected != cases.NearMiss {
			t.Errorf("case %s: expected %q", l.SourceCaseID, l.Expected)
		}
	}
}

func TestRequestTarget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		uri, path, rawQuery string
	}{
		{`"/a/b"`, "/a/b", ""},
		{`"/a?x=1&y=2"`, "/a", "x=1&y=2"},
		{`"/a?x=1?y=2"`, "/a", "x=1?y=2"},
		{`"/a b?x=1 2#f"`, "/a b", "x=1 2#f"},
		{`"/café?q=é"`, "/café", "q=é"},
		// Bytes a case line cannot carry are percent-encoded: "/\xff\xfe?a=\xff".
		{"!!binary L//+P2E9/w==", "/%FF%FE", "a=%FF"},
	}
	for _, tt := range tests {
		l := mustImport(t, stage{input: plainHeaders + "uri: " + tt.uri + "\n"})
		if l.Path != tt.path || l.RawQuery != tt.rawQuery {
			t.Errorf("uri %s: path %q, raw query %q; want %q, %q", tt.uri, l.Path, l.RawQuery, tt.path, tt.rawQuery)
		}
		if len(l.Query) != 0 {
			t.Errorf("uri %s: query pairs %v, want the raw query only", tt.uri, l.Query)
		}
	}
}

func TestBody(t *testing.T) {
	t.Parallel()
	const multipart = "headers:\n  Host: localhost\n  Content-Type: \"multipart/form-data; boundary=b\"\n"

	t.Run("default content type", func(t *testing.T) {
		t.Parallel()
		l := mustImport(t, stage{input: plainHeaders + "method: POST\ndata: \"a=1 2\"\n"})
		if l.ContentType != "application/x-www-form-urlencoded" || l.Body != "a=1 2" {
			t.Errorf("content type %q, body %q", l.ContentType, l.Body)
		}
	})
	t.Run("given content type", func(t *testing.T) {
		t.Parallel()
		l := mustImport(t, stage{input: "headers:\n  Host: localhost\n  content-type: application/json\ndata: '{\"a\": 1}'\n"})
		if l.ContentType != "" || l.Headers["content-type"] != "application/json" || l.Body != `{"a": 1}` {
			t.Errorf("content type %q, headers %v, body %q", l.ContentType, l.Headers, l.Body)
		}
	})
	t.Run("no body, no content type", func(t *testing.T) {
		t.Parallel()
		for _, data := range []string{"", "data: \"\"\n", "data:\n"} {
			l := mustImport(t, stage{input: plainHeaders + "method: POST\n" + data})
			if l.ContentType != "" || l.Body != "" || l.BodyBase64 != "" {
				t.Errorf("data %q: content type %q, body %q", data, l.ContentType, l.Body)
			}
		}
	})
	t.Run("multipart line ends", func(t *testing.T) {
		t.Parallel()
		l := mustImport(t, stage{input: multipart + "data: |\n  --b\n  Content-Disposition: form-data; name=\"a\"\n\n  1\n  --b--\n"})
		want := "--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--b--\r\n"
		if l.Body != want {
			t.Errorf("body %q, want %q", l.Body, want)
		}
	})
	t.Run("other bodies keep their line ends", func(t *testing.T) {
		t.Parallel()
		l := mustImport(t, stage{input: "headers:\n  Host: localhost\n  Content-Type: text/plain\ndata: \"a\\nb\"\n"})
		if l.Body != "a\nb" {
			t.Errorf("body %q", l.Body)
		}
	})
	t.Run("bytes that are not UTF-8", func(t *testing.T) {
		t.Parallel()
		l := mustImport(t, stage{input: plainHeaders + "data: !!binary YT3/\n"})
		got, err := base64.StdEncoding.DecodeString(l.BodyBase64)
		if err != nil || string(got) != "a=\xff" || l.Body != "" {
			t.Errorf("body %q, body_base64 %q (%v)", l.Body, l.BodyBase64, err)
		}
		payload, err := base64.StdEncoding.DecodeString(l.PayloadBase64)
		if err != nil || string(payload) != "\xff" || l.Payload != "" || l.Placement != "body" {
			t.Errorf("payload %q, payload_base64 %q (%v), placement %q", l.Payload, l.PayloadBase64, err, l.Placement)
		}
	})
}

// The framing headers go into the line as the test writes them; the sender
// then sends them unchanged or refuses the case.
func TestFramingHeadersAreKept(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, input, header, want string
	}{
		{"matching length", "headers:\n  Host: localhost\n  Content-Length: 3\ndata: \"a=1\"\n", "Content-Length", "3"},
		{"wrong length", "headers:\n  Host: localhost\n  Content-Length: 99\ndata: \"a=1\"\n", "Content-Length", "99"},
		{"length that is not a number", "headers:\n  Host: localhost\n  Content-Length: NotDigits\n", "Content-Length", "NotDigits"},
		{
			"length without completion",
			"headers:\n  Host: localhost\n  Content-Length: 3\nmethod: POST\nautocomplete_headers: false\ndata: \"a=1\"\n",
			"Content-Length", "3",
		},
		{"host", "headers:\n  Host: \"example.test:8080\"\n", "Host", "example.test:8080"},
		{
			"rewrite keeps the stated length",
			"headers:\n  Host: localhost\n  Content-Length: 27\ndata: \"u=http://callback.invalid/x\"\n",
			"Content-Length", "27",
		},
	}
	for _, tt := range tests {
		l := mustImport(t, stage{input: tt.input})
		if got := l.Headers[tt.header]; got != tt.want {
			t.Errorf("%s: %s = %q, want %q", tt.name, tt.header, got, tt.want)
		}
	}
}

func TestWithoutCompletion(t *testing.T) {
	t.Parallel()
	l := mustImport(t, stage{input: "headers:\n  Host: localhost\n  Content-Length: 3\nmethod: POST\nautocomplete_headers: false\ndata: \"a=1\"\n"})
	if l.ContentType != "" {
		t.Errorf("content type %q, want none without completion", l.ContentType)
	}
	l = mustImport(t, stage{input: plainHeaders + "method: GET\nautocomplete_headers: false\n"})
	if l.Method != "GET" || len(l.Headers) != 1 {
		t.Errorf("method %q, headers %v", l.Method, l.Headers)
	}
	l = mustImport(t, stage{input: plainHeaders + "method: POST\nautocomplete_headers: true\ndata: \"a=1\"\n"})
	if l.ContentType != "application/x-www-form-urlencoded" {
		t.Errorf("content type %q with completion", l.ContentType)
	}
}

func TestPayload(t *testing.T) {
	t.Parallel()
	const agent = "  User-Agent: \"OWASP CRS test agent\"\n  Accept: \"*/*\"\n  Accept-Encoding: gzip\n"
	tests := []struct {
		name, input, payload, placement string
	}{
		{"query value", "uri: \"/get?q=1%27+or%201\"\n", "1' or 1", "query"},
		{"query key alone", "uri: \"/get?%3Cscript%3E\"\n", "<script>", "query"},
		{"query key with an empty value", "uri: \"/get?%3Cscript%3E=\"\n", "<script>", "query"},
		{"query with a bad escape", "uri: \"/get?q=100%zz\"\n", "100%zz", "query"},
		{"two query values", "uri: \"/get?a=1&b=2\"\n", "", ""},
		{"form value", "method: POST\ndata: \"q=%3Cb%3E\"\n", "<b>", "body"},
		{"two form values", "method: POST\ndata: \"q=1&r=2\"\n", "", ""},
		{"query and form", "method: POST\nuri: \"/post?a=1\"\ndata: \"q=1\"\n", "", ""},
		{"path", "uri: \"/get/..%2f..%2fetc/passwd\"\n", "/get/../../etc/passwd", "path"},
		{"plain path", "uri: \"/get/index.php\"\n", "", ""},
		{"path and query", "uri: \"/get/../x?q=1\"\n", "", ""},
	}
	for _, tt := range tests {
		l := mustImport(t, stage{input: "headers:\n  Host: localhost\n" + agent + tt.input})
		if l.Payload != tt.payload || l.Placement != tt.placement {
			t.Errorf("%s: payload %q in %q, want %q in %q", tt.name, l.Payload, l.Placement, tt.payload, tt.placement)
		}
	}

	headerTests := []struct {
		name, headers, rest, payload, placement string
	}{
		{"one other header", agent + "  Cookie: \"a=${jndi:x}\"\n", "", "a=${jndi:x}", "header"},
		{"another user agent", "  User-Agent: sqlmap/1.0\n", "", "sqlmap/1.0", "header"},
		{"two other headers", "  Cookie: a=1\n  Referer: b\n", "", "", ""},
		{"header and query", "  Cookie: a=1\n", "uri: \"/get?q=1\"\n", "", ""},
		{"JSON body", "  Content-Type: application/json\n", "data: '{\"q\": \"1\"}'\n", "", ""},
		{"form body with parameters", "  Content-Type: \"Application/X-WWW-Form-Urlencoded; charset=utf-8\"\n", "data: \"q=a+b\"\n", "a b", "body"},
	}
	for _, tt := range headerTests {
		l := mustImport(t, stage{input: "headers:\n  Host: localhost\n" + tt.headers + tt.rest})
		if l.Payload != tt.payload || l.Placement != tt.placement {
			t.Errorf("%s: payload %q in %q, want %q in %q", tt.name, l.Payload, l.Placement, tt.payload, tt.placement)
		}
	}
}

// The payload decides the held-out split, so it must not depend on how the
// test file encodes it.
func TestPayloadIsStableAcrossEncodings(t *testing.T) {
	t.Parallel()
	a := mustImport(t, stage{input: plainHeaders + "uri: \"/get?q=%3Cscript%3Ealert(1)\"\n"})
	b := mustImport(t, stage{input: plainHeaders + "method: POST\ndata: \"other=%3cscript%3ealert%281%29\"\n"})
	if a.Payload != "<script>alert(1)" || a.Payload != b.Payload {
		t.Errorf("payloads %q and %q", a.Payload, b.Payload)
	}
}

func TestCallbackRewrittenBeforeDecoding(t *testing.T) {
	t.Parallel()
	l := mustImport(t, stage{input: plainHeaders + "uri: \"/get?u=http%3A%2F%2Fa.example.com%2Fx\"\n"})
	if l.RawQuery != "u=http%3A%2F%2Fcallback.invalid%2Fx" || l.Payload != "http://callback.invalid/x" {
		t.Errorf("raw query %q, payload %q", l.RawQuery, l.Payload)
	}
	l = mustImport(t, stage{input: "headers:\n  Host: localhost\n  Content-Type: \"multipart/form-data; boundary=b\"\n" +
		"data: |\n  --b\n  Content-Disposition: form-data; name=\"u\"\n\n  http://a.example.com/x\n  --b--\n"})
	if strings.Contains(l.Body, "example.com") || !strings.Contains(l.Body, "\r\nhttp://callback.invalid/x\r\n") {
		t.Errorf("body %q", l.Body)
	}
}

func TestBadTestsDoNotStopTheImport(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "tests", "regression", "tests", "REQUEST-941-APPLICATION-ATTACK-XSS")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	good := "    stages:\n      - input:\n          headers:\n            Host: localhost\n" +
		"        output:\n          log:\n            expect_ids: [941100]\n"
	files := map[string]string{
		"941100.yaml": "rule_id: 941100\ntests:\n" +
			"  - test_id: 1\n" + good +
			"  - test_id: one\n" + good +
			"  - test_id: 1\n" + good +
			"  - just a string\n" +
			"  - test_id: 5\n    stages: []\n" +
			"  - test_id: 6\n    stages: nonsense\n" +
			"  - test_id: 7\n" + good,
		"941200.yaml":    "rule_id: nine\ntests:\n  - test_id: 1\n" + good,
		"941300.yaml":    "rule_id: 941300\ntests: nonsense\n",
		"941400.yaml":    "- a list\n",
		"941500.yml":     "rule_id: 941500\ntests:\n  - test_id: 1\n" + good,
		"notes.txt":      "not a test file",
		"941600.yaml":    "a: &a [x, x]\nb: &b [*a, *a]\nc: &c [*b, *b]\nrule_id: 941600\ntests: *c\n",
		"sub/941700.yml": "rule_id: 941700\ntests:\n  - test_id: 1\n" + good,
	}
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A link out of the tree is not followed.
	outside := filepath.Join(t.TempDir(), "941800.yaml")
	if err := os.WriteFile(outside, []byte("rule_id: 941800\ntests:\n  - test_id: 1\n"+good), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "941800.yaml")); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}

	lines, skipped, err := Import(root)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, l := range lines {
		ids = append(ids, l.SourceCaseID)
	}
	if got, want := strings.Join(ids, " "), "941100-1 941100-7 941500-1 941700-1"; got != want {
		t.Errorf("imported %q, want %q", got, want)
	}
	const group = "REQUEST-941-APPLICATION-ATTACK-XSS/"
	want := map[string]string{
		group + "941100.yaml#2": "test_id",
		group + "941100.yaml#3": "twice",
		group + "941100.yaml#4": "mapping",
		"941100-5":              "stages",
		"941100-6":              "stages",
		group + "941200.yaml":   "rule_id",
		group + "941300.yaml":   "tests",
		group + "941400.yaml":   "mapping",
		group + "941600.yaml":   "tests",
	}
	got := map[string]string{}
	for _, s := range skipped {
		got[s.CaseID] = s.Reason
	}
	if len(got) != len(want) || len(skipped) != len(want) {
		t.Errorf("%d skips, want %d: %v", len(skipped), len(want), skipped)
	}
	for id, part := range want {
		if !strings.Contains(got[id], part) {
			t.Errorf("skip %s: reason %q, want it to mention %q", id, got[id], part)
		}
	}
}

func TestImportIsDeterministic(t *testing.T) {
	t.Parallel()
	first, firstSkips, err := Import(fixtureTree)
	if err != nil {
		t.Fatal(err)
	}
	second, secondSkips, err := Import(fixtureTree)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(first, firstSkips) != fmt.Sprint(second, secondSkips) {
		t.Error("two imports of one tree differ")
	}
}

func TestImportFailsWithoutTests(t *testing.T) {
	t.Parallel()
	empty := t.TempDir()
	withDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(withDir, "tests", "regression", "tests", "REQUEST-942-X"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, root := range map[string]string{
		"missing root":        filepath.Join(empty, "absent"),
		"no tests directory":  empty,
		"no test files":       withDir,
		"root is not a place": "",
	} {
		lines, skipped, err := Import(root)
		if err == nil || lines != nil || skipped != nil {
			t.Errorf("%s: %d lines, %d skips, error %v; want an error only", name, len(lines), len(skipped), err)
		}
	}
}

func toJSON(t *testing.T, l cases.Line) string {
	t.Helper()
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
