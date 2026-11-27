package gotestwaf

import (
	"encoding/base64"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

const fixtureTree = "testdata/tree"

// index checks the invariants of an import and indexes it by case ID.
func index(t *testing.T, lines []cases.Line, skipped []cases.Skip) (map[string]cases.Line, map[string]string) {
	t.Helper()
	byID := map[string]cases.Line{}
	for _, l := range lines {
		if _, ok := byID[l.SourceCaseID]; ok {
			t.Errorf("case ID %q is used twice", l.SourceCaseID)
		}
		byID[l.SourceCaseID] = l
		if l.Source != Source || l.Name == "" || l.Category == "" {
			t.Errorf("case %s: source %q, name %q, category %q", l.SourceCaseID, l.Source, l.Name, l.Category)
		}
		if _, err := cases.FromLine(l); err != nil {
			t.Errorf("FromLine: %v", err)
		}
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

func importFixtures(t *testing.T) (map[string]cases.Line, map[string]string) {
	t.Helper()
	lines, skipped, err := Import(fixtureTree)
	if err != nil {
		t.Fatal(err)
	}
	return index(t, lines, skipped)
}

// payloadOf returns the decoded payload a line records.
func payloadOf(t *testing.T, l cases.Line) string {
	t.Helper()
	if l.PayloadBase64 == "" {
		return l.Payload
	}
	decoded, err := base64.StdEncoding.DecodeString(l.PayloadBase64)
	if err != nil {
		t.Fatalf("case %s: payload_base64: %v", l.SourceCaseID, err)
	}
	return string(decoded)
}

func TestImportFixtureTree(t *testing.T) {
	t.Parallel()
	byID, reasons := importFixtures(t)

	want := map[string]cases.Expected{
		"attacks/pair/1/Plain/URLParam":           cases.Attack,
		"attacks/pair/1/Plain/JSONBody":           cases.Attack,
		"attacks/pair/1/Base64/URLParam":          cases.Attack,
		"attacks/pair/1/Base64/JSONBody":          cases.Attack,
		"attacks/pair/2/Plain/URLParam":           cases.Attack,
		"attacks/pair/2/Plain/JSONBody":           cases.Attack,
		"attacks/pair/2/Base64/URLParam":          cases.Attack,
		"attacks/pair/2/Base64/JSONBody":          cases.Attack,
		"attacks/odd/1/Plain/XMLBody":             cases.Attack,
		"api/raw/1/Plain/RawRequest":              cases.Attack,
		"api/raw/1/Plain/GraphQL#2":               cases.Attack,
		"api/raw/1/Plain/GraphQL#3":               cases.Attack,
		"false-pos/texts/1/URL/URLParam":          cases.Legit,
		"false-pos/texts/1/URL/HTMLForm":          cases.Legit,
		"false-pos/texts/1/URL/HTMLMultipartForm": cases.Legit,
		"false-pos/texts/2/URL/URLParam":          cases.Legit,
		"false-pos/texts/2/URL/HTMLForm":          cases.Legit,
		"false-pos/texts/2/URL/HTMLMultipartForm": cases.Legit,
	}
	if len(byID) != len(want) {
		t.Errorf("%d lines, want %d", len(byID), len(want))
	}
	for id, expected := range want {
		l, ok := byID[id]
		if !ok {
			t.Errorf("case %s was not imported (skip reason %q)", id, reasons[id])
			continue
		}
		if l.Expected != expected || l.Kind != string(expected) {
			t.Errorf("case %s: expected %q, kind %q, want %q", id, l.Expected, l.Kind, expected)
		}
		if l.Name != "gotestwaf-"+id {
			t.Errorf("case %s: name %q", id, l.Name)
		}
	}

	wantSkips := map[string]string{
		"attacks/odd/1/Plain/Teleport": "placeholder is not one of the tool's",
		"attacks/odd/1/Plain/gRPC":     "gRPC placeholder: the tool makes a gRPC call, not a plain HTTP request",
		"attacks/odd/1/Rot13/XMLBody":  "encoder is not one of the tool's",
		"attacks/odd/1/Rot13/Teleport": "encoder is not one of the tool's",
		"attacks/odd/1/Rot13/gRPC":     "encoder is not one of the tool's",
		"attacks/broken.yml":           "file is not YAML in the shape of a test case",
		"attacks/empty.yml":            "file holds no payload, no encoder or no placeholder",
		"attacks/badconfig.yml":        "the tool cannot load this file: RawRequest needs a method that is a string",
	}
	if !maps.Equal(reasons, wantSkips) {
		t.Errorf("skips:\n got %q\nwant %q", reasons, wantSkips)
	}
}

func TestImportRecordsOnePayloadForEveryVariant(t *testing.T) {
	t.Parallel()
	byID, _ := importFixtures(t)
	want := map[string]string{
		"attacks/pair/1/": "' or 1=1 --",
		"attacks/pair/2/": "<img src=http://callback.invalid/x.png>",
	}
	for prefix, payload := range want {
		n := 0
		for id, l := range byID {
			if !strings.HasPrefix(id, prefix) {
				continue
			}
			n++
			if got := payloadOf(t, l); got != payload {
				t.Errorf("case %s: payload %q, want %q", id, got, payload)
			}
		}
		if n != 4 {
			t.Errorf("%d variants of %s, want 4", n, prefix)
		}
	}
}

func TestImportFixtureRequests(t *testing.T) {
	t.Parallel()
	byID, _ := importFixtures(t)
	defaults := map[string]string{
		"Connection": "close", "User-Agent": "fixture-agent/1.0", "Accept": "*/*", "Accept-Encoding": "gzip, deflate",
		"Upgrade-Insecure-Requests": "1",
	}
	with := func(extra map[string]string) map[string]string {
		out := maps.Clone(defaults)
		maps.Copy(out, extra)
		return out
	}
	param := regexp.MustCompile(`^[0-9a-f]{10}=`)

	l := byID["attacks/pair/1/Plain/URLParam"]
	if l.Method != "GET" || l.Path != "/" || !param.MatchString(l.RawQuery) || l.RawQuery[11:] != "' or 1=1 --" ||
		l.Body != "" || l.Placement != "query" || l.Encoder != "Plain" || !maps.Equal(l.Headers, defaults) {
		t.Errorf("Plain URLParam: %+v", l)
	}
	if l.Category != "pair" {
		t.Errorf("category %q, want the test case name", l.Category)
	}

	l = byID["attacks/pair/2/Base64/JSONBody"]
	if l.Method != "POST" || l.Path != "/" || l.RawQuery != "" || l.Placement != "json" || l.Encoder != "Base64" ||
		!maps.Equal(l.Headers, with(map[string]string{"Content-Type": "application/json"})) {
		t.Errorf("Base64 JSONBody: %+v", l)
	}
	// The callback host was replaced before the payload was encoded.
	decoded, err := base64.StdEncoding.DecodeString(l.Body)
	if err != nil {
		t.Fatalf("body is not base64: %v", err)
	}
	if string(decoded) != "<img src=http://callback.invalid/x.png>" {
		t.Errorf("encoded payload is %q", decoded)
	}

	l = byID["false-pos/texts/1/URL/URLParam"]
	if l.RawQuery[11:] != "curl%20and%20divergence%20in%20vector%20calculus" || l.Category != "fp" {
		t.Errorf("URL URLParam: %+v", l)
	}

	l = byID["api/raw/1/Plain/RawRequest"]
	if l.Method != "PUT" || l.Path != "/items/id=1%20union%20select%201/edit" || l.RawQuery != "" ||
		l.Body != "value=id=1 union select 1" || l.Placement != "raw" ||
		!maps.Equal(l.Headers, with(map[string]string{"Content-Type": "text/plain", "X-Note": "note id=1 union select 1"})) {
		t.Errorf("RawRequest: %+v", l)
	}
	l = byID["api/raw/1/Plain/GraphQL#2"]
	if l.Method != "GET" || l.Path != "/graphql" || l.RawQuery != "query=id=1 union select 1" || l.Placement != "query" {
		t.Errorf("GraphQL GET: %+v", l)
	}
	l = byID["api/raw/1/Plain/GraphQL#3"]
	if l.Method != "POST" || l.Path != "/graphql" || l.Body != "id=1 union select 1" || l.Placement != "body" ||
		!maps.Equal(l.Headers, defaults) {
		t.Errorf("GraphQL POST: %+v", l)
	}
}

func TestImportIsStable(t *testing.T) {
	t.Parallel()
	lines, skipped, err := Import(fixtureTree)
	if err != nil {
		t.Fatal(err)
	}
	again, skippedAgain, err := Import(fixtureTree)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(lines, again) || !reflect.DeepEqual(skipped, skippedAgain) {
		t.Error("two imports of one tree differ")
	}
	// The names that stand for the tool's random ones differ between cases.
	byID, _ := index(t, lines, skipped)
	a, b := byID["attacks/pair/1/Plain/URLParam"].RawQuery[:10], byID["attacks/pair/2/Plain/URLParam"].RawQuery[:10]
	if a == b {
		t.Errorf("two cases share the parameter name %q", a)
	}
}

func TestEncoders(t *testing.T) {
	t.Parallel()
	tests := []struct{ encoder, in, want string }{
		{"Plain", " +%\"'<é\xff", " +%\"'<é\xff"},
		{"Plain", "", ""},

		{"Base64", "foob", "Zm9vYg=="},
		{"Base64", "a", "YQ=="},
		{"Base64", "??>", "Pz8+"},
		{"Base64", "\xff\xfe\xfd", "//79"},
		{"Base64", "", ""},
		{"Base64Flat", "foob", "Zm9vYg"},
		{"Base64Flat", "a", "YQ"},
		{"Base64Flat", "foo", "Zm9v"},
		{"Base64Flat", "\xff\xfe\xfd", "//79"},

		// Escaped as one path segment: a plus sign stays a plus sign.
		{"URL", "a b+c%d", "a%20b+c%25d"},
		{"URL", "/?#;,", "%2F%3F%23%3B%2C"},
		{"URL", "$&=:@", "$&=:@"},
		{"URL", "-._~", "-._~"},
		{"URL", "\"'<>!*()", "%22%27%3C%3E%21%2A%28%29"},
		{"URL", "é\xff\x00\n", "%C3%A9%FF%00%0A"},
		{"URL", "", ""},

		// UTF-16 code units, in lower-case hex; an invalid byte is U+FFFD.
		{"JSUnicode", "a <", `\u0061\u0020\u003c`},
		{"JSUnicode", "é\"", `\u00e9\u0022`},
		{"JSUnicode", "\U0001F600", `\ud83d\ude00`},
		{"JSUnicode", "a\xffb", `\u0061\ufffd\u0062`},
		{"JSUnicode", "\x00\n", `\u0000\u000a`},
		{"JSUnicode", "", ""},

		// The value as an XML element named after its Go type.
		{"XMLEntity", "a b+%", "<string>a b+%</string>"},
		{"XMLEntity", "<&>\"'", "<string>&lt;&amp;&gt;&#34;&#39;</string>"},
		{"XMLEntity", "\t\n\r", "<string>&#x9;&#xA;&#xD;</string>"},
		{"XMLEntity", "é\xff\x00", "<string>é\uFFFD\uFFFD</string>"},
		{"XMLEntity", "", "<string></string>"},
	}
	for _, tt := range tests {
		got, ok := encode(tt.encoder, tt.in)
		if !ok || got != tt.want {
			t.Errorf("%s(%q) = %q, %v; want %q", tt.encoder, tt.in, got, ok, tt.want)
		}
	}
	// Names are matched exactly, as the tool matches them.
	for _, name := range []string{"", "plain", "base64", "Url", "HTML", "Base64 "} {
		if got, ok := encode(name, "x"); ok || got != "" {
			t.Errorf("encoder %q: %q, %v; want none", name, got, ok)
		}
	}
}

// testToken stands for the importer's hash: "ab" for every byte.
func testToken(_ string, n int) string { return strings.Repeat("ab", n) }

var testDefaults = []header{{"Accept", "*/*"}, {"Accept-Encoding", "br"}, {"User-Agent", "agent/1"}}

// place builds the line for a payload that the Plain encoder left as it is.
func place(p placeholder, payload string) (cases.Line, string) {
	req, reason := p.request(payload, payload, testToken)
	if reason != "" {
		return cases.Line{}, reason
	}
	return req.line(testDefaults, p.name == "UserAgent")
}

const wantSOAP = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
	"<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"\n" +
	"\txmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n" +
	"\t<soapenv:Header>\n" +
	"\t\t<ns1:RequestHeader soapenv:actor=\"http://schemas.xmlsoap.org/soap/actor/next\"\n" +
	"\t\t\tsoapenv:mustUnderstand=\"0\" xmlns:ns1=\"https://www.google.com/apis/ads/publisher/v202002\">\n" +
	"\t\t</ns1:RequestHeader>\n" +
	"\t</soapenv:Header>\n" +
	"\t<soapenv:Body>\n" +
	"\t\t<getAdUnitsByStatement xmlns=\"https://www.google.com/apis/ads/publisher/v202002\">\n" +
	"\t\t\t<filterStatement>\n" +
	"\t\t\t\t<abababababab><string>a b&amp;c</string></abababababab>\n" +
	"\t\t\t</filterStatement>\n" +
	"\t\t</getAdUnitsByStatement>\n" +
	"\t</soapenv:Body>\n" +
	"</soapenv:Envelope>"

func TestPlaceholders(t *testing.T) {
	t.Parallel()
	const payload = "a b&c"
	boundary := strings.Repeat("ab", 30)
	type want struct {
		method, path, query, body, placement string
		headers                              map[string]string // besides the defaults
	}
	tests := []struct {
		p    placeholder
		want want
	}{
		{placeholder{name: "Header"}, want{"GET", "/", "", "", "header", map[string]string{"X-Ababababab": payload}}},
		{placeholder{name: "HTMLForm"}, want{"POST", "/", "", "ababababab=a b&c", "body",
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"}}},
		{placeholder{name: "HTMLMultipartForm"}, want{"POST", "/", "",
			"--" + boundary + "\r\nContent-Disposition: form-data; name=\"ababababab\"\r\n\r\na b&c\r\n--" + boundary + "--\r\n",
			"body", map[string]string{"Content-Type": "multipart/form-data; boundary=" + boundary}}},
		{placeholder{name: "JSONBody"}, want{"POST", "/", "", payload, "json",
			map[string]string{"Content-Type": "application/json"}}},
		// The value is encoded once more, as UTF-16 code units.
		{placeholder{name: "JSONRequest"}, want{"POST", "/", "",
			`{"test": true, "ababababab": "\u0061\u0020\u0062\u0026\u0063"}`, "json",
			map[string]string{"Content-Type": "application/json"}}},
		{placeholder{name: "RequestBody"}, want{"POST", "/", "", payload, "body", nil}},
		// The value is encoded once more, as an XML element.
		{placeholder{name: "SOAPBody"}, want{"POST", "/", "", wantSOAP, "body", map[string]string{
			"Content-Type": "text/xml", "Soapaction": `"http://schemas.xmlsoap.org/soap/actor/next"`}}},
		{placeholder{name: "URLParam"}, want{"GET", "/", "ababababab=a b&c", "", "query", nil}},
		// The tool's HTTP client escapes a blank in a path, but not in a query.
		{placeholder{name: "URLPath"}, want{"GET", "/a%20b&c", "", "", "path", nil}},
		{placeholder{name: "UserAgent"}, want{"GET", "/", "", "", "header", map[string]string{"User-Agent": payload}}},
		{placeholder{name: "XMLBody"}, want{"POST", "/", "", payload, "body",
			map[string]string{"Content-Type": "application/xml"}}},
		{placeholder{name: "GraphQL", method: "GET"}, want{"GET", "/graphql", "query=a b&c", "", "query", nil}},
		{placeholder{name: "GraphQL", method: "POST"}, want{"POST", "/graphql", "", payload, "body", nil}},
		{placeholder{name: "RawRequest", raw: &rawConfig{
			method: "PATCH", path: "v1/{{payload}}?q={{payload}}", body: "<{{payload}}|{{payload}}>",
			headers: []header{{"x-first", "{{payload}}"}, {"Content-Type", "text/plain"}},
		}}, want{"PATCH", "/v1/a%20b&c", "q=a%20b&c", "<a b&c|a b&c>", "raw",
			map[string]string{"X-First": payload, "Content-Type": "text/plain"}}},
	}
	for _, tt := range tests {
		l, reason := place(tt.p, payload)
		if reason != "" {
			t.Errorf("%s %s: skipped: %s", tt.p.name, tt.p.method, reason)
			continue
		}
		headers := map[string]string{"Accept": "*/*", "Accept-Encoding": "br", "User-Agent": "agent/1"}
		maps.Copy(headers, tt.want.headers)
		got := want{l.Method, l.Path, l.RawQuery, l.Body, l.Placement, l.Headers}
		if !reflect.DeepEqual(got, want{tt.want.method, tt.want.path, tt.want.query, tt.want.body, tt.want.placement, headers}) {
			t.Errorf("%s %s:\n got %+v\nwant %+v with the defaults", tt.p.name, tt.p.method, got, tt.want)
		}
		if l.ContentType != "" || l.BodyBase64 != "" || len(l.Query) != 0 {
			t.Errorf("%s: content type %q, body_base64 %q, query %v", tt.p.name, l.ContentType, l.BodyBase64, l.Query)
		}
	}
}

func TestPlaceholderSkips(t *testing.T) {
	t.Parallel()
	raw := func(c rawConfig) placeholder { return placeholder{name: "RawRequest", raw: &c} }
	tests := []struct {
		p       placeholder
		payload string
		want    string
	}{
		{placeholder{name: "gRPC"}, "x", "gRPC placeholder: the tool makes a gRPC call, not a plain HTTP request"},
		{placeholder{name: "Teleport"}, "x", "placeholder is not one of the tool's"},
		{placeholder{name: "urlparam"}, "x", "placeholder is not one of the tool's"},
		{placeholder{name: "RawRequest"}, "x", "placeholder is named without the configuration it needs"},
		{placeholder{name: "GraphQL"}, "x", "placeholder is named without the configuration it needs"},
		// What the tool's HTTP client refuses to send.
		{placeholder{name: "URLParam"}, "a\nb", "the tool's HTTP client rejects the URL of this request"},
		{placeholder{name: "URLPath"}, "a\x7fb", "the tool's HTTP client rejects the URL of this request"},
		{placeholder{name: "URLPath"}, "100%zz", "the tool's HTTP client rejects the URL of this request"},
		{placeholder{name: "Header"}, "a\r\nX-Injected: 1", "the tool's HTTP client rejects a header of this request"},
		{placeholder{name: "UserAgent"}, "a\x00b", "the tool's HTTP client rejects a header of this request"},
		{raw(rawConfig{method: "GET", headers: []header{{"Bad Name", "x"}}}), "x", "the tool's HTTP client rejects a header of this request"},
		{raw(rawConfig{method: "BAD METHOD"}), "x", "the tool's HTTP client rejects the method of this request"},
		// What a case line cannot say, or the sender cannot send as the tool does.
		{placeholder{name: "URLPath"}, "page?", "the request target ends in an empty query, which a case line cannot say"},
		{placeholder{name: "URLParam"}, "\xff", "the query is not valid UTF-8, which a case line cannot carry"},
		{placeholder{name: "Header"}, "\xff", "a header value is not valid UTF-8, which a case line cannot carry"},
		{raw(rawConfig{method: "GET", headers: []header{{"X-A", "1"}, {"x-a", "2"}}}), "x", "two headers of the request have the same name"},
		{raw(rawConfig{method: "GET", headers: []header{{"host", "a.test"}}}), "x",
			"the request sets Host, Content-Length, Transfer-Encoding or Trailer, which the tool's HTTP client does not send as written"},
		{raw(rawConfig{method: "POST", headers: []header{{"Content-Length", "3"}}, body: "abc"}), "x",
			"the request sets Host, Content-Length, Transfer-Encoding or Trailer, which the tool's HTTP client does not send as written"},
		{raw(rawConfig{method: "POST", headers: []header{{"Transfer-Encoding", "chunked"}}}), "x",
			"the request sets Host, Content-Length, Transfer-Encoding or Trailer, which the tool's HTTP client does not send as written"},
		{raw(rawConfig{method: "GET", headers: []header{{"X-Request-ID", "1"}}}), "x",
			"the request sets X-Request-Id, which the sender replaces"},
		{raw(rawConfig{method: "GET", path: "/", body: "see //{{payload}}"}), "collector.example.net/x",
			"the request template and the payload together name a public host"},
	}
	for _, tt := range tests {
		l, reason := place(tt.p, tt.payload)
		if reason != tt.want {
			t.Errorf("%s with %q: reason %q, want %q (line %+v)", tt.p.name, tt.payload, reason, tt.want, l)
		}
	}
}

// What the tool's HTTP client makes of a request before it is sent.
func TestClientBehaviour(t *testing.T) {
	t.Parallel()
	targets := []struct {
		p                 placeholder
		payload           string
		wantPath, wantQry string
	}{
		// A fragment is not sent.
		{placeholder{name: "URLParam"}, "a#b", "/", "ababababab=a"},
		{placeholder{name: "URLPath"}, "a#b?c", "/a", ""},
		{placeholder{name: "GraphQL", method: "GET"}, "{a}#b", "/graphql", "query={a}"},
		// A question mark in a path starts the query.
		{placeholder{name: "URLPath"}, "a?b=c d", "/a", "b=c d"},
		// A path is escaped unless it is validly escaped already.
		{placeholder{name: "URLPath"}, "é\"<", "/%C3%A9%22%3C", ""},
		{placeholder{name: "URLPath"}, "%2e%2e/%2F", "/%2e%2e/%2F", ""},
		{placeholder{name: "URLPath"}, "%2e é", "/.%20%C3%A9", ""},
		{placeholder{name: "URLPath"}, "/etc/passwd", "//etc/passwd", ""},
		{placeholder{name: "URLPath"}, "", "/", ""},
		// A query is sent as written.
		{placeholder{name: "URLParam"}, "é\"<%zz+ ", "/", "ababababab=é\"<%zz+ "},
		{placeholder{name: "URLParam"}, "", "/", "ababababab="},
	}
	for _, tt := range targets {
		l, reason := place(tt.p, tt.payload)
		if reason != "" || l.Path != tt.wantPath || l.RawQuery != tt.wantQry {
			t.Errorf("%s with %q: path %q, query %q, reason %q; want %q, %q", tt.p.name, tt.payload,
				l.Path, l.RawQuery, reason, tt.wantPath, tt.wantQry)
		}
	}

	// Blanks around a header value are not sent.
	if l, reason := place(placeholder{name: "Header"}, " \tpadded \t"); reason != "" || l.Headers["X-Ababababab"] != "padded" {
		t.Errorf("padded header: %q, reason %q", l.Headers["X-Ababababab"], reason)
	}
	// An empty User-Agent header is no header at all.
	l, reason := place(placeholder{name: "UserAgent"}, "")
	if _, ok := l.Headers["User-Agent"]; ok || reason != "" || len(l.Headers) != 2 {
		t.Errorf("empty user agent: headers %q, reason %q", l.Headers, reason)
	}
	if l, reason := place(placeholder{name: "UserAgent"}, " "); reason != "" || !maps.Equal(l.Headers, map[string]string{"Accept": "*/*", "Accept-Encoding": "br", "User-Agent": ""}) {
		t.Errorf("blank user agent: headers %q, reason %q", l.Headers, reason)
	}

	// A configured header is kept; an empty one gets the default value.
	p := placeholder{name: "RawRequest", raw: &rawConfig{method: "", headers: []header{{"user-agent", "custom"}, {"ACCEPT", ""}, {"X-Empty", ""}}}}
	l, reason = place(p, "x")
	wantHeaders := map[string]string{"User-Agent": "custom", "Accept": "*/*", "Accept-Encoding": "br", "X-Empty": ""}
	if reason != "" || l.Method != "GET" || l.Path != "/" || !maps.Equal(l.Headers, wantHeaders) {
		t.Errorf("raw request headers: method %q, path %q, headers %q, reason %q", l.Method, l.Path, l.Headers, reason)
	}

	// Without defaults the client names itself and asks for gzip.
	req, _ := placeholder{name: "URLPath"}.request("x", "x", testToken)
	l, reason = req.line(nil, false)
	if reason != "" || !maps.Equal(l.Headers, map[string]string{"User-Agent": "Go-http-client/1.1", "Accept-Encoding": "gzip"}) {
		t.Errorf("no defaults: headers %q, reason %q", l.Headers, reason)
	}

	// A body that is not valid UTF-8 is written as base64.
	l, reason = place(placeholder{name: "RequestBody"}, "a\xffb")
	if reason != "" || l.Body != "" || l.BodyBase64 != "Yf9i" {
		t.Errorf("binary body: body %q, body_base64 %q, reason %q", l.Body, l.BodyBase64, reason)
	}
}

func TestCategory(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"sql-injection":           "sqli",
		"community-sqli":          "sqli",
		"community-128kb-sqli":    "sqli",
		"xss-scripting":           "xss",
		"community-8kb-xss":       "xss",
		"path-traversal":          "lfi",
		"community-lfi-multipart": "lfi",
		"shell-injection":         "cmdi",
		"nosql-injection":         "nosqli",
		"sst-injection":           "ssti",
		"xml-injection":           "xxe",
		"community-xxe":           "xxe",
		"rce":                     "rce",
		"rce-urlpath":             "rce",
		"community-16kb-rce":      "rce",
		"graphql-post":            "graphql",
		// No clear match: the tool's own name, lower-cased.
		"ldap-injection": "ldap-injection",
		"CRLF":           "crlf",
		"soap":           "soap",
		"odd name!":      "other",
		"":               "other",
	}
	for name, want := range tests {
		if got := category(name, cases.Attack); got != want {
			t.Errorf("category(%q) = %q, want %q", name, got, want)
		}
	}
	if got := category("sql-injection", cases.Legit); got != "fp" {
		t.Errorf("legitimate category %q, want fp", got)
	}
}

// writeTree writes files below a new directory and returns it. Without a
// config.yaml of its own the tree gets one without headers.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	if _, ok := files["config.yaml"]; !ok {
		files["config.yaml"] = "headers: {}\n"
	}
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const oneCase = "payload: [\"<script>\"]\nencoder: [Plain]\nplaceholder: [RequestBody]\n"

func TestImportExpectedFollowsTheSetName(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"testcases/owasp/a.yml":           oneCase,
		"testcases/false-pos/a.yml":       oneCase,
		"testcases/my-false-set/a.yaml":   oneCase,
		"testcases/False/a.yml":           oneCase, // the tool looks for "false" as written
		"testcases/owasp/false.yml":       oneCase, // a file name decides nothing
		"testcases/false-pos/deep/a.yml":  oneCase, // the set is the directory the file is in
		"testcases/deep/false-pos/a.yml":  oneCase,
		"testcases/top.yml":               oneCase,
		"testcases/owasp/notes.txt":       "not a test case",
		"testcases/owasp/README.md":       "not a test case",
		"elsewhere/false-pos/ignored.yml": oneCase,
	})
	lines, skipped, err := Import(root)
	if err != nil {
		t.Fatal(err)
	}
	byID, reasons := index(t, lines, skipped)
	want := map[string]cases.Expected{
		"owasp/a/1/Plain/RequestBody":          cases.Attack,
		"false-pos/a/1/Plain/RequestBody":      cases.Legit,
		"my-false-set/a/1/Plain/RequestBody":   cases.Legit,
		"False/a/1/Plain/RequestBody":          cases.Attack,
		"owasp/false/1/Plain/RequestBody":      cases.Attack,
		"false-pos/deep/a/1/Plain/RequestBody": cases.Attack,
		"deep/false-pos/a/1/Plain/RequestBody": cases.Legit,
		"top/1/Plain/RequestBody":              cases.Attack,
	}
	if len(byID) != len(want) || len(reasons) != 0 {
		t.Errorf("%d lines, want %d; skips %q", len(byID), len(want), reasons)
	}
	for id, expected := range want {
		if got := byID[id].Expected; got != expected {
			t.Errorf("case %s: expected %q, want %q", id, got, expected)
		}
	}
}

func TestImportOddFiles(t *testing.T) {
	t.Parallel()
	const head = "payload: [x]\nencoder: [Plain]\nplaceholder:\n"
	root := writeTree(t, map[string]string{
		"testcases/s/list.yml":      "- a\n- b\n",
		"testcases/s/scalars.yml":   "payload: x\nencoder: Plain\nplaceholder: URLParam\n",
		"testcases/s/nested.yml":    "payload: [[x]]\nencoder: [Plain]\nplaceholder: [URLParam]\n",
		"testcases/s/number.yml":    head + "  - 12\n",
		"testcases/s/twokeys.yml":   head + "  - URLParam: {}\n    URLPath: {}\n",
		"testcases/s/noconfig.yml":  head + "  - URLParam:\n",
		"testcases/s/unknown.yml":   head + "  - Teleport: {}\n",
		"testcases/s/method.yml":    head + "  - GraphQL:\n      method: PUT\n",
		"testcases/s/yes.yml":       head + "  - RawRequest:\n      method: GET\n      headers:\n        X-Flag: yes\n",
		"testcases/s/length.yml":    head + "  - RawRequest:\n      method: GET\n      headers:\n        X-Count: 5\n",
		"testcases/s/nobody.yml":    head + "  - RawRequest:\n      method: GET\n      body:\n",
		"testcases/s/marker.yml":    head + "  - RawRequest:\n      method: GET\n      body: \"http://{{payload}}/\"\n",
		"testcases/s/same.yml":      oneCase,
		"testcases/s/same.yaml":     oneCase,
		"testcases/s/ignored.yml":   head + "  - URLParam: {}\n  - RawRequest:\n      method: GET\n      extra: [1]\nextra: 1\n",
		"testcases/s/empty.yml":     "",
		"testcases/s/null.yml":      "~\n",
		"testcases/s/merge.yml":     "base: &base\n  payload: [x]\n<<: *base\nencoder: [Plain]\nplaceholder: [URLPath]\n",
		"testcases/s/mixed.yml":     "payload: [1, true, 2.50, 0x1F, ~]\nencoder: [Plain]\nplaceholder: [RequestBody]\n",
		"testcases/s/nulls.yml":     "payload: [~, \"\"]\nencoder: [Plain]\nplaceholder: [URLPath]\n",
		"testcases/s/binary.yml":    "payload: [!!binary \"/2E=\"]\nencoder: [Plain, URL]\nplaceholder: [RequestBody]\n",
		"testcases/s/repeated.yml":  "payload: [x]\nencoder: [Plain, Plain]\nplaceholder: [URLPath, \"odd/name\"]\n",
		"testcases/s/template.yml":  head + "  - RawRequest:\n      method: POST\n      body: \"u=http://collector.example.net/{{payload}}\"\n",
		"testcases/s/many.yml":      "payload: [" + strings.Repeat("x,", 101) + "x]\nencoder: [" + strings.Repeat("Plain,", 100) + "Plain]\nplaceholder: [URLPath]\n",
		"testcases/s/not-utf8.yml":  "payload: [\"\xff\"]\nencoder: [Plain]\nplaceholder: [URLPath]\n",
		"testcases/s/alias.yml":     "payload: [&p \"<x>\", *p]\nencoder: [Plain]\nplaceholder: [RequestBody]\n",
		"testcases/s/two-docs.yml":  oneCase + "---\n" + oneCase,
		"testcases/s/duplicate.yml": oneCase + "encoder: [URL]\n",
	})
	if err := os.Symlink(filepath.Join(root, "testcases", "s", "same.yml"), filepath.Join(root, "testcases", "s", "link.yml")); err != nil {
		t.Fatal(err)
	}
	lines, skipped, err := Import(root)
	if err != nil {
		t.Fatal(err)
	}
	byID, reasons := index(t, lines, skipped)

	const cannotLoad = "the tool cannot load this file: "
	wantSkips := map[string]string{
		"s/list.yml":      "file is not YAML in the shape of a test case",
		"s/scalars.yml":   "file is not YAML in the shape of a test case",
		"s/nested.yml":    "file is not YAML in the shape of a test case",
		"s/not-utf8.yml":  "file is not YAML in the shape of a test case",
		"s/duplicate.yml": "file is not YAML in the shape of a test case",
		"s/number.yml":    cannotLoad + "a placeholder is neither a name nor a mapping",
		"s/twokeys.yml":   cannotLoad + "a placeholder mapping does not have exactly one name",
		"s/noconfig.yml":  cannotLoad + "a placeholder's configuration is not a mapping",
		"s/unknown.yml":   cannotLoad + "a configured placeholder is not one of the tool's",
		"s/method.yml":    cannotLoad + "GraphQL needs the method GET or POST",
		"s/yes.yml":       cannotLoad + "a RawRequest header is not a string",
		"s/length.yml":    cannotLoad + "a RawRequest header is not a string",
		"s/nobody.yml":    cannotLoad + "the RawRequest body is not a string",
		"s/same.yml":      "another file has the same name with another extension",
		"s/link.yml":      "link is not followed",
		"s/empty.yml":     "file holds no payload, no encoder or no placeholder",
		"s/null.yml":      "file holds no payload, no encoder or no placeholder",
		"s/many.yml":      "file holds more than 10000 combinations of payload, encoder and placeholder",

		"s/marker/1/Plain/RawRequest":        "the request template and the payload together name a public host",
		"s/merge.yml":                        "file uses a YAML merge key",
		"s/repeated/1/Plain#1/placeholder#2": "placeholder is not one of the tool's",
		"s/repeated/1/Plain#2/placeholder#2": "placeholder is not one of the tool's",
	}
	if !maps.Equal(reasons, wantSkips) {
		for id, reason := range reasons {
			if wantSkips[id] != reason {
				t.Errorf("skip %s: %q, want %q", id, reason, wantSkips[id])
			}
		}
		for id := range wantSkips {
			if _, ok := reasons[id]; !ok {
				t.Errorf("no skip for %s", id)
			}
		}
	}

	wantLines := []string{
		"s/same/1/Plain/RequestBody",
		"s/ignored/1/Plain/URLParam", "s/ignored/1/Plain/RawRequest",
		"s/nulls/1/Plain/URLPath", "s/nulls/2/Plain/URLPath",
		"s/binary/1/Plain/RequestBody", "s/binary/1/URL/RequestBody",
		"s/repeated/1/Plain#1/URLPath", "s/repeated/1/Plain#2/URLPath",
		"s/template/1/Plain/RawRequest",
		"s/alias/1/Plain/RequestBody", "s/alias/2/Plain/RequestBody",
		"s/two-docs/1/Plain/RequestBody",
		"s/mixed/1/Plain/RequestBody", "s/mixed/2/Plain/RequestBody", "s/mixed/3/Plain/RequestBody",
		"s/mixed/4/Plain/RequestBody", "s/mixed/5/Plain/RequestBody",
	}
	if len(byID) != len(wantLines) {
		t.Errorf("%d lines, want %d", len(byID), len(wantLines))
	}
	for _, id := range wantLines {
		if _, ok := byID[id]; !ok {
			t.Errorf("case %s was not imported", id)
		}
	}

	// A payload that is not valid UTF-8 is recorded as base64, for every
	// encoder alike.
	plain, escaped := byID["s/binary/1/Plain/RequestBody"], byID["s/binary/1/URL/RequestBody"]
	if plain.Payload != "" || plain.PayloadBase64 != "/2E=" || escaped.PayloadBase64 != "/2E=" ||
		plain.BodyBase64 != "/2E=" || escaped.Body != "%FFa" {
		t.Errorf("binary payload: %+v\n%+v", plain, escaped)
	}
	// A scalar that is not a string is a payload as it is written.
	for id, want := range map[string]string{"s/mixed/1/": "1", "s/mixed/2/": "true", "s/mixed/3/": "2.50", "s/mixed/4/": "0x1F", "s/mixed/5/": ""} {
		if got := byID[id+"Plain/RequestBody"].Body; got != want {
			t.Errorf("case %s: body %q, want %q", id, got, want)
		}
	}
	// An empty payload is a payload.
	if l := byID["s/nulls/1/Plain/URLPath"]; l.Path != "/" || l.Payload != "" || l.PayloadBase64 != "" {
		t.Errorf("empty payload: %+v", l)
	}
	// A host in a request template is replaced like one in a payload.
	if l := byID["s/template/1/Plain/RawRequest"]; l.Body != "u=http://callback.invalid/x" {
		t.Errorf("template body %q", l.Body)
	}
}

func TestImportReadsTheDefaultHeaders(t *testing.T) {
	t.Parallel()
	// The tool reads its configuration without regard to the case of a key.
	root := writeTree(t, map[string]string{
		"config.yaml":       "url: http://ignored.test\nHeaders:\n  sec-ch-ua: |-\n    \"A\";v=\"1\"\n  ACCEPT-language: en\n  X-Count: 12\n",
		"testcases/s/a.yml": "payload: [x]\nencoder: [Plain]\nplaceholder: [UserAgent, URLPath]\n",
	})
	lines, skipped, err := Import(root)
	if err != nil {
		t.Fatal(err)
	}
	byID, _ := index(t, lines, skipped)
	want := map[string]string{
		"Sec-Ch-Ua": `"A";v="1"`, "Accept-Language": "en", "X-Count": "12",
		"User-Agent": "Go-http-client/1.1", "Accept-Encoding": "gzip",
	}
	if got := byID["s/a/1/Plain/URLPath"].Headers; !maps.Equal(got, want) {
		t.Errorf("headers %q, want %q", got, want)
	}
	want["User-Agent"] = "x"
	if got := byID["s/a/1/Plain/UserAgent"].Headers; !maps.Equal(got, want) {
		t.Errorf("headers %q, want %q", got, want)
	}
}

func TestImportErrors(t *testing.T) {
	t.Parallel()
	trees := map[string]map[string]string{
		"no test cases":        {"testcases/s/readme.txt": "x"},
		"no testcases dir":     {"other/a.yml": oneCase},
		"config not YAML":      {"config.yaml": "headers: [", "testcases/s/a.yml": oneCase},
		"config not a mapping": {"config.yaml": "- a\n", "testcases/s/a.yml": oneCase},
		"headers not mapping":  {"config.yaml": "headers: [a]\n", "testcases/s/a.yml": oneCase},
		"header value a list":  {"config.yaml": "headers:\n  A: [1]\n", "testcases/s/a.yml": oneCase},
		"header value a bool":  {"config.yaml": "headers:\n  A: true\n", "testcases/s/a.yml": oneCase},
		"header twice":         {"config.yaml": "headers:\n  A: x\n  a: y\n", "testcases/s/a.yml": oneCase},
	}
	for name, files := range trees {
		if lines, skipped, err := Import(writeTree(t, files)); err == nil {
			t.Errorf("%s: no error (%d lines, %d skipped)", name, len(lines), len(skipped))
		}
	}
	root := writeTree(t, map[string]string{"testcases/s/a.yml": oneCase})
	if err := os.Remove(filepath.Join(root, "config.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Import(root); err == nil {
		t.Error("a tree without config.yaml: no error")
	}
	if _, _, err := Import(filepath.Join(root, "missing")); err == nil {
		t.Error("a missing tree: no error")
	}
}

// A case too long for a case file is skipped; it must not fail the import
// when the lines are written.
func TestImportSkipsALineTooLongToWrite(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("A", 3<<20)
	root := writeTree(t, map[string]string{
		"testcases/s/long.yml": "payload: [" + long + "]\nencoder: [Plain, JSUnicode]\nplaceholder: [RequestBody]\n",
	})
	lines, skipped, err := Import(root)
	if err != nil {
		t.Fatal(err)
	}
	byID, reasons := index(t, lines, skipped)
	if _, ok := byID["s/long/1/Plain/RequestBody"]; !ok || len(byID) != 1 {
		t.Errorf("%d lines, want the plain one", len(byID))
	}
	if got := reasons["s/long/1/JSUnicode/RequestBody"]; got != "the case is too long for a line of a case file" {
		t.Errorf("reason %q", got)
	}
	if err := cases.WriteLines(discard{}, lines); err != nil {
		t.Errorf("writing the lines: %v", err)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
