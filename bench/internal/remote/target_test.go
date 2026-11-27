package remote

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	secretToken = "Bearer s3cr3t-t0ken"
	exampleHost = "waf.example.test"
)

// validTarget returns a target that passes Validate(exampleHost, 2); tests
// change it.
func validTarget() Target {
	return Target{
		BaseURL:         "https://" + exampleHost,
		RequestIDPrefix: "bench-",
		Mode:            "enforce",
		HealthPath:      "/health",
		MaxRPS:          5,
		StopStatuses:    []int{429},
		Headers:         map[string]string{"Authorization": secretToken},
		Allow: []Entry{
			{Method: "GET", Path: "/search", Placements: []string{"query:q"}, BenignStatus: []int{200}},
			{Method: "POST", Path: "/api/notes", Placements: []string{"json:note", "header:X-Note"}, BenignStatus: []int{200, 201},
				MayWriteData: true},
		},
	}
}

func TestValidTargetPasses(t *testing.T) {
	t.Parallel()
	if err := validTarget().Validate(exampleHost, 2); err != nil {
		t.Fatal(err)
	}
	loop := validTarget()
	loop.BaseURL = "http://127.0.0.1:8088"
	if err := loop.Validate("127.0.0.1:8088", 5); err != nil {
		t.Errorf("plain http to loopback: %v", err)
	}
	monitor := validTarget()
	monitor.Mode, monitor.StopStatuses = "monitor", []int{403}
	if err := monitor.Validate(exampleHost, 1); err != nil {
		t.Errorf("403 as a stop status in monitor mode: %v", err)
	}
	root := validTarget()
	root.Allow[0].Path = "/"
	if err := root.Validate(exampleHost, 1); err != nil {
		t.Errorf("path /: %v", err)
	}
	// GET and HEAD read; they need no flag.
	read := validTarget()
	read.Allow[1].Method, read.Allow[1].MayWriteData = "HEAD", false
	if err := read.Validate(exampleHost, 1); err != nil {
		t.Errorf("HEAD without may_write_data: %v", err)
	}
	// 2xx and 4xx other than 403 are benign answers.
	benign := validTarget()
	benign.Allow[0].BenignStatus = []int{200, 204, 299, 400, 404, 422, 499}
	if err := benign.Validate(exampleHost, 1); err != nil {
		t.Errorf("2xx and 4xx benign statuses: %v", err)
	}
	// Names that merely contain a refused name are allowed.
	names := validTarget()
	names.Allow[0].Placements = []string{"query:method_name", "query:payment_method", "header:X-Forwardedness", "header:X-Originally"}
	if err := names.Validate(exampleHost, 1); err != nil {
		t.Errorf("names near refused ones: %v", err)
	}
}

func TestValidateRefuses(t *testing.T) {
	t.Parallel()
	type change struct {
		name        string
		edit        func(*Target)
		confirmHost string // exampleHost when empty
		rps         int    // 2 when 0
		want        string // part of the error
	}
	entry := func(f func(*Entry)) func(*Target) { return func(t *Target) { f(&t.Allow[1]) } }
	tests := []change{
		{name: "http to a public host", edit: func(t *Target) { t.BaseURL = "http://" + exampleHost }, want: "https"},
		{name: "http to a name ending localhost", edit: func(t *Target) { t.BaseURL = "http://localhost." }, confirmHost: "localhost.", want: "https"},
		{name: "other scheme", edit: func(t *Target) { t.BaseURL = "ftp://" + exampleHost }, want: "https"},
		{name: "user info", edit: func(t *Target) { t.BaseURL = "https://user:pw@" + exampleHost }, confirmHost: "user:pw@" + exampleHost, want: "user info"},
		{name: "path", edit: func(t *Target) { t.BaseURL = "https://" + exampleHost + "/api" }, want: "only a scheme and host"},
		{name: "slash path", edit: func(t *Target) { t.BaseURL = "https://" + exampleHost + "/" }, want: "only a scheme and host"},
		{name: "query", edit: func(t *Target) { t.BaseURL = "https://" + exampleHost + "?a=1" }, want: "only a scheme and host"},
		{name: "empty query", edit: func(t *Target) { t.BaseURL = "https://" + exampleHost + "?" }, want: "only a scheme and host"},
		{name: "fragment", edit: func(t *Target) { t.BaseURL = "https://" + exampleHost + "#a" }, want: "only a scheme and host"},
		{name: "no host", edit: func(t *Target) { t.BaseURL = "https:///x" }, want: "only a scheme and host"},
		{name: "not a URL", edit: func(t *Target) { t.BaseURL = "https://a b" }, want: "base_url"},
		{name: "confirm host without the port", edit: func(t *Target) { t.BaseURL = "https://" + exampleHost + ":8443" }, want: "--confirm-host"},
		{name: "confirm host is the port only", edit: func(t *Target) { t.BaseURL = "https://" + exampleHost + ":8443" }, confirmHost: ":8443", want: "--confirm-host"},
		{name: "confirm host adds a port", confirmHost: exampleHost + ":443", want: "--confirm-host"},
		{name: "confirm host with user info", confirmHost: "user@" + exampleHost, want: "--confirm-host"},
		{name: "confirm host in other case", confirmHost: strings.ToUpper(exampleHost), want: "--confirm-host"},
		{name: "confirm host empty", confirmHost: " ", want: "--confirm-host"},
		{name: "empty allow-list", edit: func(t *Target) { t.Allow = nil }, want: "allow"},
		{name: "rps over the ceiling", rps: 6, want: "--rps"},
		{name: "rps zero", rps: -1, want: "--rps"},
		{name: "no ceiling", edit: func(t *Target) { t.MaxRPS = 0 }, rps: 1, want: "max_rps"},
		{name: "missing prefix", edit: func(t *Target) { t.RequestIDPrefix = "" }, want: "request_id_prefix"},
		{name: "long prefix", edit: func(t *Target) { t.RequestIDPrefix = strings.Repeat("a", 55) }, want: "request_id_prefix"},
		{name: "prefix with a bad byte", edit: func(t *Target) { t.RequestIDPrefix = "a/b" }, want: "request_id_prefix"},
		{name: "mode", edit: func(t *Target) { t.Mode = "block" }, want: "mode"},
		{name: "no health path", edit: func(t *Target) { t.HealthPath = "" }, want: "health_path"},
		{name: "health path not normal", edit: func(t *Target) { t.HealthPath = "/a/../health" }, want: "health_path"},
		{name: "duplicate entry", edit: func(t *Target) { t.Allow[1].Method, t.Allow[1].Path = "GET", "/search" }, want: "twice"},
		{name: "no benign status", edit: entry(func(e *Entry) { e.BenignStatus = nil }), want: "benign_status"},
		{name: "benign 403", edit: entry(func(e *Entry) { e.BenignStatus = []int{200, 403} }), want: "benign_status"},
		{name: "benign 5xx", edit: entry(func(e *Entry) { e.BenignStatus = []int{503} }), want: "benign_status"},
		{name: "benign not a status", edit: entry(func(e *Entry) { e.BenignStatus = []int{99} }), want: "benign_status"},
		{name: "benign 100", edit: entry(func(e *Entry) { e.BenignStatus = []int{100} }), want: "benign_status"},
		{name: "benign 101", edit: entry(func(e *Entry) { e.BenignStatus = []int{200, 101} }), want: "benign_status"},
		{name: "benign 199", edit: entry(func(e *Entry) { e.BenignStatus = []int{199} }), want: "benign_status"},
		{name: "benign 301", edit: entry(func(e *Entry) { e.BenignStatus = []int{301} }), want: "benign_status"},
		{name: "benign 304", edit: entry(func(e *Entry) { e.BenignStatus = []int{200, 304} }), want: "benign_status"},
		{name: "benign 399", edit: entry(func(e *Entry) { e.BenignStatus = []int{399} }), want: "benign_status"},
		{name: "stop 403 in enforce", edit: func(t *Target) { t.StopStatuses = []int{403} }, want: "stop_statuses"},
		{name: "stop not a status", edit: func(t *Target) { t.StopStatuses = []int{600} }, want: "stop_statuses"},
		{name: "method not a token", edit: entry(func(e *Entry) { e.Method = "PO ST" }), want: "method"},
		{name: "method connect", edit: entry(func(e *Entry) { e.Method = "CONNECT" }), want: "method"},
		{name: "no placements", edit: entry(func(e *Entry) { e.Placements = nil }), want: "placement"},
		{name: "unknown placement kind", edit: entry(func(e *Entry) { e.Placements = []string{"path:id"} }), want: "placement"},
		{name: "body placement", edit: entry(func(e *Entry) { e.Placements = []string{"body:x"} }), want: "placement"},
		{name: "placement without a name", edit: entry(func(e *Entry) { e.Placements = []string{"query:"} }), want: "placement"},
		{name: "placement without a kind", edit: entry(func(e *Entry) { e.Placements = []string{"q"} }), want: "placement"},
		{name: "header placement not a token", edit: entry(func(e *Entry) { e.Placements = []string{"header:X Note"} }), want: "placement"},
		{name: "two equal placements", edit: entry(func(e *Entry) { e.Placements = []string{"query:q", "query:q"} }), want: "collide"},
		{name: "header placements differ by case", edit: entry(func(e *Entry) { e.Placements = []string{"header:X-A", "header:x-a"} }), want: "collide"},
		{name: "header placement is a target header", edit: entry(func(e *Entry) { e.Placements = []string{"header:authorization"} }), want: "collide"},
		{name: "content type with a json placement", edit: func(t *Target) { t.Headers["content-type"] = "text/plain" }, want: "Content-Type"},
		{name: "header placement content type", edit: entry(func(e *Entry) { e.Placements = []string{"json:a", "header:Content-Type"} }), want: "Content-Type"},
		{name: "target header not a token", edit: func(t *Target) { t.Headers["X Y"] = "v" }, want: "header"},
		{name: "target header value with a control byte", edit: func(t *Target) { t.Headers["X-Secret"] = "s3cr3t\r\nX: y" }, want: "header"},
		{name: "target headers differ by case", edit: func(t *Target) { t.Headers["AUTHORIZATION"] = "x" }, want: "case"},
	}
	// A method other than GET or HEAD may change data: it needs the entry's
	// may_write_data, by which the operator accepts that.
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "PROPFIND", "get", "Head", "PURGE"} {
		tests = append(tests, change{name: "method " + method + " without may_write_data",
			edit: entry(func(e *Entry) { e.Method, e.MayWriteData = method, false }), want: "may_write_data"})
	}
	// Routing and hop-by-hop names, and every X-Forwarded- and X-Original- name.
	for _, name := range []string{"X-Forwarded-Host", "X-Original-URL", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Prefix", "X-Forwarded-Port",
		"X-Forwarded-Server", "x-forwarded-anything", "X-Forwarded", "X-Original-URI", "X-Original-Host",
		"X-ORIGINAL-METHOD", "x-original-whatever", "X-Host", "Proxy-Connection", "Keep-Alive", "Via",
		"Max-Forwards", "X-Real-IP", "True-Client-IP", "X-Client-IP", "Proxy-Authorization", "X-Override-URL",
		"X-Envoy-Original-Path"} {
		tests = append(tests,
			change{name: "routing target header " + name, edit: func(t *Target) { t.Headers[name] = "v" }, want: "header"},
			change{name: "routing placement " + name, edit: entry(func(e *Entry) { e.Placements = []string{"header:" + name} }), want: "header"})
	}
	// Method overrides some frameworks read from a query or a body.
	for _, name := range []string{"_method", "_METHOD", "__method", "_Method", "method", "_HttpMethod", "_http_method",
		"httpMethod", "X-HTTP-Method-Override", "x_http_method_override", "X-HTTP-Method", "X-Method-Override", "_methodoverride"} {
		for _, kind := range []string{"query", "json"} {
			tests = append(tests, change{name: kind + " placement " + name,
				edit: entry(func(e *Entry) { e.Placements = []string{kind + ":" + name} }), want: "method override"})
		}
	}
	for _, name := range forbiddenHeaders {
		for _, spelling := range []string{name, strings.ToUpper(name), strings.ToLower(name)} {
			tests = append(tests,
				change{name: "target header " + spelling, edit: func(t *Target) { t.Headers[spelling] = "v" }, want: "header"},
				change{name: "placement " + spelling, edit: entry(func(e *Entry) { e.Placements = []string{"header:" + spelling} }), want: "header"})
		}
	}
	for _, p := range []string{"", "search", "/a/", "/a/../b", "/a/./b", "/a//b", "//a", "/a%2fb", "/a?x=1", "/a?",
		"/a;b", `/a\b`, "/a#b", "/a b", "/a\x01", "/a\x7f", "/café", "/.."} {
		tests = append(tests, change{name: "path " + p, edit: entry(func(e *Entry) { e.Path = p }), want: "path"})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			target := validTarget()
			if tc.edit != nil {
				tc.edit(&target)
			}
			confirm, rps := cmpOr(tc.confirmHost, exampleHost), tc.rps
			if rps == 0 {
				rps = 2
			}
			err := target.Validate(confirm, rps)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			for _, secret := range []string{"s3cr3t", "pw@", "user:"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error %q repeats a secret", err)
				}
			}
		})
	}
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func TestLoadTarget(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	good := `{"base_url": "https://waf.example.test", "request_id_prefix": "bench-", "mode": "monitor",
		"health_path": "/health", "max_rps": 3, "stop_statuses": [429], "headers": {"Authorization": "Bearer s3cr3t"},
		"allow": [{"method": "GET", "path": "/search", "placements": ["query:q"], "benign_status": [200]}]}`
	target, err := LoadTarget(write("good.json", good))
	if err != nil {
		t.Fatal(err)
	}
	if target.MaxRPS != 3 || target.Allow[0].Placements[0] != "query:q" || target.Headers["Authorization"] == "" {
		t.Errorf("read %+v", target)
	}
	if err := target.Validate(exampleHost, 3); err != nil {
		t.Errorf("Validate: %v", err)
	}
	write2 := strings.Replace(good, `"method": "GET"`, `"method": "POST", "may_write_data": true`, 1)
	if w, err := LoadTarget(write("write.json", write2)); err != nil || !w.Allow[0].MayWriteData || w.Validate(exampleHost, 3) != nil {
		t.Errorf("may_write_data is not read: %+v, %v", w.Allow, err)
	}
	for name, text := range map[string]string{
		"unknown key":         strings.Replace(good, `"mode"`, `"insecure": true, "mode"`, 1),
		"unknown entry key":   strings.Replace(good, `"method"`, `"methods": [], "method"`, 1),
		"trailing data":       good + ` {}`,
		"null":                `null`,
		"array":               `[]`,
		"wrong type":          strings.Replace(good, `"max_rps": 3`, `"max_rps": "3"`, 1),
		"duplicate key":       strings.Replace(good, `"mode": "monitor"`, `"mode": "monitor", "mode": "enforce"`, 1),
		"duplicate entry key": strings.Replace(good, `"method": "GET"`, `"method": "GET", "method": "POST"`, 1),
	} {
		_, err := LoadTarget(write(strings.ReplaceAll(name, " ", "-")+".json", text))
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("%s: error %q repeats the header value", name, err)
		}
	}
	if _, err := LoadTarget(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("a missing file was accepted")
	}
}

func TestExampleTargetFileIsValid(t *testing.T) {
	t.Parallel()
	target, err := LoadTarget(filepath.Join("..", "..", "target.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Validate(exampleHost, 1); err != nil {
		t.Fatal(err)
	}
	// The example a reader copies must not write: GET routes only, answered 200.
	for i, e := range target.Allow {
		if e.Method != "GET" || e.MayWriteData || len(e.BenignStatus) != 1 || e.BenignStatus[0] != 200 {
			t.Errorf("allow entry %d is %s with may_write_data %t and benign_status %v, want GET, false and [200]",
				i+1, e.Method, e.MayWriteData, e.BenignStatus)
		}
	}
}
