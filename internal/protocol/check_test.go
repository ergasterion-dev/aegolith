package protocol

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

func ids(ms []model.Match) map[string]model.Match {
	m := map[string]model.Match{}
	for _, x := range ms {
		m[x.RuleID] = x
	}
	return m
}

func TestCheck(t *testing.T) {
	json := http.Header{"Content-Type": {"application/json"}}
	tests := []struct {
		name string
		req  model.Request
		cfg  Config
		want []string
	}{
		{"trace method", model.Request{Method: "TRACE", RawPath: "/a"}, Config{}, []string{"AEG-PROTO-001"}},
		{"xml body", model.Request{Method: "POST", RawPath: "/a", Header: http.Header{"Content-Type": {"application/xml"}}, Body: []byte("<a/>")}, Config{}, []string{"AEG-PROTO-002"}},
		{"xml allowed", model.Request{Method: "POST", RawPath: "/a", Header: http.Header{"Content-Type": {"text/xml"}}, Body: []byte("<a/>")}, Config{AllowXML: true}, nil},
		{"missing content type with body", model.Request{Method: "POST", RawPath: "/a", Body: []byte("x")}, Config{}, []string{"AEG-PROTO-002"}},
		{"oversize body", model.Request{Method: "POST", RawPath: "/a", Header: json, Body: []byte("12345")}, Config{Limits: model.Limits{MaxBodyBytes: 4}}, []string{"AEG-PROTO-003"}},
		{"te chunked identity", model.Request{Method: "POST", RawPath: "/a", Header: http.Header{"Transfer-Encoding": {"chunked, identity"}}}, Config{}, []string{"AEG-PROTO-006"}},
		{"te with cl", model.Request{Method: "POST", RawPath: "/a", Header: http.Header{"Transfer-Encoding": {"chunked"}, "Content-Length": {"3"}}}, Config{}, []string{"AEG-PROTO-006"}},
		{"te chunked alone", model.Request{Method: "POST", RawPath: "/a", Header: http.Header{"Transfer-Encoding": {"chunked"}}}, Config{}, nil},
		{"traversal", model.Request{Method: "GET", RawPath: "/api/v1/files/../../etc/passwd"}, Config{}, []string{"AEG-PROTO-005"}},
		{"traversal backslash", model.Request{Method: "GET", RawPath: "/a/..\\b"}, Config{}, []string{"AEG-PROTO-005"}},
		{"traversal trailing /..", model.Request{Method: "GET", RawPath: "/api/v1/files/.."}, Config{}, []string{"AEG-PROTO-005"}},
		{"traversal trailing /%2e%2e", model.Request{Method: "GET", RawPath: "/api/v1/files/%2e%2E"}, Config{}, []string{"AEG-PROTO-005"}},
		{"traversal trailing \\..", model.Request{Method: "GET", RawPath: "/a\\.."}, Config{}, []string{"AEG-PROTO-005"}},
		{"dots in name not traversal", model.Request{Method: "GET", RawPath: "/a/b..c/x..."}, Config{}, nil},
		{"traversal ..%5c", model.Request{Method: "GET", RawPath: "/a/..%5Cb"}, Config{}, []string{"AEG-PROTO-005"}},
		{"traversal %2e%2e/", model.Request{Method: "GET", RawPath: "/a/%2E%2E/b"}, Config{}, []string{"AEG-PROTO-005"}},
		{"crlf path", model.Request{Method: "GET", RawPath: "/x%0d%0aX-Injected:%201"}, Config{}, []string{"AEG-PROTO-004"}},
		{"nul raw path", model.Request{Method: "GET", RawPath: "/x\x00"}, Config{}, []string{"AEG-PROTO-004"}},
		{"crlf header", model.Request{Method: "GET", RawPath: "/a", Header: http.Header{"X-Foo": {"a\r\nB: c"}}}, Config{}, []string{"AEG-PROTO-004"}},
		{"double encoded", model.Request{Method: "GET", RawPath: "/a/%252e%252e%252fetc"}, Config{}, []string{"AEG-PROTO-007", "AEG-PROTO-005"}},
		{"get plain", model.Request{Method: "GET", RawPath: "/a"}, Config{}, nil},
		{"patch json", model.Request{Method: "PATCH", RawPath: "/a", Header: json, Body: []byte("{}")}, Config{}, nil},
		{"json charset", model.Request{Method: "POST", RawPath: "/a", Header: http.Header{"Content-Type": {"Application/JSON; charset=utf-8"}}, Body: []byte("{}")}, Config{}, nil},
		{"uuid path", model.Request{Method: "GET", RawPath: "/api/v1/orders/4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b"}, Config{}, nil},
		{"vendor path", model.Request{Method: "GET", RawPath: "/api/v1/vendors/12/products"}, Config{}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Check(&tc.req, tc.cfg)
			gm := ids(got)
			if len(got) != len(gm) {
				t.Fatalf("duplicate rule reported: %+v", got)
			}
			if len(gm) != len(tc.want) {
				t.Fatalf("got %+v want %v", got, tc.want)
			}
			for _, w := range tc.want {
				m, ok := gm[w]
				if !ok {
					t.Fatalf("missing %s in %+v", w, got)
				}
				if m.Category != model.CatProtocol || m.Field == "" {
					t.Fatalf("bad match %+v", m)
				}
			}
		})
	}
}

func TestMatchShape(t *testing.T) {
	r := &model.Request{Method: "TRACE", RawPath: "/a"}
	m := Check(r, Config{})[0]
	if m.Action != model.ActionBlock || m.Severity != model.SeverityMedium || m.Location != model.LocMethod || m.Field != "method" || m.Snippet != "TRACE" {
		t.Fatalf("%+v", m)
	}
	r = &model.Request{Method: "POST", RawPath: "/a", Header: http.Header{"Content-Type": {"application/json"}}, Body: []byte("12345")}
	m = Check(r, Config{Limits: model.Limits{MaxBodyBytes: 4}})[0]
	if m.Action != model.ActionMonitor || m.Severity != model.SeverityLow {
		t.Fatalf("%+v", m)
	}
	r = &model.Request{Method: "GET", RawPath: "/a", Header: http.Header{"X-Evil": {"a\nb"}}}
	m = Check(r, Config{})[0]
	if m.Field != "header.x-evil" || m.Location != model.LocHeader || m.Severity != model.SeverityHigh || strings.ContainsAny(m.Snippet, "\r\n") {
		t.Fatalf("%+v", m)
	}
	r = &model.Request{Method: "POST", RawPath: "/a", Header: http.Header{"Transfer-Encoding": {"gzip"}}}
	m = Check(r, Config{})[0]
	if m.Field != "header.transfer-encoding" || m.Location != model.LocHeader {
		t.Fatalf("%+v", m)
	}
}

// TestHeaderCtlDeterministic: with control characters in several headers,
// the reported header must not depend on map iteration order.
func TestHeaderCtlDeterministic(t *testing.T) {
	r := &model.Request{Method: "GET", RawPath: "/a", Header: http.Header{
		"Z-Last": {"a\nb"}, "M-Mid": {"a\rb"}, "A-First": {"a\x00b"},
	}}
	for range 200 {
		ms := Check(r, Config{})
		if len(ms) != 1 || ms[0].Field != "header.a-first" {
			t.Fatalf("got %+v, want only header.a-first", ms)
		}
	}
}

func TestCustomAllowedMethods(t *testing.T) {
	r := &model.Request{Method: "GET", RawPath: "/a"}
	if len(Check(r, Config{AllowedMethods: []string{"POST"}})) != 1 {
		t.Fatal("GET should be rejected when only POST allowed")
	}
}
