package engine

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

const sqlInMarkup = `<q>1' UNION SELECT password FROM users--</q>`

// postBody inspects a POST /x with the given Content-Type ("" sends none).
func postBody(e *Engine, ct, body string) model.Decision {
	h := http.Header{}
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	return e.Inspect(&model.Request{Method: "POST", RawPath: "/x", Header: h, Body: []byte(body)})
}

// allowing builds an engine whose content-type allow-list is mt alone.
func allowing(t *testing.T, mode model.Mode, mt string) *Engine {
	t.Helper()
	return newEngine(t, Options{Mode: mode, FailOpen: true, AllowedContentTypes: []string{mt}})
}

func hasMatch(d model.Decision, rule, field string) bool {
	return slices.ContainsFunc(d.Matches, func(m model.Match) bool { return m.RuleID == rule && m.Field == field })
}

func TestAllowedBodyTypesAreInspected(t *testing.T) {
	for _, tc := range []struct{ allowed, sent string }{
		{"application/xml", "application/xml"},
		{"application/xml", "Application/XML; charset=utf-8"},
		{"application/soap+xml", "application/soap+xml"},
		{"application/vnd.acme+xml", "application/vnd.acme+xml"},
		{"application/graphql", "application/graphql"},
		{"application/yaml", "application/yaml"},
		{"application/x-made-up", "application/x-made-up"},
	} {
		t.Run(tc.sent, func(t *testing.T) {
			d := postBody(allowing(t, model.ModeEnforce, tc.allowed), tc.sent, sqlInMarkup)
			if d.Action != model.ActionBlock || !hasMatch(d, "AEG-SQLI-001", "body") {
				t.Fatalf("want block with AEG-SQLI-001 on body: %+v", d)
			}
		})
	}
}

func TestXXERunsOnEveryAllowedXMLType(t *testing.T) {
	const body = `<!DOCTYPE a [<!ENTITY b SYSTEM "file:///etc/hostname">]><a>&b;</a>`
	for _, ct := range []string{"application/xml", "text/xml", "application/soap+xml"} {
		t.Run(ct, func(t *testing.T) {
			d := postBody(allowing(t, model.ModeMonitor, ct), ct, body)
			if !hasMatch(d, "AEG-XXE-001", "body") {
				t.Fatalf("want AEG-XXE-001 on body: %+v", d)
			}
		})
	}
}

func TestBinaryBodyTypesAreSkipped(t *testing.T) {
	for _, ct := range []string{
		"image/png", "image/svg+xml", "audio/mpeg", "video/mp4", "font/woff2",
		"application/grpc", "application/grpc+proto",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/octet-stream", "application/pdf", "application/zip",
		"application/gzip", "application/x-gzip", "application/x-tar",
		"application/x-7z-compressed", "application/x-protobuf",
		"application/protobuf", "application/vnd.google.protobuf",
		"application/msgpack", "application/x-msgpack", "application/vnd.msgpack",
		"application/cbor", "application/wasm", "application/msword",
		"application/vnd.ms-excel", "application/vnd.ms-powerpoint",
	} {
		t.Run(ct, func(t *testing.T) {
			d := postBody(allowing(t, model.ModeEnforce, ct), ct, sqlInMarkup)
			if d.Action != model.ActionAllow || len(d.Matches) != 0 {
				t.Fatalf("want allow without matches: %+v", d)
			}
		})
	}
}

func TestLegitimateBodiesOnInspectedTypesPass(t *testing.T) {
	const order = `<order><sku>A-1</sku><qty>2</qty><note>Leave at the front desk, please.</note></order>`
	const prolog = `<?xml version="1.0"?>`
	for _, tc := range []struct{ ct, body string }{
		{"application/xml", prolog + order},
		{"application/soap+xml", prolog + `<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body>` +
			order + `</soap:Body></soap:Envelope>`},
		{"application/graphql", `query { products(first: 10) { id name price } }`},
		{"application/yaml", "name: demo\nitems:\n  - sku: A-1\n    qty: 2\n"},
	} {
		t.Run(tc.ct, func(t *testing.T) {
			d := postBody(allowing(t, model.ModeEnforce, tc.ct), tc.ct, tc.body)
			if d.Action != model.ActionAllow || len(d.Matches) != 0 {
				t.Fatalf("want allow without matches: %+v", d)
			}
		})
	}
}

func TestMissingContentTypeBodyIsInspectedWhenAllowed(t *testing.T) {
	// Monitor mode lets the refused (missing) type through to the body scan.
	e := newEngine(t, Options{Mode: model.ModeMonitor, FailOpen: true})
	d := postBody(e, "", sqlInMarkup)
	if !hasMatch(d, "AEG-SQLI-001", "body") || !hasMatch(d, "AEG-PROTO-002", "header.content-type") {
		t.Fatalf("want AEG-SQLI-001 on body and AEG-PROTO-002: %+v", d)
	}
}

func TestRefusedTypeStillBlocksBeforeBodyScan(t *testing.T) {
	e := newEngine(t, Options{Mode: model.ModeEnforce, FailOpen: true})
	d := postBody(e, "application/xml", sqlInMarkup)
	if d.Action != model.ActionBlock || len(d.Matches) != 1 || d.Matches[0].RuleID != "AEG-PROTO-002" {
		t.Fatalf("want AEG-PROTO-002 alone: %+v", d)
	}
}

const xmlDecl = `<?xml version="1.0"?>`

func TestXMLDeclarationIsNotReadAsMarkup(t *testing.T) {
	const order = `<order><sku>A-1</sku><qty>2</qty></order>`
	for _, tc := range []struct{ name, decl string }{
		{"version 1.0", xmlDecl},
		{"version 1.1", `<?xml version="1.1"?>`},
		{"byte order mark", "\ufeff" + xmlDecl},
		{"leading whitespace", " \t\r\n\v\f" + xmlDecl},
		{"byte order mark and whitespace", "\ufeff\r\n" + xmlDecl},
		{"single quotes", `<?xml version='1.0' encoding='utf-8' standalone='no'?>`},
		{"encoding", `<?xml version="1.0" encoding="UTF-8"?>` + "\n"},
		{"standalone", `<?xml version="1.0" standalone="yes"?>`},
		{"every attribute and a final blank", `<?xml version="1.0" encoding="ISO-8859-1" standalone="no" ?>` + "\n"},
		{"line breaks inside", "<?xml\r\n\tversion=\"1.0\"\n  encoding=\"windows-1252\"\n?>\n"},
		{"a quote style per attribute", `<?xml version="1.0" encoding='UTF-8'?>`},
		{"longest charset name", `<?xml version="1.0" encoding="a` + strings.Repeat("b", 39) + `"?>`},
	} {
		for _, ct := range []string{"application/xml", "text/xml", "application/soap+xml"} {
			t.Run(tc.name+" "+ct, func(t *testing.T) {
				d := postBody(allowing(t, model.ModeEnforce, ct), ct, tc.decl+order)
				if d.Action != model.ActionAllow || len(d.Matches) != 0 {
					t.Fatalf("want allow without matches: %+v", d)
				}
			})
		}
	}
}

// A value longer than MaxValueLen is read in windows, so the declaration can
// span several of them.
func TestXMLDeclarationAcrossWindows(t *testing.T) {
	lim := model.DefaultLimits()
	lim.MaxValueLen = 32
	e := newEngine(t, Options{Mode: model.ModeMonitor, FailOpen: true, Limits: lim, AllowXML: true})
	const decl = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`
	d := postBody(e, "application/xml", decl+`<order><sku>A-1</sku></order>`)
	if len(d.Matches) != 1 || d.Matches[0].RuleID != "AEG-PROTO-011" {
		t.Fatalf("want AEG-PROTO-011 alone: %+v", d)
	}
	d = postBody(e, "application/xml", decl+`<script>x()</script>`)
	if !hasMatch(d, "AEG-XSS-001", "body") {
		t.Fatalf("want AEG-XSS-001 after the declaration: %+v", d)
	}
}

func TestOnlyAWellFormedLeadingXMLDeclarationIsHidden(t *testing.T) {
	const (
		script = `<script>alert(1)</script>`
		sql    = `1' UNION SELECT password FROM users--`
		xxe    = `<!DOCTYPE a [<!ENTITY b SYSTEM "file:///etc/hostname">]><a>&b;</a>`
	)
	for _, tc := range []struct{ name, body, rule string }{
		{"extra attribute", `<?xml version="1.0" note="x"?><a/>`, "AEG-XSS-001"},
		{"extra attribute with markup", `<?xml version="1.0" note="` + script + `"?><a/>`, "AEG-XSS-001"},
		{"unterminated, then script", `<?xml version="1.0" ` + script, "AEG-XSS-001"},
		{"unterminated, then SQL", `<?xml version="1.0"` + sqlInMarkup, "AEG-SQLI-001"},
		{"second declaration", xmlDecl + xmlDecl + `<a/>`, "AEG-XSS-001"},
		{"second declaration, then script", xmlDecl + `<a/>` + xmlDecl + script, "AEG-XSS-001"},
		{"second declaration filled with script", xmlDecl + `<a><?xml x="` + script + `"?></a>`, "AEG-XSS-001"},
		{"declaration after an element", `<a/>` + xmlDecl, "AEG-XSS-001"},
		{"script after the declaration", xmlDecl + script, "AEG-XSS-001"},
		{"SQL in markup after the declaration", xmlDecl + sqlInMarkup, "AEG-SQLI-001"},
		{"bare SQL after the declaration", xmlDecl + sql, "AEG-SQLI-001"},
		{"XXE after the declaration", xmlDecl + xxe, "AEG-XXE-001"},
		{"XXE after a malformed declaration", `<?xml version="1.0" ` + xxe, "AEG-XXE-001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := postBody(allowing(t, model.ModeMonitor, "application/xml"), "application/xml", tc.body)
			if !hasMatch(d, tc.rule, "body") {
				t.Fatalf("want %s on body: %+v", tc.rule, d)
			}
			d = postBody(allowing(t, model.ModeEnforce, "application/xml"), "application/xml", tc.body)
			if d.Action != model.ActionBlock {
				t.Fatalf("want block: %+v", d)
			}
		})
	}
}

// Only the XML branch hides the declaration.
func TestXMLDeclarationIsReadOutsideXMLBodies(t *testing.T) {
	for _, ct := range []string{"text/plain", "application/x-made-up"} {
		d := postBody(allowing(t, model.ModeEnforce, ct), ct, xmlDecl+`<a/>`)
		if d.Action != model.ActionBlock || !hasMatch(d, "AEG-XSS-001", "body") {
			t.Fatalf("%s: want block with AEG-XSS-001: %+v", ct, d)
		}
	}
}

func TestXMLDeclarationLen(t *testing.T) {
	for _, decl := range []string{
		xmlDecl,
		`<?xml version='1.9'?>`,
		" \n" + xmlDecl,
		`<?xml version="1.0" encoding="x.y_z-1" standalone='yes' ?>`,
		`<?xml version="1.0" standalone="no"?>`,
	} {
		if got := xmlDeclarationLen(decl + `<a/>?>`); got != len(decl) {
			t.Errorf("%q: length %d, want %d", decl, got, len(decl))
		}
	}
	for _, v := range []string{
		"",
		`<a/>`,
		`<?xml?>`,
		`<?xml ?>`,
		`<?xmlversion="1.0"?>`,
		`<?XML version="1.0"?>`,
		`<?xml VERSION="1.0"?>`,
		`< ?xml version="1.0"?>`,
		`<?xml-stylesheet version="1.0"?>`,
		`<?xml version="2.0"?>`,
		`<?xml version="1."?>`,
		`<?xml version="1.00"?>`,
		`<?xml version=1.0?>`,
		`<?xml version = "1.0"?>`,
		`<?xml version="1.0'?>`,
		`<?xml version="1.0">`,
		`<?xml version="1.0"? >`,
		`<?xml version="1.0"`,
		`<?xml encoding="UTF-8"?>`,
		`<?xml encoding="UTF-8" version="1.0"?>`,
		`<?xml version="1.0"encoding="UTF-8"?>`,
		`<?xml version="1.0" standalone="yes" encoding="UTF-8"?>`,
		`<?xml version="1.0" encoding="UTF-8" encoding="UTF-8"?>`,
		`<?xml version="1.0" encoding=""?>`,
		`<?xml version="1.0" encoding="8859"?>`,
		`<?xml version="1.0" encoding="UTF 8"?>`,
		`<?xml version="1.0" encoding="UTF-8'?>`,
		`<?xml version="1.0" encoding="a` + strings.Repeat("b", 40) + `"?>`,
		`<?xml version="1.0" standalone="maybe"?>`,
		`<?xml version="1.0" standalone="YES"?>`,
		`<?xml version="1.0" other="x"?>`,
		`<?xml version="1.0" <?>`,
		"<?xml\fversion=\"1.0\"?>",
		"\u00a0" + xmlDecl,
		" \ufeff" + xmlDecl,
		"\ufeff\ufeff" + xmlDecl,
		`x` + xmlDecl,
		`<a/>` + xmlDecl,
	} {
		if got := xmlDeclarationLen(v); got != 0 {
			t.Errorf("%q: length %d, want 0", v, got)
		}
	}
}

// Whatever the input, the hidden prefix is one declaration made of harmless
// bytes: a single "<" that opens "<?xml" and a single ">" that ends it.
func FuzzXMLDeclarationLen(f *testing.F) {
	f.Add(xmlDecl + `<a/>`)
	f.Add("\ufeff <?xml version='1.1' encoding='UTF-8' standalone='yes' ?><a/>")
	f.Add(`<?xml version="1.0" note="<b>"?>`)
	f.Fuzz(func(t *testing.T, v string) {
		n := xmlDeclarationLen(v)
		if n == 0 {
			return
		}
		hidden := v[:n]
		rest := strings.TrimLeft(strings.TrimPrefix(hidden, "\ufeff"), " \t\n\v\f\r")
		if !strings.HasPrefix(rest, "<?xml") || !strings.HasSuffix(hidden, "?>") ||
			strings.Count(hidden, "<") != 1 || strings.Count(hidden, ">") != 1 ||
			strings.ContainsAny(hidden, "();&|$`\\/:{}[]%#!*,+") {
			t.Fatalf("hidden prefix %q", hidden)
		}
	})
}
