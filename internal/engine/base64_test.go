package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/internal/model"
	"github.com/ergasterion-dev/aegolith/internal/policy"
)

const sqlAttack = `1' UNION SELECT password FROM users--`

// dataLocations are the places a client can send the value "data", each with
// the field name a match on it carries.
var dataLocations = []struct {
	name, field string
	request     func(t *testing.T, v string) *model.Request
}{
	{"path", "path.data", func(_ *testing.T, v string) *model.Request {
		return &model.Request{Method: "GET", RawPath: "/p/" + url.PathEscape(v), Header: http.Header{}}
	}},
	{"query", "query.data", func(_ *testing.T, v string) *model.Request {
		return &model.Request{Method: "POST", RawPath: "/x", RawQuery: url.Values{"data": {v}}.Encode(), Header: http.Header{}}
	}},
	{"json", "body.data", func(t *testing.T, v string) *model.Request {
		b, err := json.Marshal(map[string]string{"data": v})
		if err != nil {
			t.Fatal(err)
		}
		return post("application/json", b)
	}},
	{"form", "form.data", func(_ *testing.T, v string) *model.Request {
		return post("application/x-www-form-urlencoded", []byte(url.Values{"data": {v}}.Encode()))
	}},
	{"multipart", "form.data", func(t *testing.T, v string) *model.Request {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		if err := w.WriteField("data", v); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return post(w.FormDataContentType(), b.Bytes())
	}},
}

func post(ct string, body []byte) *model.Request {
	return &model.Request{Method: "POST", RawPath: "/x", Header: http.Header{"Content-Type": {ct}}, Body: body}
}

// dataEngine declares "data" as typ in every location.
func dataEngine(t *testing.T, mode model.Mode, typ string, excl ...Exclusion) *Engine {
	t.Helper()
	spec := map[string]policy.FieldSpec{"data": {Type: typ}}
	return newEngine(t, Options{
		Mode: mode, FailOpen: true, UnknownRoute: model.ActionMonitor, UnknownFields: model.ActionMonitor,
		Exclusions: excl,
		Routes: []policy.Route{
			{Method: "POST", Path: "/x", Query: spec, Body: spec},
			{Method: "GET", Path: "/p/:data", PathParams: spec},
		},
	})
}

// base64Types are the two base64 field types, each with the encodings its
// alphabet has and values that only the other alphabet, or neither, reads.
var base64Types = []struct {
	typ             string
	padded, raw     *base64.Encoding
	foreign, unread []string
}{
	{policy.TypeBase64, base64.StdEncoding, base64.RawStdEncoding,
		[]string{"-_8", "aGVs-A", "aGVs_A"}, []string{"not base64!!", "aGVs bG8=", "+_8", "aGVsbG8=="}},
	{policy.TypeBase64URL, base64.URLEncoding, base64.RawURLEncoding,
		[]string{"+/8=", "aGVs+A", "aGVs/A"}, []string{"not base64!!", "aGVs bG8=", "+_8", "aGVsbG8=="}},
}

func TestBase64FieldIsDecodedAndScanned(t *testing.T) {
	for _, bt := range base64Types {
		e := dataEngine(t, model.ModeEnforce, bt.typ)
		for name, enc := range map[string]*base64.Encoding{"padded": bt.padded, "unpadded": bt.raw} {
			encoded := enc.EncodeToString([]byte(sqlAttack))
			for _, loc := range dataLocations {
				t.Run(bt.typ+"/"+name+"/"+loc.name, func(t *testing.T) {
					d := e.Inspect(loc.request(t, encoded))
					if d.Action != model.ActionBlock || !hasMatch(d, "AEG-SQLI-001", loc.field) {
						t.Fatalf("want block with AEG-SQLI-001 on %s: %+v", loc.field, d)
					}
				})
			}
		}
	}
}

func TestBase64FieldLegitimateText(t *testing.T) {
	notes := []string{
		"Leave at the desk.\nCall first, thanks.",
		// Encodes to bytes where the two alphabets differ.
		"Café menu — où? >>> 3 items ~ merci ÿÿ",
	}
	if s := base64.StdEncoding.EncodeToString([]byte(notes[1])); !strings.ContainsAny(s, "+/") {
		t.Fatalf("the second note does not tell the alphabets apart: %s", s)
	}
	for _, bt := range base64Types {
		e := dataEngine(t, model.ModeEnforce, bt.typ)
		for name, enc := range map[string]*base64.Encoding{"padded": bt.padded, "unpadded": bt.raw} {
			for _, note := range notes {
				for _, loc := range dataLocations {
					t.Run(bt.typ+"/"+name+"/"+loc.name, func(t *testing.T) {
						d := e.Inspect(loc.request(t, enc.EncodeToString([]byte(note))))
						if d.Action != model.ActionAllow || len(d.Matches) != 0 {
							t.Fatalf("want allow without matches: %+v", d)
						}
					})
				}
			}
		}
	}
}

func TestBase64FieldInvalidValue(t *testing.T) {
	for _, bt := range base64Types {
		e := dataEngine(t, model.ModeEnforce, bt.typ)
		for _, v := range slices.Concat(bt.unread, bt.foreign) {
			for _, loc := range dataLocations {
				t.Run(bt.typ+"/"+loc.name, func(t *testing.T) {
					d := e.Inspect(loc.request(t, v))
					if d.Action != model.ActionBlock || !hasMatch(d, "AEG-SCHEMA-001", loc.field) {
						t.Fatalf("%q: want block with AEG-SCHEMA-001 on %s: %+v", v, loc.field, d)
					}
				})
			}
		}
		for _, body := range []string{`{"data":1234}`, `{"data":true}`, `{"data":["aGVs"]}`} {
			d := e.Inspect(post("application/json", []byte(body)))
			if d.Action != model.ActionBlock || len(d.Matches) != 1 || d.Matches[0].RuleID != "AEG-SCHEMA-001" {
				t.Errorf("%s %s: want AEG-SCHEMA-001: %+v", bt.typ, body, d)
			}
		}
		// A null is an absent optional field, as for every type.
		if d := e.Inspect(post("application/json", []byte(`{"data":null}`))); len(d.Matches) != 0 {
			t.Errorf("%s null: %+v", bt.typ, d)
		}
	}
	// An unencoded '+' in a query string or form body means a space.
	e := dataEngine(t, model.ModeEnforce, policy.TypeBase64)
	for _, r := range []*model.Request{
		{Method: "POST", RawPath: "/x", RawQuery: "data=+/8=", Header: http.Header{}},
		post("application/x-www-form-urlencoded", []byte("data=+/8=")),
	} {
		if d := e.Inspect(r); d.Action != model.ActionBlock || len(d.Matches) != 1 || d.Matches[0].RuleID != "AEG-SCHEMA-001" {
			t.Errorf("unencoded '+': want AEG-SCHEMA-001: %+v", d)
		}
	}
}

// A standard-alphabet decoder that skips unknown bytes (Python's b64decode
// by default, Ruby's decode64) drops '-' and '_'. A base64 field must refuse
// them, or such a handler reads text the detectors never saw.
func TestBase64RefusesURLSafeBytesThatALenientDecoderDrops(t *testing.T) {
	const text = sqlAttack + "  " // two blanks: the encoding needs no '='
	std := base64.StdEncoding.EncodeToString([]byte(text))
	v := std[:1] + "_" + std[1:] + "___"
	lenient, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(v, "_", ""))
	if err != nil || string(lenient) != text || strings.ContainsAny(v, "+/=") {
		t.Fatalf("the value does not hide the attack: %q reads as %q, %v", v, lenient, err)
	}
	e := dataEngine(t, model.ModeEnforce, policy.TypeBase64)
	for _, loc := range dataLocations {
		t.Run(loc.name, func(t *testing.T) {
			d := e.Inspect(loc.request(t, v))
			if d.Action != model.ActionBlock || !hasMatch(d, "AEG-SCHEMA-001", loc.field) {
				t.Fatalf("want block with AEG-SCHEMA-001 on %s: %+v", loc.field, d)
			}
		})
	}
}

func TestStringFieldIsNotDecoded(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(sqlAttack))
	for _, typ := range []string{policy.TypeText, policy.TypeString} {
		e := dataEngine(t, model.ModeEnforce, typ)
		for _, loc := range dataLocations {
			t.Run(typ+"/"+loc.name, func(t *testing.T) {
				d := e.Inspect(loc.request(t, encoded))
				if d.Action != model.ActionAllow || len(d.Matches) != 0 {
					t.Fatalf("want allow without matches: %+v", d)
				}
			})
		}
	}
}

func TestBase64ExclusionApplies(t *testing.T) {
	for _, bt := range base64Types {
		t.Run(bt.typ, func(t *testing.T) {
			e := dataEngine(t, model.ModeEnforce, bt.typ,
				Exclusion{Rule: "AEG-SQLI-*", Route: "POST /x", Field: "body.data"})
			encoded := bt.padded.EncodeToString([]byte(sqlAttack))
			d := e.Inspect(dataLocations[2].request(t, encoded))
			if d.Action != model.ActionAllow || len(d.Matches) != 0 {
				t.Fatalf("want allow without matches: %+v", d)
			}
			// The exclusion names one field: the same value elsewhere
			// still blocks.
			if d := e.Inspect(dataLocations[1].request(t, encoded)); d.Action != model.ActionBlock {
				t.Fatalf("query.data: want block: %+v", d)
			}
		})
	}
}

// TestBase64FieldJudgedLikeText holds the invariant of both types: in every
// location, the matches on a base64 or base64url field are those on a text
// field that was sent the decoded value.
func TestBase64FieldJudgedLikeText(t *testing.T) {
	type verdict struct {
		rule   string
		loc    model.Location
		action model.Action
	}
	on := func(d model.Decision, field string) []verdict {
		var out []verdict
		for _, m := range d.Matches {
			if m.Field == field {
				out = append(out, verdict{m.RuleID, m.Location, m.Action})
			}
		}
		return out
	}
	text := dataEngine(t, model.ModeMonitor, policy.TypeText)
	enforceText := dataEngine(t, model.ModeEnforce, policy.TypeText)
	seen := map[string]bool{} // rules the text side raised, over all cases
	values := map[string]string{
		"sql":                sqlAttack,
		"markup":             `<script>alert(document.cookie)</script>`,
		"command line":       "notes\ncat /etc/passwd",
		"command after a LF": "report\nwhoami",
		"bare line":          "Notes:\nls",
		"percent-encoded":    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
		"metadata URL":       "http://169.254.169.254/latest/meta-data/",
		"session id":         "see ?JSESSIONID=0a1b2c3d4e5f",
		"session and sql":    "PHPSESSID=abc123' UNION SELECT password FROM users--",
		"late session id":    strings.Repeat("a ", 5000) + "PHPSESSID=abc123",
		"over max_value_len": strings.Repeat("a ", 6000) + sqlAttack,
		"plain note":         "Leave at the desk.\nCall first, thanks.",
		"empty":              "",
	}
	for _, bt := range base64Types {
		b64 := dataEngine(t, model.ModeMonitor, bt.typ)
		enforceB64 := dataEngine(t, model.ModeEnforce, bt.typ)
		for name, v := range values {
			for _, loc := range dataLocations {
				t.Run(bt.typ+"/"+name+"/"+loc.name, func(t *testing.T) {
					encoded := bt.raw.EncodeToString([]byte(v))
					if loc.name == "path" && v == "" {
						t.Skip("an empty path segment does not match the route")
					}
					want := on(text.Inspect(loc.request(t, v)), loc.field)
					for _, w := range want {
						seen[w.rule] = true
					}
					if got := on(b64.Inspect(loc.request(t, encoded)), loc.field); !slices.Equal(got, want) {
						t.Errorf("monitor: base64 %+v, text %+v", got, want)
					}
					// Enforce stops at the first blocking match, so order counts.
					// A line break or double encoding in the path is refused by
					// protocol before the field is read, on the text side only.
					if loc.name == "path" && strings.ContainsAny(v, "\n%") {
						return
					}
					want = on(enforceText.Inspect(loc.request(t, v)), loc.field)
					if got := on(enforceB64.Inspect(loc.request(t, encoded)), loc.field); !slices.Equal(got, want) {
						t.Errorf("enforce: base64 %+v, text %+v", got, want)
					}
				})
			}
		}
	}
	// Equal empty results would prove nothing.
	for _, rule := range []string{
		"AEG-SQLI-001", "AEG-XSS-001", "AEG-CMDI-001", "AEG-SSRF-001", "AEG-SESSION-001", "AEG-PROTO-011",
	} {
		if !seen[rule] {
			t.Errorf("no case raised %s on a text field", rule)
		}
	}
}
