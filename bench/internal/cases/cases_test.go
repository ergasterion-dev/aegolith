package cases

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// line returns a valid attack line that tests then change.
func line() Line {
	return Line{
		Name:         "n",
		Category:     "sqli",
		Kind:         "attack",
		Method:       "GET",
		Path:         "/api/v1/products/search",
		Query:        [][]string{{"q", "1' OR '1'='1"}},
		Headers:      map[string]string{},
		Source:       "a",
		SourceCaseID: "a-1",
		Expected:     Attack,
	}
}

func mustCase(t *testing.T, l Line) Case {
	t.Helper()
	c, err := FromLine(l)
	if err != nil {
		t.Fatalf("FromLine: %v", err)
	}
	return c
}

func TestFromLineEncodesQueryLikeCurl(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		query [][]string
		raw   string
		want  string
	}{
		{name: "no query", want: ""},
		{name: "quotes and spaces", query: [][]string{{"q", "1' OR '1'='1"}}, want: "q=1%27%20OR%20%271%27%3D%271"},
		{name: "unreserved kept", query: [][]string{{"aZ09-._~", "aZ09-._~"}}, want: "aZ09-._~=aZ09-._~"},
		{name: "reserved and key", query: [][]string{{"q[$ne]", "a+b&c#d/e?f%"}}, want: "q%5B%24ne%5D=a%2Bb%26c%23d%2Fe%3Ff%25"},
		{name: "multi byte and control", query: [][]string{{"q", "é\r\n\x00"}}, want: "q=%C3%A9%0D%0A%00"},
		{name: "order and repeats kept", query: [][]string{{"b", "2"}, {"a", ""}, {"b", "1"}}, want: "b=2&a=&b=1"},
		{name: "raw query replaces pairs", query: [][]string{{"q", "x"}}, raw: "a=%zz&b=<>", want: "a=%zz&b=<>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			l := line()
			l.Query, l.RawQuery = tt.query, tt.raw
			if got := mustCase(t, l).RawQuery; got != tt.want {
				t.Errorf("RawQuery = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFromLineCarriesEveryField(t *testing.T) {
	t.Parallel()
	l := line()
	l.Method, l.ContentType, l.Body = "POST", "text/plain", "hello"
	l.Headers = map[string]string{"X-Note": "v"}
	l.Payload, l.Placement, l.Encoder = "p", "body", "plain"
	c := mustCase(t, l)

	want := Case{
		ID:        c.ID,
		Sources:   []SourceRef{{Source: "a", CaseID: "a-1"}},
		Category:  "sqli",
		Expected:  Attack,
		Payload:   "p",
		Placement: "body",
		Encoder:   "plain",
		Method:    "POST",
		Path:      "/api/v1/products/search",
		RawQuery:  "q=1%27%20OR%20%271%27%3D%271",
		Headers:   map[string]string{"X-Note": "v", "Content-Type": "text/plain"},
		Body:      []byte("hello"),
	}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("case = %#v\nwant %#v", c, want)
	}
	if len(c.ID) != 64 || strings.Trim(c.ID, "0123456789abcdef") != "" {
		t.Errorf("ID = %q, want 64 hex digits", c.ID)
	}
	if len(l.Headers) != 1 {
		t.Errorf("FromLine changed the line's headers: %v", l.Headers)
	}
}

func TestFromLineHeaderOverridesContentType(t *testing.T) {
	t.Parallel()
	l := line()
	l.ContentType = "text/plain"
	l.Headers = map[string]string{"content-type": "application/json"}
	c := mustCase(t, l)
	want := map[string]string{"content-type": "application/json"}
	if !reflect.DeepEqual(c.Headers, want) {
		t.Errorf("Headers = %v, want %v", c.Headers, want)
	}
}

func TestFromLineDecodesBodyBase64(t *testing.T) {
	t.Parallel()
	l := line()
	l.BodyBase64 = "/9j/AA=="
	c := mustCase(t, l)
	if want := []byte{0xff, 0xd8, 0xff, 0x00}; !bytes.Equal(c.Body, want) {
		t.Errorf("Body = %x, want %x", c.Body, want)
	}
}

func TestFromLineRejectsBadLines(t *testing.T) {
	t.Parallel()
	const secret = "s3cr3t-value"
	tests := []struct {
		name   string
		change func(*Line)
	}{
		{name: "empty name", change: func(l *Line) { l.Name = "" }},
		{name: "empty category", change: func(l *Line) { l.Category = "" }},
		{name: "empty method", change: func(l *Line) { l.Method = "" }},
		{name: "empty path", change: func(l *Line) { l.Path = "" }},
		{name: "relative path", change: func(l *Line) { l.Path = secret }},
		{name: "query in path", change: func(l *Line) { l.Path = "/a?q=" + secret }},
		{name: "query pair of 1", change: func(l *Line) { l.Query = [][]string{{secret}} }},
		{name: "query pair of 3", change: func(l *Line) { l.Query = [][]string{{"q", secret, "x"}} }},
		{name: "body and body_base64", change: func(l *Line) { l.Body, l.BodyBase64 = secret, "eA==" }},
		{name: "bad base64", change: func(l *Line) { l.BodyBase64 = "!!" + secret }},
		{name: "empty header name", change: func(l *Line) { l.Headers = map[string]string{"": secret} }},
		{name: "header names differ only by case", change: func(l *Line) { l.Headers = map[string]string{"X-A": secret, "x-a": "2"} }},
		{name: "empty source", change: func(l *Line) { l.Source = "" }},
		{name: "empty source case id", change: func(l *Line) { l.SourceCaseID = "" }},
		{name: "empty expected", change: func(l *Line) { l.Expected = "" }},
		{name: "unknown expected", change: func(l *Line) { l.Expected = "maybe" }},
		{name: "unknown placement", change: func(l *Line) { l.Placement = "cookie" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			l := line()
			tt.change(&l)
			_, err := FromLine(l)
			if err == nil {
				t.Fatal("accepted, want an error")
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error repeats a request value: %v", err)
			}
		})
	}
}

func TestFromLineAcceptsEveryExpectedAndPlacement(t *testing.T) {
	t.Parallel()
	for _, e := range []Expected{Attack, Legit, NearMiss} {
		for _, p := range []string{"", "path", "query", "header", "body", "json", "raw"} {
			l := line()
			l.Expected, l.Placement = e, p
			if _, err := FromLine(l); err != nil {
				t.Errorf("expected %q placement %q: %v", e, p, err)
			}
		}
	}
}

func TestIDIgnoresHeaderOrderAndNameCase(t *testing.T) {
	t.Parallel()
	a := line()
	a.Headers = map[string]string{"X-One": "1", "X-Two": "2", "X-Three": "3"}
	a.ContentType = "text/plain"
	b := line()
	b.Name, b.Source, b.SourceCaseID = "other", "b", "b-9"
	b.Headers = map[string]string{"x-three": "3", "CONTENT-TYPE": "text/plain", "x-TWO": "2", "x-one": "1"}

	want := mustCase(t, a).ID
	// Map iteration order is random, so repeat to cover several orders.
	for range 50 {
		if got := mustCase(t, a).ID; got != want {
			t.Fatalf("ID changed between runs: %s and %s", want, got)
		}
		if got := mustCase(t, b).ID; got != want {
			t.Fatalf("ID = %s, want %s", got, want)
		}
	}
}

func TestIDCoversEveryRequestPart(t *testing.T) {
	t.Parallel()
	base := func() Line {
		l := line()
		l.Path, l.Query, l.RawQuery = "/ab", nil, "c=1"
		l.Headers = map[string]string{"X-A": "1"}
		l.Body = "b"
		return l
	}
	tests := []struct {
		name   string
		change func(*Line)
	}{
		{name: "method", change: func(l *Line) { l.Method = "PUT" }},
		{name: "method case", change: func(l *Line) { l.Method = "get" }},
		{name: "path", change: func(l *Line) { l.Path = "/ac" }},
		{name: "raw query", change: func(l *Line) { l.RawQuery = "c=2" }},
		{name: "path and query boundary", change: func(l *Line) { l.Path, l.RawQuery = "/a", "bc=1" }},
		{name: "header name", change: func(l *Line) { l.Headers = map[string]string{"X-B": "1"} }},
		{name: "header value", change: func(l *Line) { l.Headers = map[string]string{"X-A": "2"} }},
		{name: "extra empty header", change: func(l *Line) { l.Headers = map[string]string{"X-A": "1", "X-C": ""} }},
		{name: "header name and value boundary", change: func(l *Line) { l.Headers = map[string]string{"X-A1": ""} }},
		{name: "body", change: func(l *Line) { l.Body = "c" }},
		{name: "header moved into body", change: func(l *Line) { l.Headers, l.Body = nil, "x-a1b" }},
	}
	want := mustCase(t, base()).ID
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			l := base()
			tt.change(&l)
			if got := mustCase(t, l).ID; got == want {
				t.Errorf("ID unchanged")
			}
		})
	}
}

// Header names are case-insensitive in ASCII only. Unicode folding would give
// different requests one ID and merge them.
func TestIDKeepsNonASCIIHeaderNamesApart(t *testing.T) {
	t.Parallel()
	pairs := map[string][2]string{
		"invalid bytes":       {"X-\xff", "X-\xfe"},
		"kelvin sign and k":   {"X-K", "X-k"},
		"upper and lower e":   {"X-É", "X-é"},
		"dotted capital i, i": {"X-İ", "X-i"},
	}
	for name, p := range pairs {
		a, b := line(), line()
		a.Headers = map[string]string{p[0]: "v"}
		b.Headers = map[string]string{p[1]: "v"}
		if mustCase(t, a).ID == mustCase(t, b).ID {
			t.Errorf("%s: same ID", name)
		}
		both := line()
		both.Headers = map[string]string{p[0]: "v", p[1]: "w"}
		if _, err := FromLine(both); err != nil {
			t.Errorf("%s: two different names rejected: %v", name, err)
		}
	}
}

func TestMergeCreditsEverySource(t *testing.T) {
	t.Parallel()
	a := line()
	b := line()
	b.Source, b.SourceCaseID = "b", "b-1"
	other := line()
	other.Path, other.SourceCaseID = "/other", "a-2"

	merged, conflicts := Merge([]Case{mustCase(t, a), mustCase(t, other), mustCase(t, b)})
	if len(conflicts) != 0 {
		t.Fatalf("conflicts = %v, want none", conflicts)
	}
	if len(merged) != 2 {
		t.Fatalf("merged %d cases, want 2", len(merged))
	}
	want := []SourceRef{{Source: "a", CaseID: "a-1"}, {Source: "b", CaseID: "b-1"}}
	if !reflect.DeepEqual(merged[0].Sources, want) {
		t.Errorf("Sources = %v, want %v", merged[0].Sources, want)
	}
	if merged[1].Path != "/other" {
		t.Errorf("first-appearance order lost: second case path = %q", merged[1].Path)
	}
}

func TestMergeExcludesConflicts(t *testing.T) {
	t.Parallel()
	for _, other := range []Expected{Legit, NearMiss} {
		t.Run(string(other), func(t *testing.T) {
			t.Parallel()
			attack := line()
			same := line()
			same.Source, same.SourceCaseID = "b", "b-1"
			third := line()
			third.Source, third.SourceCaseID = "c", "c-1"
			disagreeing := line()
			disagreeing.Source, disagreeing.SourceCaseID, disagreeing.Expected = "d", "d-1", other
			clean := line()
			clean.Path = "/clean"

			merged, conflicts := Merge([]Case{
				mustCase(t, attack), mustCase(t, disagreeing), mustCase(t, clean), mustCase(t, same), mustCase(t, third),
			})
			if len(merged) != 1 || merged[0].Path != "/clean" {
				t.Fatalf("merged = %v, want only the clean case", merged)
			}
			if len(conflicts) != 4 {
				t.Fatalf("%d conflicts, want every disagreeing input (4)", len(conflicts))
			}
			got := map[string]Expected{}
			for _, c := range conflicts {
				got[c.Sources[0].Source] = c.Expected
			}
			want := map[string]Expected{"a": Attack, "b": Attack, "c": Attack, "d": other}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("conflicts = %v, want %v", got, want)
			}
		})
	}
}

// The held-out split hashes the payload, so the merged case must not depend
// on the order the sources were read in.
func TestMergeIsIndependentOfSourceOrder(t *testing.T) {
	t.Parallel()
	bare := line()
	bare.Source, bare.SourceCaseID, bare.Category = "baseline", "z", "misc"
	first := line()
	first.Source, first.SourceCaseID = "crs", "1"
	first.Payload, first.Placement, first.Encoder = "p-crs", "query", "plain"
	second := line()
	second.Source, second.SourceCaseID, second.Category = "gotestwaf", "2", "xss"
	second.Payload, second.Placement, second.Encoder = "p-gtw", "raw", "url"
	a, b, c := mustCase(t, bare), mustCase(t, first), mustCase(t, second)

	var want Case
	for i, in := range [][]Case{{a, b, c}, {c, b, a}, {b, a, c}, {c, a, b, a, c}} {
		merged, conflicts := Merge(in)
		if len(merged) != 1 || len(conflicts) != 0 {
			t.Fatalf("order %d: merged %d, conflicts %d", i, len(merged), len(conflicts))
		}
		if i == 0 {
			want = merged[0]
			continue
		}
		if !reflect.DeepEqual(merged[0], want) {
			t.Errorf("order %d: %#v\nwant %#v", i, merged[0], want)
		}
	}
	if want.Payload != "p-crs" || want.Placement != "query" || want.Encoder != "plain" || want.Category != "sqli" {
		t.Errorf("metadata not taken from the first source with a payload: %#v", want)
	}
	if len(want.Sources) != 3 {
		t.Errorf("Sources = %v, want 3 distinct", want.Sources)
	}
}

func TestMergeLeavesInputAlone(t *testing.T) {
	t.Parallel()
	a := mustCase(t, line())
	b := a
	b.Sources = []SourceRef{{Source: "b", CaseID: "b-1"}}
	// Spare capacity would let an append write into the caller's array.
	a.Sources = append(make([]SourceRef, 0, 4), a.Sources...)
	in := []Case{b, a}
	Merge(in)
	if len(in[0].Sources) != 1 || in[0].Sources[0].Source != "b" || in[1].Sources[0].Source != "a" {
		t.Errorf("input sources changed: %v %v", in[0].Sources, in[1].Sources)
	}
	if spare := a.Sources[:2][1]; spare != (SourceRef{}) {
		t.Errorf("wrote into the input's spare capacity: %v", spare)
	}
}

func TestSplitStableAndProportional(t *testing.T) {
	t.Parallel()
	third := []SourceRef{{Source: "crs", CaseID: "1"}}

	held := 0
	for i := range 10000 {
		p := fmt.Sprintf("p%d", i)
		a := Split(Case{ID: "id-a", Payload: p, Sources: third})
		b := Split(Case{ID: "id-b", Payload: p, Sources: third})
		if a != b {
			t.Fatalf("payload %s: split depends on the ID: %q and %q", p, a, b)
		}
		switch a {
		case SplitHeldOut:
			held++
		case SplitDev:
		default:
			t.Fatalf("payload %s: split %q", p, a)
		}
	}
	if held < 2800 || held > 3200 {
		t.Errorf("held-out = %d of 10000, want 2800..3200", held)
	}
}

func TestSplitUsesIDWithoutPayload(t *testing.T) {
	t.Parallel()
	third := []SourceRef{{Source: "crs", CaseID: "1"}}
	for i := range 200 {
		id := fmt.Sprintf("id%d", i)
		withID := Split(Case{ID: id, Sources: third})
		asPayload := Split(Case{ID: "unused", Payload: id, Sources: third})
		if withID != asPayload {
			t.Fatalf("%s: split without payload = %q, hashing the ID gives %q", id, withID, asPayload)
		}
	}
}

// Pins the hash rule itself, so the assignment cannot move between versions.
func TestSplitKnownAssignments(t *testing.T) {
	t.Parallel()
	third := []SourceRef{{Source: "crs", CaseID: "1"}}
	// First eight bytes of SHA-256, big endian, modulo 100, computed with an
	// independent tool: the two sides of the 30% boundary and one far from it.
	tests := map[string]string{"p20": SplitHeldOut, "p7": SplitDev, "p1": SplitDev} // 29, 30, 87
	for payload, want := range tests {
		if got := Split(Case{Payload: payload, Sources: third}); got != want {
			t.Errorf("%s: %q, want %q", payload, got, want)
		}
	}
}

func TestSplitBaseline(t *testing.T) {
	t.Parallel()
	base := SourceRef{Source: SourceBaseline, CaseID: "1"}
	other := SourceRef{Source: "crs", CaseID: "2"}
	if got := Split(Case{Payload: "p0", Sources: []SourceRef{base, base}}); got != SplitBaseline {
		t.Errorf("baseline only: %q", got)
	}
	if got := Split(Case{Payload: "p0", Sources: []SourceRef{base, other}}); got != SplitHeldOut {
		t.Errorf("baseline and another source: %q, want %q", got, SplitHeldOut)
	}
	if got := Split(Case{Payload: "p0"}); got != SplitHeldOut {
		t.Errorf("no source: %q, want %q", got, SplitHeldOut)
	}
}

const validJSON = `{"name":"n","category":"c","kind":"legit","method":"GET","path":"/a","query":[["q","v"]],"headers":{},"content_type":"","body":"","source":"s","source_case_id":"1","expected":"legit","payload":"","placement":"query","encoder":""}`

func TestReadLinesRejectsUnknownKeysAndTrailingData(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"unknown key":    strings.Replace(validJSON, `"name"`, `"extra":1,"name"`, 1),
		"trailing data":  validJSON + ` {}`,
		"trailing brace": validJSON + `}`,
		"trailing text":  validJSON + ` x`,
		"truncated":      validJSON[:len(validJSON)/2],
		"blank line":     "",
		"null":           "null",
		"array":          "[]",
		"invalid utf-8":  strings.Replace(validJSON, `"n"`, "\"\xff\"", 1),
	}
	for name, bad := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ReadLines(strings.NewReader(validJSON + "\n" + bad + "\n" + validJSON + "\n"))
			if err == nil {
				t.Fatal("accepted, want an error")
			}
			if !strings.Contains(err.Error(), "line 2") {
				t.Errorf("error does not name line 2: %v", err)
			}
		})
	}
}

func TestReadLinesAcceptsLineEndings(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		in   string
		want int
	}{
		"empty input":       {in: "", want: 0},
		"final newline":     {in: validJSON + "\n", want: 1},
		"no final newline":  {in: validJSON + "\n" + validJSON, want: 2},
		"carriage returns":  {in: validJSON + "\r\n" + validJSON + "\r\n", want: 2},
		"longer than 64KiB": {in: strings.Replace(validJSON, `"body":""`, `"body":"`+strings.Repeat("a", 1<<20)+`"`, 1), want: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := ReadLines(strings.NewReader(tt.in))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tt.want {
				t.Errorf("%d lines, want %d", len(got), tt.want)
			}
		})
	}
}

func TestReadLinesRejectsOversizeLine(t *testing.T) {
	t.Parallel()
	long := strings.Replace(validJSON, `"body":""`, `"body":"`+strings.Repeat("a", maxLineBytes)+`"`, 1)
	if _, err := ReadLines(strings.NewReader(long)); err == nil {
		t.Fatal("accepted, want an error")
	}
}

func TestWriteLinesRoundTrip(t *testing.T) {
	t.Parallel()
	full := Line{
		Name: "n", Category: "c", Kind: "attack", Method: "POST", Path: "/a%2Fb",
		Query: [][]string{{"q", "<a & b>\x00\n"}}, RawQuery: "q=%zz",
		Headers: map[string]string{"X-A": "é"}, ContentType: "text/plain",
		BodyBase64: "/9j/AA==", Source: "s", SourceCaseID: "1", Expected: Attack,
		Payload: "<script>", Placement: "raw", Encoder: "plain",
	}
	empty := line()
	empty.Query, empty.Headers = nil, nil

	var buf bytes.Buffer
	if err := WriteLines(&buf, []Line{full, empty}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if n := strings.Count(out, "\n"); n != 2 {
		t.Errorf("%d newlines, want one per line", n)
	}
	for _, key := range []string{`"content_type":`, `"source_case_id":`, `"raw_query":`, `"body_base64":`, `"expected":"attack"`, `"query":[]`, `"headers":{}`, `<script>`} {
		if !strings.Contains(out, key) {
			t.Errorf("output lacks %s", key)
		}
	}
	got, err := ReadLines(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	empty.Query, empty.Headers = [][]string{}, map[string]string{}
	if want := []Line{full, empty}; !reflect.DeepEqual(got, want) {
		t.Errorf("round trip = %#v\nwant %#v", got, want)
	}
}

// encoding/json would silently turn invalid bytes into U+FFFD, which would
// send a different request from the one the source describes.
func TestWriteLinesRejectsInvalidUTF8(t *testing.T) {
	t.Parallel()
	const bad = "a\xffb"
	tests := map[string]func(*Line){
		"name":           func(l *Line) { l.Name = bad },
		"category":       func(l *Line) { l.Category = bad },
		"kind":           func(l *Line) { l.Kind = bad },
		"method":         func(l *Line) { l.Method = bad },
		"path":           func(l *Line) { l.Path = "/" + bad },
		"query key":      func(l *Line) { l.Query = [][]string{{bad, "v"}} },
		"query value":    func(l *Line) { l.Query = [][]string{{"q", bad}} },
		"raw query":      func(l *Line) { l.RawQuery = bad },
		"header name":    func(l *Line) { l.Headers = map[string]string{bad: "v"} },
		"header value":   func(l *Line) { l.Headers = map[string]string{"X": bad} },
		"content type":   func(l *Line) { l.ContentType = bad },
		"body":           func(l *Line) { l.Body = bad },
		"body base64":    func(l *Line) { l.BodyBase64 = bad },
		"source":         func(l *Line) { l.Source = bad },
		"source case id": func(l *Line) { l.SourceCaseID = bad },
		"expected":       func(l *Line) { l.Expected = Expected(bad) },
		"payload":        func(l *Line) { l.Payload = bad },
		"placement":      func(l *Line) { l.Placement = bad },
		"encoder":        func(l *Line) { l.Encoder = bad },
	}
	// A new string field must be added to the table and to the check.
	if fields := reflect.TypeFor[Line]().NumField(); len(tests) != fields+2 {
		t.Fatalf("%d table entries for %d fields", len(tests), fields)
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			l := line()
			change(&l)
			var buf bytes.Buffer
			if err := WriteLines(&buf, []Line{line(), l}); err == nil {
				t.Fatal("accepted, want an error")
			} else if strings.Contains(err.Error(), bad) {
				t.Errorf("error repeats a request value: %v", err)
			}
		})
	}
}

func TestWriteLinesRejectsLineReadLinesCannotRead(t *testing.T) {
	t.Parallel()
	l := line()
	l.Body = strings.Repeat("a", maxLineBytes)
	var buf bytes.Buffer
	if err := WriteLines(&buf, []Line{l}); err == nil {
		t.Fatal("accepted, want an error")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("disk full") }

func TestWriteLinesReportsWriteErrors(t *testing.T) {
	t.Parallel()
	if err := WriteLines(failingWriter{}, []Line{line()}); err == nil {
		t.Fatal("want the writer's error")
	}
}
