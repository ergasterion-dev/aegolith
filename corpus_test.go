package aegolith_test

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith"
)

// corpusCase is one line of testdata/corpus/attacks.jsonl or legit.jsonl.
// BodyBase64, when set, replaces Body (for binary parts such as a JPEG in
// a multipart upload, which a JSON string cannot carry byte for byte).
type corpusCase struct {
	Name        string            `json:"name"`
	Category    string            `json:"category"`
	Kind        string            `json:"kind"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Query       [][]string        `json:"query"`
	Headers     map[string]string `json:"headers"`
	ContentType string            `json:"content_type"`
	Body        string            `json:"body"`
	BodyBase64  string            `json:"body_base64,omitempty"`
}

// The gates of spec 9.1.
const (
	corpusAttacks      = 187
	gateGenericBlocked = 183
	gateAPIBlocked     = 184
	corpusMinLegit     = 32 + 20
)

func loadCorpus(t testing.TB, file, kind string) []corpusCase {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "corpus", file))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []corpusCase
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		c, err := parseCorpusLine(sc.Text(), kind)
		if err != nil {
			t.Fatalf("%s:%d: %v", file, n, err)
		}
		out = append(out, c)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// parseCorpusLine decodes and validates one corpus line of the given kind:
// no unknown keys or trailing data, every query entry a [key, value] pair,
// and at most one of body and body_base64 (which must decode).
func parseCorpusLine(line, kind string) (corpusCase, error) {
	var c corpusCase
	dec := json.NewDecoder(strings.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return c, errors.New("trailing data after the JSON object")
	}
	if c.Kind != kind || c.Name == "" || c.Category == "" || c.Method == "" || !strings.HasPrefix(c.Path, "/") {
		return c, fmt.Errorf("bad case %+v", c)
	}
	for _, kv := range c.Query {
		if len(kv) != 2 {
			return c, fmt.Errorf("%q: query entry %q is not a [key, value] pair", c.Name, kv)
		}
	}
	if c.BodyBase64 != "" {
		if c.Body != "" {
			return c, fmt.Errorf("%q: both body and body_base64 are set", c.Name)
		}
		if _, err := base64.StdEncoding.DecodeString(c.BodyBase64); err != nil {
			return c, fmt.Errorf("%q: body_base64: %v", c.Name, err)
		}
	}
	return c, nil
}

// curlEscape percent-encodes s the way curl --data-urlencode does: every
// byte except ALPHA / DIGIT / "-" / "." / "_" / "~".
func curlEscape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

func (c corpusCase) request(t testing.TB) *aegolith.Request {
	t.Helper()
	pairs := make([]string, 0, len(c.Query))
	for _, kv := range c.Query {
		pairs = append(pairs, curlEscape(kv[0])+"="+curlEscape(kv[1]))
	}
	h := http.Header{}
	if c.ContentType != "" {
		h.Set("Content-Type", c.ContentType)
	}
	for k, v := range c.Headers {
		h.Set(k, v)
	}
	body := []byte(c.Body)
	if c.BodyBase64 != "" {
		b, err := base64.StdEncoding.DecodeString(c.BodyBase64)
		if err != nil {
			t.Fatalf("%s: body_base64: %v", c.Name, err)
		}
		body = b
	}
	return &aegolith.Request{
		Method:     c.Method,
		RawPath:    c.Path,
		RawQuery:   strings.Join(pairs, "&"),
		RemoteAddr: "192.0.2.10:40000",
		Header:     h,
		Body:       body,
	}
}

func corpusMatches(d aegolith.Decision) string {
	ids := make([]string, 0, len(d.Matches))
	for _, m := range d.Matches {
		ids = append(ids, fmt.Sprintf("%s(%s,%s)", m.RuleID, m.Field, m.Action))
	}
	return strings.Join(ids, " ")
}

// runCorpus inspects every case with fw, logs a per-category table and the
// misses and false positives, and fails when fewer than minBlocked attacks
// are blocked or any legitimate request is. With policy set, a legitimate
// request must also fit the policy: no route or schema match even in
// monitor.
func runCorpus(t *testing.T, fw *aegolith.Firewall, minBlocked int, policy bool) {
	t.Helper()
	attacks := loadCorpus(t, "attacks.jsonl", "attack")
	legit := loadCorpus(t, "legit.jsonl", "legit")
	if len(attacks) != corpusAttacks {
		t.Fatalf("attacks.jsonl has %d cases, want %d", len(attacks), corpusAttacks)
	}
	if len(legit) < corpusMinLegit {
		t.Fatalf("legit.jsonl has %d cases, want >= %d", len(legit), corpusMinLegit)
	}

	type row struct{ total, blocked int }
	cats := map[string]*row{}
	var order []string
	blocked := 0
	var misses []string
	for _, c := range attacks {
		r := cats[c.Category]
		if r == nil {
			r = &row{}
			cats[c.Category] = r
			order = append(order, c.Category)
		}
		r.total++
		d := fw.Inspect(c.request(t))
		if d.Err != nil {
			t.Errorf("attack %q: internal error %v", c.Name, d.Err)
		}
		if d.Action == aegolith.ActionBlock {
			r.blocked++
			blocked++
			continue
		}
		misses = append(misses, fmt.Sprintf("%s/%s [%s]", c.Category, c.Name, corpusMatches(d)))
	}

	var fps, monitored []string
	for _, c := range legit {
		d := fw.Inspect(c.request(t))
		if d.Err != nil {
			t.Errorf("legit %q: internal error %v", c.Name, d.Err)
		}
		if d.Action == aegolith.ActionBlock {
			fps = append(fps, fmt.Sprintf("%s [%s]", c.Name, corpusMatches(d)))
		} else if len(d.Matches) > 0 {
			monitored = append(monitored, fmt.Sprintf("%s [%s]", c.Name, corpusMatches(d)))
		}
		if policy {
			for _, m := range d.Matches {
				if m.Category == aegolith.CatSchema || m.Category == aegolith.CatRoute {
					t.Errorf("legit %q does not fit the policy: %s", c.Name, corpusMatches(d))
					break
				}
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\n%-10s %7s %5s\n", "category", "blocked", "total")
	for _, k := range order {
		fmt.Fprintf(&b, "%-10s %7d %5d\n", k, cats[k].blocked, cats[k].total)
	}
	fmt.Fprintf(&b, "%-10s %7d %5d   (gate >= %d)\n", "ATTACKS", blocked, len(attacks), minBlocked)
	fmt.Fprintf(&b, "%-10s %7d %5d   (gate 0 false positives)\n", "LEGIT", len(fps), len(legit))
	slices.Sort(misses)
	for _, m := range misses {
		fmt.Fprintf(&b, "miss: %s\n", m)
	}
	for _, f := range fps {
		fmt.Fprintf(&b, "false positive: %s\n", f)
	}
	for _, m := range monitored {
		fmt.Fprintf(&b, "legit monitored (allowed): %s\n", m)
	}
	t.Log(b.String())

	if blocked < minBlocked {
		t.Errorf("blocked %d/%d attacks, gate >= %d", blocked, len(attacks), minBlocked)
	}
	if len(fps) > 0 {
		t.Errorf("%d/%d legitimate requests blocked, gate 0", len(fps), len(legit))
	}
}

// TestCorpusGeneric is the generic gate of spec 9.1: enforce mode, no
// routes, no exclusions, every input untyped.
func TestCorpusGeneric(t *testing.T) {
	fw, err := aegolith.New(aegolith.Config{Mode: aegolith.ModeEnforce})
	if err != nil {
		t.Fatal(err)
	}
	runCorpus(t, fw, gateGenericBlocked, false)
}

// TestCorpusAPIAware is the API-aware gate of spec 9.1: the ExampleCo-shaped
// policy in testdata/corpus/example-api-policy.json, enforce mode, no
// exclusions.
func TestCorpusAPIAware(t *testing.T) {
	cfg, err := aegolith.LoadConfig(filepath.Join("testdata", "corpus", "example-api-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != aegolith.ModeEnforce || len(cfg.Exclusions) != 0 || len(cfg.RuleActions) != 0 {
		t.Fatalf("the gate policy must be enforce mode with no exclusions and no rule-action overrides (mode %q, %d exclusions, %d rule actions)",
			cfg.Mode, len(cfg.Exclusions), len(cfg.RuleActions))
	}
	fw, err := aegolith.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	runCorpus(t, fw, gateAPIBlocked, true)
}

// TestCorpusLineValidation: malformed corpus lines are rejected rather than
// silently read with missing or truncated parts.
func TestCorpusLineValidation(t *testing.T) {
	const ok = `{"name":"n","category":"c","kind":"legit","method":"GET","path":"/a","query":[["q","v"]],"headers":{},"content_type":"","body":""}`
	if _, err := parseCorpusLine(ok, "legit"); err != nil {
		t.Fatalf("valid line rejected: %v", err)
	}
	bad := map[string]string{
		"body and body_base64": `{"name":"n","category":"c","kind":"legit","method":"POST","path":"/a","query":[],"headers":{},"content_type":"text/plain","body":"x","body_base64":"eA=="}`,
		"query pair of 3":      `{"name":"n","category":"c","kind":"legit","method":"GET","path":"/a","query":[["q","v","w"]],"headers":{},"content_type":"","body":""}`,
		"query pair of 1":      `{"name":"n","category":"c","kind":"legit","method":"GET","path":"/a","query":[["q"]],"headers":{},"content_type":"","body":""}`,
		"bad base64":           `{"name":"n","category":"c","kind":"legit","method":"POST","path":"/a","query":[],"headers":{},"content_type":"text/plain","body":"","body_base64":"!!"}`,
		"wrong kind":           `{"name":"n","category":"c","kind":"attack","method":"GET","path":"/a","query":[],"headers":{},"content_type":"","body":""}`,
		"unknown key":          `{"name":"n","category":"c","kind":"legit","method":"GET","path":"/a","query":[],"headers":{},"content_type":"","body":"","extra":1}`,
		"relative path":        `{"name":"n","category":"c","kind":"legit","method":"GET","path":"a","query":[],"headers":{},"content_type":"","body":""}`,
		"trailing data":        ok + ` {}`,
		"trailing brace":       ok + `}`,
	}
	for name, line := range bad {
		if _, err := parseCorpusLine(line, "legit"); err == nil {
			t.Errorf("%s: accepted, want an error", name)
		}
	}
}
