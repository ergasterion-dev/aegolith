package legit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

func encode(t *testing.T, lines []cases.Line) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := cases.WriteLines(&b, lines); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestGenerateIsDeterministic(t *testing.T) {
	t.Parallel()
	first := encode(t, Generate(1, 5000))
	if again := encode(t, Generate(1, 5000)); !bytes.Equal(first, again) {
		t.Error("the same seed and n gave different lines")
	}
	if other := encode(t, Generate(2, 5000)); bytes.Equal(first, other) {
		t.Error("another seed gave the same lines")
	}
	// A shorter set is the start of a longer one.
	if short := encode(t, Generate(1, 300)); !bytes.HasPrefix(first, short) {
		t.Error("Generate(1, 300) is not the start of Generate(1, 5000)")
	}
}

// TestGenerateOutputIsPinned fails when the lines of seed 1 change: through
// an edit of the material, of the generator, or through a Go release that
// encodes them differently. Published numbers name a seed and a size, so a
// change here changes what they measure. Update the digest only on purpose.
func TestGenerateOutputIsPinned(t *testing.T) {
	t.Parallel()
	const want = "459e00118d37b2075401889403a9738431e5bd8db014df6e376097813e2b57a3"
	sum := sha256.Sum256(encode(t, Generate(1, 5000)))
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("SHA-256 of the lines of Generate(1, 5000) is %s, want %s", got, want)
	}
}

func TestRandomStreamIsPinned(t *testing.T) {
	t.Parallel()
	// SplitMix64 from state 1234567, the reference values of the algorithm.
	r := rng{state: 1234567}
	want := []uint64{6457827717110365317, 3203168211198807973, 9817491932198370423}
	for i, w := range want {
		if got := r.next(); got != w {
			t.Errorf("output %d is %d, want %d", i, got, w)
		}
	}
}

func TestGenerateDistinctRequests(t *testing.T) {
	t.Parallel()
	const n = 5000
	lines := Generate(1, n)
	if len(lines) != n {
		t.Fatalf("%d lines, want %d", len(lines), n)
	}
	requests := map[string]bool{}
	ids := map[string]bool{}
	texts := map[string]bool{}
	for _, l := range lines {
		c, err := cases.FromLine(l)
		if err != nil {
			t.Fatal(err)
		}
		requests[c.ID] = true
		ids[l.SourceCaseID] = true
		// Texts that differ only in their numbers count as one.
		texts[digitsFolded(l.Payload)] = true

		if l.Source != Source || l.Expected != cases.Legit || l.Kind != "legit" {
			t.Fatalf("%s: source %q, expected %q, kind %q", l.SourceCaseID, l.Source, l.Expected, l.Kind)
		}
		if l.Payload == "" || l.Payload != strings.TrimSpace(l.Payload) || !utf8.ValidString(l.Payload) {
			t.Fatalf("%s: payload is empty, padded or not UTF-8", l.SourceCaseID)
		}
		if strings.ContainsAny(l.Payload, "⟦⟧") {
			t.Fatalf("%s: payload holds an unfilled slot: %q", l.SourceCaseID, l.Payload)
		}
		if got := sentValue(t, l); got != l.Payload {
			t.Fatalf("%s: the request carries %q, the payload is %q", l.SourceCaseID, got, l.Payload)
		}
		for name := range l.Headers {
			switch strings.ToLower(name) {
			case "host", "content-length", "transfer-encoding":
				t.Fatalf("%s: sets the %s header", l.SourceCaseID, name)
			}
		}
	}
	if len(requests) != n || len(ids) != n || len(texts) != n {
		t.Errorf("%d distinct requests, %d case IDs and %d texts apart from their numbers, want %d of each",
			len(requests), len(ids), len(texts), n)
	}
}

// sentValue returns the text the request of l carries where its placement
// says, decoded as a server would decode it.
func sentValue(t *testing.T, l cases.Line) string {
	t.Helper()
	var found []string
	switch l.Placement {
	case placementQuery:
		if l.Body != "" || l.ContentType != "" {
			t.Fatalf("%s: a query case has a body", l.SourceCaseID)
		}
		for _, kv := range l.Query {
			found = append(found, kv[1])
		}
	case placementJSON:
		if l.ContentType != "application/json" || len(l.Query) != 0 {
			t.Fatalf("%s: content type %q, %d query pairs", l.SourceCaseID, l.ContentType, len(l.Query))
		}
		var fields map[string]string
		if err := json.Unmarshal([]byte(l.Body), &fields); err != nil {
			t.Fatalf("%s: body is not a JSON object of strings: %v", l.SourceCaseID, err)
		}
		for _, v := range fields {
			found = append(found, v)
		}
	case placementForm:
		if l.ContentType != "application/x-www-form-urlencoded" || len(l.Query) != 0 {
			t.Fatalf("%s: content type %q, %d query pairs", l.SourceCaseID, l.ContentType, len(l.Query))
		}
		fields, err := url.ParseQuery(l.Body)
		if err != nil {
			t.Fatalf("%s: body is not a form: %v", l.SourceCaseID, err)
		}
		for _, vs := range fields {
			found = append(found, vs...)
		}
	default:
		t.Fatalf("%s: placement %q", l.SourceCaseID, l.Placement)
	}
	if !slices.Contains(found, l.Payload) {
		return strings.Join(found, " | ")
	}
	return l.Payload
}

func TestEveryCategoryAndPlacement(t *testing.T) {
	t.Parallel()
	want := []string{
		"addresses", "code-like-prose", "names", "other-languages", "prices-and-quantities",
		"reviews", "support-messages", "urls-in-text",
	}
	// One round of the schedule already holds every category.
	var small []string
	for _, l := range Generate(3, len(schedule)) {
		small = append(small, l.Category)
	}
	slices.Sort(small)
	if got := slices.Compact(small); !slices.Equal(got, want) {
		t.Errorf("categories of the first %d lines: %v, want %v", len(schedule), got, want)
	}

	const n = 5000
	perCategory := map[string]map[string]int{}
	perPlacement := map[string]int{}
	for _, l := range Generate(1, n) {
		if perCategory[l.Category] == nil {
			perCategory[l.Category] = map[string]int{}
		}
		perCategory[l.Category][l.Placement]++
		perPlacement[l.Placement]++
	}
	if len(perCategory) != len(want) {
		t.Errorf("%d categories, want %d", len(perCategory), len(want))
	}
	for _, name := range want {
		total := 0
		for _, placement := range []string{placementQuery, placementJSON, placementForm} {
			count := perCategory[name][placement]
			total += count
			if count == 0 {
				t.Errorf("category %s has no %s case", name, placement)
			}
		}
		// The smallest share of the schedule is 2 in 20.
		if total < n/10 {
			t.Errorf("category %s has %d cases, want at least %d", name, total, n/10)
		}
	}
	for _, placement := range []string{placementQuery, placementJSON, placementForm} {
		if perPlacement[placement] < n/4 {
			t.Errorf("placement %s has %d of %d cases, want about a third", placement, perPlacement[placement], n)
		}
	}
}

// TestNoSkeletonDominates guards against a set that is one sentence with
// changing words: no template may account for more than 2% of the lines.
func TestNoSkeletonDominates(t *testing.T) {
	t.Parallel()
	const n = 5000
	items, _ := generate(material, 1, n)
	count := map[string]int{}
	for _, it := range items {
		count[it.template]++
	}
	for template, c := range count {
		if c > n/50 {
			t.Errorf("template %q gave %d of %d lines", template, c, n)
		}
	}
	if len(count) < 150 {
		t.Errorf("%d templates in use, want at least 150", len(count))
	}
}

func TestMaterialIsWellFormed(t *testing.T) {
	t.Parallel()
	check := func(where, s string) {
		if !utf8.ValidString(s) {
			t.Errorf("%s: not valid UTF-8: %q", where, s)
		}
		if s != strings.TrimSpace(s) {
			t.Errorf("%s: padded with blanks: %q", where, s)
		}
		for _, r := range s {
			if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f {
				t.Errorf("%s: control character in %q", where, s)
			}
		}
		rest := s
		for {
			_, after, ok := strings.Cut(rest, slotOpen)
			if !ok {
				break
			}
			name, tail, ok := strings.Cut(after, slotClose)
			if !ok {
				t.Errorf("%s: unclosed slot in %q", where, s)
				break
			}
			if strings.HasPrefix(name, "#") {
				if _, _, ok := numberRange(name); !ok {
					t.Errorf("%s: bad number slot %q", where, name)
				}
			} else if len(slots[name]) == 0 {
				t.Errorf("%s: unknown slot %q", where, name)
			}
			rest = tail
		}
	}
	names := map[string]bool{}
	for _, c := range material {
		if names[c.name] || c.name == "" {
			t.Errorf("category name %q is empty or repeated", c.name)
		}
		names[c.name] = true
		if c.name != strings.ToLower(c.name) || strings.ContainsAny(c.name, " _") {
			t.Errorf("category name %q is not lower-case and hyphenated", c.name)
		}
		if len(c.templates) == 0 {
			t.Errorf("category %s has no templates", c.name)
		}
		seen := map[string]bool{}
		for _, template := range c.templates {
			if seen[template] {
				t.Errorf("category %s repeats template %q", c.name, template)
			}
			seen[template] = true
			check("category "+c.name, template)
		}
		for i, endpoints := range c.endpoints {
			if len(endpoints) == 0 {
				t.Errorf("category %s has no endpoint for placement %d", c.name, i)
			}
			for _, e := range endpoints {
				marks := 0
				for _, f := range e.fields {
					if f[1] == payloadMark {
						marks++
					}
				}
				if marks != 1 || !strings.HasPrefix(e.path, "/") || e.method == "" {
					t.Errorf("category %s: endpoint %s %s is malformed", c.name, e.method, e.path)
				}
			}
		}
	}
	total := 0
	for _, set := range slotSets {
		total += len(set)
	}
	if total != len(slots) {
		t.Errorf("the material files define %d word lists under %d names: a name is used twice", total, len(slots))
	}
	for name, list := range slots {
		seen := map[string]bool{}
		for _, entry := range list {
			if seen[entry] {
				t.Errorf("slot %s repeats %q", name, entry)
			}
			seen[entry] = true
			check("slot "+name, entry)
		}
	}
	for _, name := range schedule {
		if !names[name] {
			t.Errorf("the schedule names the unknown category %q", name)
		}
	}
}

func TestGenerateStopsWhenTheMaterialRunsOut(t *testing.T) {
	t.Parallel()
	if got := Generate(1, 0); len(got) != 0 {
		t.Errorf("n = 0 gave %d lines", len(got))
	}
	if got := Generate(1, -5); len(got) != 0 {
		t.Errorf("n < 0 gave %d lines", len(got))
	}

	// Three texts, two of which differ only in a number: two distinct lines,
	// however many are asked for.
	endpoints := material[0].endpoints
	tiny := []category{{
		name:      schedule[0],
		templates: []string{"first text", "order 17 is late", "order 2044 is late"},
		endpoints: endpoints,
	}}
	for _, c := range material {
		if c.name != schedule[0] {
			tiny = append(tiny, c)
		}
	}
	items, exhausted := generate(tiny, 1, 1000)
	if !exhausted {
		t.Error("generate did not report that the material ran out")
	}
	fromTiny := 0
	texts := map[string]bool{}
	for _, it := range items {
		if it.line.Category == schedule[0] {
			fromTiny++
		}
		texts[digitsFolded(it.line.Payload)] = true
	}
	if fromTiny != 2 || len(texts) != len(items) {
		t.Errorf("%d lines from the small category and %d distinct texts in %d lines, want 2 and no repeats",
			fromTiny, len(texts), len(items))
	}
	// The mix stays that of the schedule: generation ends with the category
	// that ran out, on its third turn.
	if want := 2*len(schedule)/countOf(schedule, schedule[0]) + 1; len(items) > want {
		t.Errorf("%d lines after a category ran out, want at most %d", len(items), want)
	}
}

func countOf(list []string, name string) int {
	n := 0
	for _, s := range list {
		if s == name {
			n++
		}
	}
	return n
}
