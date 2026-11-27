// Package legit generates ordinary legitimate requests: the traffic the
// false positive rate of the bench is measured on. A wrongly blocked case
// here is a blocked customer.
//
// Each case is a free-text value that a person or a system would send (a
// name, an address, a review, a support message, a price, a text with a URL,
// prose full of punctuation or code, a text in another language) placed in a query value, a JSON body or a form body of a
// plain request. The texts are built from the templates and word lists in the
// material files of this package. They were written to be what people send,
// awkward kinds included: quoted error messages, pasted shell commands and
// SQL, HTML and template snippets, file paths, apostrophes and ampersands.
// No text was chosen, changed or left out because of what a firewall does
// with it, and none may be: that would make the measured rate a lie. Texts
// that are attack payloads in their own right are not written here at all.
//
// The mix of categories is fixed (see schedule) and is not a model of how
// often each kind occurs in real traffic; code-like text is deliberately
// over-represented. Read the rate of each category, not only the total.
//
// Names, addresses, phone numbers and e-mail addresses are invented; hosts
// are reserved names (example.com, example.org, example.net, .test,
// localhost) and IP addresses come from the documentation ranges. That
// leaves out the loopback and private addresses real messages also hold.
//
// # Determinism
//
// Generate(seed, n) returns the same lines on every platform and with every
// Go release: the random numbers come from SplitMix64, written out below, and
// not from math/rand, whose derived methods (such as IntN) are free to draw
// differently in a later release; no map is iterated; and every choice is
// made in one fixed order. Generate(seed, m) is the start of Generate(seed,
// n) for m < n. Editing the material changes the lines of every seed; a test
// pins the digest of one set so that this cannot happen unnoticed.
//
// # Distinctness
//
// No two lines hold the same text, and texts that differ only in their
// digits count as the same text: a second order number does not make a second
// case. So every line is a distinct request. Generation stops early when the
// category whose turn it is cannot produce a new text, which keeps the mix
// the same for every n; Generate then returns fewer than n lines.
package legit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/bits"
	"net/url"
	"strconv"
	"strings"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

// Source is the source name of the generated lines.
const Source = "generated-legit"

// The placements, as cases.Line names them. A form body is "body".
const (
	placementQuery = "query"
	placementJSON  = "json"
	placementForm  = "body"
)

// Slots in a template are written ⟦name⟧ and filled with an entry of the
// word list of that name, which may hold slots itself; ⟦#lo-hi⟧ is filled
// with a number from lo to hi. The brackets occur in no text people write
// here, unlike { and $.
const (
	slotOpen  = "⟦"
	slotClose = "⟧"
)

// payloadMark is the value of the field of an endpoint that takes the text.
const payloadMark = "\x00"

// maxDraws is how many texts in a row may repeat earlier ones before a
// category counts as used up, and maxDepth how deep slots may nest.
const (
	maxDraws = 400
	maxDepth = 8
)

// category is one kind of text and the requests that carry it.
type category struct {
	name      string
	templates []string
	// endpoints for the query, JSON and form placements, in that order.
	endpoints [3][]endpoint
}

// endpoint is a request shape. fields are the query pairs, the members of
// the JSON object or the form fields, in order; exactly one has payloadMark
// as its value.
type endpoint struct {
	method, path string
	fields       [][2]string
}

// schedule is the order in which categories take turns: 4 in 20 lines are
// code-like prose, 3 each reviews and support messages, 2 each the others.
var schedule = []string{
	"code-like-prose", "names", "reviews", "support-messages", "code-like-prose",
	"addresses", "prices-and-quantities", "urls-in-text", "other-languages", "reviews",
	"code-like-prose", "support-messages", "names", "addresses", "other-languages",
	"code-like-prose", "prices-and-quantities", "urls-in-text", "reviews", "support-messages",
}

// userAgents are the browsers and clients the requests claim to come from.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
	"okhttp/4.12.0",
}

// Generate returns up to n legitimate case lines for seed. It returns fewer
// than n only when the material cannot give n distinct texts in the fixed mix
// of categories; see the package comment. n < 1 gives no lines.
func Generate(seed int64, n int) []cases.Line {
	items, _ := generate(material, seed, n)
	lines := make([]cases.Line, len(items))
	for i, it := range items {
		lines[i] = it.line
	}
	return lines
}

// item is a generated line and the template its text came from.
type item struct {
	line     cases.Line
	template string
}

// generate is Generate over the given categories. exhausted reports that it
// stopped before n lines because a category ran out of new texts.
func generate(categories []category, seed int64, n int) (items []item, exhausted bool) {
	r := &rng{state: uint64(seed)}
	seen := map[string]bool{}
	for turn := 0; len(items) < n; turn++ {
		name := schedule[turn%len(schedule)]
		var c *category
		for i := range categories {
			if categories[i].name == name {
				c = &categories[i]
			}
		}
		if c == nil || len(c.templates) == 0 {
			return items, true
		}
		template, text, ok := newText(r, c, seen)
		if !ok {
			return items, true
		}
		items = append(items, item{line: request(r, c, text), template: template})
	}
	return items, false
}

// newText draws texts of c until one is new, and records it in seen.
func newText(r *rng, c *category, seen map[string]bool) (template, text string, ok bool) {
	for range maxDraws {
		template = c.templates[r.intn(len(c.templates))]
		var b strings.Builder
		if !expand(r, &b, template, 0) {
			continue
		}
		text = strings.TrimSpace(b.String())
		key := digitsFolded(text)
		if text == "" || seen[key] {
			continue
		}
		seen[key] = true
		return template, text, true
	}
	return "", "", false
}

// expand writes s to b with its slots filled. It fails on a slot that does
// not exist or nests too deep; the tests keep the material free of both.
func expand(r *rng, b *strings.Builder, s string, depth int) bool {
	if depth > maxDepth {
		return false
	}
	for {
		before, after, found := strings.Cut(s, slotOpen)
		b.WriteString(before)
		if !found {
			return true
		}
		name, rest, closed := strings.Cut(after, slotClose)
		if !closed {
			return false
		}
		if strings.HasPrefix(name, "#") {
			lo, hi, ok := numberRange(name)
			if !ok {
				return false
			}
			b.WriteString(strconv.Itoa(lo + r.intn(hi-lo+1)))
		} else {
			list := slots[name]
			if len(list) == 0 || !expand(r, b, list[r.intn(len(list))], depth+1) {
				return false
			}
		}
		s = rest
	}
}

// numberRange parses the slot name "#lo-hi".
func numberRange(name string) (lo, hi int, ok bool) {
	from, to, found := strings.Cut(strings.TrimPrefix(name, "#"), "-")
	lo, errLo := strconv.Atoi(from)
	hi, errHi := strconv.Atoi(to)
	return lo, hi, found && errLo == nil && errHi == nil && 0 <= lo && lo <= hi
}

// digitsFolded returns s with every run of ASCII digits replaced by one 0.
func digitsFolded(s string) string {
	var b strings.Builder
	inDigits := false
	for i := range len(s) {
		c := s[i]
		digit := '0' <= c && c <= '9'
		switch {
		case !digit:
			b.WriteByte(c)
		case !inDigits:
			b.WriteByte('0')
		}
		inDigits = digit
	}
	return b.String()
}

// request places text in a request of c.
func request(r *rng, c *category, text string) cases.Line {
	placements := [3]string{placementQuery, placementJSON, placementForm}
	p := r.intn(len(placements))
	e := c.endpoints[p][r.intn(len(c.endpoints[p]))]
	fields := make([][]string, len(e.fields))
	for i, f := range e.fields {
		value := f[1]
		if value == payloadMark {
			value = text
		}
		fields[i] = []string{f[0], value}
	}

	id := sha256.Sum256([]byte(e.method + " " + e.path + "\n" + text))
	caseID := c.name + "/" + hex.EncodeToString(id[:8])
	line := cases.Line{
		Name:         Source + "-" + caseID,
		Category:     c.name,
		Kind:         string(cases.Legit),
		Method:       e.method,
		Path:         e.path,
		Headers:      map[string]string{"User-Agent": userAgents[r.intn(len(userAgents))]},
		Source:       Source,
		SourceCaseID: caseID,
		Expected:     cases.Legit,
		Payload:      text,
		Placement:    placements[p],
	}
	switch placements[p] {
	case placementQuery:
		line.Query = fields
		line.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	case placementJSON:
		line.ContentType = "application/json"
		line.Body = jsonObject(fields)
		line.Headers["Accept"] = "application/json"
	case placementForm:
		line.ContentType = "application/x-www-form-urlencoded"
		line.Body = formBody(fields)
		line.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	}
	return line
}

// jsonObject writes fields as a JSON object of strings in the given order,
// the way a browser's JSON.stringify does: <, > and & are not escaped and
// text outside ASCII is sent as it is.
func jsonObject(fields [][]string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	b.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		for j, s := range f {
			// A string always encodes; Encode ends it with a newline.
			_ = enc.Encode(s)
			b.Truncate(b.Len() - 1)
			if j == 0 {
				b.WriteByte(':')
			}
		}
	}
	b.WriteByte('}')
	return b.String()
}

// formBody writes fields as a form posts them: a blank is "+".
func formBody(fields [][]string) string {
	parts := make([]string, len(fields))
	for i, f := range fields {
		parts[i] = url.QueryEscape(f[0]) + "=" + url.QueryEscape(f[1])
	}
	return strings.Join(parts, "&")
}

// rng is SplitMix64 (Steele, Lea and Flood): one addition and two
// multiply-xorshift rounds per number, fully defined by these lines.
type rng struct{ state uint64 }

func (r *rng) next() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ^ z>>30) * 0xbf58476d1ce4e5b9
	z = (z ^ z>>27) * 0x94d049bb133111eb
	return z ^ z>>31
}

// intn returns a number in [0, n) for n > 0: the high word of a 64 by 64 bit
// product. Its bias is below n/2^64.
func (r *rng) intn(n int) int {
	hi, _ := bits.Mul64(r.next(), uint64(n))
	return int(hi)
}
