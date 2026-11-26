// Package cases is the bench's case model: the JSONL line every importer
// writes, the HTTP request built from it, and how identical requests are
// merged and split between development and held-out sets.
package cases

import (
	"bufio"
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

// Expected is what the source says should happen to a request.
type Expected string

// The values of Expected. A near-miss resembles an attack without being one,
// and is reported apart from ordinary legitimate traffic.
const (
	Attack   Expected = "attack"
	Legit    Expected = "legit"
	NearMiss Expected = "near-miss"
)

// SourceBaseline names the project's own corpus. Cases that only it provides
// are not split into development and held-out sets.
const SourceBaseline = "baseline"

// The values Split returns.
const (
	SplitBaseline = "baseline"
	SplitDev      = "dev"
	SplitHeldOut  = "held-out"
)

// heldOutPercent is the share of third-party payloads that are held out.
const heldOutPercent = 30

// maxLineBytes bounds one JSONL line, newline included.
const maxLineBytes = 16 << 20

// Line is one JSONL line: the corpus line format plus source fields.
type Line struct {
	Name        string            `json:"name"`
	Category    string            `json:"category"`
	Kind        string            `json:"kind"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`  // raw (escaped) path, without a query
	Query       [][]string        `json:"query"` // decoded [key, value] pairs
	RawQuery    string            `json:"raw_query,omitempty"`
	Headers     map[string]string `json:"headers"`
	ContentType string            `json:"content_type"`
	Body        string            `json:"body"`
	// BodyBase64, when set, replaces Body (for bytes a JSON string cannot
	// carry).
	BodyBase64   string   `json:"body_base64,omitempty"`
	Source       string   `json:"source"`
	SourceCaseID string   `json:"source_case_id"`
	Expected     Expected `json:"expected"`
	Payload      string   `json:"payload"` // decoded payload, may be empty
	// PayloadBase64, when set, holds the payload in place of Payload (for
	// bytes a JSON string cannot carry).
	PayloadBase64 string `json:"payload_base64,omitempty"`
	Placement     string `json:"placement"` // path, query, header, body, json, raw or empty
	Encoder       string `json:"encoder"`
}

// SourceRef is one source's name for a case.
type SourceRef struct{ Source, CaseID string }

// Case is one distinct request and every source that provides it.
type Case struct {
	ID       string // hex SHA-256 of the request, see requestID
	Sources  []SourceRef
	Category string
	Expected Expected

	// Payloads holds the decoded payloads the sources give for this request:
	// distinct, sorted, nil when none gives one.
	Payloads [][]byte

	Placement, Encoder string

	Method, Path, RawQuery string
	Headers                map[string]string
	Body                   []byte
}

// FromLine validates l and builds the request it describes. Query pairs are
// percent-encoded as the project's corpus test encodes them; a non-empty
// RawQuery is used byte for byte instead. A header named in Headers wins over
// ContentType. Errors identify the case by source and case ID and never
// repeat request values.
func FromLine(l Line) (Case, error) {
	c, err := fromLine(l)
	if err != nil {
		return Case{}, fmt.Errorf("source %q, case %q: %w", l.Source, l.SourceCaseID, err)
	}
	return c, nil
}

func fromLine(l Line) (Case, error) {
	if err := l.validate(); err != nil {
		return Case{}, err
	}
	body, err := textOrBase64("body", l.Body, l.BodyBase64)
	if err != nil {
		return Case{}, err
	}
	payload, err := textOrBase64("payload", l.Payload, l.PayloadBase64)
	if err != nil {
		return Case{}, err
	}
	var payloads [][]byte
	if len(payload) > 0 {
		payloads = [][]byte{payload}
	}
	headers, err := requestHeaders(l.Headers, l.ContentType)
	if err != nil {
		return Case{}, err
	}
	rawQuery := l.RawQuery
	if rawQuery == "" {
		rawQuery = encodeQuery(l.Query)
	}
	c := Case{
		Sources:   []SourceRef{{Source: l.Source, CaseID: l.SourceCaseID}},
		Category:  l.Category,
		Expected:  l.Expected,
		Payloads:  payloads,
		Placement: l.Placement,
		Encoder:   l.Encoder,
		Method:    l.Method,
		Path:      l.Path,
		RawQuery:  rawQuery,
		Headers:   headers,
		Body:      body,
	}
	c.ID = requestID(c)
	return c, nil
}

// textOrBase64 returns the bytes of the named field, which a line writes
// either as text or, in field_base64, as base64.
func textOrBase64(field, text, encoded string) ([]byte, error) {
	if encoded == "" {
		return []byte(text), nil
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding %s_base64: %w", field, err)
	}
	return decoded, nil
}

// validate checks everything about l that does not need decoding.
func (l Line) validate() error {
	switch {
	case l.Name == "":
		return errors.New("name is empty")
	case l.Category == "":
		return errors.New("category is empty")
	case l.Method == "":
		return errors.New("method is empty")
	case !strings.HasPrefix(l.Path, "/"):
		return errors.New("path does not start with /")
	case strings.Contains(l.Path, "?"):
		// One request would otherwise have two spellings, and two IDs.
		return errors.New("path holds a query; use query or raw_query")
	case l.Source == "":
		return errors.New("source is empty")
	case l.SourceCaseID == "":
		return errors.New("source_case_id is empty")
	case l.Body != "" && l.BodyBase64 != "":
		return errors.New("both body and body_base64 are set")
	case l.Payload != "" && l.PayloadBase64 != "":
		return errors.New("both payload and payload_base64 are set")
	}
	switch l.Expected {
	case Attack, Legit, NearMiss:
	default:
		return errors.New("expected is not attack, legit or near-miss")
	}
	switch l.Placement {
	case "", "path", "query", "header", "body", "json", "raw":
	default:
		return errors.New("unknown placement")
	}
	for i, kv := range l.Query {
		if len(kv) != 2 {
			return fmt.Errorf("query entry %d is not a [key, value] pair", i)
		}
	}
	return nil
}

// requestHeaders copies headers and adds contentType unless headers already
// names Content-Type. Names that differ only by case are rejected: which one
// would be sent is undefined.
func requestHeaders(headers map[string]string, contentType string) (map[string]string, error) {
	out := make(map[string]string, len(headers)+1)
	seen := make(map[string]bool, len(headers))
	for name, value := range headers {
		if name == "" {
			return nil, errors.New("a header name is empty")
		}
		lower := lowerASCII(name)
		if seen[lower] {
			return nil, errors.New("two header names differ only by case")
		}
		seen[lower] = true
		out[name] = value
	}
	if contentType != "" && !seen["content-type"] {
		out["Content-Type"] = contentType
	}
	return out, nil
}

// lowerASCII lower-cases the ASCII letters of s and leaves every other byte
// alone. strings.ToLower also folds other scripts and replaces invalid bytes,
// which would make different header names look equal.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// encodeQuery joins pairs, percent-encoding keys and values.
func encodeQuery(pairs [][]string) string {
	encoded := make([]string, 0, len(pairs))
	for _, kv := range pairs {
		encoded = append(encoded, curlEscape(kv[0])+"="+curlEscape(kv[1]))
	}
	return strings.Join(encoded, "&")
}

// curlEscape percent-encodes s the way curl --data-urlencode does: every
// byte except ALPHA / DIGIT / "-" / "." / "_" / "~". It must stay equal to
// the function of the same name in the root module's corpus_test.go.
func curlEscape(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&15])
	}
	return b.String()
}

// requestID is the hex SHA-256 over the method, path, raw query, headers
// (names lower-cased in ASCII, sorted) and body. Every part is length-prefixed, so
// bytes cannot move from one part to the next without changing the ID.
func requestID(c Case) string {
	h := sha256.New()
	number := func(n int) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		h.Write(b[:]) // a hash never returns a write error
	}
	part := func(b []byte) {
		number(len(b))
		h.Write(b)
	}
	part([]byte(c.Method))
	part([]byte(c.Path))
	part([]byte(c.RawQuery))

	headers := make([][2]string, 0, len(c.Headers))
	for name, value := range c.Headers {
		headers = append(headers, [2]string{lowerASCII(name), value})
	}
	slices.SortFunc(headers, func(a, b [2]string) int { return slices.Compare(a[:], b[:]) })
	number(len(headers))
	for _, kv := range headers {
		part([]byte(kv[0]))
		part([]byte(kv[1]))
	}
	part(c.Body)
	return hex.EncodeToString(h.Sum(nil))
}

// Merge folds cases that send the same request into one case credited to
// every source, keeping the order in which requests first appear. A request
// whose cases disagree on Expected is excluded: all of its input cases are
// returned in conflicts, so each source's claim stays visible.
//
// The merged case keeps every source and every payload of its cases, each
// sorted and distinct. Its other descriptive fields come from the first case
// in source order that has a payload (the first case if none has). None of
// this depends on the order the sources were read in.
func Merge(cs []Case) (merged []Case, conflicts []Case) {
	groups := make(map[string][]Case, len(cs))
	var order []string
	for _, c := range cs {
		c.ID = requestID(c)
		if _, ok := groups[c.ID]; !ok {
			order = append(order, c.ID)
		}
		groups[c.ID] = append(groups[c.ID], c)
	}
	for _, id := range order {
		group := groups[id]
		if slices.ContainsFunc(group, func(c Case) bool { return c.Expected != group[0].Expected }) {
			conflicts = append(conflicts, group...)
			continue
		}
		merged = append(merged, combine(group))
	}
	return merged, conflicts
}

// combine makes one case of a non-empty group that sends the same request.
// It reorders group, but writes to no slice a caller passed to Merge.
func combine(group []Case) Case {
	slices.SortFunc(group, func(a, b Case) int {
		return cmp.Or(
			slices.CompareFunc(a.Sources, b.Sources, compareRefs),
			slices.CompareFunc(a.Payloads, b.Payloads, bytes.Compare),
			cmp.Compare(a.Placement, b.Placement),
			cmp.Compare(a.Encoder, b.Encoder),
			cmp.Compare(a.Category, b.Category),
		)
	})
	out := group[0]
	if i := slices.IndexFunc(group, func(c Case) bool { return len(c.Payloads) > 0 }); i >= 0 {
		out = group[i]
	}
	var refs []SourceRef
	var payloads [][]byte
	for _, c := range group {
		refs = append(refs, c.Sources...)
		payloads = append(payloads, c.Payloads...)
	}
	slices.SortFunc(refs, compareRefs)
	out.Sources = slices.Compact(refs)
	slices.SortFunc(payloads, bytes.Compare)
	out.Payloads = slices.CompactFunc(payloads, bytes.Equal)
	return out
}

func compareRefs(a, b SourceRef) int {
	return cmp.Or(cmp.Compare(a.Source, b.Source), cmp.Compare(a.CaseID, b.CaseID))
}

// Split says which set c belongs to. A case only the baseline provides is
// SplitBaseline. Any other case with payloads is SplitHeldOut if any of them
// is held out, and SplitDev if none is.
//
// Whether a payload is held out depends only on its bytes (an unsalted hash).
// So a case with a payload filled in keeps its set across source versions
// that keep its payloads, adding a source can only move it towards held-out,
// and a held-out payload is never in a development case. A case without a
// payload is assigned by its ID and has no such stability: it can change set
// when the request changes or when a source starts to fill in a payload.
func Split(c Case) string {
	thirdParty := func(r SourceRef) bool { return r.Source != SourceBaseline }
	if len(c.Sources) > 0 && !slices.ContainsFunc(c.Sources, thirdParty) {
		return SplitBaseline
	}
	keys := c.Payloads
	if len(keys) == 0 {
		keys = [][]byte{[]byte(c.ID)}
	}
	if slices.ContainsFunc(keys, heldOut) {
		return SplitHeldOut
	}
	return SplitDev
}

func heldOut(key []byte) bool {
	sum := sha256.Sum256(key)
	return binary.BigEndian.Uint64(sum[:8])%100 < heldOutPercent
}

// ReadLines reads JSONL case lines. Every line must be one JSON object of
// valid UTF-8 with no unknown keys and nothing after it. It checks the format
// only; FromLine validates the request.
func ReadLines(r io.Reader) ([]Line, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	var out []Line
	for sc.Scan() {
		l, err := parseLine(sc.Bytes())
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", len(out)+1, err)
		}
		out = append(out, l)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("line %d: %w", len(out)+1, err)
	}
	return out, nil
}

func parseLine(b []byte) (Line, error) {
	var l Line
	// The JSON decoder would replace invalid bytes instead of failing.
	if !utf8.Valid(b) {
		return l, errors.New("not valid UTF-8")
	}
	// It would also accept "null" as an empty object.
	if !bytes.HasPrefix(bytes.TrimLeft(b, " \t\r"), []byte("{")) {
		return l, errors.New("not a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return l, fmt.Errorf("decoding JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return l, errors.New("trailing data after the JSON object")
	}
	return l, nil
}

// WriteLines writes ls as JSONL. It fails rather than write a line that would
// not read back unchanged: a string that is not valid UTF-8 (raw_query,
// body_base64 and payload_base64 carry such bytes) or a line too long for
// ReadLines. On error, w may already hold some of the lines.
func WriteLines(w io.Writer, ls []Line) error {
	out := bufio.NewWriter(w)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for i, l := range ls {
		if field := l.invalidUTF8Field(); field != "" {
			return fmt.Errorf("line %d: %s is not valid UTF-8", i+1, field)
		}
		// The corpus format writes empty collections, not null.
		if l.Query == nil {
			l.Query = [][]string{}
		}
		if l.Headers == nil {
			l.Headers = map[string]string{}
		}
		buf.Reset()
		if err := enc.Encode(l); err != nil {
			return fmt.Errorf("line %d: encoding JSON: %w", i+1, err)
		}
		if buf.Len() > maxLineBytes {
			return fmt.Errorf("line %d: longer than %d bytes", i+1, maxLineBytes)
		}
		if _, err := out.Write(buf.Bytes()); err != nil {
			return fmt.Errorf("writing line %d: %w", i+1, err)
		}
	}
	if err := out.Flush(); err != nil {
		return fmt.Errorf("writing case lines: %w", err)
	}
	return nil
}

// invalidUTF8Field returns the JSON name of a field holding invalid UTF-8,
// or "" when there is none.
func (l Line) invalidUTF8Field() string {
	type field struct{ name, value string }
	fields := []field{
		{"name", l.Name},
		{"category", l.Category},
		{"kind", l.Kind},
		{"method", l.Method},
		{"path", l.Path},
		{"raw_query", l.RawQuery},
		{"content_type", l.ContentType},
		{"body", l.Body},
		{"body_base64", l.BodyBase64},
		{"source", l.Source},
		{"source_case_id", l.SourceCaseID},
		{"expected", string(l.Expected)},
		{"payload", l.Payload},
		{"payload_base64", l.PayloadBase64},
		{"placement", l.Placement},
		{"encoder", l.Encoder},
	}
	for _, kv := range l.Query {
		for _, s := range kv {
			fields = append(fields, field{"query", s})
		}
	}
	for name, value := range l.Headers {
		fields = append(fields, field{"headers", name}, field{"headers", value})
	}
	for _, f := range fields {
		if !utf8.ValidString(f.value) {
			return f.name
		}
	}
	return ""
}
