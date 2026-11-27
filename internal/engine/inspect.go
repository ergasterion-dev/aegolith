package engine

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ergasterion-dev/aegolith/internal/detect"
	"github.com/ergasterion-dev/aegolith/internal/model"
	"github.com/ergasterion-dev/aegolith/internal/normalize"
	"github.com/ergasterion-dev/aegolith/internal/policy"
	"github.com/ergasterion-dev/aegolith/internal/protocol"
)

// Rule IDs raised by the engine itself.
const (
	ruleUnknownRoute  = "AEG-ROUTE-001"  // no declared route matched
	ruleSchemaType    = "AEG-SCHEMA-001" // declared field failed validation
	ruleSchemaUnknown = "AEG-SCHEMA-002" // field not declared on the matched route
	ruleLimit         = "AEG-PROTO-010"  // MaxFields or MaxDepth exceeded
	ruleValueTooLong  = "AEG-PROTO-011"  // value longer than MaxValueLen, prefix scanned
	ruleMalformed     = "AEG-PROTO-020"  // body could not be parsed
)

// Inspect runs the pipeline on r. It never panics: a panic (or a nil
// request) yields a decision with Err set and Action from the fail-open
// setting (allow when open, block when closed). The error text is redacted.
//
// Decision.Duration is measured here, around the whole pipeline.
func (e *Engine) Inspect(r *model.Request) (d model.Decision) {
	start := time.Now()
	defer func() {
		if p := recover(); p != nil {
			d = e.fail(fmt.Errorf("aegolith: internal error: %s", model.Redact(fmt.Sprint(p))))
		}
		d.Duration = time.Since(start)
	}()
	if r == nil {
		return e.fail(errors.New("aegolith: nil request"))
	}
	if e.testHook != nil {
		e.testHook(r)
	}
	return e.inspect(r)
}

func (e *Engine) fail(err error) model.Decision {
	if e.failOpen {
		return model.Decision{Action: model.ActionAllow, Err: err}
	}
	return model.Decision{Action: model.ActionBlock, Err: err}
}

// state is the per-request working set of one inspection.
type state struct {
	e        *Engine
	req      model.Request // shallow copy with canonical header keys
	path     string        // RawPath, percent-decoded once
	routed   bool
	route    policy.Matched
	params   map[string]string // decoded path parameter values
	routeKey string
	matches  []model.Match
	seen     map[[2]string]struct{} // (RuleID, Field) already reported
	stop     bool                   // enforce mode and a blocking match: skip the rest

	// budget is how many more bytes may be handed to the text detectors
	// in this request (2 x MaxBodyBytes to start). When a window does not
	// fit, exhausted is set and no further value is scanned.
	budget    int64
	exhausted bool
}

func (e *Engine) inspect(r *model.Request) model.Decision {
	s := &state{e: e, req: *r, budget: e.scanBudget()}
	s.req.Header = canonicalHeader(r.Header)
	s.path, _ = normalize.DecodeValue(r.RawPath)
	s.matchRoute()

	for _, m := range protocol.Check(&s.req, e.proto) {
		s.add(m)
	}
	s.checkProbeAndAgent()
	s.checkRoute()
	s.checkQuery()
	s.checkBody()
	s.checkCookies()
	s.checkHeaders()
	return s.decide()
}

// canonicalHeader returns a copy of h with every key canonicalized (so
// "transfer-encoding" cannot slip past checks that look up
// "Transfer-Encoding"). Keys that canonicalize alike are merged in sorted
// key order, which keeps the merged value order deterministic.
func canonicalHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for _, k := range slices.Sorted(maps.Keys(h)) {
		ck := http.CanonicalHeaderKey(k)
		out[ck] = append(out[ck], h[k]...)
	}
	return out
}

// matchRoute matches the route on the RAW (escaped) path and decodes each
// parameter afterwards. Matching on the decoded path would let "%2F" split
// a segment or forge one ("/files/a%2F..%2Fb" must stay one parameter). A
// literal segment sent percent-encoded therefore does not match its route
// and the request is treated as an unknown route: every input is untyped
// and still gets every detector, but the route's typed fields and its
// unknown-fields action do not apply. Literal segments fold ASCII case
// when the table or the request asks for it (see policy.Table.MatchFold).
func (s *state) matchRoute() {
	if s.e.table != nil {
		if m, ok := s.e.table.MatchFold(s.req.Method, s.req.RawPath, s.req.CaseInsensitiveRoutes); ok {
			s.routed, s.route, s.routeKey = true, m, m.Key
			if len(m.Params) > 0 {
				s.params = make(map[string]string, len(m.Params))
				for k, v := range m.Params {
					s.params[k], _ = normalize.DecodeValue(v)
				}
			}
			return
		}
	}
	s.routeKey = strings.ToUpper(s.req.Method) + " " + s.path
}

// add applies rule-action overrides, then exclusions, then deduplication,
// and records m. An allow action drops the match.
func (s *state) add(m model.Match) {
	if s.stop {
		return
	}
	if a, ok := s.e.ruleAction(m.RuleID, m.Category); ok {
		m.Action = a
	}
	if m.Action == model.ActionAllow || s.e.excluded(m, s.routeKey) {
		return
	}
	k := [2]string{m.RuleID, m.Field}
	if _, dup := s.seen[k]; dup {
		return
	}
	if s.seen == nil {
		s.seen = map[[2]string]struct{}{}
	}
	s.seen[k] = struct{}{}
	s.matches = append(s.matches, m)
	if s.e.mode == model.ModeEnforce && m.Action == model.ActionBlock {
		s.stop = true
	}
}

func (s *state) hit(h detect.Hit, loc model.Location, field, val string) {
	s.add(model.Match{
		RuleID: h.RuleID, Category: h.Category, Severity: h.Severity,
		Location: loc, Field: field, Snippet: model.Redact(val), Action: model.ActionBlock,
	})
}

func (s *state) engineMatch(id string, cat model.Category, sev model.Severity, act model.Action, loc model.Location, field, val string) {
	s.add(model.Match{
		RuleID: id, Category: cat, Severity: sev,
		Location: loc, Field: field, Snippet: model.Redact(val), Action: act,
	})
}

func (s *state) protoMatch(id string, loc model.Location, field, val string) {
	s.engineMatch(id, model.CatProtocol, model.SeverityLow, model.ActionMonitor, loc, field, val)
}

// capped returns at most MaxValueLen bytes of v.
func (s *state) capped(v string) string {
	if len(v) > s.e.lim.MaxValueLen {
		return v[:s.e.lim.MaxValueLen]
	}
	return v
}

// scanBudget is the per-request limit on bytes handed to the text
// detectors: 8 x (MaxBodyBytes + 256 KiB) + 64 KiB. Every scanned value is
// charged its length once per window it occupies; windows of a value over
// MaxValueLen overlap by half, so a value is charged at most 2x its length.
// Per byte of input, then:
//   - a body byte is charged at most 8x. A walked JSON value can be up to
//     3x as long as its source bytes (the decoder turns each invalid UTF-8
//     byte into U+FFFD, 1 -> 3 bytes; escapes only shrink), and the
//     overlapping windows double that: 6x. The windowed raw rescan after
//     malformed JSON or a depth overflow adds 2x: 8x. A JSON key is
//     scanned once (scanKey): at most 3x. Form, multipart, XML and text
//     values are not expanded: at most 2x, plus 1x for a form pair whose
//     key ends with the quote its value starts with (the whole pair is
//     checked again): at most 3x;
//   - a byte of any other input (path, query, cookies, scanned headers) is
//     charged at most 3x (2x for a value; key bytes and the whole-pair
//     check of a quote-split pair add at most 1x each).
//
// So no request whose body is within MaxBodyBytes and whose other inputs
// total at most 256 KiB can exhaust it. Beyond that it can (a documented
// gap: one monitor match, never a block or a panic); servers cap those
// inputs well below it anyway (net/http: 1 MiB of headers; Fiber: 4 KiB
// buffers).
func (e *Engine) scanBudget() int64 { return 8*(e.lim.MaxBodyBytes+256<<10) + 64<<10 }

// bodyInspectLimit is how much of a body is inspected: 2 x MaxBodyBytes.
// Protocol reports a body over MaxBodyBytes (AEG-PROTO-003, block by
// default); when that rule is monitored, inspecting past that point means
// padding cannot hide a payload just beyond it.
func (e *Engine) bodyInspectLimit() int64 { return 2 * e.lim.MaxBodyBytes }

// scan runs every text detector on v.
func (s *state) scan(loc model.Location, field, v string) {
	s.scanWindows(loc, field, v, nil, "")
}

// scanWindows hands v to the text detectors (and extra, when set) in
// windows. A value up to MaxValueLen bytes is one window, so ordinary
// values cost exactly what they did before. A longer value is reported
// (AEG-PROTO-011, monitor) and scanned in windows of MaxValueLen bytes
// that start every MaxValueLen/2 bytes: every byte is scanned at most
// twice, and an attack shorter than half a window always lies wholly
// inside one window, so padding cannot push it out of sight. An empty
// value is not scanned and costs nothing. Every window is charged its
// length against the per-request budget; the first window that does not
// fit raises AEG-PROTO-011 once and stops all further scanning in the
// request (a documented gap: it stays a monitor match). Hits whose
// category is skip are dropped.
func (s *state) scanWindows(loc model.Location, field, v string, extra func(string) (detect.Hit, bool), skip model.Category) {
	s.scanWindowsAfter(loc, field, v, 0, extra, skip)
}

// scanWindowsAfter is scanWindows with the first hidden bytes of v kept from
// the text detectors. Windows, charges and what extra reads are those of the
// whole value.
func (s *state) scanWindowsAfter(loc model.Location, field, v string, hidden int, extra func(string) (detect.Hit, bool), skip model.Category) {
	if s.stop || s.exhausted || v == "" {
		return
	}
	size := s.e.lim.MaxValueLen
	if len(v) > size {
		s.protoMatch(ruleValueTooLong, loc, field, v)
	}
	// A query value was percent-decoded from the request line, which cannot
	// hold a raw line break: line breaks in it were sent encoded.
	scanText := detect.ScanText
	if loc == model.LocQuery {
		scanText = detect.ScanQueryText
	}
	step := max(size/2, 1)
	for start := 0; ; start += step {
		end := min(start+size, len(v))
		win := v[start:end]
		if int64(len(win)) > s.budget {
			s.exhausted = true
			s.protoMatch(ruleValueTooLong, loc, field, win)
			return
		}
		s.budget -= int64(len(win))
		if extra != nil {
			if h, ok := extra(win); ok {
				s.hit(h, loc, field, win)
			}
		}
		for _, h := range scanText(win[min(max(hidden-start, 0), len(win)):]) {
			if h.Category != skip {
				s.hit(h, loc, field, win)
			}
		}
		if end == len(v) || s.stop {
			return
		}
	}
}

// scanKey runs the SQL injection detector on a key name: a key reaches the
// backend too (a dynamic column name, an ORDER BY or a filter built from
// form keys). Only the first MaxValueLen bytes are read (capped); a longer
// key raises AEG-PROTO-011 (monitor, no snippet) on its field, so padding a
// key past the cap to push an injection out of sight leaves a signal. The
// match names the key in its field and carries no snippet, so nothing
// beyond the (sanitised, length-capped) field name is reported. The other
// text detectors are not run on keys: names are short identifiers, and
// their rules are tuned for free-text values.
func (s *state) scanKey(loc model.Location, field, key string) {
	if s.stop || s.exhausted || key == "" {
		return
	}
	if len(key) > s.e.lim.MaxValueLen {
		s.protoMatch(ruleValueTooLong, loc, field, "")
	}
	s.keySQLi(loc, field, s.capped(key))
}

// keySQLi charges k (at most MaxValueLen bytes) against the scan budget
// like a value window and runs detect.KeySQLi on it; once the budget is
// spent nothing more is scanned.
func (s *state) keySQLi(loc model.Location, field, k string) {
	if s.stop || s.exhausted || k == "" {
		return
	}
	if int64(len(k)) > s.budget {
		s.exhausted = true
		s.protoMatch(ruleValueTooLong, loc, field, "")
		return
	}
	s.budget -= int64(len(k))
	if h, ok := detect.KeySQLi(k); ok {
		s.hit(h, loc, field, "")
	}
}

func joinField(prefix, name string) string { return prefix + "." + model.SafeName(name) }

// decide applies the mode: enforce blocks when any match blocks; otherwise
// the request is allowed and Monitored says whether anything matched.
func (s *state) decide() model.Decision {
	d := model.Decision{Action: model.ActionAllow, Matches: s.matches}
	if s.routed {
		d.Route = s.route.Key
	}
	if s.e.mode == model.ModeEnforce && slices.ContainsFunc(s.matches, func(m model.Match) bool { return m.Action == model.ActionBlock }) {
		d.Action = model.ActionBlock
		return d
	}
	d.Monitored = len(s.matches) > 0
	return d
}
