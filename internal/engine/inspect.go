package engine

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

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
func (e *Engine) Inspect(r *model.Request) (d model.Decision) {
	defer func() {
		if p := recover(); p != nil {
			d = e.fail(fmt.Errorf("aegolith: internal error: %s", model.Redact(fmt.Sprint(p))))
		}
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
}

func (e *Engine) inspect(r *model.Request) model.Decision {
	s := &state{e: e, req: *r}
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
// and the request is treated as an unknown route (every input untyped),
// which only adds inspection.
func (s *state) matchRoute() {
	if s.e.table != nil {
		if m, ok := s.e.table.Match(s.req.Method, s.req.RawPath); ok {
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

// capValue is capped plus an AEG-PROTO-011 match when v was cut.
func (s *state) capValue(loc model.Location, field, v string) string {
	if len(v) > s.e.lim.MaxValueLen {
		s.protoMatch(ruleValueTooLong, loc, field, v)
		return v[:s.e.lim.MaxValueLen]
	}
	return v
}

// scan runs every text detector on the capped value.
func (s *state) scan(loc model.Location, field, v string) {
	if s.stop {
		return
	}
	v = s.capValue(loc, field, v)
	for _, h := range detect.ScanText(v) {
		s.hit(h, loc, field, v)
	}
}

func joinField(prefix, name string) string { return prefix + "." + model.SafeName(name) }

// decide applies the mode: enforce blocks when any match blocks; otherwise
// the request is allowed and Monitored says whether anything matched.
func (s *state) decide() model.Decision {
	d := model.Decision{Action: model.ActionAllow, Matches: s.matches}
	if s.e.mode == model.ModeEnforce && slices.ContainsFunc(s.matches, func(m model.Match) bool { return m.Action == model.ActionBlock }) {
		d.Action = model.ActionBlock
		return d
	}
	d.Monitored = len(s.matches) > 0
	return d
}
