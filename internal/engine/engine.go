// Package engine runs Aegolith's inspection pipeline (spec §5.2): protocol
// checks, path and user-agent rules, route policy, input inspection, then
// rule-action overrides, exclusions and the mode decide the verdict.
//
// An Engine is immutable after New and safe for concurrent use; all
// per-request state lives in a state value owned by one Inspect call.
package engine

import (
	"errors"
	"fmt"
	"maps"
	"mime"
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

// Exclusion drops matches whose rule, route key and field all match. Rule
// is a rule ID, an ID prefix ending in "*", or a category name. Route is a
// route key ("METHOD /template" for a matched route, "METHOD /decoded/path"
// otherwise). Field is a match field such as "query.q". Route and Field
// accept a trailing "*" as a prefix wildcard; "" or "*" match anything.
type Exclusion struct {
	Rule, Route, Field string
}

// Options is the fully resolved engine configuration: every limit is
// positive and every action has its default filled in.
type Options struct {
	Mode                model.Mode
	AllowedMethods      []string
	AllowedContentTypes []string
	AllowXML            bool
	Limits              model.Limits
	Routes              []policy.Route
	UnknownRoute        model.Action
	UnknownFields       model.Action
	Exclusions          []Exclusion
	RuleActions         map[string]model.Action
	InspectHeaders      []string
	FailOpen            bool
}

type prefixAction struct {
	prefix string
	action model.Action
}

// Engine is a compiled, immutable pipeline.
type Engine struct {
	mode           model.Mode
	proto          protocol.Config
	lim            model.Limits
	table          *policy.Table // nil when no routes are configured
	unknownRoute   model.Action
	unknownFields  model.Action
	exclusions     []Exclusion
	ruleExact      map[string]model.Action
	rulePrefix     []prefixAction // longest prefix first
	ruleCategory   map[model.Category]model.Action
	inspectHeaders []string // canonical header names
	failOpen       bool

	// testHook, when set, runs at the start of every inspection inside the
	// recover guard. Tests use it to inject panics.
	testHook func(*model.Request)
}

var categories = []model.Category{
	model.CatSQLi, model.CatXSS, model.CatCmdi, model.CatCodei, model.CatLDAP, model.CatSSTI,
	model.CatJNDI, model.CatCRLF, model.CatLFI, model.CatRFI, model.CatSSRF, model.CatXXE,
	model.CatNoSQLi, model.CatProtoPollute, model.CatSession, model.CatScanner,
	model.CatProtocol, model.CatSchema, model.CatRoute,
}

func validAction(a model.Action) bool { return a >= model.ActionAllow && a <= model.ActionMonitor }

// rulePattern normalizes and checks a rule selector: "*", a rule ID or ID
// prefix (AEG-..., upper-cased), or a category name (lower-cased).
func rulePattern(p string) (string, error) {
	p = strings.TrimSpace(p)
	switch {
	case p == "":
		return "", errors.New("empty rule")
	case p == "*":
		return p, nil
	case strings.HasPrefix(strings.ToUpper(p), "AEG-"):
		return strings.ToUpper(p), nil
	case slices.Contains(categories, model.Category(strings.ToLower(p))):
		return strings.ToLower(p), nil
	}
	return "", fmt.Errorf("rule %q is not a rule ID (AEG-...), ID prefix ending in * or category", p)
}

// New validates o and compiles the route table and rule selectors.
func New(o Options) (*Engine, error) {
	if o.Mode != model.ModeEnforce && o.Mode != model.ModeMonitor {
		return nil, fmt.Errorf("invalid mode %d", int(o.Mode))
	}
	if !validAction(o.UnknownRoute) || !validAction(o.UnknownFields) {
		return nil, errors.New("invalid unknown_route or unknown_fields action")
	}
	if o.Limits.MaxBodyBytes <= 0 || o.Limits.MaxDepth <= 0 || o.Limits.MaxFields <= 0 || o.Limits.MaxValueLen <= 0 {
		return nil, fmt.Errorf("limits must be positive: %+v", o.Limits)
	}
	e := &Engine{
		mode:          o.Mode,
		lim:           o.Limits,
		unknownRoute:  o.UnknownRoute,
		unknownFields: o.UnknownFields,
		failOpen:      o.FailOpen,
		proto: protocol.Config{
			AllowedMethods:      slices.Clone(o.AllowedMethods),
			AllowedContentTypes: slices.Clone(o.AllowedContentTypes),
			Limits:              o.Limits,
			AllowXML:            o.AllowXML,
		},
	}
	if len(o.Routes) > 0 {
		t, err := policy.Compile(o.Routes)
		if err != nil {
			return nil, err
		}
		e.table = t
	}
	for i, x := range o.Exclusions {
		r, err := rulePattern(x.Rule)
		if err != nil {
			return nil, fmt.Errorf("exclusion %d: %w", i, err)
		}
		route, err := routePattern(x.Route)
		if err != nil {
			return nil, fmt.Errorf("exclusion %d: %w", i, err)
		}
		field, err := fieldPattern(x.Field)
		if err != nil {
			return nil, fmt.Errorf("exclusion %d: %w", i, err)
		}
		e.exclusions = append(e.exclusions, Exclusion{Rule: r, Route: route, Field: field})
	}
	e.ruleExact = map[string]model.Action{}
	e.ruleCategory = map[model.Category]model.Action{}
	// Sorted keys keep compilation deterministic.
	for _, k := range slices.Sorted(maps.Keys(o.RuleActions)) {
		a := o.RuleActions[k]
		if !validAction(a) {
			return nil, fmt.Errorf("rule_actions[%q]: invalid action %d", k, int(a))
		}
		p, err := rulePattern(k)
		if err != nil {
			return nil, fmt.Errorf("rule_actions: %w", err)
		}
		switch {
		case strings.HasSuffix(p, "*"):
			e.rulePrefix = append(e.rulePrefix, prefixAction{prefix: strings.TrimSuffix(p, "*"), action: a})
		case strings.HasPrefix(p, "AEG-"):
			e.ruleExact[p] = a
		default:
			e.ruleCategory[model.Category(p)] = a
		}
	}
	slices.SortStableFunc(e.rulePrefix, func(a, b prefixAction) int { return len(b.prefix) - len(a.prefix) })
	for _, h := range o.InspectHeaders {
		if strings.TrimSpace(h) == "" {
			return nil, errors.New("inspect_headers: empty header name")
		}
		e.inspectHeaders = append(e.inspectHeaders, http.CanonicalHeaderKey(strings.TrimSpace(h)))
	}
	return e, nil
}

// routePattern checks an exclusion route: "", "*", or "METHOD /path" (the
// method is upper-cased; the path may end in "*").
func routePattern(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "*" {
		return p, nil
	}
	method, path, ok := strings.Cut(p, " ")
	if !ok || method == "" || !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("route %q must be \"METHOD /path\", \"*\" or empty", p)
	}
	return strings.ToUpper(method) + " " + path, nil
}

var fieldLocations = []string{"path", "query", "body", "form", "header", "cookie", "method"}

// fieldPattern checks an exclusion field: "", "*", or a match field such as
// "query.q" (header names are lower-cased, as in matches).
func fieldPattern(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "*" {
		return p, nil
	}
	loc, _, _ := strings.Cut(strings.TrimSuffix(p, "*"), ".")
	if !slices.Contains(fieldLocations, loc) {
		return "", fmt.Errorf("field %q must start with one of %s", p, strings.Join(fieldLocations, ", "))
	}
	if loc == "header" {
		p = strings.ToLower(p)
	}
	return p, nil
}

// matchPattern reports whether v matches pat: "" and "*" match anything, a
// trailing "*" matches by prefix, anything else must be equal.
func matchPattern(pat, v string) bool {
	switch {
	case pat == "" || pat == "*":
		return true
	case strings.HasSuffix(pat, "*"):
		return strings.HasPrefix(v, pat[:len(pat)-1])
	}
	return pat == v
}

// ruleAction returns the configured override for a rule: exact rule ID
// first, then the longest matching ID prefix, then the category.
func (e *Engine) ruleAction(id string, cat model.Category) (model.Action, bool) {
	if a, ok := e.ruleExact[id]; ok {
		return a, true
	}
	for _, p := range e.rulePrefix {
		if strings.HasPrefix(id, p.prefix) {
			return p.action, true
		}
	}
	a, ok := e.ruleCategory[cat]
	return a, ok
}

func (e *Engine) excluded(m model.Match, routeKey string) bool {
	for _, x := range e.exclusions {
		if (matchPattern(x.Rule, m.RuleID) || x.Rule == string(m.Category)) &&
			matchPattern(x.Route, routeKey) && matchPattern(x.Field, m.Field) {
			return true
		}
	}
	return false
}

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

// checkProbeAndAgent runs the probe-path and backup-file rules on the
// decoded path and the scanner rule on every User-Agent value.
func (s *state) checkProbeAndAgent() {
	if h, ok := detect.ProbePath(s.path); ok {
		s.hit(h, model.LocPath, "path", s.path)
	}
	for _, ua := range s.req.Header.Values("User-Agent") {
		if h, ok := detect.UserAgent(s.capped(ua)); ok {
			s.hit(h, model.LocHeader, "header.user-agent", ua)
		}
	}
}

// checkRoute reports an unknown route and inspects the path: declared
// parameters are validated, undeclared ones and a wildcard rest are scanned,
// and without a matched route the whole decoded path is scanned.
func (s *state) checkRoute() {
	if s.e.table != nil && !s.routed {
		s.engineMatch(ruleUnknownRoute, model.CatRoute, model.SeverityLow, s.e.unknownRoute, model.LocPath, "path", s.path)
	}
	if !s.routed {
		s.scan(model.LocPath, "path", s.path)
		return
	}
	for _, name := range slices.Sorted(maps.Keys(s.params)) {
		v := s.params[name]
		if name == "*" {
			if v != "" {
				s.scan(model.LocPath, "path", v)
			}
			continue
		}
		field := joinField("path", name)
		if spec, ok := s.route.Field(model.LocPath, name); ok {
			s.typed(model.LocPath, field, spec, v, true)
		} else {
			s.scan(model.LocPath, field, v)
		}
	}
}

// typed validates a declared value. A mismatch is AEG-SCHEMA-001 (block).
// Valid string-like values (string, text, email, url) are still scanned as
// defense in depth; url values also get the SSRF rules. Fully constrained
// types (uuid, int, number, bool, enum, phone) skip the detectors.
func (s *state) typed(loc model.Location, field string, spec policy.FieldSpec, v string, isString bool) {
	if s.stop {
		return
	}
	if !policy.Validate(spec, v, isString) {
		s.engineMatch(ruleSchemaType, model.CatSchema, model.SeverityMedium, model.ActionBlock, loc, field, v)
		return
	}
	switch spec.Type {
	case policy.TypeURL:
		if h, ok := detect.SSRF(s.capped(v)); ok {
			s.hit(h, loc, field, v)
		}
		s.scan(loc, field, v)
	case policy.TypeString, policy.TypeText, policy.TypeEmail:
		s.scan(loc, field, v)
	}
}

// value inspects one query, form or JSON value. On a matched route whose
// specLoc map is declared, a declared name is typed and an undeclared one
// is AEG-SCHEMA-002 (route or config unknown-fields action) and then
// treated as untyped. A route that declares no map for the location does
// not model it, so its values are untyped without a schema match.
// Untyped strings are scanned; untyped JSON numbers and booleans are not.
func (s *state) value(loc, specLoc model.Location, field, name, v string, isString bool) {
	if s.stop {
		return
	}
	if s.routed && s.declares(specLoc) {
		if spec, ok := s.route.Field(specLoc, name); ok {
			s.typed(loc, field, spec, v, isString)
			return
		}
		act := s.e.unknownFields
		if s.route.Route.UnknownFields != nil {
			act = *s.route.Route.UnknownFields
		}
		s.engineMatch(ruleSchemaUnknown, model.CatSchema, model.SeverityLow, act, loc, field, v)
	}
	if isString {
		s.scan(loc, field, v)
	}
}

func (s *state) declares(loc model.Location) bool {
	switch loc {
	case model.LocQuery:
		return s.route.Route.Query != nil
	case model.LocBody:
		return s.route.Route.Body != nil
	}
	return false
}

// limitPairs returns the prefix of an &-separated string holding at most n
// non-empty segments, and whether a non-empty segment was cut off.
func limitPairs(raw string, n int) (string, bool) {
	count := 0
	for i := 0; i < len(raw); {
		j := strings.IndexByte(raw[i:], '&')
		end := len(raw)
		if j >= 0 {
			end = i + j
		}
		if end > i {
			if count == n {
				return strings.TrimRight(raw[:i], "&"), true
			}
			count++
		}
		i = end + 1
	}
	return raw, false
}

// pairs inspects query or form pairs: key rules (NoSQL operator keys,
// session identifiers) and the value, typed against the route's specLoc
// map (query specs for the query string, body specs for a form body).
func (s *state) pairs(loc, specLoc model.Location, prefix string, kvs []normalize.KV) {
	for _, kv := range kvs {
		if s.stop {
			return
		}
		field := joinField(prefix, kv.Key)
		if h, ok := detect.QueryKey(s.capped(kv.Key)); ok {
			s.hit(h, loc, field, kv.Key)
		}
		if h, ok := detect.Session(s.capped(kv.Key), s.capped(kv.Value)); ok {
			s.hit(h, loc, field, kv.Key+"="+kv.Value)
		}
		s.value(loc, specLoc, field, kv.Key, kv.Value, true)
	}
}

func (s *state) checkQuery() {
	if s.stop || s.req.RawQuery == "" {
		return
	}
	raw, over := limitPairs(s.req.RawQuery, s.e.lim.MaxFields)
	if over {
		s.protoMatch(ruleLimit, model.LocQuery, "query", "")
	}
	s.pairs(model.LocQuery, model.LocQuery, "query", normalize.ParseQuery(raw))
}

func mediaType(ct string) string {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mt, _, _ = strings.Cut(ct, ";")
	}
	return strings.ToLower(strings.TrimSpace(mt))
}

// checkBody inspects at most MaxBodyBytes of the body (protocol reports a
// larger body) according to its media type. Bodies of other media types
// are scanned raw only when textual (text/*); binary bodies are not.
func (s *state) checkBody() {
	body := s.req.Body
	if s.stop || len(body) == 0 {
		return
	}
	if int64(len(body)) > s.e.lim.MaxBodyBytes {
		body = body[:s.e.lim.MaxBodyBytes]
	}
	ct := s.req.Header.Get("Content-Type")
	switch mt := mediaType(ct); {
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		s.checkJSON(body)
	case mt == "application/x-www-form-urlencoded":
		raw, over := limitPairs(string(body), s.e.lim.MaxFields)
		if over {
			s.protoMatch(ruleLimit, model.LocBody, "form", "")
		}
		s.pairs(model.LocBody, model.LocBody, "form", normalize.ParseForm([]byte(raw)))
	case strings.HasPrefix(mt, "multipart/"):
		s.checkMultipart(body, ct)
	case s.e.proto.AllowXML && (mt == "application/xml" || mt == "text/xml"):
		v := s.capValue(model.LocBody, "body", string(body))
		if h, ok := detect.XXE(v); ok {
			s.hit(h, model.LocBody, "body", v)
		}
		s.scan(model.LocBody, "body", v)
	case strings.HasPrefix(mt, "text/"):
		s.scan(model.LocBody, "body", string(body))
	}
}

// checkJSON walks the body: keys go to the NoSQL and prototype-pollution
// rules, values to value(). Too many fields or too deep nesting is
// AEG-PROTO-010; a syntax error is AEG-PROTO-020 and the raw body prefix is
// scanned, so an attack in the unparsable part is still seen.
func (s *state) checkJSON(body []byte) {
	err := normalize.WalkJSON(body, s.e.lim, func(v normalize.JSONValue) {
		if s.stop {
			return
		}
		field := "body"
		if v.Path != "" {
			field = joinField("body", v.Path)
		}
		if v.IsKey {
			if h, ok := detect.JSONKey(v.Key); ok {
				s.hit(h, model.LocBody, field, v.Key)
			}
			return
		}
		if v.IsString {
			if h, ok := detect.Session(s.capped(v.Key), s.capped(v.Value)); ok {
				s.hit(h, model.LocBody, field, v.Key+"="+v.Value)
			}
		}
		s.value(model.LocBody, model.LocBody, field, v.Path, v.Value, v.IsString)
	})
	switch {
	case errors.Is(err, normalize.ErrLimit):
		s.protoMatch(ruleLimit, model.LocBody, "body", "")
	case errors.Is(err, normalize.ErrMalformed):
		s.protoMatch(ruleMalformed, model.LocBody, "body", "")
		s.scan(model.LocBody, "body", string(body))
	}
}

// checkMultipart inspects non-file parts like form fields; file parts are
// never read or scanned. A value cut at MaxValueLen is AEG-PROTO-011, too
// many parts AEG-PROTO-010, and a parse failure AEG-PROTO-020 (the parts
// read before it are still inspected).
func (s *state) checkMultipart(body []byte, ct string) {
	parts, err := normalize.ParseMultipart(body, ct, s.e.lim)
	for _, p := range parts {
		if s.stop {
			return
		}
		if p.IsFile {
			continue
		}
		field := joinField("form", p.Name)
		if p.Truncated {
			s.protoMatch(ruleValueTooLong, model.LocBody, field, p.Value)
		}
		if h, ok := detect.Session(s.capped(p.Name), p.Value); ok {
			s.hit(h, model.LocBody, field, p.Name+"="+p.Value)
		}
		s.value(model.LocBody, model.LocBody, field, p.Name, p.Value, true)
	}
	switch {
	case err == nil:
	case errors.Is(err, normalize.ErrLimit):
		s.protoMatch(ruleLimit, model.LocBody, "form", "")
	default:
		s.protoMatch(ruleMalformed, model.LocBody, "body", "")
	}
}

func (s *state) checkCookies() {
	if s.stop {
		return
	}
	kvs := normalize.ParseCookies(s.req.Header)
	if len(kvs) > s.e.lim.MaxFields {
		s.protoMatch(ruleLimit, model.LocCookie, "cookie", "")
		kvs = kvs[:s.e.lim.MaxFields]
	}
	for _, kv := range kvs {
		s.scan(model.LocCookie, joinField("cookie", kv.Key), kv.Value)
	}
}

// checkHeaders scans User-Agent, Referer and the configured extra headers.
// SSRF hits are ignored on Referer: the server never fetches it, and a
// browser on an internal or localhost page sends one legitimately.
func (s *state) checkHeaders() {
	for _, v := range s.req.Header.Values("User-Agent") {
		s.scan(model.LocHeader, "header.user-agent", v)
	}
	for _, v := range s.req.Header.Values("Referer") {
		if s.stop {
			return
		}
		v = s.capValue(model.LocHeader, "header.referer", v)
		for _, h := range detect.ScanText(v) {
			if h.Category != model.CatSSRF {
				s.hit(h, model.LocHeader, "header.referer", v)
			}
		}
	}
	for _, name := range s.e.inspectHeaders {
		field := "header." + strings.ToLower(name)
		for _, v := range s.req.Header.Values(name) {
			s.scan(model.LocHeader, field, v)
		}
	}
}

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
