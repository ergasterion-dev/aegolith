package engine

import (
	"errors"
	"maps"
	"mime"
	"slices"
	"strings"

	"github.com/ergasterion-dev/aegolith/internal/detect"
	"github.com/ergasterion-dev/aegolith/internal/model"
	"github.com/ergasterion-dev/aegolith/internal/normalize"
	"github.com/ergasterion-dev/aegolith/internal/policy"
)

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
		s.scanWindows(loc, field, v, detect.SSRF, "")
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

// pairs inspects the &-separated pairs of a query string or form body: key
// rules (NoSQL operator keys, session identifiers) and the value, typed
// against the route's specLoc map (query specs for the query string, body
// specs for a form body). Pairs beyond MaxFields raise AEG-PROTO-010 once
// (limitField) and are still inspected; the scan budget bounds the work.
// Segments are decoded one at a time, so no slice of every pair is built.
func (s *state) pairs(loc, specLoc model.Location, prefix, raw, limitField string) {
	count := 0
	for raw != "" && !s.stop {
		var seg string
		seg, raw, _ = strings.Cut(raw, "&")
		if seg == "" {
			continue
		}
		if count++; count == s.e.lim.MaxFields+1 {
			s.protoMatch(ruleLimit, loc, limitField, "")
		}
		for _, kv := range normalize.ParseQuery(seg) {
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
}

func (s *state) checkQuery() {
	if s.stop || s.req.RawQuery == "" {
		return
	}
	s.pairs(model.LocQuery, model.LocQuery, "query", s.req.RawQuery, "query")
}

func mediaType(ct string) string {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mt, _, _ = strings.Cut(ct, ";")
	}
	return strings.ToLower(strings.TrimSpace(mt))
}

// checkBody inspects the body according to its media type. Protocol
// reports a body over MaxBodyBytes (AEG-PROTO-003, monitor); up to
// bodyInspectLimit (2 x MaxBodyBytes) of it is still inspected so an attack
// placed after padding is seen. Bodies of other media types are scanned raw only
// when textual (text/*); binary bodies are not.
func (s *state) checkBody() {
	body := s.req.Body
	if s.stop || len(body) == 0 {
		return
	}
	if n := s.e.bodyInspectLimit(); int64(len(body)) > n {
		body = body[:n]
	}
	ct := s.req.Header.Get("Content-Type")
	switch mt := mediaType(ct); {
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		s.checkJSON(body)
	case mt == "application/x-www-form-urlencoded":
		s.pairs(model.LocBody, model.LocBody, "form", string(body), "form")
	case strings.HasPrefix(mt, "multipart/"):
		s.checkMultipart(body, ct)
	case s.e.proto.AllowXML && (mt == "application/xml" || mt == "text/xml"):
		s.scanWindows(model.LocBody, "body", string(body), detect.XXE, "")
	case strings.HasPrefix(mt, "text/"):
		s.scan(model.LocBody, "body", string(body))
	}
}

// checkJSON walks the body: keys go to the NoSQL and prototype-pollution
// rules, values to value(), and an object or array where a declared field
// expects a scalar is AEG-SCHEMA-001 (null is allowed: optional fields are
// often sent as null).
//
// The walk is not stopped at MaxFields: keys and values beyond it raise
// AEG-PROTO-010 once and are still inspected field by field, so
// field-scoped exclusions keep applying. WalkJSON gets a field limit just
// above anything the body could hold, so the body size (at most
// bodyInspectLimit) bounds the walk and the scan budget bounds detector
// work. Nesting deeper than MaxDepth (AEG-PROTO-010) and a syntax error
// (AEG-PROTO-020) stop the walk; the raw body is then scanned in windows so
// nothing after that point goes unseen. Known limitation: that raw scan
// reports hits on the field "body", so field-scoped exclusions do not
// apply to it (only to the fields walked before the stop).
func (s *state) checkJSON(body []byte) {
	lim := s.e.lim
	lim.MaxFields = len(body) + 1 // every counted item takes at least one byte
	fields := 0
	// WalkJSON reuses one Path string while the path is unchanged (every
	// element of an array), so the field name is rebuilt only when it changes.
	lastPath, field := "", "body"
	err := normalize.WalkJSON(body, lim, func(v normalize.JSONValue) {
		if s.stop {
			return
		}
		if v.Path != lastPath {
			lastPath, field = v.Path, "body"
			if v.Path != "" {
				field = joinField("body", v.Path)
			}
		}
		if v.IsContainer {
			if s.routed && s.declares(model.LocBody) {
				if _, ok := s.route.Field(model.LocBody, v.Path); ok {
					s.engineMatch(ruleSchemaType, model.CatSchema, model.SeverityMedium, model.ActionBlock, model.LocBody, field, "")
				}
			}
			return
		}
		if fields++; fields == s.e.lim.MaxFields+1 {
			s.protoMatch(ruleLimit, model.LocBody, "body", "")
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
	case errors.Is(err, normalize.ErrLimit): // only depth can trip it here
		s.protoMatch(ruleLimit, model.LocBody, "body", "")
	case errors.Is(err, normalize.ErrMalformed):
		s.protoMatch(ruleMalformed, model.LocBody, "body", "")
	default:
		return
	}
	s.scan(model.LocBody, "body", string(body))
}

// checkMultipart inspects non-file parts like form fields (quoted-printable
// parts arrive decoded); file parts are never read or scanned. Parsing is
// bounded by the body itself, not by MaxFields or MaxValueLen, so a long
// value is scanned in windows (AEG-PROTO-011) and parts beyond MaxFields
// raise AEG-PROTO-010 and are still inspected, under the scan budget. A
// parse failure is AEG-PROTO-020; the parts read before it are inspected.
// With these bounds ParseMultipart can neither truncate a value nor hit its
// part limit, so neither case is handled here.
func (s *state) checkMultipart(body []byte, ct string) {
	lim := s.e.lim
	lim.MaxFields, lim.MaxValueLen = len(body)+1, len(body)+1
	parts, err := normalize.ParseMultipart(body, ct, lim)
	count := 0
	for _, p := range parts {
		if s.stop {
			return
		}
		if p.IsFile {
			continue
		}
		if count++; count == s.e.lim.MaxFields+1 {
			s.protoMatch(ruleLimit, model.LocBody, "form", "")
		}
		field := joinField("form", p.Name)
		if h, ok := detect.QueryKey(s.capped(p.Name)); ok {
			s.hit(h, model.LocBody, field, p.Name)
		}
		if h, ok := detect.Session(s.capped(p.Name), s.capped(p.Value)); ok {
			s.hit(h, model.LocBody, field, p.Name+"="+p.Value)
		}
		s.value(model.LocBody, model.LocBody, field, p.Name, p.Value, true)
	}
	if err != nil {
		s.protoMatch(ruleMalformed, model.LocBody, "body", "")
	}
}

// checkCookies scans every cookie value; cookies beyond MaxFields raise
// AEG-PROTO-010 and are still scanned, under the scan budget.
func (s *state) checkCookies() {
	for i, kv := range normalize.ParseCookies(s.req.Header) {
		if s.stop {
			return
		}
		if i == s.e.lim.MaxFields {
			s.protoMatch(ruleLimit, model.LocCookie, "cookie", "")
		}
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
		s.scanWindows(model.LocHeader, "header.referer", v, nil, model.CatSSRF)
	}
	for _, name := range s.e.inspectHeaders {
		field := "header." + strings.ToLower(name)
		for _, v := range s.req.Header.Values(name) {
			s.scan(model.LocHeader, field, v)
		}
	}
}
