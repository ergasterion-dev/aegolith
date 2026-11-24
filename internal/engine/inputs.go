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
