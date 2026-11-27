package engine

import (
	"errors"
	"maps"
	"mime"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ergasterion-dev/aegolith/internal/detect"
	"github.com/ergasterion-dev/aegolith/internal/model"
	"github.com/ergasterion-dev/aegolith/internal/normalize"
	"github.com/ergasterion-dev/aegolith/internal/policy"
)

// checkProbeAndAgent runs the probe-path and backup-file rules on the
// decoded path and the scanner rule on every User-Agent value.
//
// A declared route is never judged by the scanner path rules for text its
// author wrote: a probe-path match whose text lies wholly in literal
// segments of the route the request matched (GET
// /api/v1/stores/:id/actuator/health) is not reported. A match that
// touches a parameter or wildcard segment still counts, so "/:slug" or a
// trailing "*" does not switch the rules off for "/.git/config"; so does
// every match on an unrouted request (an undeclared path or method, a
// literal sent percent-encoded or in another case on a case-sensitive
// table, an empty segment). Other matches in the same path are reported
// as before. The route is the one matchRoute found, with the router's own
// rules (raw path, case folding, HEAD to GET). User agents and every
// other detector are unaffected.
//
// Accepted misses (declared routes, alpha.6; the same list is in
// docs/threat-model.md, testdata/corpus/README.md and
// TestDeclaredRouteAcceptedMisses):
//  1. A probe-path match whose text lies wholly in literal segments of the
//     declared route the request matched: `GET
//     /api/v1/stores/7/actuator/health` when `GET
//     /api/v1/stores/:id/actuator/health` is declared, and `GET
//     /actuator/health` when `GET /actuator/health` is declared (for a
//     root name such as `/actuator` or `/wp-admin` the text runs to the
//     end of the path). The route's own handler answers it only if the
//     server picks that handler: Fiber serves the first registered
//     handler that matches, not the most specific one (with
//     `/actuator/:ep` registered before `/actuator/health` and both
//     declared, the `:ep` handler answers `GET /actuator/health`).
//  2. The same request as `HEAD` for a `GET` route, and in other letter
//     case when routes fold case (`/API/V1/Stores/7/Actuator/Health`). A
//     trailing slash on only one of the template and the request, and
//     `%2F` in any case in a parameter or wildcard segment, excuse
//     nothing: ServeMux, Fiber `StrictRouting` and Fiber `UnescapePath`
//     can send those to another handler.
func (s *state) checkProbeAndAgent() {
	if h, ok := detect.ProbePathExcept(s.path, s.declaredLiteral()); ok {
		s.hit(h, model.LocPath, "path", s.path)
	}
	for _, ua := range s.req.Header.Values("User-Agent") {
		if h, ok := detect.UserAgent(s.capped(ua)); ok {
			s.hit(h, model.LocHeader, "header.user-agent", ua)
		}
	}
}

// declaredLiteral returns the excuse for ProbePathExcept: whether the
// decoded path range [start, end) lies wholly in segments that the
// matched route's template spells literally. It is nil without a matched
// route. The per-byte map is built on the first call only (most requests
// raise no probe match and pay nothing). It decodes each raw segment on
// its own, as matchRoute decodes parameters, and joins them back; if that
// does not rebuild s.path exactly, nothing is excused.
func (s *state) declaredLiteral() func(start, end int) bool {
	if !s.routed {
		return nil
	}
	// Two forms excuse nothing, because a common Go router may send them
	// to another handler than the declared one: a final '/' on only one
	// of the template and the request, added or dropped (ServeMux, Fiber
	// StrictRouting), and an encoded '/' in a parameter or wildcard
	// segment (Fiber UnescapePath splits on it). They are not all such
	// forms. The path "/" has no final slash to add or drop.
	raw, tmpl := s.req.RawPath, s.route.Route.Path
	added := len(raw) > 1 && strings.HasSuffix(raw, "/") && !strings.HasSuffix(tmpl, "/")
	dropped := len(tmpl) > 1 && strings.HasSuffix(tmpl, "/") && !strings.HasSuffix(raw, "/")
	if added || dropped {
		return nil
	}
	for i, seg := range policy.Segments(raw) {
		if !s.route.Literal(i) && hasEncodedSlash(seg) {
			return nil
		}
	}
	var mask []byte // per byte of s.path: 0 outside literal segments, 1 in one, 2 a separator
	built := false
	return func(start, end int) bool {
		if !built {
			built = true
			mask = literalMask(s.req.RawPath, s.path, s.route)
		}
		if mask == nil || start < 0 || end > len(mask) || start >= end {
			return false
		}
		lit := false
		for _, b := range mask[start:end] {
			if b == 0 {
				return false
			}
			lit = lit || b == 1
		}
		return lit
	}
}

// hasEncodedSlash reports whether seg holds "%2F" in any case.
func hasEncodedSlash(seg string) bool {
	for i := 0; i+2 < len(seg); i++ {
		if seg[i] == '%' && seg[i+1] == '2' && (seg[i+2] == 'F' || seg[i+2] == 'f') {
			return true
		}
	}
	return false
}

// literalMask maps each byte of decoded (the decoded form of raw) to the
// kind of raw segment it came from (see declaredLiteral), or returns nil
// when decoding raw segment by segment does not give decoded. Segments are
// split exactly as policy.Table.Match splits them.
func literalMask(raw, decoded string, m policy.Matched) []byte {
	mask := make([]byte, 0, len(decoded))
	rest := raw
	lead := strings.HasPrefix(rest, "/")
	if lead {
		mask = append(mask, 2)
		rest = rest[1:]
	}
	trail := strings.HasSuffix(rest, "/")
	if trail {
		rest = rest[:len(rest)-1]
	}
	var b strings.Builder
	if lead {
		b.WriteByte('/')
	}
	if rest != "" {
		for i, seg := range policy.Segments(raw) {
			if i > 0 {
				b.WriteByte('/')
				mask = append(mask, 2)
			}
			d, _ := normalize.DecodeValue(seg)
			b.WriteString(d)
			k := byte(0)
			if m.Literal(i) {
				k = 1
			}
			for range len(d) {
				mask = append(mask, k)
			}
		}
	}
	if trail {
		b.WriteByte('/')
		mask = append(mask, 2)
	}
	if b.String() != decoded || len(mask) != len(decoded) {
		return nil
	}
	return mask
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
// defense in depth; url values also get the SSRF rules. Of a base64 or
// base64url value the text detectors scan the decoded form and not the
// encoded one.
// Fully constrained types (uuid, uuid_lenient, int, number, bool, enum,
// phone) skip the detectors.
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
	case policy.TypeBase64:
		s.decoded(loc, field, v, policy.DecodeBase64)
	case policy.TypeBase64URL:
		s.decoded(loc, field, v, policy.DecodeBase64URL)
	}
}

// decoded inspects the text a valid base64 or base64url value encodes, read
// once by decode, as a JSON body value is inspected, in every location; the
// matches carry loc and field. Decoded text holds real line breaks wherever
// it was sent, so a query value is not read with detect.ScanQueryText, whose
// command rule would flag ordinary multi-line text. A query, form or JSON
// value also gets the session identifier rule, which its caller ran on the
// encoded value (that call covers the key); then the text detectors run.
func (s *state) decoded(loc model.Location, field, v string, decode func(string) (string, bool)) {
	text, ok := decode(v)
	if !ok { // typed validated v
		return
	}
	if loc != model.LocPath {
		if h, ok := detect.Session("", s.capped(text)); ok {
			s.hit(h, loc, field, text)
		}
	}
	s.scanWindowsWith(detect.ScanText, loc, field, text, 0, nil, "")
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
			s.scanKey(loc, field, kv.Key)
			// A pair splits on its first '=', so an unencoded injection such
			// as ?1' OR '1'='1=x leaves "1' OR '1'" in the key and "'1=x" in
			// the value, neither of which reads as SQL alone: the '=' sat
			// between two quoted operands. Only that shape, a key that ends
			// with a quote and a value that starts with the same quote, is
			// checked again as the whole decoded pair; prose keys with an
			// apostrophe (children's size=6-7 or 8) never take this path.
			if !s.stop && !s.exhausted && splitAtQuotedEquals(kv.Key, kv.Value) {
				s.keySQLi(loc, field, s.capped(s.capped(kv.Key)+"="+s.capped(kv.Value)))
			}
			if h, ok := detect.Session(s.capped(kv.Key), s.capped(kv.Value)); ok {
				s.hit(h, loc, field, kv.Key+"="+kv.Value)
			}
			s.value(loc, specLoc, field, kv.Key, kv.Value, true)
		}
	}
}

// splitAtQuotedEquals reports whether a pair looks split at an '=' that
// joined two quoted SQL operands: the key ends with ' or " and the value
// starts with the same quote.
func splitAtQuotedEquals(k, v string) bool {
	return k != "" && v != "" && (k[len(k)-1] == '\'' || k[len(k)-1] == '"') && v[0] == k[len(k)-1]
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

// binaryMediaType reports whether mt (lower-case, no parameters) names
// content that is not read as text, so its body is not inspected. checkBody
// walks JSON (a "+json" suffix included) before it asks. A "model/" type with
// the "+xml" suffix is XML, not binary.
func binaryMediaType(mt string) bool {
	switch mt {
	case "application/octet-stream", "application/pdf", "application/zip",
		"application/gzip", "application/x-gzip", "application/x-tar",
		"application/x-7z-compressed", "application/x-protobuf",
		"application/protobuf", "application/vnd.google.protobuf",
		"application/msgpack", "application/x-msgpack", "application/vnd.msgpack",
		"application/cbor", "application/wasm", "application/msword",
		"application/vnd.ms-excel", "application/vnd.ms-powerpoint",
		"application/zstd", "application/x-zstd", "application/x-bzip2",
		"application/x-xz", "application/x-lz4", "application/x-brotli",
		"application/vnd.rar", "application/x-rar-compressed",
		"application/java-archive", "application/vnd.android.package-archive",
		"application/vnd.sqlite3", "application/x-sqlite3", "application/bson",
		"application/avro", "application/vnd.apache.parquet",
		"application/x-parquet", "application/vnd.apache.thrift.binary",
		"application/x-thrift", "application/x-rpm",
		"application/vnd.debian.binary-package", "application/x-iso9660-image":
		return true
	}
	for _, prefix := range [...]string{
		"image/", "audio/", "video/", "font/", "application/grpc",
		"application/vnd.openxmlformats-officedocument.",
		"application/vnd.oasis.opendocument.",
	} {
		if strings.HasPrefix(mt, prefix) {
			return true
		}
	}
	for _, suffix := range [...]string{"+zip", "+gzip", "+cbor", "+der"} {
		if strings.HasSuffix(mt, suffix) {
			return true
		}
	}
	return strings.HasPrefix(mt, "model/") && !xmlMediaType(mt)
}

// xmlMediaType reports whether mt (lower-case, no parameters) is XML.
func xmlMediaType(mt string) bool {
	return mt == "application/xml" || mt == "text/xml" || strings.HasSuffix(mt, "+xml")
}

// xmlDeclaration matches an XML declaration at the very start of a body,
// where only a UTF-8 byte order mark and ASCII whitespace may precede it:
// version "1.<digit>", then optionally encoding, then optionally
// standalone, each quoted, and nothing else.
var xmlDeclaration = regexp.MustCompile(`\A\x{FEFF}?[\t\n\v\f\r ]*<\?xml` +
	`[\t\n\r ]+version=(?:"1\.[0-9]"|'1\.[0-9]')` +
	`(?:[\t\n\r ]+encoding=(?:"[A-Za-z][A-Za-z0-9._-]{0,39}"|'[A-Za-z][A-Za-z0-9._-]{0,39}'))?` +
	`(?:[\t\n\r ]+standalone=(?:"(?:yes|no)"|'(?:yes|no)'))?` +
	`[\t\n\r ]*\?>`)

// xmlDeclarationLen returns the length of the XML declaration body starts
// with, what precedes it included, or 0 without one that xmlDeclaration
// matches.
func xmlDeclarationLen(body string) int {
	if loc := xmlDeclaration.FindStringIndex(body); loc != nil {
		return loc[1]
	}
	return 0
}

// checkBody inspects the body according to its media type. Protocol
// reports a body over MaxBodyBytes (AEG-PROTO-003, block by default, so in
// enforce mode an over-size body never gets this far); with that rule set to
// monitor, up to bodyInspectLimit (2 x MaxBodyBytes) of it is still inspected
// so an attack placed after padding is seen. JSON, urlencoded form and
// multipart bodies are parsed; binary types (binaryMediaType, which is asked
// before XML, so image/svg+xml is binary) are not inspected; XML is scanned
// as text with the XXE rule, the text detectors not seeing a leading XML
// declaration (xmlDeclaration), which libinjection reads as markup; every
// other body, one without a content type included, is scanned as text.
// Whether the type was allowed is protocol's decision (AEG-PROTO-002) and
// does not change how the body is inspected.
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
		s.checkJSON(body, s.bodyCut(body))
	case mt == "application/x-www-form-urlencoded":
		s.pairs(model.LocBody, model.LocBody, "form", string(body), "form")
	case strings.HasPrefix(mt, "multipart/"):
		s.checkMultipart(body, ct, s.bodyCut(body))
	case binaryMediaType(mt):
		return
	case xmlMediaType(mt):
		text := string(body)
		s.scanWindowsAfter(model.LocBody, "body", text, xmlDeclarationLen(text), detect.XXE, "")
	default:
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
//
// cut reports that body is only a prefix of the request body (see bodyCut):
// an unexpected end of the JSON is then the cut, not a syntax error, so it
// does not raise AEG-PROTO-020; the raw scan still runs.
func (s *state) checkJSON(body []byte, cut bool) {
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
			s.scanKey(model.LocBody, field, v.Key)
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
	case cut && errors.Is(err, normalize.ErrIncomplete):
		// Cut short by an inspection cap: nothing to report, but the part
		// after the last complete value is still scanned raw.
	case errors.Is(err, normalize.ErrMalformed):
		s.protoMatch(ruleMalformed, model.LocBody, "body", "")
	default:
		return
	}
	s.scan(model.LocBody, "body", string(body))
}

// bodyCut reports whether body, what checkBody inspects, is only a prefix
// of the request body: either the engine cut it at bodyInspectLimit, or an
// adapter handed over a prefix of an over-cap body (longer than
// MaxBodyBytes, so AEG-PROTO-003 already reports it) shorter than its
// Content-Length. A body within MaxBodyBytes is never treated as cut, so a
// small incomplete body (or one whose decoded form is shorter than its
// compressed Content-Length) is still malformed.
func (s *state) bodyCut(body []byte) bool {
	n := int64(len(s.req.Body))
	if n > int64(len(body)) {
		return true
	}
	if n <= s.e.lim.MaxBodyBytes {
		return false
	}
	cl, err := strconv.ParseInt(strings.TrimSpace(s.req.Header.Get("Content-Length")), 10, 64)
	return err == nil && cl > n
}

// checkMultipart inspects non-file parts like form fields (quoted-printable
// parts arrive decoded); file parts are never read or scanned. Parsing is
// bounded by the body itself, not by MaxFields or MaxValueLen, so a long
// value is scanned in windows (AEG-PROTO-011) and parts beyond MaxFields
// raise AEG-PROTO-010 and are still inspected, under the scan budget. A
// parse failure is AEG-PROTO-020; the parts read before it are inspected.
// With these bounds ParseMultipart can neither truncate a value nor hit its
// part limit, so neither case is handled here. cut reports that body is
// only a prefix of the request body (see bodyCut): a failure caused only by
// the input ending inside the last part is then the cut, not a malformed
// body, and raises nothing.
func (s *state) checkMultipart(body []byte, ct string, cut bool) {
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
		s.scanKey(model.LocBody, field, p.Name)
		if h, ok := detect.Session(s.capped(p.Name), s.capped(p.Value)); ok {
			s.hit(h, model.LocBody, field, p.Name+"="+p.Value)
		}
		s.value(model.LocBody, model.LocBody, field, p.Name, p.Value, true)
	}
	if err != nil && !(cut && errors.Is(err, normalize.ErrIncomplete)) {
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
