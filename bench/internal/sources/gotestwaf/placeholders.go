package gotestwaf

import (
	"encoding/base64"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

const (
	// marker is where a RawRequest takes the payload.
	marker = "{{payload}}"
	// graphQLPath is the first endpoint the tool's GraphQL check tries.
	graphQLPath = "/graphql"
	// targetRoot stands for the URL the tool is pointed at. Only what follows
	// it reaches a line.
	targetRoot = "http://target.invalid"
	// nameBytes is how many random bytes the tool draws for a name.
	nameBytes = 5
	// boundaryBytes is how many random bytes a multipart boundary is made of.
	boundaryBytes = 30
)

// soapEnvelope is the document the SOAPBody placeholder sends. The three
// gaps take the element name, its content and the element name again.
var soapEnvelope = [4]string{
	`<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"` + "\n" +
		"\t" + `xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` + "\n" +
		"\t<soapenv:Header>\n" +
		"\t\t" + `<ns1:RequestHeader soapenv:actor="http://schemas.xmlsoap.org/soap/actor/next"` + "\n" +
		"\t\t\t" + `soapenv:mustUnderstand="0" xmlns:ns1="https://www.google.com/apis/ads/publisher/v202002">` + "\n" +
		"\t\t</ns1:RequestHeader>\n" +
		"\t</soapenv:Header>\n" +
		"\t<soapenv:Body>\n" +
		"\t\t" + `<getAdUnitsByStatement xmlns="https://www.google.com/apis/ads/publisher/v202002">` + "\n" +
		"\t\t\t<filterStatement>\n" +
		"\t\t\t\t<",
	">",
	"</",
	">\n" +
		"\t\t\t</filterStatement>\n" +
		"\t\t</getAdUnitsByStatement>\n" +
		"\t</soapenv:Body>\n" +
		"</soapenv:Envelope>",
}

// Reasons for which a combination is skipped.
const (
	reasonGRPC         = "gRPC placeholder: the tool makes a gRPC call, not a plain HTTP request"
	reasonPlaceholder  = "placeholder is not one of the tool's"
	reasonNoConfig     = "placeholder is named without the configuration it needs"
	reasonEncodeTwice  = "the placeholder's own encoding of the value fails"
	reasonTemplateHost = "the request template and the payload together name a public host"
	reasonMethod       = "the tool's HTTP client rejects the method of this request"
	reasonURL          = "the tool's HTTP client rejects the URL of this request"
	reasonHeader       = "the tool's HTTP client rejects a header of this request"
	reasonEmptyQuery   = "the request target ends in an empty query, which a case line cannot say"
	reasonQueryBytes   = "the query is not valid UTF-8, which a case line cannot carry"
	reasonHeaderBytes  = "a header value is not valid UTF-8, which a case line cannot carry"
	reasonHeaderTwice  = "two headers of the request have the same name"
	reasonFraming      = "the request sets Host, Content-Length, Transfer-Encoding or Trailer, which the tool's HTTP client does not send as written"
	reasonRequestID    = "the request sets X-Request-Id, which the sender replaces"
	reasonNoEncoding   = "the request sets an empty Accept-Encoding, next to which the tool's HTTP client sends its own"
)

// header is one request header.
type header struct{ name, value string }

// placeholder is one entry of a test case's placeholder list: where the
// encoded payload goes in the request.
type placeholder struct {
	name string
	// method is the configuration of a GraphQL placeholder.
	method string
	// raw is the configuration of a RawRequest placeholder.
	raw *rawConfig
}

// rawConfig is the request a RawRequest placeholder describes. Path, body and
// header values may hold the marker.
type rawConfig struct {
	method, path, body string
	headers            []header
}

// request is what a placeholder hands to the tool's HTTP client.
type request struct {
	method string
	// target follows the root URL of the tool's target: empty, or a path and
	// what the placeholder appends to it.
	target    string
	headers   []header
	body      string
	placement string
}

// request builds the request for a payload. encoded is the payload after the
// case's encoder; payload itself is only looked at, never sent. token gives
// the hex of n bytes that stand for the random bytes the tool draws.
func (p placeholder) request(payload, encoded string, token func(label string, n int) string) (req request, reason string) {
	name := func() string { return token("name", nameBytes) }
	post := func(contentType, body, placement string) request {
		req := request{method: "POST", body: body, placement: placement}
		if contentType != "" {
			req.headers = []header{{"Content-Type", contentType}}
		}
		return req
	}
	switch p.name {
	case "Header":
		return request{method: "GET", headers: []header{{"X-" + name(), encoded}}, placement: "header"}, ""
	case "UserAgent":
		return request{method: "GET", headers: []header{{"User-Agent", encoded}}, placement: "header"}, ""
	case "URLParam":
		return request{method: "GET", target: "/?" + name() + "=" + encoded, placement: "query"}, ""
	case "URLPath":
		return request{method: "GET", target: "/" + encoded, placement: "path"}, ""
	case "RequestBody":
		return post("", encoded, "body"), ""
	case "JSONBody":
		return post("application/json", encoded, "json"), ""
	case "XMLBody":
		return post("application/xml", encoded, "body"), ""
	case "HTMLForm":
		return post("application/x-www-form-urlencoded", name()+"="+encoded, "body"), ""
	case "HTMLMultipartForm":
		contentType, body, ok := multipartForm(name(), encoded, token("boundary", boundaryBytes))
		if !ok {
			return req, reasonEncodeTwice
		}
		return post(contentType, body, "body"), ""
	case "JSONRequest":
		return post("application/json", `{"test": true, "`+name()+`": "`+jsUnicode(encoded)+`"}`, "json"), ""
	case "SOAPBody":
		element := "ab" + name()
		content, ok := xmlEntity(encoded)
		if !ok {
			return req, reasonEncodeTwice
		}
		req = post("text/xml", soapEnvelope[0]+element+soapEnvelope[1]+content+soapEnvelope[2]+element+soapEnvelope[3], "body")
		req.headers = append([]header{{"SOAPAction", `"http://schemas.xmlsoap.org/soap/actor/next"`}}, req.headers...)
		return req, ""
	case "GraphQL":
		switch p.method {
		case "GET":
			return request{method: "GET", target: graphQLPath + "?query=" + encoded, placement: "query"}, ""
		case "POST":
			req = post("", encoded, "body")
			req.target = graphQLPath
			return req, ""
		}
		return req, reasonNoConfig
	case "RawRequest":
		if p.raw == nil {
			return req, reasonNoConfig
		}
		return p.raw.request(payload, encoded)
	case "gRPC":
		return req, reasonGRPC
	}
	return req, reasonPlaceholder
}

// multipartForm returns the body and Content-Type of a form with one field.
func multipartForm(name, value, boundary string) (contentType, body string, ok bool) {
	var b strings.Builder
	w := multipart.NewWriter(&b)
	if err := w.SetBoundary(boundary); err != nil {
		return "", "", false
	}
	field, err := w.CreateFormField(name)
	if err != nil {
		return "", "", false
	}
	if _, err := field.Write([]byte(value)); err != nil {
		return "", "", false
	}
	if err := w.Close(); err != nil {
		return "", "", false
	}
	return w.FormDataContentType(), b.String(), true
}

// request fills the marker in. The value is escaped as a path segment in the
// path, on top of the case's encoder, and put as it is anywhere else.
func (c rawConfig) request(payload, encoded string) (req request, reason string) {
	templates := []string{c.path, c.body}
	for _, h := range c.headers {
		templates = append(templates, h.value)
	}
	for _, template := range templates {
		// The payload and the templates have had their hosts replaced one by
		// one; a host that only the two together spell has not.
		if joined := strings.ReplaceAll(template, marker, payload); cases.RewriteCallbacks(joined) != joined {
			return req, reasonTemplateHost
		}
	}
	req = request{
		method:    c.method,
		target:    strings.ReplaceAll("/"+strings.TrimPrefix(c.path, "/"), marker, url.PathEscape(encoded)),
		body:      strings.ReplaceAll(c.body, marker, encoded),
		placement: "raw",
	}
	for _, h := range c.headers {
		req.headers = append(req.headers, header{h.name, strings.ReplaceAll(h.value, marker, encoded)})
	}
	return req, ""
}

// line is the request as the tool's HTTP client (Go's net/http) sends it:
// the method, the target as net/url parses and writes it again, the headers
// of the placeholder, the default headers of the tool's configuration for
// every header the request does not set, and the body. Without a default the
// client adds its own User-Agent and Accept-Encoding. payloadIsAgent says
// that the placeholder is UserAgent, which takes no default User-Agent.
//
// A request that the client refuses to send, that a case line cannot say or
// that the bench's sender would not send the same way gives a reason instead.
func (r request) line(defaults []header, payloadIsAgent bool) (line cases.Line, reason string) {
	method := r.method
	if method == "" {
		method = "GET"
	}
	if !isToken(method) {
		return line, reasonMethod
	}
	// Parsing drops a fragment and fails on a control character or, in the
	// path, on a "%" that starts no escape. Writing escapes the path unless
	// it is validly escaped already, and leaves the query alone.
	u, err := url.Parse(targetRoot + r.target)
	if err != nil {
		return line, reasonURL
	}
	rawPath, rawQuery, hasQuery := strings.Cut(u.RequestURI(), "?")
	switch {
	case hasQuery && rawQuery == "":
		return line, reasonEmptyQuery
	case !utf8.ValidString(rawQuery):
		return line, reasonQueryBytes
	}

	sent := make(map[string]string, len(r.headers)+len(defaults)+2)
	for _, h := range r.headers {
		name := textproto.CanonicalMIMEHeaderKey(h.name)
		if _, ok := sent[name]; ok {
			return line, reasonHeaderTwice
		}
		sent[name] = h.value
	}
	for _, d := range defaults {
		if payloadIsAgent && d.name == "User-Agent" {
			continue
		}
		if sent[d.name] == "" {
			sent[d.name] = d.value
		}
	}
	for name, value := range sent {
		if !isToken(name) || hasControlByte(value) {
			return line, reasonHeader
		}
	}
	for _, name := range []string{"Host", "Content-Length", "Transfer-Encoding", "Trailer"} {
		if _, ok := sent[name]; ok {
			return line, reasonFraming
		}
	}
	if _, ok := sent["X-Request-Id"]; ok {
		return line, reasonRequestID
	}
	// The client sends no empty User-Agent, and its own name without one.
	switch agent, ok := sent["User-Agent"]; {
	case !ok:
		sent["User-Agent"] = "Go-http-client/1.1"
	case agent == "":
		delete(sent, "User-Agent")
	}
	// The client asks for gzip unless the request says what it accepts.
	if sent["Accept-Encoding"] == "" && sent["Range"] == "" && method != "HEAD" {
		if _, ok := sent["Accept-Encoding"]; ok {
			return line, reasonNoEncoding
		}
		sent["Accept-Encoding"] = "gzip"
	}
	for name, value := range sent {
		if !utf8.ValidString(value) {
			return line, reasonHeaderBytes
		}
		// The client sends no blanks around a value.
		sent[name] = strings.Trim(value, " \t")
	}

	line.Method = method
	line.Path = rawPath
	line.RawQuery = rawQuery
	line.Headers = sent
	line.Placement = r.placement
	if utf8.ValidString(r.body) {
		line.Body = r.body
	} else {
		line.BodyBase64 = base64.StdEncoding.EncodeToString([]byte(r.body))
	}
	return line, ""
}

// isToken reports whether s is an RFC 9110 token: what net/http accepts as a
// method or a header name.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

// hasControlByte reports whether s holds a byte that net/http refuses in a
// header value: a control character other than a tab.
func hasControlByte(s string) bool {
	for i := range len(s) {
		if c := s[i]; c < 0x20 && c != '\t' || c == 0x7f {
			return true
		}
	}
	return false
}

// Reasons for which the tool cannot load a test case file. It reads all its
// files at once and stops at the first of these.
const (
	cannotLoad         = "the tool cannot load this file: "
	reasonKind         = cannotLoad + "a placeholder is neither a name nor a mapping"
	reasonKeys         = cannotLoad + "a placeholder mapping does not have exactly one name"
	reasonConfig       = cannotLoad + "a placeholder's configuration is not a mapping"
	reasonConfigured   = cannotLoad + "a configured placeholder is not one of the tool's"
	reasonGraphQL      = cannotLoad + "GraphQL needs the method GET or POST"
	reasonRawMethod    = cannotLoad + "RawRequest needs a method that is a string"
	reasonRawPath      = cannotLoad + "the RawRequest path is not a string"
	reasonRawBody      = cannotLoad + "the RawRequest body is not a string"
	reasonRawHeaders   = cannotLoad + "the RawRequest headers are not a mapping"
	reasonRawHeader    = cannotLoad + "a RawRequest header is not a string"
	reasonRepeatedKey  = "a placeholder's configuration names a key twice"
	reasonRepeatedName = "a RawRequest names a header twice"
)

// known are the tool's placeholders.
var known = []string{
	"GraphQL", "gRPC", "Header", "HTMLForm", "HTMLMultipartForm", "JSONBody", "JSONRequest",
	"RawRequest", "RequestBody", "SOAPBody", "URLParam", "URLPath", "UserAgent", "XMLBody",
}

// readPlaceholder reads one entry of a placeholder list: a name, or a
// mapping of one name to that placeholder's configuration. A name is taken
// as it is, known or not; the tool finds out when it sends.
func readPlaceholder(n *yaml.Node) (p placeholder, reason string) {
	n = resolve(n)
	if name, ok := text(n); ok {
		return placeholder{name: name}, ""
	}
	if n.Kind != yaml.MappingNode {
		return p, reasonKind
	}
	if len(n.Content) != 2 {
		return p, reasonKeys
	}
	name, ok := text(n.Content[0])
	if !ok {
		return p, reasonKeys
	}
	if !slices.Contains(known, name) {
		return p, reasonConfigured
	}
	config, reason := readMapping(n.Content[1])
	if reason != "" {
		return p, reason
	}
	p.name = name
	switch name {
	case "GraphQL":
		method, ok := text(config["method"])
		if !ok || method != "GET" && method != "POST" {
			return p, reasonGraphQL
		}
		p.method = method
	case "RawRequest":
		p.raw, reason = readRaw(config)
	}
	return p, reason
}

// readRaw reads the configuration of a RawRequest. Hosts in its templates
// are replaced like hosts in a payload.
func readRaw(config map[string]*yaml.Node) (c *rawConfig, reason string) {
	c = &rawConfig{path: "/"}
	var ok bool
	if c.method, ok = text(config["method"]); !ok {
		return nil, reasonRawMethod
	}
	if n, set := config["path"]; set {
		if c.path, ok = text(n); !ok {
			return nil, reasonRawPath
		}
		if c.path == "" {
			c.path = "/"
		}
	}
	if n, set := config["body"]; set {
		if c.body, ok = text(n); !ok {
			return nil, reasonRawBody
		}
	}
	if n, set := config["headers"]; set {
		n = resolve(n)
		if n.Kind != yaml.MappingNode {
			return nil, reasonRawHeaders
		}
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			name, okName := text(n.Content[i])
			value, okValue := text(n.Content[i+1])
			if !okName || !okValue {
				return nil, reasonRawHeader
			}
			if seen[name] {
				return nil, reasonRepeatedName
			}
			seen[name] = true
			c.headers = append(c.headers, header{name, value})
		}
	}

	// The marker survives: only the bytes that spell a host change, and a
	// brace spells none.
	c.path, c.body = cases.RewriteCallbacks(c.path), cases.RewriteCallbacks(c.body)
	for i, h := range c.headers {
		c.headers[i].value = cases.RewriteCallbacks(h.value)
	}
	return c, ""
}

// readMapping reads a placeholder's configuration: a mapping with string
// keys, each used once. The tool would use the last of two equal keys;
// such a file is left out instead.
func readMapping(n *yaml.Node) (map[string]*yaml.Node, string) {
	n = resolve(n)
	if n.Kind != yaml.MappingNode {
		return nil, reasonConfig
	}
	out := make(map[string]*yaml.Node, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, ok := text(n.Content[i])
		if !ok {
			return nil, reasonConfig
		}
		if _, ok := out[key]; ok {
			return nil, reasonRepeatedKey
		}
		out[key] = n.Content[i+1]
	}
	return out, ""
}

// resolve follows an alias to the node it names.
func resolve(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode && n.Alias != nil {
		return n.Alias
	}
	return n
}

// yaml11Words are plain scalars that the tool's YAML 1.1 reader takes for
// booleans and this package's reader takes for strings.
var yaml11Words = []string{"y", "Y", "yes", "Yes", "YES", "n", "N", "no", "No", "NO", "on", "On", "ON", "off", "Off", "OFF"}

// text returns the value of a scalar that the tool reads as a string. A
// number, a boolean, a null or a binary value is not one.
func text(n *yaml.Node) (string, bool) {
	n = resolve(n)
	if n == nil || n.Kind != yaml.ScalarNode || n.ShortTag() != "!!str" {
		return "", false
	}
	if n.Style == 0 && slices.Contains(yaml11Words, n.Value) {
		return "", false
	}
	return n.Value, true
}
