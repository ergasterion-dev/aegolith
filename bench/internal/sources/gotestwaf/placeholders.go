package gotestwaf

import (
	"encoding/base64"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

const (
	// marker is where a RawRequest takes the payload.
	marker = "{{payload}}"
	// targetRoot stands for the URL the tool is pointed at. Only what follows
	// it reaches a line.
	targetRoot = "http://target.invalid"
	// nameBytes is how many random bytes the tool draws for a name.
	nameBytes = 5
	// boundaryBytes is how many random bytes a multipart boundary is made of.
	boundaryBytes = 30
)

// Reasons for which a combination is skipped.
const (
	reasonGRPC         = "gRPC placeholder: the tool makes a gRPC call, not a plain HTTP request"
	reasonGraphQL      = "GraphQL placeholder: the tool sends it only to a target that answers its GraphQL check"
	reasonSOAP         = "SOAPBody placeholder: the tool's envelope cannot be read from the tree"
	reasonPlaceholder  = "placeholder is not one of the tool's"
	reasonNoConfig     = "placeholder is named without the configuration it needs"
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
	// raw is the configuration of a RawRequest placeholder.
	raw *rawConfig
	// soap is what a SOAPBody placeholder sends around the payload, nil if
	// the tree does not say.
	soap *soapEnvelope
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
		contentType, body := multipartForm(name(), encoded, token("boundary", boundaryBytes))
		return post(contentType, body, "body"), ""
	case "JSONRequest":
		return post("application/json", `{"test": true, "`+name()+`": "`+jsUnicode(encoded)+`"}`, "json"), ""
	case "SOAPBody":
		if p.soap == nil {
			return req, reasonSOAP
		}
		element, parts := "ab"+name(), p.soap.parts
		req = post("text/xml", parts[0]+element+parts[1]+xmlEntity(encoded)+parts[2]+element+parts[3], "body")
		req.headers = append([]header{{"SOAPAction", p.soap.action}}, req.headers...)
		return req, ""
	case "GraphQL":
		// Its request needs an endpoint that only the tool's check of the
		// target can name.
		return req, reasonGraphQL
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

// multipartForm returns the Content-Type and body of a form with one field.
// name and boundary are hex digits. Nothing here can fail: the boundary is
// a valid one and the builder never fails to write.
func multipartForm(name, value, boundary string) (contentType, body string) {
	var b strings.Builder
	w := multipart.NewWriter(&b)
	_ = w.SetBoundary(boundary)
	if field, err := w.CreateFormField(name); err == nil {
		_, _ = field.Write([]byte(value))
	}
	_ = w.Close()
	return w.FormDataContentType(), b.String()
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
