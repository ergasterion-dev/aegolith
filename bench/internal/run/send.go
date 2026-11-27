// Package run sends cases to a target over HTTP. In the detection phase it
// sends each case once and judges it from the answer and the target's two
// logs; in the load phase it sends a mix of cases at a fixed rate and measures
// latency, errors and the target's memory, without judging any case.
package run

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

const requestIDHeader = "X-Request-Id"

// maxIDLen is the longest request ID the target records.
const maxIDLen = 128

// maxAnswerBytes bounds how much of an answer is read so that its connection
// can be used again. A longer answer costs the connection.
const maxAnswerBytes = 64 << 10

// NotSentError says that a case was not sent because the client cannot send it
// as given. Reason never repeats a value of the request.
type NotSentError struct{ Reason string }

func (e *NotSentError) Error() string { return "not sent: " + e.Reason }

func refuse(reason string) error { return &NotSentError{Reason: reason} }

// NewClient returns the client cases are sent with. It gives up on a request
// after timeout, never follows a redirect, takes no proxy from the
// environment, keeps no cookies, adds no Accept-Encoding and speaks only
// HTTP/1, so that a request arrives as the case spells it.
func NewClient(timeout time.Duration) *http.Client {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Protocols:             protocols,
			DisableCompression:    true,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       30 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}
}

// Send sends cs to the scheme and host of base, with requestID as its
// X-Request-Id, and returns the status of the answer and the time until it was
// read. The path and query go on the wire byte for byte, and the headers and
// body are those of the case. Header names are not case sensitive and may be
// respelled; net/http adds the framing the body needs and trims blanks around
// a value. A request with a Transfer-Encoding other than "chunked" also gets
// "Connection: close".
//
// What cannot be sent that way is not sent at all: the error is then a
// *NotSentError. Any other error means no answer arrived. No error repeats the
// request's path, query, header values or body.
//
// c should come from NewClient: another client may follow redirects or change
// the request.
func Send(ctx context.Context, c *http.Client, base *url.URL, cs cases.Case, requestID string) (status int, latency time.Duration, err error) {
	req, err := newRequest(ctx, base, cs, requestID)
	if err != nil {
		return 0, 0, err
	}
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		// The URL in a *url.Error holds the path and the query.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return 0, time.Since(start), fmt.Errorf("sending request: %w", err)
	}
	// The status is the answer; a body that cannot be read changes nothing.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxAnswerBytes))
	_ = resp.Body.Close()
	return resp.StatusCode, time.Since(start), nil
}

// ValidRequestID reports whether the target records a request with this ID: 1
// to 128 characters of A-Z, a-z, 0-9, ".", "_" and "-".
func ValidRequestID(id string) bool {
	if id == "" || len(id) > maxIDLen {
		return false
	}
	for i := range len(id) {
		if c := id[i]; !isAlphanumeric(c) && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// newRequest builds the request for cs, or says why net/http would not send
// the case as given.
func newRequest(ctx context.Context, base *url.URL, cs cases.Case, requestID string) (*http.Request, error) {
	switch {
	case base == nil || base.Scheme != "http" && base.Scheme != "https" || base.Host == "":
		return nil, refuse("the base URL is not http or https with a host")
	case !ValidRequestID(requestID):
		return nil, refuse("the request ID is not 1 to 128 characters of A-Za-z0-9._-")
	case !isToken(cs.Method):
		return nil, refuse("the method is not a valid token")
	case !strings.HasPrefix(cs.Path, "/"):
		return nil, refuse("the path does not start with /")
	case hasControlByte(cs.Path):
		return nil, refuse("the path holds a control character")
	case hasControlByte(cs.RawQuery):
		return nil, refuse("the query holds a control character")
	}
	headers, err := canonicalHeaders(cs.Headers)
	if err != nil {
		return nil, err
	}

	// The URL built here only has to parse: the case's own replaces it below.
	req, err := http.NewRequestWithContext(ctx, cs.Method,
		(&url.URL{Scheme: base.Scheme, Host: base.Host}).String(), bodyReader(cs.Body))
	if err != nil {
		return nil, refuse("the base URL cannot be used")
	}
	var absolute bool
	req.URL, absolute = targetURL(base, cs.Path, cs.RawQuery)

	// An empty value stops net/http from adding its own User-Agent.
	req.Header["User-Agent"] = []string{""}
	req.Header[requestIDHeader] = []string{requestID}
	for name, value := range headers {
		switch name {
		case "Host", "Content-Length", "Transfer-Encoding":
			// net/http writes these itself; see below.
		case "User-Agent":
			if value == "" {
				req.Header["user-agent"] = []string{""}
				continue
			}
			req.Header[name] = []string{value}
		case "Trailer":
			// Under its canonical name net/http would leave it out.
			req.Header["trailer"] = []string{value}
		default:
			req.Header[name] = []string{value}
		}
	}
	if host, ok := headers["Host"]; ok {
		if absolute {
			return nil, refuse("the path needs the absolute request form, which would replace the Host header")
		}
		if !sendableHost(host) {
			return nil, refuse("net/http would change the Host header")
		}
		req.Host = host
	}
	if err := setFraming(req, headers, cs.Body); err != nil {
		return nil, err
	}
	return req, nil
}

// canonicalHeaders checks the headers of a case and keys them by their
// canonical names, which net/http acts on.
func canonicalHeaders(headers map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(headers))
	for name, value := range headers {
		if !isToken(name) {
			return nil, refuse("a header name is not a valid token")
		}
		if hasControlByte(strings.ReplaceAll(value, "\t", " ")) {
			return nil, refuse("a header value holds a control character")
		}
		canonical := textproto.CanonicalMIMEHeaderKey(name)
		if _, ok := out[canonical]; ok {
			return nil, refuse("two header names differ only by case")
		}
		out[canonical] = value
	}
	if _, ok := out[requestIDHeader]; ok {
		return nil, refuse("the case sets X-Request-Id, which carries the request ID")
	}
	return out, nil
}

// targetURL returns the URL that puts path and rawQuery on the request line
// byte for byte. absolute reports that only the absolute form
// "http://host//path" can do so, in which the server ignores the Host header.
func targetURL(base *url.URL, path, rawQuery string) (u *url.URL, absolute bool) {
	u = &url.URL{Scheme: base.Scheme, Host: base.Host, RawQuery: rawQuery}
	if !strings.HasPrefix(path, "//") {
		u.Opaque = path
		return u, false
	}
	// net/url puts the scheme before an opaque "//...", turning the first
	// segment into a host. As a path it is kept, if net/url finds its
	// encoding valid.
	if decoded, err := url.PathUnescape(path); err == nil {
		u.Path, u.RawPath = decoded, path
		if u.EscapedPath() == path {
			return u, false
		}
		u.Path, u.RawPath = "", ""
	}
	u.Opaque = "//" + base.Host + path
	return u, true
}

// setFraming applies the Content-Length and Transfer-Encoding headers of a
// case, or refuses a case whose headers net/http would drop, replace or send
// next to its own.
func setFraming(req *http.Request, headers map[string]string, body []byte) error {
	length, hasLength := headers["Content-Length"]
	encoding, hasEncoding := headers["Transfer-Encoding"]
	// What net/http writes by itself for a body that is not chunked.
	writesLength := len(body) > 0 ||
		slices.Contains([]string{http.MethodPost, http.MethodPut, http.MethodPatch}, req.Method)
	switch {
	case hasLength && hasEncoding:
		return refuse("net/http cannot send both Content-Length and Transfer-Encoding")
	case hasLength:
		if !writesLength || length != strconv.Itoa(len(body)) {
			return refuse("net/http would replace or leave out the Content-Length header")
		}
	case !hasEncoding:
	case encoding == "chunked":
		req.TransferEncoding = []string{"chunked"}
		req.ContentLength = -1
		// A body that is not nil makes net/http write the chunks, even none.
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		req.Body = io.NopCloser(bytes.NewReader(body))
	case strings.EqualFold(encoding, "chunked"):
		return refuse("net/http would respell the Transfer-Encoding header")
	case writesLength:
		return refuse("net/http would add a Content-Length next to the Transfer-Encoding header")
	default:
		// Under its canonical name net/http would leave it out.
		req.Header["transfer-encoding"] = []string{encoding}
		// A server may still wait for a body after answering; the next
		// case must not become that body.
		req.Close = true
	}
	return nil
}

// bodyReader returns nil for an empty body, so that net/http sends none.
func bodyReader(body []byte) io.Reader {
	if len(body) == 0 {
		return nil
	}
	return bytes.NewReader(body)
}

// sendableHost reports whether net/http writes host unchanged. It blanks a
// value with other bytes, encodes non-ASCII names, uses the URL's host for an
// empty one and removes an IPv6 zone.
func sendableHost(host string) bool {
	if host == "" {
		return false
	}
	for i := range len(host) {
		if c := host[i]; !isAlphanumeric(c) && !strings.ContainsRune("!$%&'()*+,-.:;=[]_~", rune(c)) {
			return false
		}
	}
	if end := strings.LastIndex(host, "]"); strings.HasPrefix(host, "[") && end >= 0 {
		return !strings.Contains(host[:end], "%")
	}
	return true
}

// isToken reports whether s is an RFC 9110 token: a method or a header name.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if c := s[i]; !isAlphanumeric(c) && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

func isAlphanumeric(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

func hasControlByte(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
