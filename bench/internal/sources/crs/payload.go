package crs

import (
	"net/url"
	"regexp"
	"strings"
)

// boilerplate are the headers that describe the client, the connection or
// the body. One is looked at for a payload only if its value is not ordinary.
var boilerplate = map[string]bool{
	"host": true, "accept": true, "accept-encoding": true, "accept-language": true, "accept-charset": true,
	"connection": true, "proxy-connection": true, "keep-alive": true, "cache-control": true,
	"content-type": true, "content-length": true,
}

var (
	// plainPath is a path of ordinary segments, such as /get/index.php.
	plainPath = regexp.MustCompile(`^(/[A-Za-z0-9_-]+(\.[A-Za-z0-9]+)?)*/?$`)
	// plainName is a parameter or cookie name that carries nothing.
	plainName = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
	// filler is a value a test puts where some value is needed, such as
	// "test" or "1". It is never a payload: many unrelated tests share it,
	// and all of them would land in the same set.
	filler = regexp.MustCompile(`^[A-Za-z0-9]{0,12}$`)
	// ordinary is the value of a boilerplate header that carries nothing,
	// such as "text/html;q=0.9,*/*;q=0.5" or "multipart/form-data; boundary=x".
	ordinary = regexp.MustCompile(`^[A-Za-z0-9 ,;=./*+:_-]*$`)
)

// payloadFinder collects the parts of a request that could carry its attack.
type payloadFinder struct {
	found []candidate
	// unclear is set when one parameter has two such parts.
	unclear bool
}

type candidate struct{ value, placement string }

// parameter looks at one decoded name and value. A name that is more than a
// plain name is a candidate, and so is a value that is more than filler. If
// both are, the parameter has no single part to name.
func (f *payloadFinder) parameter(name, value, placement string) {
	oddName, oddValue := !plainName.MatchString(name), !filler.MatchString(value)
	switch {
	case oddName && oddValue:
		f.unclear = true
	case oddName:
		f.found = append(f.found, candidate{name, placement})
	case oddValue:
		f.found = append(f.found, candidate{value, placement})
	}
}

// parameters looks at the name=value parts of encoded.
func (f *payloadFinder) parameters(encoded, separator, placement string, decode func(string) (string, error)) {
	for _, part := range strings.Split(encoded, separator) {
		name, value, _ := strings.Cut(strings.TrimSpace(part), "=")
		f.parameter(decodeOr(decode, name), decodeOr(decode, value), placement)
	}
}

// findPayload returns the decoded part of the request that carries the
// attack, and where it is. The candidates are: the names and values of query
// parameters, of the parameters of a form body and of cookies (see
// parameter); any other header whose value is more than filler, or more than
// ordinary for a boilerplate header; and a path that is more than plain
// segments. The same attack so gives the same payload in a query, a form and
// a cookie.
//
// With no candidate, with several, or with a body that is not a form, no
// part can be named and both results are empty.
func findPayload(rawPath, rawQuery string, headers []pair, contentType, body string) (payload, placement string) {
	var f payloadFinder
	f.parameters(rawQuery, "&", "query", url.QueryUnescape)
	if body != "" {
		mediaType, _, _ := strings.Cut(contentType, ";")
		if lowerASCII(strings.TrimSpace(mediaType)) != formContentType {
			return "", ""
		}
		f.parameters(body, "&", "body", url.QueryUnescape)
	}
	for _, h := range headers {
		switch name := lowerASCII(h.name); {
		case name == "cookie":
			// A plus sign in a cookie is a plus sign.
			f.parameters(h.value, ";", "header", url.PathUnescape)
		case name == "user-agent" && h.value == testAgent:
		case boilerplate[name] && ordinary.MatchString(h.value):
		case !boilerplate[name] && filler.MatchString(h.value):
		default:
			f.found = append(f.found, candidate{h.value, "header"})
		}
	}
	if !plainPath.MatchString(rawPath) {
		f.found = append(f.found, candidate{decodeOr(url.PathUnescape, rawPath), "path"})
	}
	if f.unclear || len(f.found) != 1 {
		return "", ""
	}
	return f.found[0].value, f.found[0].placement
}

// decodeOr returns s decoded, or s itself if it is not validly encoded.
func decodeOr(decode func(string) (string, error), s string) string {
	if decoded, err := decode(s); err == nil {
		return decoded
	}
	return s
}
