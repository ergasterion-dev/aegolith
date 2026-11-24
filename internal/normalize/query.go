package normalize

import (
	"net/http"
	"strings"
)

// KV is one decoded name/value pair.
type KV struct{ Key, Value string }

// ParseQuery splits a raw query string into decoded pairs, preserving order
// and repeated keys. It never fails: invalid escapes stay literal and '+'
// becomes a space, per form encoding. Empty segments are skipped.
func ParseQuery(raw string) []KV {
	var out []KV
	for raw != "" {
		var seg string
		seg, raw, _ = strings.Cut(raw, "&")
		if seg == "" {
			continue
		}
		k, v, _ := strings.Cut(seg, "=")
		out = append(out, KV{Key: percentDecode(k, true), Value: percentDecode(v, true)})
	}
	return out
}

// ParseForm parses an application/x-www-form-urlencoded body.
func ParseForm(body []byte) []KV { return ParseQuery(string(body)) }

// ParseCookies returns the cookies of every Cookie header, in order. Values
// are returned as sent (not percent-decoded).
func ParseCookies(h http.Header) []KV {
	cs := (&http.Request{Header: h}).Cookies()
	if len(cs) == 0 {
		return nil
	}
	out := make([]KV, 0, len(cs))
	for _, c := range cs {
		out = append(out, KV{Key: c.Name, Value: c.Value})
	}
	return out
}
