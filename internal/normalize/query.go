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

// ParseCookies returns every name/value pair of every Cookie header, in
// order. It deliberately does not use net/http's strict cookie parser, which
// silently drops pairs with bytes outside the RFC grammar (an evasion path
// for a WAF). Pairs split on the first '='; surrounding spaces are trimmed
// and one pair of double quotes is stripped from the value. A token without
// '=' becomes a key with an empty value. Values are not percent-decoded.
func ParseCookies(h http.Header) []KV {
	var out []KV
	for _, line := range h.Values("Cookie") {
		for _, tok := range strings.Split(line, ";") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			k, v, found := strings.Cut(tok, "=")
			if !found {
				out = append(out, KV{Key: tok})
				continue
			}
			v = strings.TrimSpace(v)
			if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
				v = v[1 : len(v)-1]
			}
			out = append(out, KV{Key: strings.TrimSpace(k), Value: v})
		}
	}
	return out
}
