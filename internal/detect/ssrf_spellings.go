package detect

import "strings"

// This file reads the spellings of a URL host that URL parsers accept and the
// "://" scan of ssrfRule does not: "http:host" and "http:/host" without both
// slashes, and a host written with ideographic full stops.

// hostRule returns the worst class of the hosts of the URLs in s, however
// they are spelled.
func hostRule(s string) int { return max(ssrfRule(s), slashlessRule(s)) }

// slashlessRule classifies the host of every "http:host" and "http:/host" in
// s (see nextSlashless), read as "http://host/", and returns the worst class
// found. Unlike after "://", an address in 0.0.0.0/8 counts only when it is
// written as four numbers ("0.0.0.0"): "http:404", "http:80" and "http:0.9"
// in text are statuses, ports and versions, which inet_aton would read as
// such addresses.
//
// Each authority ends at the first byte that ends a URL authority and at the
// latest where the next candidate starts, so no byte is read for two
// candidates: linear in len(s).
func slashlessRule(s string) int {
	worst := ssrfNone
	for k := nextSlashless(s, 0); k >= 0; {
		next := nextSlashless(s, k)
		limit := len(s)
		if next >= 0 {
			limit = next - len("http:")
		}
		if k < limit && s[k] == '/' {
			k++
		}
		end := k
		for end < limit && !isAuthorityEnd(s[end]) {
			end++
		}
		host := urlHost(s[k:end])
		if class := hostClass(host); class > worst && !isShortZeroNet(host) {
			worst = class
		}
		k = next
	}
	return worst
}

// nextSlashless returns the index just past the colon of the first "http:"
// (any case) at or after from that does not start "http://" and is not the end
// of a longer name, or -1: the byte before "http" is not a letter, a digit or
// one of "_+-.:/@", so "okhttp:", "git+http:", "client-http:" and the
// coordinate "group:http:10.0.0" are not URLs. One search for ':', linear in
// the bytes it passes.
func nextSlashless(s string, from int) int {
	for off := from; ; {
		n := strings.IndexByte(s[off:], ':')
		if n < 0 {
			return -1
		}
		colon := off + n
		off = colon + 1
		at := colon - len("http")
		if at < 0 || !hasPrefixFold(s[at:], "http") || strings.HasPrefix(s[off:], "//") {
			continue
		}
		if at > 0 && (isIdentByte(s[at-1]) || strings.IndexByte("+-.:/@", s[at-1]) >= 0) {
			continue
		}
		return off
	}
}

// isShortZeroNet reports whether host is a number inet_aton reads as an
// address in 0.0.0.0/8 and that is not written as four dotted numbers.
func isShortZeroNet(host string) bool {
	ip, ok := parseInetAton(host)
	return ok && ip>>24 == 0 && strings.Count(host, ".") != 3
}

// ideographicDots replaces the full stops that URL parsers read as "." in a
// host (U+3002, U+FF0E, U+FF61). It is safe for concurrent use.
var ideographicDots = strings.NewReplacer("\u3002", ".", "\uff0e", ".", "\uff61", ".")

// asciiDots returns host with its ideographic full stops written as ".". A
// host without the first byte of any of them is returned as it is.
func asciiDots(host string) string {
	if strings.IndexByte(host, 0xe3) < 0 && strings.IndexByte(host, 0xef) < 0 {
		return host
	}
	return ideographicDots.Replace(host)
}
