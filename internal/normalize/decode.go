// Package normalize turns raw request material (query strings, forms,
// cookies, JSON and multipart bodies) into flat, bounded key/value views
// that detectors can inspect.
package normalize

import "strings"

// unhex returns the value of a hex digit, or -1.
func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// DecodeValue performs one tolerant percent-decoding pass. Invalid escapes
// (a stray '%') stay literal and '+' is left untouched. doubleEncoded is
// true when the result still contains a valid %XX escape of a character
// that matters to attackers: % . / \ < ' " NUL CR LF.
func DecodeValue(s string) (decoded string, doubleEncoded bool) {
	if strings.IndexByte(s, '%') < 0 {
		return s, false
	}
	decoded = percentDecode(s, false)
	return decoded, hasSuspiciousEscape(decoded)
}

// percentDecode decodes valid %XX sequences; plus converts '+' to space.
func percentDecode(s string, plus bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%' && i+2 < len(s) && unhex(s[i+1]) >= 0 && unhex(s[i+2]) >= 0:
			b.WriteByte(byte(unhex(s[i+1])<<4 | unhex(s[i+2])))
			i += 2
		case c == '+' && plus:
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func hasSuspiciousEscape(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		hi, lo := unhex(s[i+1]), unhex(s[i+2])
		if hi < 0 || lo < 0 {
			continue
		}
		switch byte(hi<<4 | lo) {
		case '%', '.', '/', '\\', '<', '\'', '"', 0, '\r', '\n':
			return true
		}
	}
	return false
}
