package gotestwaf

import (
	"encoding/base64"
	"encoding/xml"
	"net/url"
	"strings"
	"unicode/utf16"
)

// encode applies the tool's encoder of that name to a payload. Names are
// matched as the tool matches them: exactly. ok is false for a name that is
// not one of the tool's encoders.
func encode(name, payload string) (encoded string, ok bool) {
	switch name {
	case "Plain":
		return payload, true
	case "Base64":
		return base64.StdEncoding.EncodeToString([]byte(payload)), true
	case "Base64Flat":
		// Base64 without its padding.
		return strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte(payload)), "=", ""), true
	case "URL":
		// Escaped as one segment of a path: a blank is %20 and "$&+=:@" stay.
		return url.PathEscape(payload), true
	case "JSUnicode":
		return jsUnicode(payload), true
	case "XMLEntity":
		return xmlEntity(payload)
	}
	return "", false
}

// jsUnicode writes every UTF-16 code unit of s as \uXXXX in lower-case hex. A
// byte that is not valid UTF-8 becomes U+FFFD, as in the tool's conversion.
func jsUnicode(s string) string {
	const hexDigits = "0123456789abcdef"
	var b strings.Builder
	b.Grow(6 * len(s))
	unit := func(u rune) {
		b.WriteString(`\u`)
		for shift := 12; shift >= 0; shift -= 4 {
			b.WriteByte(hexDigits[u>>shift&0xf])
		}
	}
	for _, r := range s {
		if high, low := utf16.EncodeRune(r); high != '�' {
			unit(high)
			unit(low)
			continue
		}
		unit(r)
	}
	return b.String()
}

// xmlEntity writes s the way the tool does: as a Go string value marshalled
// to XML, which is an element named "string" around the escaped text.
func xmlEntity(s string) (string, bool) {
	var b strings.Builder
	if err := xml.NewEncoder(&b).Encode(s); err != nil {
		return "", false
	}
	return b.String(), true
}
