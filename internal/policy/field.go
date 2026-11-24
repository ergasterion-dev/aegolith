package policy

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Field types accepted in FieldSpec.Type.
const (
	TypeUUID   = "uuid"
	TypeInt    = "int"
	TypeNumber = "number"
	TypeBool   = "bool"
	TypeEnum   = "enum"
	TypeString = "string"
	TypeText   = "text"
	TypeEmail  = "email"
	TypePhone  = "phone"
	TypeURL    = "url"
)

// Hard caps that keep every validator linear and cheap whatever the input.
const (
	maxNumberLen = 64   // decimal literal, int or float
	maxEmailLen  = 254  // RFC 5321 path limit
	maxPhoneLen  = 32   // 15 digits plus separators and '+'
	maxURLLen    = 8192 // room for long presigned URLs
)

// FieldSpec declares the type of one path parameter, query value or JSON
// body value. Only Type is required; the other fields refine it:
// Min/Max bound int and number, MaxLen (in runes) bounds string and text,
// Pattern (RE2, whole-value match) refines string, Enum lists enum values.
// A url value must be an absolute http(s) URL in ASCII: non-ASCII bytes are
// rejected, so clients must percent-encode them.
type FieldSpec struct {
	Type    string   `json:"type"`
	Min     *float64 `json:"min,omitempty"`
	Max     *float64 `json:"max,omitempty"`
	MaxLen  int      `json:"max_len,omitempty"`
	Pattern string   `json:"pattern,omitempty"`
	Enum    []string `json:"enum,omitempty"`

	re *regexp.Regexp // compiled Pattern, set by Compile
}

func knownType(t string) bool {
	switch t {
	case TypeUUID, TypeInt, TypeNumber, TypeBool, TypeEnum, TypeString, TypeText, TypeEmail, TypePhone, TypeURL:
		return true
	}
	return false
}

// compile checks the spec and returns a copy with its Pattern compiled.
func (s FieldSpec) compile() (FieldSpec, error) {
	if !knownType(s.Type) {
		return s, fmt.Errorf("unknown type %q", s.Type)
	}
	if s.Min != nil && s.Max != nil && *s.Min > *s.Max {
		return s, fmt.Errorf("min %v > max %v", *s.Min, *s.Max)
	}
	if s.MaxLen < 0 {
		return s, fmt.Errorf("negative max_len %d", s.MaxLen)
	}
	if s.Type == TypeEnum && len(s.Enum) == 0 {
		return s, fmt.Errorf("enum type without enum values")
	}
	if s.Pattern != "" {
		re, err := anchored(s.Pattern)
		if err != nil {
			return s, fmt.Errorf("bad pattern: %v", err)
		}
		s.re = re
	}
	s.Enum = append([]string(nil), s.Enum...)
	return s, nil
}

// anchored compiles a pattern so it must match the whole value. The raw
// pattern is compiled first so that unbalanced input such as "a)|(?:.*"
// cannot break out of the anchoring group. Go's RE2 engine runs in time
// linear in the input, so a user pattern cannot cause catastrophic
// backtracking.
func anchored(p string) (*regexp.Regexp, error) {
	if _, err := regexp.Compile(p); err != nil {
		return nil, err
	}
	return regexp.Compile(`^(?:` + p + `)$`)
}

// Validate reports whether value conforms to spec. isString says whether
// the value was a JSON string (query, path and form values always are);
// JSON numbers, booleans and null arrive with isString false and their
// literal text as value. Only int, number and bool accept such values;
// for every other type a non-string JSON value is a schema mismatch.
// Validate never logs the value.
func Validate(spec FieldSpec, value string, isString bool) bool {
	switch spec.Type {
	case TypeInt, TypeNumber, TypeBool:
	default:
		if !isString {
			return false
		}
	}
	switch spec.Type {
	case TypeUUID:
		return isUUID(value)
	case TypeInt:
		if !isIntLiteral(value) {
			return false
		}
		n, err := strconv.ParseInt(value, 10, 64)
		return err == nil && inRange(spec, float64(n))
	case TypeNumber:
		if !isDecimalLiteral(value) {
			return false
		}
		f, err := strconv.ParseFloat(value, 64)
		return err == nil && inRange(spec, f)
	case TypeBool:
		if !isString {
			return value == "true" || value == "false"
		}
		if len(value) > 5 {
			return false
		}
		_, err := strconv.ParseBool(value)
		return err == nil
	case TypeEnum:
		return slices.Contains(spec.Enum, value)
	case TypeString:
		if !withinRunes(value, spec.MaxLen) {
			return false
		}
		if spec.Pattern == "" {
			return true
		}
		re := spec.re
		if re == nil { // spec did not come through Compile
			var err error
			if re, err = anchored(spec.Pattern); err != nil {
				return false
			}
		}
		return re.MatchString(value)
	case TypeText:
		return withinRunes(value, spec.MaxLen)
	case TypeEmail:
		return isEmail(value)
	case TypePhone:
		return isPhone(value)
	case TypeURL:
		return isHTTPURL(value)
	}
	return false
}

func inRange(spec FieldSpec, f float64) bool {
	if spec.Min != nil && f < *spec.Min {
		return false
	}
	if spec.Max != nil && f > *spec.Max {
		return false
	}
	return true
}

// withinRunes reports whether s has at most limit runes (0 = no limit).
// It stops counting as soon as the limit is exceeded.
func withinRunes(s string, limit int) bool {
	if limit == 0 || len(s) <= limit {
		return true
	}
	n := 0
	for range s {
		n++
		if n > limit {
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// isUUID accepts the canonical 8-4-4-4-12 hex form, any case.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := range 36 {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHex(s[i]) {
				return false
			}
		}
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// digits returns the index just past a run of ASCII digits starting at i.
func digits(s string, i int) int {
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return i
}

// isIntLiteral accepts an optional '-' followed by one or more digits.
func isIntLiteral(s string) bool {
	if len(s) == 0 || len(s) > maxNumberLen {
		return false
	}
	i := 0
	if s[0] == '-' {
		i++
	}
	j := digits(s, i)
	return j > i && j == len(s)
}

// isDecimalLiteral accepts the JSON number grammar without its leading-zero
// restriction: -?digits(.digits)?([eE][+-]?digits)?. That rules out NaN,
// Inf, hex floats and underscores, which strconv.ParseFloat would take.
func isDecimalLiteral(s string) bool {
	if len(s) == 0 || len(s) > maxNumberLen {
		return false
	}
	i := 0
	if s[0] == '-' {
		i++
	}
	j := digits(s, i)
	if j == i {
		return false
	}
	i = j
	if i < len(s) && s[i] == '.' {
		j = digits(s, i+1)
		if j == i+1 {
			return false
		}
		i = j
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		j = digits(s, i)
		if j == i {
			return false
		}
		i = j
	}
	return i == len(s)
}

// isEmail checks the shape of an address: a dot-atom local part made of
// RFC 5322 atext minus the backtick (so o'brien is accepted), an '@', and
// a domain of hostname labels ([A-Za-z0-9-], or bytes >= 0x80 for IDN)
// joined by single dots; at most 254 bytes. Quoted local parts, address
// literals and comments are rejected, so markup (<>) and the remaining
// specials ()[]\,;:" never pass. The type checks shape only: the engine
// still runs ScanText on email values, which catches SQLi in the local part.
func isEmail(s string) bool {
	if len(s) == 0 || len(s) > maxEmailLen {
		return false
	}
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}
	return dotted(s[:at], isAtext) && dotted(s[at+1:], isHostByte)
}

// dotted reports whether s is one or more non-empty runs of ok bytes
// separated by single dots.
func dotted(s string, ok func(byte) bool) bool {
	run := 0
	for i := range len(s) {
		c := s[i]
		switch {
		case c == '.':
			if run == 0 {
				return false
			}
			run = 0
		case ok(c):
			run++
		default:
			return false
		}
	}
	return run > 0
}

func isAlnum(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// isAtext is RFC 5322 atext without the backtick.
func isAtext(c byte) bool {
	return isAlnum(c) || strings.IndexByte("!#$%&'*+-/=?^_{|}~", c) >= 0
}

func isHostByte(c byte) bool { return isAlnum(c) || c == '-' || c >= 0x80 }

// isPhone accepts an optional leading '+', then digits, spaces and dashes,
// with 7 to 15 digits in total (E.164 allows at most 15).
func isPhone(s string) bool {
	if len(s) == 0 || len(s) > maxPhoneLen {
		return false
	}
	i, n := 0, 0
	if s[0] == '+' {
		i++
	}
	for ; i < len(s); i++ {
		switch c := s[i]; {
		case isDigit(c):
			n++
		case c == ' ' || c == '-':
		default:
			return false
		}
	}
	return n >= 7 && n <= 15
}

// isHTTPURL accepts an absolute http or https URL with a host, made only of
// RFC 3986 unreserved and reserved characters and percent-encoding (minus
// the single quote). Non-ASCII bytes are rejected: clients must send IRIs
// percent-encoded (and IDN hosts in punycode). Whether the host is safe to
// fetch is the SSRF detector's job, not the type's.
func isHTTPURL(s string) bool {
	if len(s) == 0 || len(s) > maxURLLen {
		return false
	}
	for i := range len(s) {
		if !isURLByte(s[i]) {
			return false
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	return (scheme == "http" || scheme == "https") && u.Hostname() != "" && u.Opaque == ""
}

func isURLByte(c byte) bool {
	return isAlnum(c) || strings.IndexByte("-._~:/?#[]@!$&()*+,;=%", c) >= 0
}
