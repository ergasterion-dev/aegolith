// Package model holds the types shared by every Aegolith component: the
// normalized request, rule matches, decisions and the limits that bound
// request inspection.
package model

import (
	"fmt"
	"net/http"
	"unicode"
	"unicode/utf8"
)

// Action is what the firewall does with a request or a single match.
type Action int

// Actions. A Decision only ever carries ActionAllow or ActionBlock;
// ActionMonitor appears on a Match whose rule is in monitor mode.
const (
	ActionAllow Action = iota
	ActionBlock
	ActionMonitor
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionBlock:
		return "block"
	case ActionMonitor:
		return "monitor"
	}
	return "unknown"
}

// ParseAction converts "allow", "block" or "monitor" to an Action.
func ParseAction(s string) (Action, error) {
	switch s {
	case "allow":
		return ActionAllow, nil
	case "block":
		return ActionBlock, nil
	case "monitor":
		return ActionMonitor, nil
	}
	return 0, fmt.Errorf("model: unknown action %q", s)
}

// MarshalText implements encoding.TextMarshaler (JSON string form).
func (a Action) MarshalText() ([]byte, error) {
	if a < ActionAllow || a > ActionMonitor {
		return nil, fmt.Errorf("model: invalid action %d", int(a))
	}
	return []byte(a.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (a *Action) UnmarshalText(b []byte) error {
	v, err := ParseAction(string(b))
	if err != nil {
		return err
	}
	*a = v
	return nil
}

// Mode is the global or per-route enforcement mode.
type Mode int

// Modes.
const (
	ModeEnforce Mode = iota
	ModeMonitor
)

func (m Mode) String() string {
	switch m {
	case ModeEnforce:
		return "enforce"
	case ModeMonitor:
		return "monitor"
	}
	return "unknown"
}

// ParseMode converts "enforce" or "monitor" to a Mode.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "enforce":
		return ModeEnforce, nil
	case "monitor":
		return ModeMonitor, nil
	}
	return 0, fmt.Errorf("model: unknown mode %q", s)
}

// MarshalText implements encoding.TextMarshaler (JSON string form).
func (m Mode) MarshalText() ([]byte, error) {
	if m < ModeEnforce || m > ModeMonitor {
		return nil, fmt.Errorf("model: invalid mode %d", int(m))
	}
	return []byte(m.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (m *Mode) UnmarshalText(b []byte) error {
	v, err := ParseMode(string(b))
	if err != nil {
		return err
	}
	*m = v
	return nil
}

// Severity ranks how dangerous a match is.
type Severity int

// Severities, lowest to highest.
const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// Location says which part of the request a match came from.
type Location string

// Request locations.
const (
	LocMethod   Location = "method"
	LocPath     Location = "path"
	LocQuery    Location = "query"
	LocHeader   Location = "header"
	LocCookie   Location = "cookie"
	LocBody     Location = "body"
	LocProtocol Location = "protocol"
)

// Category groups rules by the attack class they detect.
type Category string

// Rule categories.
const (
	CatSQLi         Category = "sqli"
	CatXSS          Category = "xss"
	CatCmdi         Category = "cmdi"
	CatCodei        Category = "codei"
	CatLDAP         Category = "ldap"
	CatSSTI         Category = "ssti"
	CatJNDI         Category = "jndi"
	CatCRLF         Category = "crlf"
	CatLFI          Category = "lfi"
	CatRFI          Category = "rfi"
	CatSSRF         Category = "ssrf"
	CatXXE          Category = "xxe"
	CatNoSQLi       Category = "nosqli"
	CatProtoPollute Category = "protopollution"
	CatSession      Category = "session"
	CatScanner      Category = "scanner"
	CatProtocol     Category = "protocol"
	CatSchema       Category = "schema"
	CatRoute        Category = "route"
)

// Match is one rule hit. Snippet is always redacted (see Redact).
type Match struct {
	RuleID   string
	Category Category
	Severity Severity
	Location Location
	Field    string
	Snippet  string
	Action   Action
}

// Decision is the engine's verdict. Action is only ActionAllow or
// ActionBlock. Monitored is true when matches were found but not enforced.
// Err records an internal error that was resolved by the fail-open or
// fail-closed setting.
type Decision struct {
	Action    Action
	Monitored bool
	Matches   []Match
	Err       error
}

// Request is the transport-independent view of an HTTP request. RawPath is
// the escaped path exactly as received.
//
// CaseInsensitiveRoutes is set by an adapter whose server routes literal
// path segments case-insensitively (Fiber's default): the route table then
// matches "/API/v1/x" to the template "/api/v1/x" for this request, so the
// route policy the handler is actually served under still applies.
// Parameter values keep their case. Config.CaseInsensitiveRoutes does the
// same for every request.
type Request struct {
	Method                string
	RawPath               string
	RawQuery              string
	RemoteAddr            string
	Header                http.Header
	Body                  []byte
	CaseInsensitiveRoutes bool
}

// Limits bound the work done per request.
type Limits struct {
	MaxBodyBytes int64 `json:"max_body_bytes"`
	MaxDepth     int   `json:"max_depth"`
	MaxFields    int   `json:"max_fields"`
	// MaxValueLen is the window size for scanning one value. Config rounds
	// it down to an even number, minimum 2.
	MaxValueLen int `json:"max_value_len"`
}

// DefaultLimits returns the v0.1 defaults.
func DefaultLimits() Limits {
	return Limits{MaxBodyBytes: 1 << 20, MaxDepth: 32, MaxFields: 1000, MaxValueLen: 8192}
}

const (
	maxSnippet = 64
	maxName    = 256
)

// Redact returns a log-safe snippet of s: at most 64 bytes, cut on a rune
// boundary, with control characters, line and paragraph separators
// (U+2028, U+2029), format characters (Unicode Cf, which includes bidi
// overrides and zero-width characters) and invalid UTF-8 replaced by '?'.
func Redact(s string) string { return neutralize(s, maxSnippet) }

// SafeName applies Redact's character rules to a field name (a query, form
// or cookie key, a JSON path or a header name) and caps it at 256 bytes, so
// a Match.Field is safe to log while staying long enough to match exclusions.
func SafeName(s string) string { return neutralize(s, maxName) }

func neutralize(s string, limit int) string {
	out := make([]byte, 0, min(len(s), limit))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size <= 1 || unsafeRune(r) {
			r = '?'
		}
		if len(out)+utf8.RuneLen(r) > limit {
			break
		}
		out = utf8.AppendRune(out, r)
		i += size
	}
	return string(out)
}

func unsafeRune(r rune) bool {
	return unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || unicode.Is(unicode.Cf, r)
}
