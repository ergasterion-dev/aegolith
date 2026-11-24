package detect

import (
	"strings"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

// The key detectors look at names, not values: a JSON object key or a
// query/form key that carries a MongoDB operator or reaches the JavaScript
// prototype chain, and a session identifier smuggled into the URL or body.

// JSONKey reports whether a JSON object key is a NoSQL query operator (it
// starts with '$': AEG-NOSQL-001) or a prototype-pollution key (exactly
// __proto__, constructor or prototype: AEG-PPOLL-001).
func JSONKey(k string) (Hit, bool) {
	switch {
	case strings.HasPrefix(k, "$"):
		return Hit{RuleID: "AEG-NOSQL-001", Category: model.CatNoSQLi, Severity: model.SeverityHigh}, true
	case k == "__proto__" || k == "constructor" || k == "prototype":
		return Hit{RuleID: "AEG-PPOLL-001", Category: model.CatProtoPollute, Severity: model.SeverityHigh}, true
	}
	return Hit{}, false
}

// QueryKey reports whether a query or form key carries a MongoDB operator
// the way qs-style parsers expand it (email[$ne]=x becomes
// {email: {$ne: x}}): one of the bracketed operators anywhere in the key,
// or a key that itself starts with "[$" or "$" (AEG-NOSQL-002). The key is
// also checked once percent-decoded.
func QueryKey(k string) (Hit, bool) {
	if valueOrDecoded(k, isOperatorKey) {
		return Hit{RuleID: "AEG-NOSQL-002", Category: model.CatNoSQLi, Severity: model.SeverityHigh}, true
	}
	return Hit{}, false
}

func isOperatorKey(k string) bool {
	if strings.HasPrefix(k, "$") || strings.HasPrefix(k, "[$") {
		return true
	}
	for off := 0; ; {
		n := strings.Index(k[off:], "[$")
		if n < 0 {
			return false
		}
		at := off + n + 2
		for _, op := range [...]string{"ne]", "gt]", "gte]", "lt]", "lte]", "regex]", "where]", "in]", "nin]", "exists]"} {
			if strings.HasPrefix(k[at:], op) {
				return true
			}
		}
		off = at
	}
}

// Session reports whether a query, form or JSON key or value carries a
// session identifier, the sign of a session-fixation link: PHPSESSID= or
// JSESSIONID= or ASPSESSIONID in the key or value, or a key that is
// PHPSESSID or JSESSIONID (all any case): AEG-SESSION-001. Cookies are not
// passed here; that is where session identifiers belong.
func Session(k, v string) (Hit, bool) {
	if strings.EqualFold(k, "phpsessid") || strings.EqualFold(k, "jsessionid") || hasSessionID(k) || hasSessionID(v) {
		return Hit{RuleID: "AEG-SESSION-001", Category: model.CatSession, Severity: model.SeverityMedium}, true
	}
	return Hit{}, false
}

func hasSessionID(s string) bool {
	return indexFold(s, "phpsessid=") >= 0 || indexFold(s, "jsessionid=") >= 0 || indexFold(s, "aspsessionid") >= 0
}
