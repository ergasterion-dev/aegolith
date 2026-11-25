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
// {email: {$ne: x}}): a bracketed operator anywhere in the key
// (email[$ne], a[$or][0][b]), or a key that itself is an operator
// ($where, [$ne], $in[]) (AEG-NOSQL-002). Only the operators in
// mongoOperators count, matched case-sensitively as MongoDB does, so a form
// key such as amount[$USD] or price[$EUR] is not a hit. The key is also
// checked once percent-decoded.
//
// It also reports prototype pollution in the bracket or dot form qs-style
// parsers and deep-set helpers expand (AEG-PPOLL-001): a key whose segments,
// split on '[', ']' and '.', include __proto__ (__proto__[isAdmin],
// a.__proto__.x), or a constructor segment followed by a prototype segment
// (constructor[prototype][x], a.constructor.prototype.x). A constructor or
// prototype segment on its own is not a hit: filter[constructor] and
// item[prototype] are ordinary form fields and reach no prototype.
func QueryKey(k string) (Hit, bool) {
	if valueOrDecoded(k, isOperatorKey) {
		return Hit{RuleID: "AEG-NOSQL-002", Category: model.CatNoSQLi, Severity: model.SeverityHigh}, true
	}
	if valueOrDecoded(k, isProtoPathKey) {
		return Hit{RuleID: "AEG-PPOLL-001", Category: model.CatProtoPollute, Severity: model.SeverityHigh}, true
	}
	return Hit{}, false
}

// isProtoPathKey walks the non-empty segments of k (split on '[', ']' and
// '.') once, without allocating: a __proto__ segment, or a constructor
// segment whose next non-empty segment is prototype.
func isProtoPathKey(k string) bool {
	if !strings.Contains(k, "__proto__") && !strings.Contains(k, "prototype") {
		return false
	}
	prev := ""
	for i := 0; i < len(k); {
		j := i
		for j < len(k) && k[j] != '[' && k[j] != ']' && k[j] != '.' {
			j++
		}
		if seg := k[i:j]; seg != "" {
			if seg == "__proto__" || seg == "prototype" && prev == "constructor" {
				return true
			}
			prev = seg
		}
		i = j + 1
	}
	return false
}

// KeySQLi is SQLi for a key name. A key that is a plain identifier (an
// ASCII letter or '_', then letters, digits and '_') is one bareword token
// to libinjection, and a single bareword or keyword is never an injection
// fingerprint; it has no blank, quote, ';' or escape for the other SQLi
// checks either. Such keys, nearly every real one, skip the detector, so a
// body of many small keys costs one byte loop per key.
func KeySQLi(k string) (Hit, bool) {
	if isIdentifier(k) {
		return Hit{}, false
	}
	return SQLi(k)
}

func isIdentifier(k string) bool {
	if k == "" || !(k[0] >= 'a' && k[0] <= 'z' || k[0] >= 'A' && k[0] <= 'Z' || k[0] == '_') {
		return false
	}
	for i := 1; i < len(k); i++ {
		c := k[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// mongoOperators are the MongoDB query operators a qs-style key can smuggle
// into a filter: comparison, logical, element, evaluation and array.
var mongoOperators = map[string]struct{}{
	"eq": {}, "ne": {}, "gt": {}, "gte": {}, "lt": {}, "lte": {}, "in": {}, "nin": {},
	"or": {}, "and": {}, "nor": {}, "not": {},
	"exists": {}, "type": {},
	"regex": {}, "where": {}, "expr": {}, "mod": {}, "text": {}, "jsonSchema": {},
	"size": {}, "elemMatch": {}, "all": {},
}

// operatorAt reports whether k[at:] starts with a known operator name
// (without its '$') that ends at end of k or at a byte in stops.
func operatorAt(k string, at int, stops string) bool {
	j := at
	for j < len(k) && (k[j] >= 'a' && k[j] <= 'z' || k[j] >= 'A' && k[j] <= 'Z') {
		j++
	}
	if _, ok := mongoOperators[k[at:j]]; !ok {
		return false
	}
	return j == len(k) && stops == "" || j < len(k) && strings.IndexByte(stops, k[j]) >= 0
}

func isOperatorKey(k string) bool {
	// The whole key is an operator: "$where", "$in[]", "$or[0][a]".
	if strings.HasPrefix(k, "$") && (operatorAt(k, 1, "[") || operatorAt(k, 1, "")) {
		return true
	}
	// A bracketed operator anywhere, including at the start: "[$ne]",
	// "email[$ne]", "a[$elemMatch][b]".
	for off := 0; ; {
		n := strings.Index(k[off:], "[$")
		if n < 0 {
			return false
		}
		at := off + n + 2
		if operatorAt(k, at, "]") {
			return true
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
