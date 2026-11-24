package detect

import (
	"strings"

	libinjection "github.com/corazawaf/libinjection-go"

	"github.com/ergasterion-dev/pylolith/internal/model"
)

// SQLi reports whether v looks like SQL injection. It checks v and, when one
// percent-decoding pass changes it, the decoded value too.
func SQLi(v string) (Hit, bool) {
	if valueOrDecoded(v, isSQLi) {
		return Hit{RuleID: "PYL-SQLI-001", Category: model.CatSQLi, Severity: model.SeverityCritical}, true
	}
	return Hit{}, false
}

// XSS reports whether v looks like cross-site scripting. It checks v and,
// when one percent-decoding pass changes it, the decoded value too.
func XSS(v string) (Hit, bool) {
	if valueOrDecoded(v, isXSS) {
		return Hit{RuleID: "PYL-XSS-001", Category: model.CatXSS, Severity: model.SeverityHigh}, true
	}
	return Hit{}, false
}

func isSQLi(s string) bool {
	if ok, _ := libinjection.IsSQLi(s); ok {
		return true
	}
	return hasStackedCopyProgram(s)
}

func isXSS(s string) bool {
	return libinjection.IsXSS(s) || isScriptURL(s)
}

// hasStackedCopyProgram finds a stacked PostgreSQL "COPY ... TO|FROM PROGRAM"
// statement, which runs a shell command on the database host, e.g.
// "'; COPY (SELECT ”) TO PROGRAM 'id'--". libinjection has no COPY keyword
// and reads it as plain words, so it misses this. The match follows the
// statement's grammar to stay off prose: a ';', then COPY, then either a
// parenthesised query or one table name with an optional column list, then
// TO or FROM, PROGRAM and a quoted command. "Meet at 5; copy the list to
// program 'abc'" does not match (two words between COPY and TO).
//
// The scan never looks at a ';' inside a parenthesis group or comment that
// an earlier COPY already parsed (it does not start a statement there), and
// stops at the first group or comment that never closes (everything after it
// is inside). That keeps it linear on input such as a long repetition of
// ";copy(".
func hasStackedCopyProgram(s string) bool {
	for i := strings.IndexByte(s, ';'); i >= 0; {
		match, end := copyProgramAt(s, i+1)
		if match {
			return true
		}
		if end < 0 {
			return false
		}
		from := max(i+1, end)
		n := strings.IndexByte(s[from:], ';')
		if n < 0 {
			return false
		}
		i = from + n
	}
	return false
}

// copyProgramAt reports whether a COPY ... TO|FROM PROGRAM statement starts
// at s[i]. end is how far it parsed, or -1 when a parenthesis group or
// comment it entered never closes.
func copyProgramAt(s string, i int) (match bool, end int) {
	if i, _ = skipSQLSpace(s, i); i < 0 {
		return false, -1
	}
	if !wordAt(s, i, "copy") {
		return false, i
	}
	i += len("copy")
	i, sep := skipSQLSpace(s, i)
	switch {
	case i < 0:
		return false, -1
	case i < len(s) && s[i] == '(':
		if i = skipParens(s, i); i < 0 {
			return false, -1
		}
	case sep:
		start := i
		for i < len(s) && (isIdentByte(s[i]) || s[i] == '.' || s[i] == '"') {
			i++
		}
		if i == start {
			return false, i
		}
		j, _ := skipSQLSpace(s, i)
		if j < 0 {
			return false, -1
		}
		if j < len(s) && s[j] == '(' {
			if i = skipParens(s, j); i < 0 {
				return false, -1
			}
		}
	default:
		return false, i
	}
	if i, _ = skipSQLSpace(s, i); i < 0 {
		return false, -1
	}
	switch {
	case wordAt(s, i, "to"):
		i += len("to")
	case wordAt(s, i, "from"):
		i += len("from")
	default:
		return false, i
	}
	i, sep = skipSQLSpace(s, i)
	if i < 0 {
		return false, -1
	}
	if !sep || !wordAt(s, i, "program") {
		return false, i
	}
	if i, _ = skipSQLSpace(s, i+len("program")); i < 0 {
		return false, -1
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++ // E'...' escape-string literal
	}
	return i < len(s) && (s[i] == '\'' || s[i] == '$'), i
}

// skipSQLSpace skips whitespace and /* */ comments from i. sep reports
// whether anything was skipped. next is -1 when a comment never closes.
func skipSQLSpace(s string, i int) (next int, sep bool) {
	start := i
	for i < len(s) {
		switch {
		case s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' || s[i] == '\f' || s[i] == '\v':
			i++
		case strings.HasPrefix(s[i:], "/*"):
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return -1, true
			}
			i += 2 + end + 2
		default:
			return i, i > start
		}
	}
	return i, i > start
}

// skipParens returns the index just past the parenthesis group opening at
// s[i], skipping single-quoted strings, or -1 when it is not closed.
func skipParens(s string, i int) int {
	depth := 0
	inQuote := false
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote:
			if c == '\'' {
				inQuote = false
			}
		case c == '\'':
			inQuote = true
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

// wordAt reports whether the ASCII word w (lower case) starts at s[i],
// case-insensitively, and is not followed by another identifier byte.
func wordAt(s string, i int, w string) bool {
	if i+len(w) > len(s) || !strings.EqualFold(s[i:i+len(w)], w) {
		return false
	}
	return i+len(w) == len(s) || !isIdentByte(s[i+len(w)])
}

func isIdentByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// isScriptURL reports whether the whole value is a javascript: or vbscript:
// URL that runs code, e.g. "javascript:alert(1)" submitted as a link that is
// later rendered into an href. libinjection only flags such URLs inside an
// HTML attribute it can see, so a bare value slips through.
//
// Browsers ignore leading whitespace/control characters and tabs or
// newlines inside the scheme, so those are skipped too. To stay off prose
// such as the book title "JavaScript: The Good Parts", the scheme must be
// followed by code: an optional dotted identifier chain directly followed
// by '(', '`' or '=' (alert(1), window.location=...), or a '/' comment
// opener (javascript://%0Aalert(1)).
func isScriptURL(s string) bool {
	i := 0
	for i < len(s) && s[i] <= ' ' {
		i++
	}
	var ok bool
	if i, ok = schemeAt(s, i, "javascript:"); !ok {
		if i, ok = schemeAt(s, i, "vbscript:"); !ok {
			return false
		}
	}
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	if i < len(s) && s[i] == '/' {
		return true
	}
	start := i
	for i < len(s) && (isIdentByte(s[i]) || s[i] == '$' || s[i] == '.') {
		i++
	}
	return i > start && i < len(s) && (s[i] == '(' || s[i] == '`' || s[i] == '=')
}

// schemeAt matches the lower-case scheme at s[i] case-insensitively,
// ignoring tab, CR and LF between its letters as browsers do. It returns the
// index after the match, or i unchanged and false.
func schemeAt(s string, i int, scheme string) (int, bool) {
	j := i
	for k := 0; k < len(scheme); j++ {
		if j >= len(s) {
			return i, false
		}
		c := s[j]
		if c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != scheme[k] {
			return i, false
		}
		k++
	}
	return j, true
}
