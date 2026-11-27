package detect

import "strings"

// SQL injection shapes that libinjection lets through. AEG-SQLI-001 runs
// hasSQLTechnique after libinjection: Postgres JSON operators and casts, and
// a quote breakout that ends in a comment or ';'. AEG-SQLI-002 runs
// delayCallAt on each identifier: a MySQL delay inside an expression. Each
// check starts at a fixed byte or substring (a quote, "::", a trailing "--",
// "#" or ';', the name "sleep" or "benchmark"), so a value without it pays
// only the search, and each is linear in the value's length. The accepted
// false positives and misses are in docs/threat-model.md ("SQL techniques
// added in alpha.7").

// hasSQLTechnique reports whether s holds one of the AEG-SQLI-001 shapes.
// isSQLi calls it, so SQLi applies it to a value and to its percent-decoded
// form, and KeySQLi to a key name that is not a plain identifier. Where a
// shape speaks of the end of s, a value longer than MaxValueLen is judged at
// the end of each scan window.
func hasSQLTechnique(s string) bool {
	return hasPostgresCast(s) || hasBooleanJSON(s) || hasParenCast(s) || hasQuoteBreakout(s)
}

// --- Postgres JSON operators and casts ---

// maxSQLLiteral is the longest single-quoted literal, between its quotes,
// that the Postgres checks read.
const maxSQLLiteral = 200

// jsonOperators are the Postgres JSON and containment operators, each longer
// form before the shorter one it starts with. A lone '?' is read apart.
// Read-only.
var jsonOperators = [...]string{"@>", "<@", "?|", "?&", "#>>", "#>", "->>", "->"}

// hasPostgresCast reports whether s holds a single-quoted literal of at most
// maxSQLLiteral bytes cast with "::json" or "::jsonb" directly after its
// closing quote and followed, after blanks, by a JSON operator, a '?' before
// a quote, a further JSON cast, "||" before a quote, or '-' before a digit
// ("'{}'::jsonb @> x", "'[1]'::jsonb - 0"). A cast literal on its own
// ("'{}'::jsonb") and a cast of anything else ("data->>'name'") do not
// match.
//
// Each "::" reads at most maxSQLLiteral bytes back and two gaps of tokenGap
// bytes forward: linear in len(s).
func hasPostgresCast(s string) bool {
	for off := 0; ; {
		n := strings.Index(s[off:], "::")
		if n < 0 {
			return false
		}
		i := off + n
		off = i + 1
		end := jsonCastEnd(s, i)
		if end < 0 || i == 0 || s[i-1] != '\'' ||
			strings.LastIndexByte(s[max(0, i-maxSQLLiteral-2):i-1], '\'') < 0 {
			continue
		}
		k, ok := skipTokenGap(s, end, false)
		if !ok {
			continue
		}
		if jsonOperatorAt(s, k) || jsonCastEnd(s, k) >= 0 {
			return true
		}
		switch {
		case strings.HasPrefix(s[k:], "||"):
			if n, ok := skipTokenGap(s, k+2, false); ok && s[n] == '\'' {
				return true
			}
		case s[k] == '-':
			if n, ok := skipTokenGap(s, k+1, false); ok && isDigit(s[n]) {
				return true
			}
		}
	}
}

// jsonCastEnd returns the index just past a "::json" or "::jsonb" cast that
// starts at s[i], in any case and not part of a longer name, or -1.
func jsonCastEnd(s string, i int) int {
	if !strings.HasPrefix(s[i:], "::") {
		return -1
	}
	switch {
	case wordAt(s, i+2, "json"):
		return i + len("::json")
	case wordAt(s, i+2, "jsonb"):
		return i + len("::jsonb")
	}
	return -1
}

// jsonOperatorAt reports whether a JSON operator starts at s[k]: one of
// jsonOperators, or '?' followed, after blanks, by a quote.
func jsonOperatorAt(s string, k int) bool {
	for _, op := range jsonOperators {
		if strings.HasPrefix(s[k:], op) {
			return true
		}
	}
	if s[k] != '?' {
		return false
	}
	n, ok := skipTokenGap(s, k+1, false)
	return ok && (s[n] == '\'' || s[n] == '"')
}

// uncastOperators are the JSON and containment operators read after a
// literal that carries no cast, each longer form before the shorter one it
// starts with. Prose writes "?", "->" and "->>" after quoted text, so they
// are not among them. Read-only.
var uncastOperators = [...]string{"@>", "<@", "?|", "?&", "#>>", "#>"}

// uncastOperatorAt reports whether one of uncastOperators starts at s[k] and
// is followed, after blanks, by an operand SQL gives it there: a quote or
// "array[". So a chat mention ("<@U1234>"), an entity ("?&nbsp;") and a
// Markdown table cell ("?| yes |") do not match.
func uncastOperatorAt(s string, k int) bool {
	for _, op := range uncastOperators {
		if !strings.HasPrefix(s[k:], op) {
			continue
		}
		n, ok := skipTokenGap(s, k+len(op), false)
		return ok && (s[n] == '\'' || hasPrefixFold(s[n:], "array["))
	}
	return false
}

// hasBooleanJSON reports whether s holds "or" or "and", blanks, and a
// single-quoted literal of at most maxSQLLiteral bytes followed, after
// blanks, by either
//
//   - one of uncastOperators and its operand (see uncastOperatorAt), when the
//     literal is written as a JSON or array value: it starts with '{' or '['
//     ("or '{"a":1}' @> '{}'"). Developer prose quotes such values and words
//     around arrows and questions ("'{}' or '[]' -> 'empty'"), so both
//     conditions are needed; or
//   - a "::json" or "::jsonb" cast, when "or" or "and" itself follows a
//     quote, a digit or ")" ("x' or '1'::json"), the end of the expression a
//     breakout leaves. "NULL or '{}'::jsonb" in a note does not match.
//
// Each quote looks back over one gap and reads at most maxSQLLiteral bytes
// forward: linear in len(s).
func hasBooleanJSON(s string) bool {
	for off := 0; ; {
		n := strings.IndexByte(s[off:], '\'')
		if n < 0 {
			return false
		}
		q := off + n
		off = q + 1
		word := booleanBefore(s, q)
		if word < 0 {
			continue
		}
		end := literalEnd(s, q)
		if end < 0 {
			continue
		}
		k, ok := skipTokenGap(s, end, false)
		if !ok {
			continue
		}
		if jsonCastEnd(s, k) >= 0 && endsOperand(s, word) {
			return true
		}
		if isJSONLiteral(s[q+1:end-1]) && uncastOperatorAt(s, k) {
			return true
		}
	}
}

// booleanBefore returns the start of the word "or" or "and" that stands
// before s[q], separated from it by blanks, or -1.
func booleanBefore(s string, q int) int {
	e := blanksBefore(s, q)
	if e < 0 || e == q {
		return -1
	}
	i := e
	for i > 0 && e-i < 4 && isIdentByte(s[i-1]) {
		i--
	}
	if w := s[i:e]; strings.EqualFold(w, "or") || strings.EqualFold(w, "and") {
		return i
	}
	return -1
}

// blanksBefore returns where the run of blanks that ends at s[i] starts, or
// -1 when it is longer than tokenGap.
func blanksBefore(s string, i int) int {
	for k := i; ; k-- {
		if k == 0 || !isSQLBlank(s[k-1]) {
			return k
		}
		if i-k >= tokenGap {
			return -1
		}
	}
}

// endsOperand reports whether the last byte before s[i], skipping blanks,
// closes an operand: a quote, a digit or ')'.
func endsOperand(s string, i int) bool {
	k := blanksBefore(s, i)
	if k <= 0 {
		return false
	}
	c := s[k-1]
	return c == '\'' || c == '"' || c == ')' || isDigit(c)
}

// literalEnd returns the index just past the quote that closes the literal
// opening at s[q], or -1 when none does within maxSQLLiteral bytes. A
// doubled quote stands for one quote inside the literal.
func literalEnd(s string, q int) int {
	for i := q + 1; i < len(s) && i-q-1 <= maxSQLLiteral; i++ {
		if s[i] != '\'' {
			continue
		}
		if i+1 < len(s) && s[i+1] == '\'' {
			i++
			continue
		}
		return i + 1
	}
	return -1
}

// isJSONLiteral reports whether the literal text starts, after blanks, like a
// JSON object or an array.
func isJSONLiteral(lit string) bool {
	i := 0
	for i < len(lit) && isSQLBlank(lit[i]) {
		i++
	}
	return i < len(lit) && (lit[i] == '{' || lit[i] == '[')
}

// hasParenCast reports whether s holds ")::int", ")::integer", ")::bool" or
// ")::text" followed by the end of s or, after blanks, by "and", "or" or
// "::", where the ')' either closes nothing opened in s (the value breaks out
// of a parenthesis of the query: "7)::int and 1=1") or closes a group that
// holds the word "select" ("(select current_user)::text"). A balanced
// expression without a select is how ordinary SQL is quoted in a ticket
// ("(data->>'live')::bool AND ...", "count(*)::int") and does not match.
//
// One pass over s that counts the parentheses: depth is the number open, and
// selected the deepest open group that holds a select (its parents hold it
// too). Quotes are not read, so a parenthesis inside a string counts.
func hasParenCast(s string) bool {
	if !strings.Contains(s, ")::") {
		return false
	}
	depth, selected := 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '(':
			depth++
		case c == ')':
			counts := depth == 0 || selected >= depth
			depth = max(depth-1, 0)
			selected = min(selected, depth)
			if counts && strings.HasPrefix(s[i+1:], "::") && castEndsCondition(s, i+3) {
				return true
			}
		case c|0x20 == 's' && depth > selected && (i == 0 || !isIdentByte(s[i-1])) && wordAt(s, i, "select"):
			selected = depth
		}
	}
	return false
}

// castEndsCondition reports whether s[k:] starts with the type int, integer,
// bool or text and then ends, or goes on after blanks with "and", "or" or
// "::".
func castEndsCondition(s string, k int) bool {
	for _, typ := range [...]string{"int", "integer", "bool", "text"} {
		if !wordAt(s, k, typ) {
			continue
		}
		n := k + len(typ)
		lim := min(len(s), n+tokenGap)
		for n < lim && isSQLBlank(s[n]) {
			n++
		}
		return n == len(s) || wordAt(s, n, "and") || wordAt(s, n, "or") || strings.HasPrefix(s[n:], "::")
	}
	return false
}

// --- quote breakout and trailing comment ---

// maxBreakoutSpan is the most bytes between the keyword of a breakout and
// the comment or ';' that ends the value.
const maxBreakoutSpan = 64

// gluedKeywords are the words a breakout writes directly after its quote.
// Read-only.
var gluedKeywords = [...]string{"and", "or", "xor", "not", "is", "mod", "glob", "like", "regexp", "rlike", "collate"}

// spacedKeywords are the operators prose rarely writes that a breakout
// writes after its quote and blanks; "similar to" and "sounds like" are two
// words with blanks between. Read-only.
var spacedKeywords = [...][2]string{
	{"xor"}, {"mod"}, {"div"}, {"glob"}, {"regexp"}, {"rlike"}, {"collate"}, {"similar", "to"}, {"sounds", "like"},
}

// sqlEnding is how a value ends: in a "--" comment, a '#' comment or ';'.
type sqlEnding byte

const (
	noEnding sqlEnding = iota
	dashEnding
	hashEnding
	semicolonEnding
)

// trailingEnding returns how s ends and where that ending starts. A comment
// ("--" or '#') may be followed by blanks and '-' only ("-- -"), a ';' by
// blanks only. It reads only the trailing bytes.
func trailingEnding(s string) (sqlEnding, int) {
	e := len(s)
	for e > 0 && (isSQLBlank(s[e-1]) || s[e-1] == '-') {
		e--
	}
	if e > 0 && s[e-1] == '#' {
		return hashEnding, e - 1
	}
	if n := strings.Index(s[e:], "--"); n >= 0 {
		return dashEnding, e + n
	}
	if e > 0 && s[e-1] == ';' && strings.IndexByte(s[e:], '-') < 0 {
		return semicolonEnding, e - 1
	}
	return noEnding, 0
}

// hasQuoteBreakout reports whether s breaks out of a quoted string and ends
// the statement. The quote must be the one that would close the string: no
// quote stands before it, apart from apostrophes between letters ("don't",
// "l'été"). So a quoted word in prose or code ("the 'dist' glob;", "name =
// 'x' collate nocase;") never matches. The shapes:
//
//   - (a) a letter or digit, the quote, one of gluedKeywords as a whole word,
//     at most maxBreakoutSpan bytes without a quote, and a closing "--" or
//     '#' comment: "x'or 1=1#". French "d'or" and "l'or" (gold) do not match.
//   - (b) the quote, blanks, one of spacedKeywords, at most maxBreakoutSpan
//     bytes, and a closing comment or ';': "x' mod 2;".
//   - (c) the quote, blanks, one of ^ & | % < > ~ -, blanks, a name and a
//     closing "--" comment: "x' ^ y--".
//   - (d) the quote written "\'", then "and" or "or", a name directly
//     followed by '(', and a ")" with ';' at the end: "\' or f();".
//
// In (b) and (c), where nothing is glued to the quote, it must also read as
// a closing one (see closesString): code and prose that open a quoted string
// ("s += ' div ';") and a plural ("the kids' mod #") do not match.
//
// Only two quotes can qualify, the first that is not an apostrophe and the
// last in s, so the work is a fixed number of passes over s.
func hasQuoteBreakout(s string) bool {
	if strings.IndexByte(s, '\'') < 0 {
		return false
	}
	end, cs := trailingEnding(s)
	if end == noEnding {
		return false
	}
	first := firstStringQuote(s)
	comment := end == dashEnding || end == hashEnding
	// (a): the last quote, with no string quote before it.
	if last := strings.LastIndexByte(s, '\''); comment && (first < 0 || first >= last) && gluedBreakoutAt(s, last, cs) {
		return true
	}
	if first < 0 {
		return false
	}
	if end == semicolonEnding && escapedCallAt(s, first, cs) {
		return true
	}
	return closesString(s, first) && (spacedBreakoutAt(s, first, cs) || end == dashEnding && symbolBreakoutAt(s, first, cs))
}

// closesString reports whether the quote s[q] reads as the one that closes a
// string of the query: it starts s, or follows a byte after which code and
// prose do not open a quoted string (not a blank or one of ( [ { , = + . :
// " or a backtick), and it does not end a plural ("kids'").
func closesString(s string, q int) bool {
	if q == 0 {
		return true
	}
	if c := s[q-1]; isSQLBlank(c) || strings.IndexByte("([{,=+.:\"`", c) >= 0 {
		return false
	}
	return q < 2 || s[q-1]|0x20 != 's' || !isWordByte(s[q-2])
}

// firstStringQuote returns the index of the first single quote in s that is
// not an apostrophe between two letters (any non-ASCII byte counts as a
// letter), or -1.
func firstStringQuote(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' && (i == 0 || i == len(s)-1 || !isWordByte(s[i-1]) || !isWordByte(s[i+1])) {
			return i
		}
	}
	return -1
}

// gluedBreakoutAt reports shape (a) of hasQuoteBreakout at the quote s[q],
// with the comment starting at cs.
func gluedBreakoutAt(s string, q, cs int) bool {
	if q == 0 || !isIdentByte(s[q-1]) || s[q-1] == '_' {
		return false
	}
	for _, kw := range gluedKeywords {
		if !wordAt(s, q+1, kw) {
			continue
		}
		e := q + 1 + len(kw)
		if e > cs || cs-e > maxBreakoutSpan || strings.IndexByte(s[e:cs], '"') >= 0 {
			return false
		}
		return kw != "or" || !isElidedArticle(s, q)
	}
	return false
}

// isElidedArticle reports whether the quote s[q] ends the French article "d'"
// or "l'".
func isElidedArticle(s string, q int) bool {
	c := s[q-1] | 0x20
	return (c == 'd' || c == 'l') && (q == 1 || !isIdentByte(s[q-2]) && !isWordByte(s[q-2]))
}

// spacedBreakoutAt reports shape (b) of hasQuoteBreakout at the quote s[q].
func spacedBreakoutAt(s string, q, cs int) bool {
	k := blanksAfter(s, q+1)
	if k == q+1 {
		return false
	}
	for _, kw := range spacedKeywords {
		if !wordAt(s, k, kw[0]) {
			continue
		}
		e := k + len(kw[0])
		if second := kw[1]; second != "" {
			n := blanksAfter(s, e)
			if n == e || !wordAt(s, n, second) {
				return false
			}
			e = n + len(second)
		}
		return e <= cs && cs-e <= maxBreakoutSpan
	}
	return false
}

// symbolBreakoutAt reports shape (c) of hasQuoteBreakout at the quote s[q].
func symbolBreakoutAt(s string, q, cs int) bool {
	k := blanksAfter(s, q+1)
	if k == q+1 || k >= len(s) || strings.IndexByte("^&|%<>~-", s[k]) < 0 {
		return false
	}
	n := blanksAfter(s, k+1)
	if n == k+1 || n >= len(s) || !isLetter(s[n]) && s[n] != '_' {
		return false
	}
	for n < len(s) && isIdentByte(s[n]) {
		n++
	}
	return blanksAfter(s, n) == cs
}

// escapedCallAt reports shape (d) of hasQuoteBreakout at the quote s[q], with
// the ';' at cs.
func escapedCallAt(s string, q, cs int) bool {
	if q == 0 || s[q-1] != '\\' {
		return false
	}
	k := blanksAfter(s, q+1)
	switch {
	case wordAt(s, k, "and"):
		k += len("and")
	case wordAt(s, k, "or"):
		k += len("or")
	default:
		return false
	}
	k = blanksAfter(s, k)
	if k >= len(s) || !isLetter(s[k]) && s[k] != '_' {
		return false
	}
	for k < len(s) && isIdentByte(s[k]) {
		k++
	}
	e := cs
	for e > 0 && isSQLBlank(s[e-1]) {
		e--
	}
	return k < e-1 && s[k] == '(' && s[e-1] == ')'
}

// blanksAfter returns the index of the first byte at or after i that is not a
// blank, or len(s).
func blanksAfter(s string, i int) int {
	for i < len(s) && isSQLBlank(s[i]) {
		i++
	}
	return i
}

// isSQLBlank reports the blanks SQL skips: space, tab, CR, LF, FF and VT.
func isSQLBlank(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// --- delay inside an expression (AEG-SQLI-002) ---

// delayCallAt reports whether the identifier s[i:j] is a MySQL delay call
// written inside an expression: "sleep(" or "benchmark(" directly after
//
//   - ")," or a digit and ",", as in a column or value list;
//   - "(select(" or "if(";
//   - the word select, and, or, or by, and blanks;
//
// with a first argument that starts with a number (see delayNumberAt), '(',
// "mod(" or the word select. "(sleep (2))" in a routine list, "9, sleep(5)"
// and "and sleep(8 hours)" do not match.
//
// The context and the argument each read at most tokenGap blanks, and the
// digits of one argument belong to no other call: linear in len(s).
func delayCallAt(s string, i, j int) bool {
	switch w := s[i:j]; len(w) {
	case len("sleep"):
		if !strings.EqualFold(w, "sleep") {
			return false
		}
	case len("benchmark"):
		if !strings.EqualFold(w, "benchmark") {
			return false
		}
	default:
		return false
	}
	if j >= len(s) || s[j] != '(' || !delayContext(s, i) {
		return false
	}
	k, ok := skipTokenGap(s, j+1, false)
	if !ok {
		return false
	}
	switch c := s[k]; {
	case c == '(':
		return true
	case isDigit(c):
		return delayNumberAt(s, k)
	}
	return hasPrefixFold(s[k:], "mod(") || wordAt(s, k, "select")
}

// delayContext reports whether the text before the name at s[i] is one a
// delay call follows inside an expression (see delayCallAt).
func delayContext(s string, i int) bool {
	before := s[:i]
	if n := len(before); n >= 2 && before[n-1] == ',' && (before[n-2] == ')' || isDigit(before[n-2])) {
		return true
	}
	if n := len(before); n >= len("(select(") && hasPrefixFold(before[n-len("(select("):], "(select(") {
		return true
	}
	if n := len(before); n >= 3 && hasPrefixFold(before[n-3:], "if(") {
		return n == 3 || !isIdentByte(before[n-4])
	}
	e := blanksBefore(s, i)
	if e < 0 || e == i {
		return false
	}
	k := e
	for k > 0 && e-k <= len("select") && isIdentByte(s[k-1]) {
		k--
	}
	for _, w := range [...]string{"select", "and", "or", "by"} {
		if strings.EqualFold(s[k:e], w) {
			return true
		}
	}
	return false
}

// delayNumberAt reports whether the number at s[k] is an argument and not a
// duration in prose: digits with an optional fraction and exponent, or a 0x
// or 0b literal, not glued to a letter ("8h"), and followed after blanks by
// ')', ',' or an operator ("8 hours" is not).
func delayNumberAt(s string, k int) bool {
	digits := func(i int, hex bool) int {
		for i < len(s) && (isDigit(s[i]) || hex && isHexByte(s[i])) {
			i++
		}
		return i
	}
	var e int
	if s[k] == '0' && k+1 < len(s) && (s[k+1]|0x20 == 'x' || s[k+1]|0x20 == 'b') {
		if e = digits(k+2, s[k+1]|0x20 == 'x'); e == k+2 {
			return false
		}
	} else {
		e = digits(k, false)
		if e < len(s) && s[e] == '.' {
			e = digits(e+1, false)
		}
		if e < len(s) && s[e]|0x20 == 'e' {
			n := e + 1
			if n < len(s) && (s[n] == '+' || s[n] == '-') {
				n++
			}
			if d := digits(n, false); d > n {
				e = d
			}
		}
	}
	if e < len(s) && isIdentByte(s[e]) {
		return false
	}
	n, ok := skipTokenGap(s, e, false)
	return ok && strings.IndexByte("),+-*/%|&^<>=!", s[n]) >= 0
}
