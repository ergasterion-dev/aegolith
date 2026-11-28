package detect

import (
	"slices"
	"strings"
)

// Template, PHP and LDAP shapes that the older checks of SSTI, CodeI and
// LDAP let through. Each starts at a fixed byte or substring, so a value
// without it pays only the search, and each is linear in the value's length.
// Each rule applies them to a value and to its once percent-decoded form.
// The accepted false positives and misses are in docs/threat-model.md
// ("Template, PHP and LDAP techniques added in alpha.7").

// --- Perl interpolation (AEG-SSTI-001) ---

// maxPerlExpr bounds the text between "[" and "]" in a Perl "@{[ ]}".
const maxPerlExpr = 128

// hasPerlInterpolation reports whether s holds the Perl idiom that runs an
// expression inside a string: "@{", optional blanks, "[", 1 to maxPerlExpr
// bytes other than "]" or a line break, and "]". Two readings of the same
// bytes are not Perl and stay clear: a text that starts with "}", the LaTeX
// column specification "@{[}c@{]}", and a PowerShell hashtable whose first
// key has a type, "@{[string]'a' = 1}" (see isPowerShellTypedKey).
//
// Each "@{" reads its own blanks and at most maxPerlExpr bytes, so the scan
// is linear in len(s).
func hasPerlInterpolation(s string) bool {
	for off := 0; ; {
		n := strings.Index(s[off:], "@{")
		if n < 0 {
			return false
		}
		off += n + 2
		if j := skipBlanks(s, off); j < len(s) && s[j] == '[' && perlExprAt(s, j+1) {
			return true
		}
	}
}

// perlExprAt reports whether s[i:] is a Perl expression and the "]" that
// closes it.
func perlExprAt(s string, i int) bool {
	n := strings.IndexByte(s[i:min(len(s), i+maxPerlExpr+1)], ']')
	if n < 1 {
		return false
	}
	expr := s[i : i+n]
	return expr[0] != '}' && strings.IndexByte(expr, '\r') < 0 && strings.IndexByte(expr, '\n') < 0 &&
		!isPowerShellTypedKey(expr, s, i+n+1)
}

// isPowerShellTypedKey reports whether name, found between "[" and "]", is a
// type name and the text at s[after:] continues as a PowerShell key does:
// after blanks, a quote, "$", "(", ":" or a letter, digit or "_". Perl has
// no such form: there "}", "[" or "->" follows the "]".
//
// Only a name without "@" reaches the blanks, so no two "@{[" read the same
// ones.
func isPowerShellTypedKey(name, s string, after int) bool {
	if !isASCIILetter(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !isIdentByte(name[i]) && name[i] != '.' {
			return false
		}
	}
	j := skipBlanks(s, after)
	if j == len(s) {
		return false
	}
	switch c := s[j]; c {
	case '\'', '"', '$', '(', ':':
		return true
	default:
		return isIdentByte(c)
	}
}

// --- PHP dynamic calls (AEG-CODEI-001) ---

// hasPHPDynamicCall reports whether s calls PHP code in one of the ways a
// filter on function names misses: a short open tag, a listed function named
// in parentheses or quotes and then called, or a call of a variable.
func hasPHPDynamicCall(s string) bool {
	return hasPHPShortTag(s) || hasPHPNamedCall(s) || hasPHPVariableCall(s)
}

// phpTagWords are the words that make "<?" and blanks a PHP open tag, in
// lower case. Read-only.
var phpTagWords = [...]string{"php", "echo", "print", "system", "exec"}

// hasPHPShortTag reports whether s holds "<?", at least one blank or line
// break, and then one of phpTagWords (any case) or a variable. "<?php" and
// "<?=" with no blank are hasPHPOpenTag's.
//
// The blanks after one "<?" belong to no other: linear in len(s).
func hasPHPShortTag(s string) bool {
	for off := 0; ; {
		n := strings.Index(s[off:], "<?")
		if n < 0 {
			return false
		}
		i := off + n + 2
		off = skipPHPSpace(s, i)
		if off == i {
			continue
		}
		if isPHPVariableAt(s, off) {
			return true
		}
		for _, word := range phpTagWords {
			if hasPrefixFold(s[off:], word) {
				return true
			}
		}
	}
}

// phpFuncNames are the functions that run a command or code, or probe the
// server, and are read when they are named in parentheses or quotes and then
// called. Lower case; matched in any case. Read-only.
var phpFuncNames = [...]string{
	"system", "exec", "shell_exec", "passthru", "popen", "proc_open", "assert", "eval", "phpinfo",
	"create_function", "call_user_func",
}

// hasPHPNamedCall reports whether s calls one of phpFuncNames without
// writing the name directly before the "(":
//
//   - ('system')( : the quoted name in parentheses, then "(". When the first
//     "(" follows a letter, digit or "_" it opens an argument list, as in the
//     JavaScript "require('assert')(ok)", and the second call's argument must
//     then start with a quote or a variable.
//   - 'system'( : the quoted name directly followed by "(".
//   - [system][0](
//   - (system)( : the unquoted name in parentheses, where the argument starts
//     with a quote or a variable, or the call ends ");". Not read when the
//     first "(" follows a word other than echo, print or return, as in the
//     JavaScript "promisify(exec)('ls')".
//
// Only the bytes before a "(" are compared, at most the longest name, and
// anyCallEndsStatement reads s once more, so the check is linear in len(s).
func hasPHPNamedCall(s string) bool {
	var statements []int // calls to check for ");"
	for off := 0; ; {
		n := strings.IndexByte(s[off:], '(')
		if n < 0 {
			return anyCallEndsStatement(s, statements)
		}
		call := off + n
		off = call + 1
		if call == 0 {
			continue
		}
		switch s[call-1] {
		case '\'', '"':
			if _, ok := quotedFuncName(s, call); ok {
				return true
			}
		case ']':
			const index = "[system][0]"
			if call >= len(index) && hasPrefixFold(s[call-len(index):call], index) {
				return true
			}
		case ')':
			if quote, ok := quotedFuncName(s, call-1); ok {
				if open := quote - 1; open >= 0 && s[open] == '(' &&
					(!followsWord(s, open) || hasPHPValueArg(s, call)) {
					return true
				}
				continue
			}
			name, ok := funcName(s, call-1, '(')
			if !ok || followsWord(s, name-1) && !followsPHPStatement(s, name-1) {
				continue
			}
			if hasPHPValueArg(s, call) {
				return true
			}
			statements = append(statements, call)
		}
	}
}

// funcName returns where one of phpFuncNames that ends before s[end] and
// follows the byte before starts.
func funcName(s string, end int, before byte) (int, bool) {
	for _, name := range phpFuncNames {
		if start := end - len(name); start > 0 && s[start-1] == before && hasPrefixFold(s[start:end], name) {
			return start, true
		}
	}
	return 0, false
}

// quotedFuncName returns where the opening quote stands of a quoted name of
// phpFuncNames that ends before s[end].
func quotedFuncName(s string, end int) (int, bool) {
	if end < 1 || s[end-1] != '\'' && s[end-1] != '"' {
		return 0, false
	}
	start, ok := funcName(s, end-1, s[end-1])
	return start - 1, ok
}

// followsWord reports whether a letter, digit or "_" stands directly before
// s[i].
func followsWord(s string, i int) bool { return i > 0 && isIdentByte(s[i-1]) }

// followsPHPStatement reports whether the word directly before s[i] is echo,
// print or return, after which PHP reads "(" as the start of an expression.
func followsPHPStatement(s string, i int) bool {
	const longest = len("return")
	start := i
	for start > 0 && i-start <= longest && isIdentByte(s[start-1]) {
		start--
	}
	word := s[start:i]
	return strings.EqualFold(word, "echo") || strings.EqualFold(word, "print") || strings.EqualFold(word, "return")
}

// hasPHPValueArg reports whether the first argument of the call that opens at
// s[call] starts with a quote or a variable.
func hasPHPValueArg(s string, call int) bool {
	j := skipPHPSpace(s, call+1)
	return j < len(s) && (s[j] == '\'' || s[j] == '"') || isPHPVariableAt(s, j)
}

// isPHPVariableAt reports whether a variable starts at s[j]: one or more "$"
// and then a letter, "_" or "{". A price ("$5") and the shell's "$$" are not.
func isPHPVariableAt(s string, j int) bool {
	if j >= len(s) || s[j] != '$' {
		return false
	}
	for j < len(s) && s[j] == '$' {
		j++
	}
	return j < len(s) && (isASCIILetter(s[j]) || s[j] == '_' || s[j] == '{')
}

// isPHPSpace reports whether c is white space to PHP.
func isPHPSpace(c byte) bool { return isBlankByte(c) || c == '\v' || c == '\f' }

// skipPHPSpace returns the first index at or after j that holds no PHP white
// space.
func skipPHPSpace(s string, j int) int {
	for j < len(s) && isPHPSpace(s[j]) {
		j++
	}
	return j
}

// anyCallEndsStatement reports whether one of the calls that open at the
// indexes in calls (each holds "(") closes directly before ";". Parentheses
// are counted as they stand, also inside strings. It sorts calls and reads s
// once.
func anyCallEndsStatement(s string, calls []int) bool {
	if len(calls) == 0 {
		return false
	}
	slices.Sort(calls)
	if !strings.Contains(s[calls[0]:], ");") {
		return false
	}
	var open []int // the depths of the listed calls still open
	depth, next := 0, 0
	for i := calls[0]; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
			if next < len(calls) && calls[next] == i {
				open = append(open, depth)
				next++
			}
		case ')':
			if n := len(open); n > 0 && open[n-1] == depth {
				if i+1 < len(s) && s[i+1] == ';' {
					return true
				}
				open = open[:n-1]
			}
			depth--
		}
	}
	return false
}

// phpArgRule says which arguments make a variable followed by "(" a call.
type phpArgRule uint8

const (
	// anyArg: every argument.
	anyArg phpArgRule = iota
	// valueArg: one that starts with a quote or a variable.
	valueArg
	// valueArgOrStatement: valueArg, or any argument of a call that ends
	// ");".
	valueArgOrStatement
)

// phpBracket is a bracket whose closing one may be followed by a call: the
// "{" of "${", or the "[" or "{" of an index after "$name".
type phpBracket struct {
	open   int // its index; 0 means none, as a "$" or a name precedes it
	depth  int
	dollar bool // the "{" of "${"
	rule   phpArgRule
}

// phpNest pairs the brackets of one kind, "[ ]" or "{ }", and keeps those
// that may precede a call.
type phpNest struct {
	depth   int
	watched []phpBracket
}

// opening counts the bracket at s[i] and keeps it when it is next. A bracket
// at the start of s never is: no "$" precedes it.
func (n *phpNest) opening(i int, next phpBracket) {
	n.depth++
	if i > 0 && next.open == i {
		next.depth = n.depth
		n.watched = append(n.watched, next)
	}
}

// closing counts a closing bracket and returns the kept one it closes.
func (n *phpNest) closing() (phpBracket, bool) {
	depth := n.depth
	n.depth--
	if k := len(n.watched); k > 0 && n.watched[k-1].depth == depth {
		b := n.watched[k-1]
		n.watched = n.watched[:k-1]
		return b, true
	}
	return phpBracket{}, false
}

// phpCallScan is the state of one pass of hasPHPVariableCall.
type phpCallScan struct {
	s             string
	next          phpBracket // the bracket to keep when the pass reaches it
	square, curly phpNest
	statements    []int // calls to check for ");"
	commentsEnd   int   // where the last run of comments read ends
}

// hasPHPVariableCall reports whether s calls what a variable holds:
//
//   - ${...}( : where the argument starts with a quote or a variable, or the
//     call ends ");". Template text such as "${name}(${id})" is not read
//     (see isTemplateCall).
//   - $$name( : with the same arguments. Not read for "$$eval", the browser
//     automation selector call.
//   - $_name( : with the same arguments.
//   - $name[...]( and $name{...}( : one or more indexes, none empty, then any
//     argument. When the name and the first bracket read as LaTeX (see
//     isMathSymbol: "$a_{n}(x)$", "$E[X](1-p)$"), the argument must start
//     with a quote or a variable.
//   - @$name( : any argument; when the "@" follows a letter, digit or "_", as
//     in an address or a password, a quoted or variable one.
//
// "/* */" comments may stand before the "(". "$$name", "$_name" and an
// indexed name that is not a PHP superglobal are not read after a member
// access ("this.$refs['form'](x)", "page.$$eval(...)"; see isMemberAccess).
//
// Brackets are paired as they stand, also inside strings, "[ ]" apart from
// "{ }". The pass reads every byte once, a run of comments at most once, and
// keeps one entry per open bracket after a "$"; anyCallEndsStatement reads s
// once more. It is linear in len(s) apart from sorting the calls it checks.
func hasPHPVariableCall(s string) bool {
	if strings.IndexByte(s, '$') < 0 || strings.IndexByte(s, '(') < 0 {
		return false
	}
	p := phpCallScan{s: s}
	for i := 0; i < len(s); i++ {
		var b phpBracket
		var ok bool
		switch s[i] {
		case '$':
			if p.dollar(i) {
				return true
			}
		case '[':
			p.square.opening(i, p.next)
		case '{':
			p.curly.opening(i, p.next)
		case ']':
			b, ok = p.square.closing()
		case '}':
			b, ok = p.curly.closing()
		}
		if ok && p.closed(b, i) {
			return true
		}
	}
	return anyCallEndsStatement(s, p.statements)
}

// dollar reads what starts at the "$" at s[i]: a "${", or a name that is
// called or indexed.
func (p *phpCallScan) dollar(i int) bool {
	s := p.s
	if i+1 < len(s) && s[i+1] == '{' {
		p.next = phpBracket{open: i + 1, dollar: true, rule: valueArgOrStatement}
		return false
	}
	end := i + 1
	if end < len(s) && (isASCIILetter(s[end]) || s[end] == '_') {
		for end < len(s) && isIdentByte(s[end]) {
			end++
		}
	}
	if end == i+1 {
		return false
	}
	name := s[i+1 : end]
	variableVariable := i > 0 && s[i-1] == '$'
	start := i // the first "$" of the form
	if variableVariable {
		start = i - 1
	}
	member := isMemberAccess(s, start)
	if end < len(s) && (s[end] == '[' || s[end] == '{') {
		if !member || isSuperglobal(name) {
			rule := anyArg
			if isMathSymbol(name, s[end]) {
				rule = valueArg
			}
			p.next = phpBracket{open: end, rule: rule}
		}
		return false
	}
	switch {
	case variableVariable:
		return !member && name != "eval" && p.call(end, valueArgOrStatement)
	case i > 0 && s[i-1] == '@':
		rule := anyArg
		if followsWord(s, i-1) {
			rule = valueArg
		}
		return p.call(end, rule)
	case len(name) > 1 && name[0] == '_':
		return !member && p.call(end, valueArgOrStatement)
	}
	return false
}

// closed reads what follows the kept bracket b, closed at s[i].
func (p *phpCallScan) closed(b phpBracket, i int) bool {
	s := p.s
	if !b.dollar {
		if i == b.open+1 { // an empty index is not one PHP can call
			return false
		}
		if i+1 < len(s) && (s[i+1] == '[' || s[i+1] == '{') {
			p.next = phpBracket{open: i + 1, rule: b.rule}
			return false
		}
		return p.call(i+1, b.rule)
	}
	call := p.skipComments(i + 1)
	if call < len(s) && s[call] == '(' && isTemplateCall(s[b.open+1:i], s, call) {
		return false
	}
	return p.call(call, b.rule)
}

// call reports whether a "(" at s[i], or after the comments there, makes a
// call under rule. A call that counts only when it ends ");" is kept for
// the end of the pass.
func (p *phpCallScan) call(i int, rule phpArgRule) bool {
	i = p.skipComments(i)
	if i >= len(p.s) || p.s[i] != '(' {
		return false
	}
	if rule == anyArg || hasPHPValueArg(p.s, i) {
		return true
	}
	if rule == valueArgOrStatement {
		p.statements = append(p.statements, i)
	}
	return false
}

// skipComments returns the end of the "/* */" comments that start at s[i], or
// i when there are none. Comments inside a run already read are not read
// again, and once one has no "*/" no later one can, so all runs together are
// read once.
func (p *phpCallScan) skipComments(i int) int {
	if i < p.commentsEnd {
		return i
	}
	for i < len(p.s) && strings.HasPrefix(p.s[i:], "/*") {
		n := strings.Index(p.s[i+2:], "*/")
		if n < 0 {
			p.commentsEnd = len(p.s)
			return i
		}
		i += 2 + n + 2
	}
	p.commentsEnd = i
	return i
}

// isMemberAccess reports whether the "$" at s[i] names a member of what
// stands before it, as in JavaScript: a "." after a letter, digit, "_", ")",
// "]" or "?". A "." after anything else, such as the quote in "'.$f", joins
// PHP strings.
func isMemberAccess(s string, i int) bool {
	if i < 2 || s[i-1] != '.' {
		return false
	}
	c := s[i-2]
	return isIdentByte(c) || c == ')' || c == ']' || c == '?'
}

// isSuperglobal reports whether name is a PHP array of request or server
// data, which no JavaScript member is named after.
func isSuperglobal(name string) bool {
	switch name {
	case "GLOBALS", "_GET", "_POST", "_REQUEST", "_COOKIE", "_SERVER", "_ENV", "_FILES", "_SESSION":
		return true
	}
	return false
}

// isMathSymbol reports whether name before the bracket opener reads as
// LaTeX: a symbol and its subscript mark before "{" (the name ends in "_" and
// holds more than "_"), or one capital letter before "[", as in "$E[X]".
func isMathSymbol(name string, opener byte) bool {
	if opener == '[' {
		return len(name) == 1 && name[0] >= 'A' && name[0] <= 'Z'
	}
	return strings.HasSuffix(name, "_") && strings.Trim(name, "_") != ""
}

// isTemplateCall reports whether "${path}" before the "(" at s[call] is two
// parts of a template string and not a call: path is a plain one and the
// argument starts with another "${", also behind a currency sign, as in
// "${name}(${id})" and "${name}($${price})".
//
// A path is read up to its first other byte, which stands before any "${"
// inside it, so no two "${" read the same bytes.
func isTemplateCall(path, s string, call int) bool {
	arg := s[skipPHPSpace(s, call+1):]
	return (strings.HasPrefix(arg, "${") || strings.HasPrefix(arg, "$${")) && isPlainPath(path)
}

// isPlainPath reports whether path is letters, digits, "_", "." and "?." only.
func isPlainPath(path string) bool {
	for i := 0; i < len(path); i++ {
		if c := path[i]; !isIdentByte(c) && c != '.' && (c != '?' || i+1 == len(path) || path[i+1] != '.') {
			return false
		}
	}
	return path != ""
}

// --- LDAP filters (AEG-LDAP-001) ---

// maxLDAPAttr bounds an attribute name.
const maxLDAPAttr = 41

// hasLDAPTechnique reports whether s breaks out of an LDAP filter or carries
// an extensible match.
func hasLDAPTechnique(s string) bool { return hasLDAPBreakout(s) || hasLDAPExtensibleMatch(s) }

// hasLDAPBreakout reports whether s holds one of these around a "(", where
// attr is an attribute name (see ldapAttrEnd):
//
//   - )(attr~= or )(attr=*
//   - ) then ! & or |, then (attr= ~= >= or <=. With >= or <= the name holds
//     no ".": "(df.a>0)&(df.b>=2)" is data-frame code.
//   - ( then | & or !, then (attr=
//   - )(&) or )(|)
//
// In the first three the value must be one a filter can hold (see
// isLDAPValue).
//
// The name is read up to maxLDAPAttr bytes and the value up to the next
// parenthesis, so the scan is linear in len(s).
func hasLDAPBreakout(s string) bool {
	for off := 0; ; {
		n := strings.IndexByte(s[off:], '(')
		if n < 0 {
			return false
		}
		at := off + n
		off = at + 1
		if at < 1 {
			continue
		}
		prev := s[at-1]
		afterClose := prev == ')'
		joined := at >= 2 && (prev == '!' || prev == '&' || prev == '|')
		closeJoined := joined && s[at-2] == ')'
		openJoined := joined && s[at-2] == '('
		if !afterClose && !closeJoined && !openJoined {
			continue
		}
		if afterClose && at+2 < len(s) && (s[at+1] == '&' || s[at+1] == '|') && s[at+2] == ')' {
			return true
		}
		end := ldapAttrEnd(s, at+1)
		if end < 0 {
			continue
		}
		op := ldapOperator(s, end)
		if op == "" {
			continue
		}
		value := s[end+len(op):]
		var shape bool
		switch {
		case afterClose:
			shape = op == "~=" || op == "=" && strings.HasPrefix(value, "*")
		case closeJoined:
			shape = op == "=" || op == "~=" || strings.IndexByte(s[at+1:end], '.') < 0
		default:
			shape = op == "="
		}
		if shape && isLDAPValue(value, op == "=") {
			return true
		}
	}
}

// ldapOperator returns the filter operator at s[i], "=", "~=", ">=" or "<=",
// or "" when there is none.
func ldapOperator(s string, i int) string {
	switch {
	case i < len(s) && s[i] == '=':
		return "="
	case i+1 < len(s) && s[i+1] == '=' && (s[i] == '~' || s[i] == '>' || s[i] == '<'):
		return s[i : i+2]
	}
	return ""
}

// isLDAPValue reports whether v, the text after an operator, can be a filter
// value: no "(" before the next ")", as a filter escapes it, and after "=" no
// second "=". So the comparisons and assignments of code ("(!(a==b))",
// "(!(n=read()))") are not read.
func isLDAPValue(v string, equals bool) bool {
	if equals && strings.HasPrefix(v, "=") {
		return false
	}
	i := strings.IndexAny(v, "()")
	return i < 0 || v[i] == ')'
}

// ldapAttrEnd returns the end of the attribute name at s[i]: 1 to
// maxLDAPAttr letters, digits, ".", "_" and "-", starting with a letter. It
// returns -1 when there is none or it is longer.
func ldapAttrEnd(s string, i int) int {
	if i >= len(s) || !isASCIILetter(s[i]) {
		return -1
	}
	end := i + 1
	for end < len(s) && end-i <= maxLDAPAttr && isLDAPAttrByte(s[end]) {
		end++
	}
	if end-i > maxLDAPAttr {
		return -1
	}
	return end
}

func isLDAPAttrByte(c byte) bool { return isIdentByte(c) || c == '.' || c == '-' }

// hasLDAPExtensibleMatch reports whether s holds "attr:OID:=", a match by a
// named rule such as "userAccountControl:1.2.840.113556.1.4.803:=2". The OID
// is three or more numbers joined by ".".
//
// The digits before one ":=" belong to no other, and the name is read up to
// maxLDAPAttr bytes: linear in len(s).
func hasLDAPExtensibleMatch(s string) bool {
	for off := 0; ; {
		n := strings.Index(s[off:], ":=")
		if n < 0 {
			return false
		}
		at := off + n
		off = at + 2
		start, digits, dots := at, 0, 0
		for start > 0 {
			if c := s[start-1]; c >= '0' && c <= '9' {
				digits++
			} else if c == '.' && digits > 0 {
				digits, dots = 0, dots+1
			} else {
				break
			}
			start--
		}
		if digits == 0 || dots < 2 || start == 0 || s[start-1] != ':' {
			continue
		}
		end := start - 1 // the ":" after the name
		name := end
		for name > 0 && end-name <= maxLDAPAttr && isLDAPAttrByte(s[name-1]) {
			name--
		}
		if name < end && end-name <= maxLDAPAttr && isASCIILetter(s[name]) {
			return true
		}
	}
}
