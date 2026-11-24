package detect

import (
	"bytes"
	"strings"

	"github.com/ergasterion-dev/pylolith/internal/model"
	"github.com/ergasterion-dev/pylolith/internal/normalize"
)

// The injection-family detectors share one shape: a hand-written scan over
// the value and, when one percent-decoding pass changes it, over the decoded
// value too. Each scan is linear in the value's length and needs a
// structural signal (an operator plus a command, a closed template
// expression, a filter breaker), never a bare English word, so delivery
// notes, product names and reviews stay clear.

// CmdI reports whether v looks like OS command injection: a shell operator
// (; | & ` $( or a line break) followed by a known command used the way a
// shell is used, or an absolute system path, or a reverse-shell or
// Shellshock marker.
func CmdI(v string) (Hit, bool) {
	if valueOrDecoded(v, isCmdI) {
		return Hit{RuleID: "PYL-CMDI-001", Category: model.CatCmdi, Severity: model.SeverityCritical}, true
	}
	return Hit{}, false
}

// CodeI reports whether v carries code for an interpreter: PHP open tags,
// eval/assert of base64_decode, Node child_process access
// (PYL-CODEI-001), or a Java serialized object (PYL-CODEI-002).
func CodeI(v string) (Hit, bool) {
	id := codeIRule(v)
	if id == "" {
		if d, _ := normalize.DecodeValue(v); d != v {
			id = codeIRule(d)
		}
	}
	if id == "" {
		return Hit{}, false
	}
	return Hit{RuleID: id, Category: model.CatCodei, Severity: model.SeverityCritical}, true
}

// LDAP reports whether v contains an LDAP filter breaker: *)( or a closing
// parenthesis directly followed by a new |, & or ! filter.
func LDAP(v string) (Hit, bool) {
	if valueOrDecoded(v, isLDAP) {
		return Hit{RuleID: "PYL-LDAP-001", Category: model.CatLDAP, Severity: model.SeverityHigh}, true
	}
	return Hit{}, false
}

// SSTI reports whether v contains a server-side template expression with
// code in it: {{ }} holding an attribute walk, filter, call or arithmetic;
// Spring ${T( }; #{ } expressions; ERB <%= %>; or a Jinja {% %} statement.
// Plain placeholders such as {{name}} do not match.
func SSTI(v string) (Hit, bool) {
	if valueOrDecoded(v, isSSTI) {
		return Hit{RuleID: "PYL-SSTI-001", Category: model.CatSSTI, Severity: model.SeverityHigh}, true
	}
	return Hit{}, false
}

// JNDI reports whether v is a Log4Shell lookup: ${jndi: after lowercasing and
// resolving the nested lookups attackers use to hide it (${lower:j},
// ${upper:n}, ${::-d}, ${env:X:-i}).
func JNDI(v string) (Hit, bool) {
	if valueOrDecoded(v, isJNDI) {
		return Hit{RuleID: "PYL-JNDI-001", Category: model.CatJNDI, Severity: model.SeverityCritical}, true
	}
	return Hit{}, false
}

// CRLF reports whether v injects an HTTP header: a CR or LF (raw or
// percent-encoded) followed by a response header an attacker would set.
// Multi-line notes such as "Note: ring bell" on a new line do not match.
func CRLF(v string) (Hit, bool) {
	if valueOrDecoded(v, isCRLF) {
		return Hit{RuleID: "PYL-CRLF-001", Category: model.CatCRLF, Severity: model.SeverityHigh}, true
	}
	return Hit{}, false
}

// --- command injection ---

// cmdWord is a command name the CmdI scan looks for after a shell operator.
type cmdWord struct {
	name string
	// bare: the command alone is an attack (id, whoami), so it matches at the
	// end of the value or before another operator. Commands that need an
	// argument to do harm (cat, curl, rm) match only with a shell-like one.
	bare bool
	// fold: Windows command names are case-insensitive. Unix ones must be
	// lower case as the shell needs, which keeps "ID" and "Cat" in prose
	// clear.
	fold bool
}

// cmdWords is read-only after init.
var cmdWords = [...]cmdWord{
	{name: "id", bare: true},
	{name: "whoami", bare: true},
	{name: "uname", bare: true},
	{name: "ls", bare: true},
	{name: "sh", bare: true},
	{name: "cat"},
	{name: "wget"},
	{name: "curl"},
	{name: "nc"},
	{name: "bash"},
	{name: "python"},
	{name: "perl"},
	{name: "ping"},
	{name: "rm"},
	{name: "chmod"},
	{name: "dir", bare: true, fold: true},
	{name: "powershell", bare: true, fold: true},
	{name: "powershell.exe", bare: true, fold: true},
	{name: "type", fold: true},
	{name: "cmd", fold: true},
	{name: "cmd.exe", fold: true},
}

func isCmdI(s string) bool {
	if hasCmdMarker(s) {
		return true
	}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ';', '|', '&', '`', '\n', '\r':
		case '$':
			if i+1 >= len(s) || s[i+1] != '(' {
				continue
			}
			i++
		default:
			continue
		}
		j := i + 1
		for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '|' || s[j] == '&') {
			j++
		}
		if commandAt(s, j) {
			return true
		}
		// The skipped bytes all lead to the same j: do not rescan them.
		i = j - 1
	}
	return false
}

// commandAt reports whether a command invocation starts at s[i]: a known
// command used as a shell would use it, or an absolute system path.
func commandAt(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	first := s[i]
	if first == '/' {
		return absPathAt(s, i)
	}
	if !isASCIILetter(first) {
		return false
	}
	lower := first | 0x20
	for _, w := range cmdWords {
		end := i + len(w.name)
		if end > len(s) || w.name[0] != lower || !w.fold && first != lower {
			continue
		}
		if w.fold {
			if !hasPrefixFold(s[i:], w.name) {
				continue
			}
		} else if s[i:end] != w.name {
			continue
		}
		if end == len(s) || isShellOperator(s[end]) {
			if w.bare {
				return true
			}
			continue
		}
		if s[end] != ' ' && s[end] != '\t' {
			continue // part of a longer word: "cats", "identity", "sh."
		}
		for end < len(s) && (s[end] == ' ' || s[end] == '\t') {
			end++
		}
		if end == len(s) || isShellOperator(s[end]) {
			if w.bare {
				return true
			}
			continue
		}
		if shellArgAt(s, end) {
			return true
		}
	}
	return false
}

func isShellOperator(c byte) bool {
	return c == ';' || c == '|' || c == '&' || c == '`' || c == ')' || c == '\n' || c == '\r'
}

// shellArgAt reports whether the argument at s[i] looks like one given to a
// shell command rather than an English word: a flag, a path, a variable, a
// redirection, a URL or an IPv4 address. "$5", "/2" and "-" alone do not
// count.
func shellArgAt(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	next := byte(0)
	if i+1 < len(s) {
		next = s[i+1]
	}
	switch c := s[i]; {
	case c == '-':
		return isASCIILetter(next) || next == '-'
	case c == '+':
		return isASCIILetter(next)
	case c == '/':
		return isASCIILetter(next) || next == '.' || next == '_'
	case c == '\\':
		return true
	case c == '~':
		return next == '/' || isASCIILetter(next)
	case c == '$':
		return isASCIILetter(next) || next == '{' || next == '(' || next == '_'
	case c == '.':
		return next == '/' || next == '.' && i+2 < len(s) && s[i+2] == '/'
	case c == '<' || c == '>':
		j := i + 1
		for j < len(s) && (s[j] == '>' || s[j] == ' ') {
			j++
		}
		return j < len(s) && (s[j] == '/' || s[j] == '&')
	case c == '\'' || c == '"':
		return shellArgAt(s, i+1)
	case isASCIILetter(c) && next == ':' && i+2 < len(s) && (s[i+2] == '\\' || s[i+2] == '/'):
		return true // Windows drive path, C:\
	case c >= '0' && c <= '9':
		return ipv4At(s, i)
	}
	return hasPrefixFold(s[i:], "http://") || hasPrefixFold(s[i:], "https://") || hasPrefixFold(s[i:], "ftp://")
}

// ipv4At reports whether a dotted quad (four dot-separated groups of one to
// three digits) starts at s[i].
func ipv4At(s string, i int) bool {
	for g := 0; g < 4; g++ {
		n := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' && n < 4 {
			i++
			n++
		}
		if n == 0 || n > 3 {
			return false
		}
		if g < 3 {
			if i >= len(s) || s[i] != '.' {
				return false
			}
			i++
		}
	}
	return true
}

// absPathAt reports whether s[i] starts an absolute path into a Unix system
// directory, such as /bin/sh or /etc/passwd.
func absPathAt(s string, i int) bool {
	for _, dir := range [...]string{"/bin/", "/sbin/", "/usr/", "/etc/", "/tmp/", "/dev/", "/var/", "/proc/", "/home/", "/root/", "/opt/"} {
		if strings.HasPrefix(s[i:], dir) {
			return true
		}
	}
	return false
}

// hasCmdMarker finds reverse-shell and Shellshock markers that need no
// leading operator.
func hasCmdMarker(s string) bool {
	if strings.Contains(s, "/dev/tcp/") || strings.Contains(s, "/dev/udp/") {
		return true
	}
	if wordThen(s, "bash", " -i") || wordThen(s, "nc", " -e") || wordThenFold(s, "powershell", " -e") {
		return true
	}
	return hasShellshock(s)
}

// wordThen reports whether word (case-sensitive) appears at a word start and
// is directly followed by tail, which must itself end at a word end.
func wordThen(s, word, tail string) bool {
	pat := word + tail
	for off := 0; ; {
		n := strings.Index(s[off:], pat)
		if n < 0 {
			return false
		}
		at := off + n
		end := at + len(pat)
		if (at == 0 || !isIdentByte(s[at-1])) && (end == len(s) || !isIdentByte(s[end])) {
			return true
		}
		off = at + 1
	}
}

// wordThenFold is wordThen for a case-insensitive word and tail prefix (the
// tail may continue, as in -enc or -EncodedCommand).
func wordThenFold(s, word, tail string) bool {
	pat := word + tail
	for i := 0; i+len(pat) <= len(s); i++ {
		if (i == 0 || !isIdentByte(s[i-1])) && hasPrefixFold(s[i:], pat) {
			return true
		}
	}
	return false
}

// hasShellshock finds a Bash function definition used to smuggle a command
// through an environment variable: "() {" then, within the next 64 bytes,
// a ';' before the closing brace, as in "() { :; };".
func hasShellshock(s string) bool {
	for off := 0; ; {
		n := strings.Index(s[off:], "()")
		if n < 0 {
			return false
		}
		i := off + n + 2
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if i < len(s) && s[i] == '{' {
			body := s[i+1:]
			if len(body) > 64 {
				body = body[:64]
			}
			if c := strings.IndexByte(body, '}'); c > 0 && strings.IndexByte(body[:c], ';') >= 0 {
				return true
			}
		}
		off = off + n + 2
	}
}

// --- code injection ---

func codeIRule(s string) string {
	if hasPHPOpenTag(s) || hasEvalBase64(s) || hasNodeExec(s) {
		return "PYL-CODEI-001"
	}
	if hasJavaSerialized(s) {
		return "PYL-CODEI-002"
	}
	return ""
}

// hasPHPOpenTag finds "<?php" (any case) or the short echo tag "<?=".
func hasPHPOpenTag(s string) bool {
	for off := 0; ; {
		n := strings.Index(s[off:], "<?")
		if n < 0 {
			return false
		}
		i := off + n + 2
		if i < len(s) && s[i] == '=' || hasPrefixFold(s[i:], "php") {
			return true
		}
		off = i
	}
}

// hasEvalBase64 finds eval( or assert( together with base64_decode, the
// usual PHP webshell dropper.
func hasEvalBase64(s string) bool {
	return indexFold(s, "base64_decode") >= 0 && (hasCallFold(s, "eval") || hasCallFold(s, "assert"))
}

// hasNodeExec finds Node.js process access: process.mainModule, or the
// child_process module loaded with require( or used via .exec/.spawn.
func hasNodeExec(s string) bool {
	if indexFold(s, "process.mainmodule") >= 0 {
		return true
	}
	if indexFold(s, "child_process") < 0 {
		return false
	}
	return hasCallFold(s, "require") || indexFold(s, ".exec") >= 0 || indexFold(s, ".spawn") >= 0
}

// hasCallFold reports whether name (lower case, matched case-insensitively)
// appears as a whole word followed by optional spaces and '('.
func hasCallFold(s, name string) bool {
	for off := 0; ; {
		n := indexFold(s[off:], name)
		if n < 0 {
			return false
		}
		at := off + n
		i := at + len(name)
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if (at == 0 || !isIdentByte(s[at-1])) && i < len(s) && s[i] == '(' {
			return true
		}
		off = at + 1
	}
}

// hasJavaSerialized finds the Java serialization stream header AC ED 00 05
// at the start of a token: base64 "rO0AB" or hex "aced0005" followed by
// more hex (a UUID's "aced0005-" does not count).
func hasJavaSerialized(s string) bool {
	for off := 0; ; {
		n := strings.Index(s[off:], "rO0AB")
		if n < 0 {
			break
		}
		at := off + n
		if at == 0 || !isBase64Byte(s[at-1]) {
			return true
		}
		off = at + 1
	}
	for off := 0; ; {
		n := indexFold(s[off:], "aced0005")
		if n < 0 {
			return false
		}
		at := off + n
		end := at + len("aced0005")
		if (at == 0 || !isIdentByte(s[at-1])) && end < len(s) && isHexByte(s[end]) {
			return true
		}
		off = at + 1
	}
}

// --- LDAP injection ---

func isLDAP(s string) bool {
	return strings.Contains(s, "*)(") || strings.Contains(s, ")(|(") ||
		strings.Contains(s, ")(&(") || strings.Contains(s, ")(!(")
}

// --- server-side template injection ---

func isSSTI(s string) bool {
	return strings.Contains(s, "${T(") ||
		eachDelimited(s, "{{", "}}", isCodeExpr) ||
		eachDelimited(s, "#{", "}", isHashExpr) ||
		eachDelimited(s, "{%", "%}", isJinjaStatement) ||
		hasERBOutput(s)
}

// eachDelimited calls match on the text between each closing delimiter and
// the last opening delimiter before it (since the previous close), and
// reports whether any call returns true. Every byte is looked at a bounded
// number of times however many openers are left unclosed.
func eachDelimited(s, open, close string, match func(string) bool) bool {
	for from := 0; from < len(s); {
		c := strings.Index(s[from:], close)
		if c < 0 {
			return false
		}
		c += from
		if o := strings.LastIndex(s[from:c], open); o >= 0 && match(s[from+o+len(open):c]) {
			return true
		}
		from = c + len(close)
	}
	return false
}

// isCodeExpr reports whether the inside of a {{ }} is template code rather
// than a placeholder: a dunder attribute walk, a filter, a call, a Go
// template field (.Env), arithmetic (7*7), or config/self/request used as an
// object.
func isCodeExpr(in string) bool {
	if strings.Contains(in, "__") || strings.IndexByte(in, '|') >= 0 {
		return true
	}
	for i := 1; i < len(in); i++ {
		if in[i] == '(' && isIdentByte(in[i-1]) {
			return true
		}
	}
	in = strings.Trim(in, " \t")
	if len(in) >= 2 && in[0] == '.' && isASCIILetter(in[1]) {
		return true
	}
	if isArithmetic(in) {
		return true
	}
	end := 0
	for end < len(in) && isIdentByte(in[end]) {
		end++
	}
	switch in[:end] {
	case "config", "self", "request":
		rest := strings.TrimLeft(in[end:], " \t")
		return rest == "" || rest[0] == '.' || rest[0] == '[' || rest[0] == '|'
	}
	return false
}

// isArithmetic matches a template probe such as "7*7" or "7*'7'".
func isArithmetic(in string) bool {
	i := 0
	for i < len(in) && in[i] >= '0' && in[i] <= '9' {
		i++
	}
	if i == 0 {
		return false
	}
	rest := strings.TrimLeft(in[i:], " ")
	if rest == "" || rest[0] != '*' {
		return false
	}
	rest = strings.Trim(rest[1:], " '\"")
	if rest == "" {
		return false
	}
	for j := 0; j < len(rest); j++ {
		if rest[j] < '0' || rest[j] > '9' {
			return false
		}
	}
	return true
}

// isHashExpr reports whether the inside of a #{ } (Ruby, EL, Thymeleaf)
// holds code: a call, member access, index or multiplication. "#{12}" or
// "#{3B}" in an address does not.
func isHashExpr(in string) bool {
	for i := 0; i < len(in); i++ {
		switch in[i] {
		case '(', '[', '*':
			return true
		case '.':
			if i+1 < len(in) && isASCIILetter(in[i+1]) {
				return true
			}
		}
	}
	return false
}

// isJinjaStatement reports whether the inside of a {% %} starts with a
// Jinja/Django statement keyword.
func isJinjaStatement(in string) bool {
	in = strings.TrimLeft(in, " \t-+")
	end := 0
	for end < len(in) && isASCIILetter(in[end]) {
		end++
	}
	switch in[:end] {
	case "for", "if", "set", "import", "include", "extends", "block", "macro", "print",
		"with", "from", "raw", "call", "filter", "debug", "load", "url":
		return true
	}
	return false
}

// hasERBOutput finds an ERB/JSP output tag "<%=" closed by a later "%>".
func hasERBOutput(s string) bool {
	i := strings.Index(s, "<%=")
	return i >= 0 && strings.Contains(s[i+3:], "%>")
}

// --- Log4Shell ---

// isJNDI resolves Log4j lookups left to right with a stack of open "${"
// frames over an output buffer. When a lookup closes, ${lower:x} and
// ${upper:x} become x and ${anything:-x} becomes its default x; other
// lookups stay as written. A lookup whose resolved content starts with
// "jndi:" is a hit, and so is an unclosed "${jndi:" left at the end.
//
// Each frame remembers where its first ":-" is as bytes arrive, so closing a
// lookup never rescans its content and deep nesting stays linear.
func isJNDI(s string) bool {
	if !strings.Contains(s, "${") {
		return false
	}
	l := strings.ToLower(s)
	buf := make([]byte, 0, len(l))
	var frames []lookupFrame
	for i := 0; i < len(l); i++ {
		switch c := l[i]; {
		case c == '$' && i+1 < len(l) && l[i+1] == '{':
			buf = append(buf, '$', '{')
			frames = append(frames, lookupFrame{start: len(buf), sep: -1})
			i++
		case c == '}' && len(frames) > 0:
			f := frames[len(frames)-1]
			frames = frames[:len(frames)-1]
			content := buf[f.start:]
			if bytes.HasPrefix(content, []byte("jndi:")) {
				return true
			}
			var r []byte
			switch {
			case bytes.HasPrefix(content, []byte("lower:")) || bytes.HasPrefix(content, []byte("upper:")):
				r = content[len("lower:"):]
			case f.sep >= 0:
				r = buf[f.sep+2:]
			default:
				buf = append(buf, '}')
				continue
			}
			at := f.start - 2
			buf = buf[:at+copy(buf[at:], r)]
			if len(frames) > 0 {
				frames[len(frames)-1].noteSep(buf, at)
			}
		default:
			buf = append(buf, c)
			if len(frames) > 0 {
				frames[len(frames)-1].noteSep(buf, len(buf)-1)
			}
		}
	}
	return bytes.Contains(buf, []byte("${jndi:"))
}

// lookupFrame is one open "${" in isJNDI: where its content starts in the
// buffer and where its first ":-" default separator is (-1 if none yet).
type lookupFrame struct {
	start, sep int
}

// noteSep records the frame's first ":-" if one ends in buf[from:], the
// bytes just added to the frame's content.
func (f *lookupFrame) noteSep(buf []byte, from int) {
	if f.sep >= 0 {
		return
	}
	from = max(from-1, f.start)
	if i := bytes.Index(buf[from:], []byte(":-")); i >= 0 {
		f.sep = from + i
	}
}

// --- CRLF / header injection ---

func isCRLF(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '\r' && s[i] != '\n' {
			continue
		}
		j := i + 1
		for j < len(s) && (s[j] == '\r' || s[j] == '\n') {
			j++
		}
		if injectedHeaderAt(s, j) {
			return true
		}
		i = j - 1
	}
	return false
}

// injectedHeaderAt reports whether s[i] starts a response header an attacker
// would inject, followed by ':'. Location needs a URL or path value so that
// "Location: near masjid" in an address stays clear.
func injectedHeaderAt(s string, i int) bool {
	for _, name := range [...]string{
		"set-cookie", "location", "content-type", "content-length", "transfer-encoding",
		"access-control-allow-origin", "content-security-policy", "x-xss-protection",
	} {
		if !hasPrefixFold(s[i:], name) {
			continue
		}
		j := i + len(name)
		for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
			j++
		}
		if j >= len(s) || s[j] != ':' {
			continue
		}
		if name != "location" {
			return true
		}
		j++
		for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
			j++
		}
		return j < len(s) && s[j] == '/' || hasPrefixFold(s[j:], "http:") || hasPrefixFold(s[j:], "https:")
	}
	return false
}

// --- byte helpers ---

// hasPrefixFold reports whether s starts with the ASCII lower-case prefix p,
// ignoring ASCII case. It does no Unicode folding, so "K" (Kelvin) is not k.
func hasPrefixFold(s, p string) bool {
	if len(s) < len(p) {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != p[i] {
			return false
		}
	}
	return true
}

// indexFold returns the index of the first ASCII-case-insensitive match of
// the lower-case p in s, or -1. p is short, so the scan is linear in s.
func indexFold(s, p string) int {
	for i := 0; i+len(p) <= len(s); i++ {
		if hasPrefixFold(s[i:], p) {
			return i
		}
	}
	return -1
}

func isASCIILetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func isBase64Byte(c byte) bool {
	return isIdentByte(c) && c != '_' || c == '+' || c == '/'
}
