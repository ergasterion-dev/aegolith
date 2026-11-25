package detect

import (
	"bytes"
	"strings"

	"github.com/ergasterion-dev/aegolith/internal/model"
	"github.com/ergasterion-dev/aegolith/internal/normalize"
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
//
// A literal line break in the value gets a stricter rule than other
// operators (a bare command alone on a line, "Notes:\nls", is prose). A
// line break that only appears after percent-decoding (%0a, %0d) is what
// scanners send and keeps the ordinary rule.
func CmdI(v string) (Hit, bool) { return cmdI(v, true) }

// cmdIQuery is CmdI for a URL query value, which the engine has already
// percent-decoded once. A query string cannot carry a raw line break, so
// every line break in the value arrived percent-encoded ("q=x%0aid") and
// the ordinary rule applies to it, not the prose rule for a literal one.
func cmdIQuery(v string) (Hit, bool) { return cmdI(v, false) }

// cmdI is CmdI; strictLiteral applies the stricter line-break rule to line
// breaks already present in v.
func cmdI(v string, strictLiteral bool) (Hit, bool) {
	hit := isCmdI(v, strictLiteral)
	if !hit {
		if d, _ := normalize.DecodeValue(v); d != v {
			hit = isCmdI(d, strictLiteral && !hasEncodedLineBreak(v))
		}
	}
	if hit {
		return Hit{RuleID: "AEG-CMDI-001", Category: model.CatCmdi, Severity: model.SeverityCritical}, true
	}
	return Hit{}, false
}

// hasEncodedLineBreak reports whether s contains %0a or %0d (any case).
func hasEncodedLineBreak(s string) bool {
	for i := strings.IndexByte(s, '%'); i >= 0 && i+2 < len(s); {
		if s[i+1] == '0' && (s[i+2]|0x20 == 'a' || s[i+2]|0x20 == 'd') {
			return true
		}
		n := strings.IndexByte(s[i+1:], '%')
		if n < 0 {
			break
		}
		i += 1 + n
	}
	return false
}

// CodeI reports whether v carries code for an interpreter: PHP open tags,
// eval/assert of base64_decode, Node child_process access
// (AEG-CODEI-001), or a Java serialized object (AEG-CODEI-002).
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
		return Hit{RuleID: "AEG-LDAP-001", Category: model.CatLDAP, Severity: model.SeverityHigh}, true
	}
	return Hit{}, false
}

// SSTI reports whether v contains a server-side template expression with
// code in it: {{ }} holding an attribute walk, filter, call or arithmetic;
// Spring ${T( }; #{ } expressions; ERB <%= %>; or a Jinja {% %} statement.
// Plain placeholders such as {{name}} do not match.
func SSTI(v string) (Hit, bool) {
	if valueOrDecoded(v, isSSTI) {
		return Hit{RuleID: "AEG-SSTI-001", Category: model.CatSSTI, Severity: model.SeverityHigh}, true
	}
	return Hit{}, false
}

// JNDI reports whether v is a Log4Shell lookup: ${jndi: after lowercasing and
// resolving the nested lookups attackers use to hide it (${lower:j},
// ${upper:n}, ${::-d}, ${env:X:-i}).
func JNDI(v string) (Hit, bool) {
	if valueOrDecoded(v, isJNDI) {
		return Hit{RuleID: "AEG-JNDI-001", Category: model.CatJNDI, Severity: model.SeverityCritical}, true
	}
	return Hit{}, false
}

// CRLF reports whether v injects an HTTP header: a CR or LF (raw or
// percent-encoded) followed by a response header an attacker would set.
// Multi-line notes such as "Note: ring bell" on a new line do not match.
func CRLF(v string) (Hit, bool) {
	if valueOrDecoded(v, isCRLF) {
		return Hit{RuleID: "AEG-CRLF-001", Category: model.CatCRLF, Severity: model.SeverityHigh}, true
	}
	return Hit{}, false
}

// --- command injection ---

// cmdWord is a command name the CmdI scan looks for after a shell operator.
type cmdWord struct {
	name string
	// bare: the command alone is an attack (id, whoami), so it matches with
	// only flags after it, at the end of the value or before another
	// operator. Other commands need an operand that looks like a shell one.
	bare bool
	// windows: a case-insensitive Windows command. It matches only with a
	// Windows-shaped argument (C:\, a backslash path, a /x switch), never
	// bare, so "Timergara; Dir" (a district) and "Order & type -C cable"
	// stay clear. Unix names must be lower case as the shell needs, which
	// keeps "ID" and "Cat" in prose clear.
	windows bool
	// url: a URL operand counts (curl, wget). "dog & cat https://..." does
	// not match.
	url bool
	// interp: an interpreter, where -c or -e followed by a quoted string is
	// code.
	interp bool
	// netcat: any flag plus a port-like number (nc -lvnp 4444), or -e/-c
	// with an argument, is a hit.
	netcat bool
	// sleep: a hit only with a whole number of seconds and nothing after
	// it but an operator (see sleepArgAt): "; sleep 10", not "rest; sleep
	// well" or "Tea & sleep 8 hours".
	sleep bool
}

// cmdWords is read-only after init.
var cmdWords = [...]cmdWord{
	{name: "id", bare: true},
	{name: "whoami", bare: true},
	{name: "uname", bare: true},
	{name: "ls", bare: true},
	{name: "sh", bare: true, interp: true},
	{name: "bash", interp: true},
	{name: "python", interp: true},
	{name: "perl", interp: true},
	{name: "cat"},
	{name: "wget", url: true},
	{name: "curl", url: true},
	{name: "nc", netcat: true},
	{name: "ncat", netcat: true},
	{name: "netcat", netcat: true},
	{name: "ping"},
	{name: "rm"},
	{name: "chmod"},
	{name: "sleep", sleep: true},
	{name: "dir", windows: true},
	{name: "type", windows: true},
	{name: "cmd", windows: true},
	{name: "cmd.exe", windows: true},
	{name: "powershell", windows: true},
	{name: "powershell.exe", windows: true},
}

// opContext says how much the operator before a command proves on its own.
type opContext uint8

const (
	// opShell: an operator only a shell gives meaning to (";id", "&&",
	// "|", a backtick, "$(", or ";" after anything but a prose sentence).
	opShell opContext = iota
	// opProseSemi: "; " ending a prose sentence of at least two words
	// ("see you; id"). A two-letter bare command (id, ls, sh) with no flag
	// is then a word, not a command; "see you; id -u" still matches.
	opProseSemi
	// opProseAmp: a lone "&" after a blank, which is how people write
	// "and" ("dog & cat /dog-food", "Bring CNIC & id -card"). A command
	// after it needs an operand only a shell user writes: a system path, a
	// variable, a home or relative path or a redirection; a URL, an IPv4
	// address or another absolute path is prose there. A two-letter
	// command needs a short flag (-u, -la, -lah).
	opProseAmp
)

// operatorContext classifies the operator at s[i] (see opContext).
// firstBlank is the index of the first space or tab in s, or -1; isCmdI
// computes it once so the check stays linear in len(s).
func operatorContext(s string, i, firstBlank int) opContext {
	switch s[i] {
	case '&':
		if i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') && (i+1 == len(s) || s[i+1] != '&') {
			return opProseAmp
		}
	case ';':
		if i+1 < len(s) && s[i+1] == ' ' && endsProseSentence(s, i, firstBlank) {
			return opProseSemi
		}
	}
	return opShell
}

// endsProseSentence reports whether s[:end] ends with a word of letters
// (ASCII or any non-ASCII character) and has a blank before that word: at
// least two words of prose, as in "see you". firstBlank is the index of the
// first space or tab in s, or -1. The backward walk covers only the letter
// run directly before s[end], which no other call walks, so all calls in
// one isCmdI scan are linear together.
func endsProseSentence(s string, end, firstBlank int) bool {
	j := end
	for j > 0 && (isASCIILetter(s[j-1]) || s[j-1] >= 0x80) {
		j--
	}
	return j < end && firstBlank >= 0 && firstBlank < j
}

// isCmdI scans s for an operator followed by a command. strictNewline
// applies the stricter bare-command rule after a line break.
func isCmdI(s string, strictNewline bool) bool {
	if hasCmdMarker(s) {
		return true
	}
	firstBlank := strings.IndexAny(s, " \t")
	for i := 0; i < len(s); i++ {
		afterNewline := false
		ctx := opShell
		switch s[i] {
		case ';', '|', '&', '`':
			ctx = operatorContext(s, i, firstBlank)
		case '\n', '\r':
			afterNewline = true
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
		if commandAt(s, j, afterNewline && strictNewline, ctx) {
			return true
		}
		// The skipped bytes all lead to the same j: do not rescan them.
		i = j - 1
	}
	return false
}

// commandAt reports whether a command invocation starts at s[i]: a known
// command used as a shell would use it, or an absolute system path.
// afterNewline is set when the operator before it is only a line break,
// where a bare command at the end of a line ("Notes:\nls") is prose. ctx
// is what the operator itself proves (see opContext).
//
// The command word is the whole token at s[i] (up to a blank or an
// operator), so "cats", "identity" and "sh." are not commands. A Unix word
// split by shell quoting or backslashes ("w'h'o'am'i", "c\at") is matched
// after dequoteShellWord; Windows names are matched only as written.
func commandAt(s string, i int, afterNewline bool, ctx opContext) bool {
	if i >= len(s) {
		return false
	}
	first := s[i]
	if first == '/' {
		return absPathAt(s, i)
	}
	if !isASCIILetter(first) && first != '\'' && first != '"' && first != '\\' {
		return false
	}
	k := cmdTokenEnd(s, i)
	if k < 0 {
		return false
	}
	word := s[i:k]
	split := strings.ContainsAny(word, `'"\`)
	if split {
		if word = dequoteShellWord(word); word == "" {
			return false
		}
	}
	j := skipBlanks(s, k)
	for _, w := range cmdWords {
		if w.windows {
			if !split && strings.EqualFold(word, w.name) && windowsArgAt(s, j, w.name[0] == 'p', w.name != "type") {
				return true
			}
			continue
		}
		if word != w.name {
			continue // Unix names are lower case as the shell needs: "ID", "Cat" are prose
		}
		if w.sleep {
			return sleepArgAt(s, j, afterNewline, ctx)
		}
		return unixArgsAt(s, j, w, afterNewline, ctx)
	}
	return false
}

// maxCmdToken bounds the command-word token commandAt reads: longer than
// any (quote-split) command name, and it keeps each call O(1).
const maxCmdToken = 64

// cmdTokenEnd returns the end of the token at s[i] (the next blank or shell
// operator), or -1 when it runs past maxCmdToken bytes.
func cmdTokenEnd(s string, i int) int {
	for k := i; k < len(s) && k-i <= maxCmdToken; k++ {
		if c := s[k]; c == ' ' || c == '\t' || isShellOperator(c) {
			return k
		}
	}
	if len(s)-i <= maxCmdToken {
		return len(s)
	}
	return -1
}

// dequoteShellWord returns the word s as the shell would read it after
// quote removal: paired ' and " are dropped and a backslash outside single
// quotes keeps only the byte after it ("w'h'o'am'i" and "c\at" become
// whoami and cat). It is used only to match the command word after an
// operator. It returns "" when a quote is not closed (an apostrophe, as in
// "i'd" or "it's", is prose, not quoting), when a backslash ends the word,
// or when the result is longer than any command name. Linear in len(s).
func dequoteShellWord(s string) string {
	const maxName = len("powershell.exe")
	var buf [maxName]byte
	n := 0
	var open byte // the quote currently open, or 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case open != 0 && c == open:
			open = 0
			continue
		case open == 0 && (c == '\'' || c == '"'):
			open = c
			continue
		case c == '\\' && open != '\'':
			if i++; i == len(s) {
				return ""
			}
			c = s[i]
		}
		if n == maxName {
			return ""
		}
		buf[n] = c
		n++
	}
	if open != 0 {
		return ""
	}
	return string(buf[:n])
}

// sleepArgAt reports whether the argument at s[j] makes "sleep" a shell
// invocation: a whole number of seconds followed only by blanks and then
// the end of the value or an operator ("; sleep 10", "| sleep 5 |").
// "sleep well", "sleep 8 hours" and "sleep 1.5h" are prose. After a
// prose-like operator ("Kids & sleep 8", "Long day; sleep 8") the number
// must be followed by another non-line-break operator ("x & sleep 10 &"),
// and after a literal line break it may not end the line.
func sleepArgAt(s string, j int, afterNewline bool, ctx opContext) bool {
	e := digitsEnd(s, j)
	if e == j {
		return false
	}
	n := skipBlanks(s, e)
	if n < len(s) && !isShellOperator(s[n]) {
		return false
	}
	atLineEnd := n >= len(s) || s[n] == '\n' || s[n] == '\r'
	if ctx != opShell || afterNewline {
		return !atLineEnd
	}
	return true
}

// unixArgsAt reports whether the arguments starting at s[j] make the
// command w a shell invocation. It walks up to maxArgTokens tokens: flags
// ("-x", "--word", "+x"), each optionally followed by one value token
// ("-c 3", "-X POST"), and a lone "--" (end of options). It reports a hit at
// the first operand that looks like a shell one (see unixOperandAt), for
// chmod with a mode, for an interpreter's -c/-e with a quoted string, and
// for netcat with a flag and a port number or -e/-c. A bare command also
// matches when only flags and numeric values follow it up to the end of the
// value or an operator; with afterNewline it then needs at least one flag
// or a following non-newline operator. An English word that is neither a
// flag's value nor an operand ends the scan with no hit: "ping -Ali at
// gate", "cat -lovers mug". ctx tightens the rules after a prose-like
// operator (see opContext). Netcat flags must start with a letter or be
// -4/-6 ("nc -2 3" is a size list).
func unixArgsAt(s string, j int, w cmdWord, afterNewline bool, ctx opContext) bool {
	const maxArgTokens = 16
	flags := 0
	lastFlag := ""
	afterFlag := false // the previous token was a flag, so this one may be its value
	wordValue := false // a non-numeric flag value was skipped
	sawNumber := false
	for t := 0; t < maxArgTokens; t++ {
		if j >= len(s) || isShellOperator(s[j]) {
			if w.netcat && flags > 0 && sawNumber {
				return true
			}
			if !w.bare || wordValue {
				return false
			}
			if len(w.name) <= 2 && ctx != opShell && flags == 0 {
				return false // "see you; id", "Bring passport & id"
			}
			atLineEnd := j >= len(s) || s[j] == '\n' || s[j] == '\r'
			return !afterNewline || flags > 0 || !atLineEnd
		}
		// After a prose "&" the operand rules tighten only while nothing
		// shell-like came first: a real flag (and no English word as a
		// flag value) restores them ("x & curl -s http://...").
		if unixOperandAt(s, j, w.url, ctx == opProseAmp && (flags == 0 || wordValue), w.netcat) {
			return true
		}
		if t == 0 && w.name == "chmod" && chmodModeAt(s, j) {
			return true
		}
		if lastFlag == "-c" || lastFlag == "-e" {
			if w.netcat || w.interp && (s[j] == '\'' || s[j] == '"') {
				return true
			}
		}
		k := tokenEnd(s, j)
		if k == j+2 && s[j] == '-' && s[j+1] == '-' {
			lastFlag, afterFlag = "", false // end of options
			j = skipBlanks(s, k)
			continue
		}
		if f := flagEnd(s, j); f > j {
			if w.netcat && s[j+1] >= '0' && s[j+1] <= '9' && s[j:f] != "-4" && s[j:f] != "-6" {
				return false // "Size: M | nc -2 3"
			}
			if ctx == opProseAmp && len(w.name) <= 2 && s[j+1] != '-' && f-j > 4 {
				return false // a hyphenated word: "Bring CNIC & id -card"
			}
			if ctx == opProseAmp && !w.netcat && s[j+1] != '-' && isDashedWord(s[j+1:f]) {
				// "Delivery & ping -me 10.0.0.1", "Tea & cat -lovers /club":
				// an English word after a dash is not a flag, so the prose
				// operand rules stay on.
				wordValue = true
				lastFlag, afterFlag = "", false
				j = skipBlanks(s, f)
				continue
			}
			flags++
			lastFlag, afterFlag = s[j:f], true
			j = skipBlanks(s, f)
			continue
		}
		if !afterFlag {
			return false
		}
		if digitsEnd(s, j) == k {
			sawNumber = true
		} else {
			wordValue = true
		}
		lastFlag, afterFlag = "", false
		j = skipBlanks(s, k)
	}
	return false
}

// isDashedWord reports whether the letters after a single '-' read as an
// English word rather than a cluster of short options: a common two- or
// three-letter lower-case word ("me", "you", "the"), or five or more
// lower-case letters with at least two vowels ("lovers"). Option clusters
// such as -la, -lah, -rf or -lvnp are neither.
func isDashedWord(w string) bool {
	vowels := 0
	for i := 0; i < len(w); i++ {
		c := w[i]
		if c < 'a' || c > 'z' {
			return false
		}
		if strings.IndexByte("aeiou", c) >= 0 {
			vowels++
		}
	}
	switch len(w) {
	case 2, 3:
		switch w {
		case "me", "my", "us", "we", "he", "is", "am", "as", "at", "be", "by", "do", "go", "if", "no",
			"of", "on", "or", "so", "to", "up", "ok", "the", "and", "for", "you", "our", "not", "are",
			"all", "can", "her", "him", "his", "its", "was", "who", "why", "how", "new", "old", "too",
			"get", "got", "any", "now", "out", "one", "two", "yes", "she", "see", "pls":
			return true
		}
		return false
	case 4:
		return false
	}
	return len(w) >= 5 && vowels >= 2
}

// tokenEnd returns the end of the token at s[j]: the next blank or shell
// operator.
func tokenEnd(s string, j int) int {
	for j < len(s) && s[j] != ' ' && s[j] != '\t' && !isShellOperator(s[j]) {
		j++
	}
	return j
}

// chmodModeAt reports whether s[j] starts a chmod mode followed by a file
// operand: three or four octal digits (755, 4777) or a symbolic mode such as
// +x, u+s or go-w, then a blank and another token. A mode alone at the end
// ("Notes; chmod 755") changes nothing and reads as a note.
func chmodModeAt(s string, j int) bool {
	k := tokenEnd(s, j)
	if o := skipBlanks(s, k); o == k || o >= len(s) || isShellOperator(s[o]) {
		return false
	}
	tok := s[j:k]
	if n := len(tok); n == 3 || n == 4 {
		octal := true
		for i := 0; i < n; i++ {
			if tok[i] < '0' || tok[i] > '7' {
				octal = false
			}
		}
		if octal {
			return true
		}
	}
	i := 0
	for i < len(tok) && strings.IndexByte("ugoa", tok[i]) >= 0 {
		i++
	}
	if i >= len(tok) || strings.IndexByte("+-=", tok[i]) < 0 {
		return false
	}
	i++
	if i == len(tok) {
		return false
	}
	for ; i < len(tok); i++ {
		if strings.IndexByte("rwxXst", tok[i]) < 0 {
			return false
		}
	}
	return true
}

// flagEnd returns the end of a command-line flag token at s[j] ("-la",
// "-O", "--output", "+x"), or j when there is none. "--" alone, "-" alone
// and "-ing," are not flags.
func flagEnd(s string, j int) int {
	k := j
	switch {
	case strings.HasPrefix(s[j:], "--"):
		k += 2
		if k >= len(s) || !isASCIILetter(s[k]) {
			return j
		}
	case s[j] == '-':
		k++
		if k >= len(s) || !isASCIILetter(s[k]) && (s[k] < '0' || s[k] > '9') {
			return j
		}
	case s[j] == '+':
		k++
		if k >= len(s) || !isASCIILetter(s[k]) {
			return j
		}
	default:
		return j
	}
	for k < len(s) && (isIdentByte(s[k]) || s[k] == '-') {
		k++
	}
	if k < len(s) && !isShellOperator(s[k]) && s[k] != ' ' && s[k] != '\t' {
		return j
	}
	return k
}

// digitsEnd returns the end of an all-digit token at s[j], or j.
func digitsEnd(s string, j int) int {
	k := j
	for k < len(s) && s[k] >= '0' && s[k] <= '9' {
		k++
	}
	if k < len(s) && !isShellOperator(s[k]) && s[k] != ' ' && s[k] != '\t' {
		return j
	}
	return k
}

func skipBlanks(s string, j int) int {
	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	return j
}

func isShellOperator(c byte) bool {
	return c == ';' || c == '|' || c == '&' || c == '`' || c == ')' || c == '\n' || c == '\r'
}

// unixOperandAt reports whether the operand at s[i] (optionally quoted)
// looks like one given to a Unix command rather than an English word: a
// path, a home or relative path, a variable, a redirection into a path or
// descriptor, an IPv4 address, or (for curl and wget) a URL. "$5", "/2",
// "-- both" and "food" do not count. With prose set (after a lone "&" and
// no real flag), a URL and a one-segment root path that is not a dot-file are prose
// ("dog & cat /dog-food", "Hair & curl https://..."), and an IPv4 address
// counts only for netcat ("x & nc 10.0.0.1 4444"); a system path, a deeper
// path, a root dot-file, a home or relative path, a variable and a
// redirection still count.
func unixOperandAt(s string, i int, url, prose, netcat bool) bool {
	for i < len(s) && (s[i] == '\'' || s[i] == '"') {
		i++
	}
	if i >= len(s) {
		return false
	}
	next := byte(0)
	if i+1 < len(s) {
		next = s[i+1]
	}
	switch c := s[i]; {
	case c == '/' && prose:
		// A system path, a deeper path or a root dot-file ("/.env")
		// counts; "/dog-food" and "/pet-food.html" read as prose.
		tok := s[i+1 : tokenEnd(s, i)]
		return absPathAt(s, i) || strings.Contains(tok, "/") || strings.HasPrefix(tok, ".")
	case c == '/':
		return isASCIILetter(next) || next == '.' || next == '_' || i+1 == len(s) || isShellOperator(next)
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
	case c >= '0' && c <= '9':
		return (!prose || netcat) && ipv4At(s, i)
	}
	return url && !prose && (hasPrefixFold(s[i:], "http://") || hasPrefixFold(s[i:], "https://") || hasPrefixFold(s[i:], "ftp://"))
}

// windowsArgAt reports whether s[i] starts a Windows-shaped argument: a
// drive path (C:\ or C:/), a backslash path, or a one-letter /x switch or
// /? (only with switches set: type takes none, so "Pack of 2 | type /a" is
// not one). With flags set (PowerShell), a -Name parameter also counts.
func windowsArgAt(s string, i int, flags, switches bool) bool {
	for i < len(s) && (s[i] == '\'' || s[i] == '"') {
		i++
	}
	if i >= len(s) {
		return false
	}
	c := s[i]
	switch {
	case isASCIILetter(c) && i+2 < len(s) && s[i+1] == ':' && (s[i+2] == '\\' || s[i+2] == '/'):
		return true
	case c == '\\':
		return i+1 < len(s) && (isASCIILetter(s[i+1]) || s[i+1] == '\\')
	case c == '/' && switches:
		if i+1 >= len(s) || !isASCIILetter(s[i+1]) && s[i+1] != '?' {
			return false
		}
		return i+2 == len(s) || s[i+2] == ' ' || s[i+2] == '\t' || isShellOperator(s[i+2])
	case c == '-' && flags:
		return flagEnd(s, i) > i
	}
	return false
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
	if wordThen(s, "bash", " -i") || wordThen(s, "nc", " -e") || hasPowerShellEncoded(s) {
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

// hasPowerShellEncoded finds "powershell -e..." (any case) whose parameter
// is one PowerShell resolves: -ec, -ep, or a prefix of -EncodedCommand or
// -ExecutionPolicy (-e, -enc, -exec, ...). PowerShell accepts unambiguous
// parameter prefixes, which payloads use; "Powershell -experience
// required" names a job requirement.
func hasPowerShellEncoded(s string) bool {
	const pat = "powershell -e"
	for i := 0; i+len(pat) <= len(s); i++ {
		if i > 0 && isIdentByte(s[i-1]) || !hasPrefixFold(s[i:], pat) {
			continue
		}
		start := i + len(pat) - 1 // the 'e' after '-'
		end := start
		for end < len(s) && isASCIILetter(s[end]) {
			end++
		}
		if end < len(s) && isIdentByte(s[end]) {
			continue
		}
		p := strings.ToLower(s[start:end])
		if p == "ec" || p == "ep" || strings.HasPrefix("encodedcommand", p) || strings.HasPrefix("executionpolicy", p) {
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
		return "AEG-CODEI-001"
	}
	if hasJavaSerialized(s) {
		return "AEG-CODEI-002"
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
		eachDelimited(s, "${", "}", isELExpr) ||
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
	case "printf", "call", "define", "template", "index", "html", "js", "block", "with", "range", "slice":
		// A Go template action: its argument starts with a field, string or
		// variable. A bare keyword or a prose word after it is not code.
		rest := strings.TrimLeft(in[end:], " \t")
		return rest != "" && (end < len(in) && in[end] == '.' ||
			len(rest) < len(in)-end && strings.ContainsRune(".\"$`", rune(rest[0])))
	case "config", "self", "request":
		rest := strings.TrimLeft(in[end:], " \t")
		return rest == "" || rest[0] == '.' || rest[0] == '[' || rest[0] == '|'
	}
	return false
}

// isELExpr reports whether the inside of a ${ } (EL, Spring, Groovy) holds
// code: number arithmetic (7*7, 7+7), member access (user.password) or a call.
// A placeholder such as "${PRICE}" or a number such as "${5}" does not.
func isELExpr(in string) bool {
	in = strings.Trim(in, " \t")
	i := 0
	for i < len(in) && in[i] >= '0' && in[i] <= '9' {
		i++
	}
	if i > 0 {
		rest := strings.TrimLeft(in[i:], " ")
		if rest == "" || (rest[0] != '*' && rest[0] != '+') {
			return false
		}
		rest = strings.TrimLeft(rest[1:], " ")
		return rest != "" && rest[0] >= '0' && rest[0] <= '9'
	}
	for j := 1; j < len(in); j++ {
		if in[j] == ':' {
			// A lookup such as ${jndi:ldap://host/a} or ${env:HOME} belongs
			// to the JNDI rule, not to EL member access.
			return false
		}
		if isIdentByte(in[j-1]) && (in[j] == '(' || in[j] == '.' && j+1 < len(in) && isASCIILetter(in[j+1])) {
			return true
		}
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
// Each frame remembers where its first ":-" is as bytes arrive. Closing a
// lookup still moves its resolved text into the parent, so the work is
// depth x length; nesting is therefore capped at maxLookupDepth. Real
// obfuscation nests two to four deep and no customer text nests "${" at
// all, so a value that goes deeper is reported (fail closed) rather than
// resolved, which also stops an attacker hiding ${jndi: below the cap.
func isJNDI(s string) bool {
	if !strings.Contains(s, "${") {
		return false
	}
	// Lower-case ASCII as bytes are copied: the letters that matter
	// (j, n, d, i, lower, upper) are ASCII, and this avoids a second copy.
	buf := make([]byte, 0, len(s))
	var frameArr [maxLookupDepth]lookupFrame
	frames := frameArr[:0]
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		switch {
		case c == '$' && i+1 < len(s) && s[i+1] == '{':
			if len(frames) == maxLookupDepth {
				return true
			}
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
			if c == '-' && len(frames) > 0 {
				if f := &frames[len(frames)-1]; f.sep < 0 && len(buf) > f.start && buf[len(buf)-1] == ':' {
					f.sep = len(buf) - 1
				}
			}
			buf = append(buf, c)
		}
	}
	return bytes.Contains(buf, []byte("${jndi:"))
}

// maxLookupDepth is the deepest "${" nesting isJNDI resolves.
const maxLookupDepth = 8

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
// would inject, followed by ':'. Location needs a URL or path value ("/",
// "\\" or a "scheme:") and Refresh a "<seconds>;url=" value, so that
// "Location: near masjid" or "Refresh: later" in prose stays clear.
func injectedHeaderAt(s string, i int) bool {
	for _, name := range [...]string{
		"set-cookie", "location", "refresh", "content-type", "content-length", "transfer-encoding",
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
		if name != "location" && name != "refresh" {
			return true
		}
		j++
		for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
			j++
		}
		if name == "refresh" {
			return refreshURLAt(s[j:])
		}
		return j < len(s) && (s[j] == '/' || s[j] == '\\') || urlSchemeAt(s[j:])
	}
	return false
}

// urlSchemeAt reports whether s starts with a URL scheme, its colon and a
// non-blank byte: a letter, then letters, digits, '+', '-' or '.', then ':'
// ("http://", "javascript:alert", "data:text"). "near masjid", "5pm: gate"
// and "Karachi: Block 5" do not.
func urlSchemeAt(s string) bool {
	if s == "" || !isASCIILetter(s[0]) {
		return false
	}
	for j := 1; j < len(s); j++ {
		c := s[j]
		switch {
		case c == ':':
			return j+1 < len(s) && s[j+1] != ' ' && s[j+1] != '\t' && s[j+1] != '\r' && s[j+1] != '\n'
		case isASCIILetter(c), c >= '0' && c <= '9', c == '+', c == '-', c == '.':
		default:
			return false
		}
	}
	return false
}

// refreshURLAt reports whether s is a Refresh redirect value: digits, then
// ';' or ',', optional blanks, then "url=" (any case).
func refreshURLAt(s string) bool {
	j := 0
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	if j == 0 {
		return false
	}
	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	if j >= len(s) || (s[j] != ';' && s[j] != ',') {
		return false
	}
	j++
	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	return hasPrefixFold(s[j:], "url=")
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
