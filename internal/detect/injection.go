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
// the ordinary rule applies to it, not the prose rule for a literal one,
// unless the line before the break is prose ("Dear team\nid", see
// proseLine). A backtick span is always command substitution here.
func cmdIQuery(v string) (Hit, bool) { return cmdI(v, false) }

// cmdMode says which prose readings an isCmdI scan allows.
type cmdMode struct {
	// strictNewline: every line break uses the prose rule for a bare
	// command (a literal line break in a JSON note or a form textarea).
	strictNewline bool
	// proseLineNewline: a line break uses the prose rule only when the
	// line before it is prose (see proseLine); a query value.
	proseLineNewline bool
	// proseBacktick: a single-backtick span in a sentence is inline code
	// (see proseBacktickAt), not command substitution.
	proseBacktick bool
	// encodedSemi: the value was decoded from one carrying %3b, so every
	// ";" is opShell.
	encodedSemi bool
}

// cmdI is CmdI; strictLiteral applies the stricter line-break rule to line
// breaks already present in v and reads prose backtick spans as inline
// code. Without it (a query value) the line-break rule applies only after a
// prose line. What arrives percent-encoded keeps the ordinary rules: a
// person does not type %0a or %60 into a note.
func cmdI(v string, strictLiteral bool) (Hit, bool) {
	hit := isCmdI(v, cmdMode{strictNewline: strictLiteral, proseLineNewline: !strictLiteral, proseBacktick: strictLiteral})
	if !hit {
		if d, _ := normalize.DecodeValue(v); d != v {
			encLB := hasEncodedLineBreak(v)
			hit = isCmdI(d, cmdMode{
				strictNewline:    strictLiteral && !encLB,
				proseLineNewline: !strictLiteral && !encLB,
				proseBacktick:    strictLiteral && !hasEncodedBacktick(v),
				encodedSemi:      hasEncodedSemicolon(v),
			})
		}
	}
	if hit {
		return Hit{RuleID: "AEG-CMDI-001", Category: model.CatCmdi, Severity: model.SeverityCritical}, true
	}
	return Hit{}, false
}

// hasPercentEscape reports whether s contains a percent escape %XY with
// match(X, Y); match gets the hex digits with letters lower-cased.
func hasPercentEscape(s string, match func(hi, lo byte) bool) bool {
	for i := strings.IndexByte(s, '%'); i >= 0 && i+2 < len(s); {
		if match(s[i+1]|0x20, s[i+2]|0x20) {
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

// hasEncodedLineBreak reports whether s contains %0a or %0d (any case).
func hasEncodedLineBreak(s string) bool {
	return hasPercentEscape(s, func(hi, lo byte) bool { return hi == '0' && (lo == 'a' || lo == 'd') })
}

// hasEncodedSemicolon reports whether s contains %3b (any case): a ";"
// still percent-encoded after transport decoding was encoded twice, which
// a scanner does and a person typing a note does not.
func hasEncodedSemicolon(s string) bool {
	return hasPercentEscape(s, func(hi, lo byte) bool { return hi == '3' && lo == 'b' })
}

// hasEncodedBacktick reports whether s contains %60: a backtick a person
// typed in markdown is sent as is inside a JSON or form value.
func hasEncodedBacktick(s string) bool {
	return hasPercentEscape(s, func(hi, lo byte) bool { return hi == '6' && lo == '0' })
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
	// opWordSemi: "; " directly after a token made only of letters,
	// digits or non-ASCII bytes, starting at the start of the value or
	// after a blank, that does not end a prose sentence ("Mon; sleep 8",
	// "Gate 2; sleep 10", "Café; sleep 8"). An address, a file name or an
	// assignment before the ";" ("127.0.0.1; sleep 5", "file.txt; sleep
	// 10", "a=1; sleep 10") is opShell. Only sleep reads opWordSemi as
	// prose (see sleepArgAt); every other command treats it as opShell, so
	// "Mon; id" still matches. A value that is only one ASCII letter or a
	// number before the "; " ("x; sleep 10", "1; sleep 5") is a probe, not
	// a note, and stays opShell (see probeTokenBefore).
	opWordSemi
	// opUAComment: "; " inside the parenthesised comment of a User-Agent
	// shaped value ("Mozilla/5.0 (Linux; U; Android 4.4.2; id; ...)", see
	// uaCommentStart). The comment is a "; "-separated list of tokens, and
	// "id" there is the Indonesian locale tag, so a two-letter bare command
	// with no flag is a token, as after opProseSemi. Every other command
	// shape keeps the opShell rules ("(Linux; id -u)", "(Linux; cat
	// /etc/passwd)", "(Linux; `id`)"). The comment must be closed: a ")"
	// must follow the ";" somewhere in the value ("x/1 (; id" is opShell).
	// The rule is structural, not tied to the User-Agent header: any value
	// that starts with a product token gets it. Accepted cost: a two-letter
	// bare command after "; " in a closed comment of a UA-shaped value is
	// clean ("Mozilla/5.0 (x; id)", "Mozilla/5.0 (x; id; ls)", "a/1 (b;
	// sh)").
	opUAComment
)

// operatorContext classifies the operator at s[i] (see opContext).
// firstBlank is the index of the first space or tab in s, or -1; isCmdI
// computes it once so the check stays linear in len(s). With
// encodedSemi (the ";" arrived double-encoded) a ";" is always opShell.
// inUAComment says s[i] is inside a User-Agent comment.
func operatorContext(s string, i, firstBlank int, encodedSemi, inUAComment bool) opContext {
	switch s[i] {
	case '&':
		if i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') && (i+1 == len(s) || s[i+1] != '&') {
			return opProseAmp
		}
	case ';':
		if encodedSemi || i+1 >= len(s) || s[i+1] != ' ' {
			break
		}
		if inUAComment {
			return opUAComment
		}
		if endsProseSentence(s, i, firstBlank) {
			return opProseSemi
		}
		if plainTokenBefore(s, i) && !probeTokenBefore(s, i) {
			return opWordSemi
		}
	}
	return opShell
}

// probeTokenBefore reports whether s[:end] is a single ASCII letter or a
// run of digits and nothing else: the "x; sleep 10" and "1; sleep 5"
// probes. A person's note has a word ("Mon; sleep 8") or more than one
// token ("Gate 2; sleep 10") before the "; ".
func probeTokenBefore(s string, end int) bool {
	if end == 1 && isASCIILetter(s[0]) {
		return true
	}
	return end > 0 && digitsEnd(s[:end], 0) == end
}

// uaCommentStart returns the index after which a "(" opens a User-Agent
// comment: the end of a leading product token ("Mozilla/5.0", "UCWEB/2.0",
// "Opera/9.80"), a letter-led name, a "/" and a version that starts with a
// digit, followed by a blank. It returns -1 when s does not start that way.
// It reads at most the first token.
func uaCommentStart(s string) int {
	i := 0
	for i < len(s) && (isIdentByte(s[i]) || s[i] == '.' || s[i] == '-') {
		i++
	}
	if i == 0 || !isASCIILetter(s[0]) || i+1 >= len(s) || s[i] != '/' || s[i+1] < '0' || s[i+1] > '9' {
		return -1
	}
	for i++; i < len(s) && s[i] != ' ' && s[i] != '\t'; i++ {
		if isShellOperator(s[i]) || s[i] == '(' || s[i] == '$' {
			return -1
		}
	}
	if i == len(s) {
		return -1
	}
	return i
}

// proseBacktickAt reports whether the backtick at s[i] opens inline code in
// a sentence, as markdown writes it ("Use `ls` to list files", "Se også:
// `id`.", "On LoongArch, `uname -m` returns ..."): a blank before it with a
// letter, a non-ASCII byte or sentence punctuation (. , : ! ? ) " ') before
// the blank, and a closing backtick on the same line at close (the next
// backtick in s, or -1) followed by sentence text: punctuation, or blanks
// and then a letter or a non-ASCII byte. A span after a shell operator
// ("x; `id`", "x = `id`"), glued to a word ("x`id`"), alone ("`id`") or
// with nothing after it ("Name `id`") stays command substitution. The span
// itself must be a name (see inlineNameSpan), so "a `sleep 10` b" and
// "Run `wget http://x -O /tmp/x` now" stay hits. Only the opening backtick
// is excused: operators inside the span and the closing backtick are still
// scanned ("Use `curl x | sh` now" is a hit).
func proseBacktickAt(s string, i, close int) bool {
	if i < 2 || close < 0 || (s[i-1] != ' ' && s[i-1] != '\t') {
		return false
	}
	if p := s[i-2]; !isASCIILetter(p) && p < 0x80 && strings.IndexByte(`.,:!?)"'`, p) < 0 {
		return false
	}
	if close == i+1 || strings.ContainsAny(s[i+1:close], "\n\r") {
		return false
	}
	if !inlineNameSpan(s[i+1 : close]) {
		return false
	}
	k := close + 1
	if k < len(s) && strings.IndexByte(`.,:!?)"'`, s[k]) >= 0 {
		return true
	}
	n := skipBlanks(s, k)
	return n > k && n < len(s) && (isASCIILetter(s[n]) || s[n] >= 0x80)
}

// inlineNameSpan reports whether span (the text between two backticks)
// names a command rather than running one: a word of letters, digits, '.',
// '_' or '-' that starts with a letter, then only flags made of letters and
// '-' ("id", "uname -m", "id --user --name", "ls -l --escape"). Any other
// token (an argument, a number, a path, a URL, a quote, an operator), the
// flags -c and -e, and any flag at all after sh, bash, python, perl, nc,
// ncat or netcat make it a command. Accepted cost: a command word with
// such flags in a prose span is clean ("a `whoami` b", "a `uname -a` b",
// "a `ls -la` b", "a `sh` b"). Linear in len(span).
func inlineNameSpan(span string) bool {
	i := skipBlanks(span, 0)
	start := i
	if i >= len(span) || !isASCIILetter(span[i]) {
		return false
	}
	for i < len(span) && (isIdentByte(span[i]) || span[i] == '.' || span[i] == '-') {
		i++
	}
	switch span[start:i] {
	case "sh", "bash", "python", "perl", "nc", "ncat", "netcat":
		return skipBlanks(span, i) == len(span)
	}
	for {
		if i < len(span) && span[i] != ' ' && span[i] != '\t' {
			return false
		}
		if i = skipBlanks(span, i); i == len(span) {
			return true
		}
		f := i
		for i < len(span) && span[i] == '-' && i-f < 2 {
			i++
		}
		if i == f || i >= len(span) || !isASCIILetter(span[i]) {
			return false
		}
		for i < len(span) && (isASCIILetter(span[i]) || span[i] == '-') {
			i++
		}
		if tok := span[f:i]; tok == "-c" || tok == "-e" {
			return false
		}
	}
}

// loneProseWordAt reports whether s[j:] (after blanks) is "id" or "ls" as a
// whole token: the two command words a line of prose in a query value may
// end with on the next line ("Dear team" newline "id"). Other commands
// after a prose line keep the ordinary rule ("foo bar" newline "whoami",
// "sleep 10", "uname", "sh"). O(1).
func loneProseWordAt(s string, j int) bool {
	j = skipBlanks(s, j)
	if j+2 > len(s) || (s[j:j+2] != "id" && s[j:j+2] != "ls") {
		return false
	}
	return j+2 == len(s) || s[j+2] == ' ' || s[j+2] == '\t' || isShellOperator(s[j+2])
}

// proseLine reports whether line (the text between two line breaks) reads
// as a line of prose: at least two words, no shell operator, quote-free of
// shell syntax ($ ( ) < > { } = \ and backticks), ending in a letter, a
// non-ASCII byte or sentence punctuation. "Dear team" and "Dear team," are
// prose; "x", "127.0.0.1", "x;" and "a=b c" are not. In a query value only
// "id" or "ls" alone after such a line is then a word (loneProseWordAt).
// Accepted cost: "?q=foo%20bar%0aid" and "?q=foo%20bar%0als" are clean.
func proseLine(line string) bool {
	line = strings.Trim(line, " \t")
	if strings.IndexAny(line, " \t") <= 0 || strings.ContainsAny(line, ";|&`$()<>{}=\\") {
		return false
	}
	last := line[len(line)-1]
	return isASCIILetter(last) || last >= 0x80 || strings.IndexByte(".,:!?", last) >= 0
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

// plainTokenBefore reports whether s[:end] ends with a non-empty token of
// only letters, digits or non-ASCII bytes that starts at the start of s or
// after a blank. The backward walk covers only the run of such bytes
// directly before s[end] (an operator ends it), so the walks of one isCmdI
// scan are disjoint and linear together.
func plainTokenBefore(s string, end int) bool {
	j := end
	for j > 0 {
		c := s[j-1]
		if !isASCIILetter(c) && (c < '0' || c > '9') && c < 0x80 {
			break
		}
		j--
	}
	return j < end && (j == 0 || s[j-1] == ' ' || s[j-1] == '\t')
}

// isCmdI scans s for an operator followed by a command, with the prose
// readings m allows (see cmdMode).
//
// Every helper it calls per operator either reads O(1) bytes or walks a
// stretch no other call walks (the line before a line break, the bytes up
// to the next backtick), so a scan is linear in len(s).
func isCmdI(s string, m cmdMode) bool {
	if hasCmdMarker(s) {
		return true
	}
	firstBlank := strings.IndexAny(s, " \t")
	uaStart := uaCommentStart(s)
	lastClose := strings.LastIndexByte(s, ')')
	uaDepth := 0           // open "(" of a User-Agent comment, after uaStart
	lineStart := 0         // start of the current line
	lastLineProse := false // the last non-empty line was prose (proseLine)
	for i := 0; i < len(s); i++ {
		afterNewline := false
		ctx := opShell
		switch s[i] {
		case '(':
			if uaStart >= 0 && i > uaStart {
				uaDepth++
			}
			continue
		case ')':
			if uaDepth > 0 {
				uaDepth--
			}
			continue
		case '`':
			if m.proseBacktick {
				close := strings.IndexByte(s[i+1:], '`')
				if close >= 0 {
					close += i + 1
				}
				if proseBacktickAt(s, i, close) {
					continue
				}
			}
		case ';', '|', '&':
			ctx = operatorContext(s, i, firstBlank, m.encodedSemi, uaDepth > 0 && i < lastClose)
		case '\n', '\r':
			if m.strictNewline {
				afterNewline = true
			} else if m.proseLineNewline {
				if i > lineStart {
					lastLineProse = proseLine(s[lineStart:i])
				}
				afterNewline = lastLineProse && loneProseWordAt(s, i+1)
			}
			lineStart = i + 1
		case '$':
			if i+1 >= len(s) || s[i+1] != '(' {
				continue
			}
			if substitutionAt(s, i) {
				return true
			}
			i++
		default:
			continue
		}
		j := i + 1
		for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '|' || s[j] == '&') {
			j++
		}
		if commandAt(s, j, afterNewline, ctx) {
			return true
		}
		if (s[i] == ';' || s[i] == '|' || s[i] == '&') && echoProbeAt(s, j, ctx) {
			return true
		}
		// The skipped bytes all lead to the same j: do not rescan them.
		i = j - 1
	}
	return false
}

// maxSubst bounds how many non-blank bytes substitutionAt reads looking for
// the closing parenthesis of a "$(" or "$((" substitution. Commix's probes
// close within a few dozen bytes. Blanks do not count against the bound
// ("$(echo" then 130 blanks then ")" is still read), but every scan stops at
// the next "(" or line break, so the stretches two scans walk never overlap
// and "$($($(...", a long unclosed "$(" and blank padding stay linear.
const maxSubst = 128

// substitutionAt reports whether the "$(" at s[i] opens a shell command or
// arithmetic substitution of any word, not only a listed command: commix's
// default probe "$(echo IPTSZG)" and "$((46+17))".
//
//   - "$((": the body starts with an identifier byte or a digit, then holds
//     only identifier bytes, digits, blanks and + - * / %, closed by "))".
//   - "$(": a word that starts with a letter or "_" (never a digit: "$(5)",
//     "US$(10)", "$(45.00)" and the accounting negative "$(1,234.56)" are
//     amounts), then any bytes but "(" and a line break up to a ")".
//
// A dollar amount in prose stays clear (see proseDollarWord): "costs
// $(approx) 5", "($(approx) 5)", "$(amount) due". "Price ($5)" and "$5
// (usd)" have no "$(". A line break inside ends the scan ("$(echo" newline
// "hi)" is missed). Accepted costs, flagged as code-like text: a closed
// "$(...)" or "$((...))" in shell snippets (tldr-style command lines, fenced
// shell blocks, inline code spans holding a substitution), jQuery calls
// with more than one bare name ("$(this.el).hide() not working"; a single
// name such as "$(document).ready(fn)" has the prose shape), arithmetic written in shell syntax
// ("$((a+b)) is the sum"), and prose amounts with two tokens or a dot inside
// ("costs $(about 5)", "around $(approx. 50)").
func substitutionAt(s string, i int) bool {
	j := i + 2
	if j < len(s) && s[j] == '(' {
		k := j + 1
		if k >= len(s) || !isIdentByte(s[k]) {
			return false
		}
		for n := 0; k < len(s) && n <= maxSubst; k++ {
			c := s[k]
			switch {
			case c == ')':
				return k+1 < len(s) && s[k+1] == ')'
			case c == ' ' || c == '\t':
				continue
			case !isIdentByte(c) && strings.IndexByte("+-*/%", c) < 0:
				return false
			}
			n++
		}
		return false
	}
	if j >= len(s) || (!isASCIILetter(s[j]) && s[j] != '_') {
		return false
	}
	k := j
	for k < len(s) && isIdentByte(s[k]) && k-j <= maxSubst {
		k++
	}
	word := s[j:k]
	for n := k - j; k < len(s) && n <= maxSubst; k++ {
		switch s[k] {
		case ')':
			return !proseDollarWord(s, i, word, k)
		case '(', '\n', '\r':
			return false
		case ' ', '\t':
			continue
		}
		n++
	}
	return false
}

// substCmds are commands that count inside "$(...)" even in the prose
// dollar shape, on top of cmdWords: "x $(reboot)", "a $(hostname) b". They
// are matched only there (not after ";" or "|", where "env" and "hostname"
// are common words), case-insensitively. Read-only.
var substCmds = [...]string{"reboot", "halt", "poweroff", "shutdown", "env", "printenv", "hostname"}

// proseDollarWord reports whether the "$(word)" at s[i] with its ")" at
// close reads as a dollar amount in prose: the "$" at the start of the
// value or after a blank or "(", nothing but the letters of word inside,
// and after the ")" the end of the value, a blank or sentence punctuation
// ("costs $(approx) 5", "($(approx) 5)", "$(amount) due"). A listed command
// (cmdWords, substCmds, any case) is never prose: "x $(reboot)", "a
// $(hostname) b". Other commands there are caught by commandAt ("a $(id)
// b"). Accepted cost: an unlisted letter-only word in that shape is clean
// ("a $(foo) b", "$(foo)").
func proseDollarWord(s string, i int, word string, close int) bool {
	if i > 0 && s[i-1] != ' ' && s[i-1] != '\t' && s[i-1] != '(' {
		return false
	}
	if close != i+2+len(word) {
		return false
	}
	for k := 0; k < len(word); k++ {
		if !isASCIILetter(word[k]) {
			return false
		}
	}
	for _, c := range substCmds {
		if strings.EqualFold(word, c) {
			return false
		}
	}
	for _, w := range cmdWords {
		if strings.EqualFold(word, w.name) {
			return false
		}
	}
	n := close + 1
	return n == len(s) || s[n] == ' ' || s[n] == '\t' || strings.IndexByte(".,:;!?)", s[n]) >= 0
}

// echoProbeAt reports whether s[j:] is echo with an argument that starts
// with a variable or substitution ("$" then a letter, "_", "{", "(" or
// "?"), a backtick or a quote ("; echo $HOME", "|| echo `id`", "&& echo
// 'x'"): commix's echo probe after a shell operator. "$5" is an amount, not
// a variable ("Ok; echo $5 back" is clear). ctx is what the operator
// proves: after a lone " & " (opProseAmp) it never matches ("Tom & echo
// \"hi\""), and after a prose sentence's "; " (opProseSemi) or "; " after one
// plain word (opWordSemi) a quote is prose quoting, so only "$" or a
// backtick counts ("see you; echo \"hi\"", "Mon; echo \"hi\"" and "Yes; echo
// \"same\"" are clear; "x; echo \"hi\"" is not). "Echo Park; echo of the
// past" stays clear: echo must be lower case and the argument must start
// with one of those bytes. O(1) apart from the blanks after echo.
func echoProbeAt(s string, j int, ctx opContext) bool {
	if ctx == opProseAmp || !strings.HasPrefix(s[j:], "echo") {
		return false
	}
	k := j + 4
	n := skipBlanks(s, k)
	if n == k || n >= len(s) {
		return false
	}
	switch s[n] {
	case '`':
		return true
	case '$':
		if n+1 >= len(s) {
			return false
		}
		c := s[n+1]
		return isASCIILetter(c) || strings.IndexByte("_{(?", c) >= 0
	case '\'', '"':
		return ctx != opProseSemi && ctx != opWordSemi
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
		if ctx == opWordSemi {
			ctx = opShell
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
// prose-like operator ("Kids & sleep 8", "Long day; sleep 8", and "; "
// after a single word or number: "Mon; sleep 8", "Gate 2; sleep 10") the number
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
// three-letter lower-case word ("me", "you", "the"), four lower-case
// letters with at least two vowels counting y ("cozy", "cute"), or five or
// more lower-case letters with at least two vowels ("lovers"). Option clusters
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
		// "cozy", "cute", "easy", "nice": two vowels, counting y. Four-letter
		// option clusters (-lvnp, -ltrh, -rfiv) have at most one.
		return vowels+strings.Count(w, "y") >= 2
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
//
// '/' is a base64 byte, but it is also the path separator, so a stream sent
// as a path segment (/api/v1/x/rO0AB...) sits after one (G1b). After a '/'
// the header must be followed by 'X', which is how base64 carries the type
// code byte (0x70 to 0x7E) every real stream has after the header: a '/'
// followed by "rO0ABX" inside a legitimate standard-base64 blob is a 1 in
// 64^7 chance per position, where "/rO0AB" alone would be 1 in 64^6.
func hasJavaSerialized(s string) bool {
	for off := 0; ; {
		n := strings.Index(s[off:], "rO0AB")
		if n < 0 {
			break
		}
		at := off + n
		if at == 0 || !isBase64Byte(s[at-1]) ||
			s[at-1] == '/' && at+len("rO0AB") < len(s) && s[at+len("rO0AB")] == 'X' {
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

// isSSTI reports whether s holds a server-side template expression.
//
// alpha.6 reads some template text as data so that real customer and docs
// text is not blocked: a {{ }} filter pipe made of placeholder text
// ("{{ price | currency }}", "Dear {{ name|title }},", tldr's
// "{{[-p|--patch]}}"), a short i18n call in ${ } ("${t('cart.title')}"),
// member access to a field named pass ("${bus.pass}"), and a plain data path
// in #{ } ("#{order.total}"); #{ } stays stricter than ${ } for anything
// else. The accepted SSTI misses of alpha.6 (the same list
// is in the threat model and the corpus README; each has an entry in
// TestSSTIAlpha6AcceptedMisses):
//
//  1. A `{{ }}` filter pipe made only of placeholder text:
//     blank-separated tokens of letters, digits and `_ . / < > ? = [ ]
//     -` (up to two leading `-` or `+`), split by `|`, with no call,
//     quote or argument, no template global or sensitive name except as
//     a filter name (the leading name of the first token after a `|`;
//     such a token that starts with `-` or `+` does not parse) or as a
//     one-letter name right after a leading `-` or `+`, and no `e`,
//     `escape`, `safe` or `raw` filter unless the whole is tldr
//     alternation in brackets: `{{ name|upper }}`, `{{ x|list }}`, `{{
//     x|attr }}`, `{{ x|config }}`, `{{ name|system }}`, `{{[a|b]}}`,
//     `{{[a|b][0]}}`, `{{ x|y if a else b }}`, `{{[x|safe]}}`,
//     `{{[c|config]}}`, `{{ -g|list }}`. Without a call or an argument
//     a filter cannot reach a callable, and an unknown filter name does
//     not compile in Jinja, Django, Twig or Nunjucks.
//  2. In `${ }`, a call of a one-letter lower-case name, `$t` or
//     `i18n.t` with one plain string literal (letters, digits, blanks,
//     `.`, `_`, `-`) that names no Java class, reflection or process
//     word, when the name was bound to an executor outside the value:
//     `${e('id')}`, `${t('whoami')}`. A FreeMarker directive (`<#`,
//     `[#`, `<@`, `[@`) or a `?new`, `?api`, `?eval` or `?interpret`
//     built-in anywhere in the same value turns this reading off.
//  3. Member access to, or a call of, a name `pass` in `${ }` when no
//     other sensitive name is present, and a `#{ }` data path ending in
//     `pass`: `${user.pass}`, `${user.pass()}`, `#{user.pass}`.
//     `password`, `passwd` and `pwd` still count.
//  4. In `#{ }`, a plain data path: names joined by single `.` and
//     nothing else, a root that starts with a lower-case letter or `_`
//     and is not a scope, environment or global object (`binding`,
//     `header`, `param`, `cookie`, `initParam`, the JSF and JSP
//     `*Scope` objects, `facesContext`, `externalContext`,
//     `systemEnvironment`, `systemProperties`, `self`, `this`,
//     `require`, `constructor`, ...), and no sensitive name or
//     zero-argument code method (`irb`, `methods`,
//     `instance_variables`, `constructor`, `call`, ...) in it:
//     `#{x.fork}`, `#{x.class}`, `#{a.b.c}`, `#{order.send}`,
//     `#{file.read}`. A method reached this way runs only on an object
//     the template already holds. Anything else in `#{ }` (a call, an
//     index, `*`, `&.`, any other byte, an upper-case root) is code as
//     in alpha.5.
func isSSTI(s string) bool {
	if strings.Contains(s, "${T(") || strings.Contains(s, "#{T(") ||
		hasFreeMarkerNew(s) || eachCodeTemplate(s) {
		return true
	}
	// A FreeMarker directive or a ?new, ?api, ?eval or ?interpret built-in
	// anywhere in the value can bind an executor to a short name, so no
	// i18n call is read as data then ("<#assign e=c?new()>${e('id')}").
	bind := hasFreeMarkerBinding(s)
	return eachDelimited(s, "${", "}", func(in string) bool { return elExpr(in, bind) }) ||
		eachDelimited(s, "#{", "}", isHashExpr) ||
		eachDelimited(s, "{%", "%}", isJinjaStatement) ||
		hasERBOutput(s)
}

// hasFreeMarkerNew finds FreeMarker's ?new built-in applied to a string
// literal that names a Java class ("freemarker.template.utility.Execute"?new()),
// the step that binds an executor, wherever it sits in the value. The
// literal must be dotted names ("a.B"), so prose such as `"hi"?new(ish)`
// is not one. The look back is bounded, so the scan stays linear.
func hasFreeMarkerNew(s string) bool {
	for off := 0; ; {
		n := indexFold(s[off:], "?new(")
		if n < 0 {
			return false
		}
		at := off + n
		e := at // blanks may sit between the literal and "?"
		for e > 0 && at-e < maxClassLiteral && (s[e-1] == ' ' || s[e-1] == '\t') {
			e--
		}
		if e > 0 && (s[e-1] == '"' || s[e-1] == '\'') {
			q := s[e-1]
			lo := max(e-1-maxClassLiteral, 0)
			if i := strings.LastIndexByte(s[lo:e-1], q); i >= 0 {
				lit := s[lo+i+1 : e-1]
				if strings.IndexByte(lit, '.') > 0 && isDataPath(lit) {
					return true
				}
			}
		}
		off = at + 1
	}
}

// hasFreeMarkerBinding reports whether s holds a FreeMarker directive
// ("<#", "[#", "<@", "[@") or a ?new, ?api, ?eval or ?interpret built-in:
// "?", optional blanks or line breaks, then the name (any case) not
// followed by a name byte. "what?news" is not one. Each "?" skips blanks
// only up to the next non-blank, so the scan is linear.
func hasFreeMarkerBinding(s string) bool {
	if strings.Contains(s, "<#") || strings.Contains(s, "[#") ||
		strings.Contains(s, "<@") || strings.Contains(s, "[@") {
		return true
	}
	for off := 0; ; {
		n := strings.IndexByte(s[off:], '?')
		if n < 0 {
			return false
		}
		j := off + n + 1
		for j < len(s) && isBlankByte(s[j]) {
			j++
		}
		for _, b := range [...]string{"new", "api", "eval", "interpret"} {
			if hasPrefixFold(s[j:], b) && (j+len(b) >= len(s) || !isIdentByte(s[j+len(b)])) {
				return true
			}
		}
		off = j
	}
}

// isBlankByte reports whether c is a blank or a line break.
func isBlankByte(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// maxClassLiteral bounds how far hasFreeMarkerNew looks back for the
// opening quote of a class-name literal.
const maxClassLiteral = 128

// eachCodeTemplate is eachDelimited for "{{ }}" with one more reading: when
// the text since the previous close holds more than one "{{", the text from
// the first of them is also checked for a dunder walk or a call. Jinja
// balances braces inside an expression, so in
// "{{ lipsum.__globals__.os.popen('id').read() ~ {{a|b}} }}" the call runs
// before the inner set literal fails; reading only the inner "a|b" would
// miss it. The ranges are disjoint, so every byte is read a bounded number
// of times.
func eachCodeTemplate(s string) bool {
	for from := 0; from < len(s); {
		c := strings.Index(s[from:], "}}")
		if c < 0 {
			return false
		}
		c += from
		if o := strings.LastIndex(s[from:c], "{{"); o >= 0 {
			if isCodeExpr(s[from+o+2 : c]) {
				return true
			}
			if f := strings.Index(s[from:c], "{{"); f < o && hasDunderOrCall(s[from+f+2:c]) {
				return true
			}
		}
		from = c + 2
	}
	return false
}

// hasDunderOrCall reports whether in holds "__" or a name followed by "(".
func hasDunderOrCall(in string) bool {
	if strings.Contains(in, "__") {
		return true
	}
	for i := 1; i < len(in); i++ {
		if in[i] == '(' && isIdentByte(in[i-1]) {
			return true
		}
	}
	return false
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
	if hasDunderOrCall(in) {
		return true
	}
	if strings.IndexByte(in, '|') >= 0 {
		return !isPlainPipe(in)
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

// isPlainPipe reports whether the inside of a {{ }} that holds a "|" (and,
// as isCodeExpr checked first, no "__" and no name followed by "(") is
// positively benign-shaped: segments split by "|", each one or more
// blank-separated placeholder tokens. This covers Jinja, Django and Liquid
// pipes with bare filters ("{{ user.name | upper }}") and tldr placeholders
// ("{{[-p|--patch]}}", "{{[images|image ls]}}", "{{dev|test|...}}",
// "{{path/to/file|url}}"). Without a call, a quote or an argument a filter
// pipe cannot reach code, so what is left to refuse is a sensitive name:
//
//   - a token is "...", or up to two "-" or "+" then one or more letters,
//     digits and "_ . / < > ? = [ ] -", not starting with "." (a Go field,
//     "{{ .Name | html }}"); any other byte (quote, "(", "*", "~", ":",
//     "%", "{", "#", "$", "!", "&", ",", "@", "\") makes the value code;
//   - no segment is empty ("||", a leading or trailing "|"), the outer
//     "[...]" of tldr alternation removed first;
//   - no name in any token is a template global (pipeGlobals) or an
//     elSensitive name, except in the filter name right after a "|": an
//     unknown filter does not compile in Jinja, Django, Twig or Nunjucks,
//     so "{{[c|config]}}" and "{{b|k|m|g}}" cannot reach a global;
//   - unless the whole inside is wrapped in "[...]" (tldr alternation), no
//     segment after the first is one of the escape-control filters e,
//     escape, safe or raw ("{{ value|e }}", "{{ x | safe }}");
//   - a first segment that is a plain number is not followed by a filter
//     name ("{{364|add:733}}" also has ":"; "{{ 7|int }}" is a probe).
//
// Single linear pass.
func isPlainPipe(in string) bool {
	in = strings.Trim(in, " \t\r\n")
	bracketed := len(in) >= 2 && in[0] == '[' && in[len(in)-1] == ']'
	if bracketed {
		in = in[1 : len(in)-1]
	}
	numRoot := false
	for seg := 0; ; seg++ {
		var part string
		i := strings.IndexByte(in, '|')
		if i >= 0 {
			part, in = in[:i], in[i+1:]
		} else {
			part, in = in, ""
		}
		part = strings.Trim(part, " \t\r\n")
		if part == "" {
			return false
		}
		if seg > 0 && !bracketed && escapeFilters[strings.ToLower(part)] {
			return false
		}
		allDigits := true
		for k, tok := range strings.Fields(part) {
			// The filter name itself (the leading name of the first token
			// after a "|") is not checked for sensitive names: Jinja, Django,
			// Twig and Nunjucks refuse to compile an unknown filter, so
			// "{{ x|config }}" cannot reach the config global. What follows
			// the name in the same token is checked ("{{ x|e[config] }}").
			if !isPlaceholderToken(tok, seg > 0 && k == 0) {
				return false
			}
			for j := 0; j < len(tok); j++ {
				if tok[j] < '0' || tok[j] > '9' {
					allDigits = false
				}
			}
		}
		switch {
		case seg == 0:
			numRoot = allDigits
		case numRoot && !allDigits:
			return false
		}
		if i < 0 {
			return true
		}
	}
}

// isPlaceholderToken checks one blank-free token for isPlainPipe and
// refuses a sensitive name in it. With filter set the token is the first
// after a "|": its leading name is the filter name and is not checked, and
// a token that starts with "-" or "+" there does not parse ("|--config").
// Every name after the leading one is checked, since an operator byte ends
// the filter name and starts an expression ("{{ x|raw??app.request... }}",
// "{{ x|length<config.SECRET_KEY|length }}").
func isPlaceholderToken(tok string, filter bool) bool {
	if tok == "..." {
		return true
	}
	i := 0
	for i < len(tok) && i < 2 && (tok[i] == '-' || tok[i] == '+') {
		i++
	}
	if i >= len(tok) || tok[i] == '.' {
		return false
	}
	for j := i; j < len(tok); j++ {
		if !isIdentByte(tok[j]) && strings.IndexByte("./<>?=[]-", tok[j]) < 0 {
			return false
		}
	}
	start := i
	if filter {
		if i > 0 {
			return true
		}
		for start < len(tok) && isIdentByte(tok[start]) {
			start++
		}
	}
	// Names are checked in dashed tokens too: "+" and "-" are operators,
	// and "{{ [x]|list +config|dictsort }}" concatenates the config items.
	for j := start; j < len(tok); {
		if !isIdentByte(tok[j]) {
			j++
			continue
		}
		k := j
		for k < len(tok) && isIdentByte(tok[k]) {
			k++
		}
		// A one-letter name right after a leading dash is a tldr short
		// option ("{{[-g|--global]}}"); as Jinja it negates a value, which
		// leaks nothing from Flask's g.
		if lower := strings.ToLower(tok[j:k]); (pipeGlobals[lower] || elSensitive[lower]) && !(i > 0 && j == i && k-j == 1) {
			return false
		}
		j = k
	}
	return true
}

// pipeGlobals holds the lower-cased names that keep a {{ }} pipe code
// outside the filter name: Jinja, Flask, Django and Twig globals that reach
// the runtime, the request or the app configuration ("{{ config|list }}",
// "{{ app.request.server.all|join }}", Twig _context, Flask g, Ansible
// ansible_env and hostvars), and attr.
var pipeGlobals = map[string]bool{
	"config": true, "self": true, "_self": true, "request": true, "session": true,
	"cycler": true, "joiner": true, "namespace": true, "lipsum": true,
	"url_for": true, "get_flashed_messages": true, "app": true, "os": true,
	"_context": true, "g": true, "ansible_env": true, "hostvars": true,
	"env": true, "settings": true, "application": true, "attr": true,
	"passthru": true, "shell_exec": true,
}

// escapeFilters are the filters that turn autoescaping off or on; as a
// filter they keep a {{ }} pipe code ("{{ value|e }}", "{{ x|safe }}").
var escapeFilters = map[string]bool{"e": true, "escape": true, "safe": true, "raw": true}

// isName reports whether s is one ASCII identifier that starts with a
// letter or "_".
func isName(s string) bool {
	if s == "" || !(isASCIILetter(s[0]) || s[0] == '_') {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isIdentByte(s[i]) {
			return false
		}
	}
	return true
}

// isDataPath reports whether s is names joined by single dots
// ("user.name").
func isDataPath(s string) bool {
	for {
		i := strings.IndexByte(s, '.')
		if i < 0 {
			return isName(s)
		}
		if !isName(s[:i]) {
			return false
		}
		s = s[i+1:]
	}
}

// isI18nCall reports whether the inside of a ${ } or #{ } is a short
// translation call: a one-letter lower-case name, "$t" or "i18n.t", then
// "(", one string literal of letters, digits, blanks, ".", "_" or "-",
// and ")" with nothing after it, whose text names no elCodeSensitive word
// ("t('cart.title')"). in is already trimmed.
func isI18nCall(in string) bool {
	var rest string
	switch {
	case len(in) >= 2 && in[0] >= 'a' && in[0] <= 'z' && in[1] == '(':
		rest = in[1:]
	case strings.HasPrefix(in, "$t("):
		rest = in[2:]
	case strings.HasPrefix(in, "i18n.t("):
		rest = in[6:]
	default:
		return false
	}
	// rest is "(" q key q ")".
	if len(rest) < 5 || rest[len(rest)-1] != ')' {
		return false
	}
	q := rest[1]
	if (q != '\'' && q != '"') || rest[len(rest)-2] != q {
		return false
	}
	key := rest[2 : len(rest)-2]
	if strings.TrimSpace(key) == "" {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if !isIdentByte(c) && c != ' ' && c != '.' && c != '-' {
			return false
		}
	}
	for i := 0; i < len(key); {
		if !isIdentByte(key[i]) {
			i++
			continue
		}
		j := i
		for j < len(key) && isIdentByte(key[j]) {
			j++
		}
		if j-i <= maxELName && elCodeSensitive[strings.ToLower(key[i:j])] {
			return false
		}
		i = j
	}
	return true
}

// elCodeSensitive holds the names that keep an i18n call's key code: Java
// and FreeMarker class roots, reflection and process words. Credential and
// web-context words are ordinary translation keys ("auth.password.label",
// "session.expired").
var elCodeSensitive = map[string]bool{
	"java": true, "javax": true, "freemarker": true, "groovy": true, "runtime": true,
	"getruntime": true, "processbuilder": true, "scriptengine": true, "classloader": true,
	"forname": true, "getclass": true, "newinstance": true, "getmethod": true,
	"exec": true, "popen": true, "eval": true,
}

// isELExpr reports whether the inside of a ${ } (EL, Spring, Groovy,
// FreeMarker) holds code: number arithmetic (7*7, 7+7, 7*'7'), a dunder
// walk, a string literal used as an object ("id".execute()), FreeMarker
// ?new or ?api, a call with a string literal argument (ex("id")), or member
// access (user.password) or a call that names something sensitive (see
// elSensitive). Plain data paths such as "${order.total}", a placeholder
// such as "${PRICE}", a number such as "${5}" and a short i18n call such as
// "${t('cart.title')}" (see isI18nCall) are not code.
func isELExpr(in string) bool { return elExpr(in, false) }

// elExpr is isELExpr. bind is set when the value holds a FreeMarker
// directive or binding built-in, and then no i18n call is read as data.
func elExpr(in string, bind bool) bool {
	in = strings.Trim(in, " \t")
	if !bind && isI18nCall(in) {
		return false
	}
	i := 0
	for i < len(in) && in[i] >= '0' && in[i] <= '9' {
		i++
	}
	if i > 0 {
		rest := strings.TrimLeft(in[i:], " ")
		if rest == "" || (rest[0] != '*' && rest[0] != '+') {
			return false
		}
		// The second number may be quoted, as in the probe ${7*'7'}.
		rest = strings.TrimLeft(rest[1:], " '\"")
		return rest != "" && rest[0] >= '0' && rest[0] <= '9'
	}
	if strings.Contains(in, "__") {
		return true // a dunder walk: ${self.__init__}, ${__import__('os')}
	}
	access := false
	for j := 1; j < len(in); j++ {
		c, p := in[j], in[j-1]
		if c == ':' && !access {
			// A lookup such as ${jndi:ldap://host/a} or ${env:HOME} belongs
			// to the JNDI rule, not to EL member access.
			return false
		}
		switch {
		case (c == '.' || c == '?' || c == '(') && (p == '"' || p == '\''):
			return true // a string literal used as an object: ${"id".execute()}
		case c == '?' && (hasPrefixFold(in[j+1:], "new") || hasPrefixFold(in[j+1:], "api")):
			return true // FreeMarker ?new / ?api
		case c == '(' && isIdentByte(p) && j+1 < len(in) && (in[j+1] == '"' || in[j+1] == '\''):
			return true // a call with a string literal: ${ex("id")}
		case isIdentByte(p) && (c == '(' || c == '.' && j+1 < len(in) && isASCIILetter(in[j+1])):
			access = true
		}
	}
	return access && hasSensitiveName(in)
}

// isHashExpr reports whether the inside of a #{ } (Ruby, EL, Thymeleaf,
// Spring) holds code. #{ } stays stricter than ${ }: anything with a call,
// an index, a "*" or member access is code ("#{order.total.round(2)}",
// "#{x[0]}", "#{7*'7'}"), and so is a Ruby %x command ("#{%x{id}}"), unless
// the whole expression is a plain data path (see isHashDataPath):
// "#{order.total}", "#{user.name}", "#{repo.fork}" and "#{bus.pass}" are
// data. "#{12}" or "#{3B}" in an address has none of these.
func isHashExpr(in string) bool {
	t := strings.Trim(in, " \t\r\n")
	if hasRubyCommand(t) {
		return true
	}
	if isHashDataPath(t) {
		return false
	}
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

// isHashDataPath reports whether t (a trimmed #{ } inside) is names joined
// by single dots with no elSensitive or hashCodeSegments name in it and a
// root that is not a module, environment or scope object: the root starts
// with a lower-case letter or "_" (an upper-case root is a Ruby constant, a
// module or class such as ENV, File, Kernel or Etc) and is not in
// hashRootsFold, matched in any case.
func isHashDataPath(t string) bool {
	if !isDataPath(t) {
		return false
	}
	root := t
	if i := strings.IndexByte(t, '.'); i >= 0 {
		root = t[:i]
	}
	if root[0] >= 'A' && root[0] <= 'Z' || hashRootsFold[strings.ToLower(root)] {
		return false
	}
	for seg := t; seg != ""; {
		part := seg
		if i := strings.IndexByte(seg, '.'); i >= 0 {
			part, seg = seg[:i], seg[i+1:]
		} else {
			seg = ""
		}
		if lower := strings.ToLower(part); elSensitive[lower] || hashCodeSegments[lower] {
			return false
		}
	}
	return true
}

// hashRootsFold are names, matched in any case, that a #{ } path may not
// start with: binding, JSF and JSP implicit and scope objects, Spring's
// environment and property maps and bean factory, and JavaScript globals.
var hashRootsFold = map[string]bool{
	"binding": true, "header": true, "headervalues": true, "param": true,
	"paramvalues": true, "cookie": true, "initparam": true, "pagescope": true,
	"requestscope": true, "sessionscope": true, "applicationscope": true,
	"viewscope": true, "flowscope": true, "conversationscope": true, "conversation": true,
	"cc": true, "component": true, "resource": true,
	"facescontext": true, "externalcontext": true, "view": true, "flash": true,
	"systemenvironment": true, "systemproperties": true, "environment": true,
	"beanfactory": true, "applicationcontext": true, "servletcontext": true,
	"application": true, "self": true, "this": true, "global": true,
	"globalthis": true, "window": true, "root": true, "require": true,
	"module": true, "exports": true, "constructor": true, "prototype": true,
}

// hashCodeSegments are zero-argument methods that reach code or
// reflection from any object, so a #{ } path holding one is code
// ("#{x.instance_variables}", "#{x.irb}", "#{x.constructor}").
var hashCodeSegments = map[string]bool{
	"irb": true, "pry": true, "exit": true, "abort": true, "instance_variables": true,
	"local_variables": true, "global_variables": true, "methods": true,
	"public_methods": true, "private_methods": true, "protected_methods": true,
	"singleton_methods": true, "constants": true, "ancestors": true, "superclass": true,
	"class_variables": true, "constructor": true, "prototype": true, "caller": true,
	"mainmodule": true, "getclass": true, "classloader": true, "getclassloader": true,
	"call": true, "instance_exec": true, "binding_of_caller": true,
}

// hasRubyCommand finds Ruby's %x command literal: "%x" then a delimiter
// ("%x(id)", "%x[id]", "%x{id}", "%x|id|"). Only #{ } reads it: in ${ }
// "%x" is shell parameter expansion ("${f%x*}").
func hasRubyCommand(in string) bool {
	for off := 0; ; {
		n := strings.Index(in[off:], "%x")
		if n < 0 {
			return false
		}
		at := off + n + 2
		if at < len(in) && !isIdentByte(in[at]) && in[at] != ' ' {
			return true
		}
		off = at
	}
}

// elSensitive holds the lower-cased names that make member access or a call
// inside ${ } attack-shaped (and keep a #{ } data path code): credentials,
// reflection, process and web-context objects, and the Java package roots.
// "pass" is not one from alpha.6: it is an ordinary word ("${bus.pass}",
// "${ticket.pass}").
var elSensitive = map[string]bool{
	"password": true, "passwd": true, "pwd": true,
	"secret": true, "token": true, "credential": true, "credentials": true,
	"apikey": true, "env": true, "getclass": true, "forname": true,
	"classloader": true, "getclassloader": true, "newinstance": true,
	"getmethod": true, "invoke": true, "runtime": true, "getruntime": true,
	"system": true, "process": true, "exec": true, "execute": true,
	"popen": true, "eval": true, "import": true, "scriptengine": true,
	"session": true, "request": true, "response": true, "pagecontext": true,
	"java": true, "javax": true,
}

// maxELName bounds the identifier length hasSensitiveName looks up (longer
// than any elSensitive name), so each lookup is O(1).
const maxELName = 16

// hasSensitiveName reports whether any identifier in in is in elSensitive.
// Single linear pass.
func hasSensitiveName(in string) bool {
	for i := 0; i < len(in); {
		if !isIdentByte(in[i]) {
			i++
			continue
		}
		j := i
		for j < len(in) && isIdentByte(in[j]) {
			j++
		}
		if j-i <= maxELName && elSensitive[strings.ToLower(in[i:j])] {
			return true
		}
		i = j
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
