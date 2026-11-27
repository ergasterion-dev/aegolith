package detect

import "strings"

// Three command injection shapes that need no listed command word after an
// operator: a here-string, a glob that names a system file and a Windows FOR
// loop chained to another command. Each starts at a fixed byte or substring
// ("<<<", "/" with a glob byte in the value, "%" and "(" with an operator),
// so a value without it pays only the search, and each is linear in the
// value's length.

// hasCmdTechnique reports whether s holds one of the three shapes. isCmdI
// calls it, so both CmdI entry points apply it to a value and to its
// percent-decoded form, whatever their prose rules say. The accepted false
// positives and misses are in docs/threat-model.md ("Command injection
// techniques added in alpha.7").
func hasCmdTechnique(s string) bool {
	return hasHereString(s) || hasSystemGlob(s) || hasChainedFor(s)
}

// --- here-string ---

// hasHereString reports whether s holds a Bash here-string written against a
// word: a letter, digit or "_" directly before "<<<", then optional blanks,
// an optional quote and a letter or "_" ("cat<<<uname", "rev<<< 'x'"). A
// blank before "<<<" ("x = <<<EOT"), a digit after it ("miss you<<<3") and a
// longer run of "<" ("main<<<<<<< HEAD") do not match.
//
// Each run of "<" is looked at once, and the blanks after one run belong to
// no other: linear in len(s).
func hasHereString(s string) bool {
	for off := 0; ; {
		n := strings.Index(s[off:], "<<<")
		if n < 0 {
			return false
		}
		i := off + n
		if i > 0 && isIdentByte(s[i-1]) {
			j := skipBlanks(s, i+3)
			if j < len(s) && (s[j] == '\'' || s[j] == '"') {
				j++
			}
			if j < len(s) && (isASCIILetter(s[j]) || s[j] == '_') {
				return true
			}
		}
		// A later "<<<" in the same run follows a "<", never a word.
		for off = i + 3; off < len(s) && s[off] == '<'; off++ {
		}
	}
}

// --- globbed system path ---

// maxGlobToken bounds the rooted token hasSystemGlob reads, from its leading
// "/". The longest file in systemFiles is 18 bytes; spelling every letter of
// it as a bracket still fits.
const maxGlobToken = 64

// systemFiles are the files a glob may not name, as path segments.
// Read-only.
var systemFiles = [...][]string{
	{"etc"},
	{"etc", "passwd"},
	{"etc", "shadow"},
	{"etc", "group"},
	{"etc", "hosts"},
	{"etc", "issue"},
	{"bin", "sh"},
	{"bin", "bash"},
	{"bin", "cat"},
	{"bin", "ls"},
	{"bin", "nc"},
	{"bin", "id"},
	{"usr", "bin", "cat"},
	{"usr", "bin", "id"},
	{"usr", "bin", "whoami"},
	{"usr", "bin", "wget"},
	{"usr", "bin", "curl"},
	{"usr", "bin", "nc"},
	{"usr", "bin", "bash"},
	{"usr", "bin", "sh"},
	{"usr", "sbin", "bash"},
	{"dev", "tcp"},
	{"proc", "self", "environ"},
}

// maxGlobSegments is the most segments any entry of systemFiles has.
const maxGlobSegments = 3

// isGlobLead reports whether a rooted glob may start after c: a blank or a
// byte a shell word can directly follow.
func isGlobLead(c byte) bool {
	switch c {
	case ' ', '\t', ';', '|', '&', '+', '`', '(', ',', '{', '\'', '"', '=', '<', '>':
		return true
	}
	return false
}

// isGlobEnd reports whether c ends a rooted token: every isGlobLead byte,
// plus ")", "}" and a line break. Because it holds every lead byte, no token
// starts inside another.
func isGlobEnd(c byte) bool {
	return isGlobLead(c) || c == ')' || c == '}' || c == '\r' || c == '\n'
}

// hasSystemGlob reports whether s holds a rooted glob that matches one of
// systemFiles: a token starting with "/" at the start of s or after an
// isGlobLead byte, holding "?", "*" or "[...]", whose segments match the
// file's by Bash's rules, with a letter in the last segment (see
// globsSystemFile). So "/???/?a?h" and "/e?c/pa[s]swd" match, and "/???",
// "/usr/bin/*" and "/usr/bin/py*" do not.
//
// Tokens do not overlap and each is read up to maxGlobToken bytes, so the
// work is linear in len(s).
func hasSystemGlob(s string) bool {
	if strings.IndexByte(s, '?') < 0 && strings.IndexByte(s, '*') < 0 && strings.IndexByte(s, '[') < 0 {
		return false
	}
	for off := 0; ; {
		n := strings.IndexByte(s[off:], '/')
		if n < 0 {
			return false
		}
		i := off + n
		off = i + 1
		if i > 0 && !isGlobLead(s[i-1]) {
			continue
		}
		end := i + 1
		for end < len(s) && end-i <= maxGlobToken && !isGlobEnd(s[end]) {
			end++
		}
		if end-i <= maxGlobToken && globsSystemFile(s[i+1:end]) {
			return true
		}
		off = end
	}
}

// globsSystemFile reports whether p (a rooted token without its leading "/")
// is a glob that matches one of systemFiles. A "/" inside brackets belongs
// to the bracket and is dropped from it; every other "/" separates segments.
// p must hold a glob ("?", "*" or "[...]"), and its last segment a letter
// that is written out: outside brackets, or listed on its own in a bracket
// that is not negated. A range or a negated class names no letter, so
// regular expressions such as "/[a-z]*" and "/[^/]*" stay clear. A "["
// with no "]" is literal, which no listed file holds. A backslash, "$" and
// POSIX classes are read literally.
func globsSystemFile(p string) bool {
	var segs [maxGlobSegments]string
	n, start := 0, 0
	glob, letter := false, false
	for k := 0; k < len(p); k++ {
		switch c := p[k]; {
		case c == '/':
			if n == len(segs)-1 {
				return false
			}
			segs[n] = p[start:k]
			n++
			start = k + 1
			letter = false
		case c == '*' || c == '?':
			glob = true
		case c == '[':
			end, _, named := globBracket(p, k, 0)
			if end < 0 {
				return false
			}
			glob = true
			letter = letter || named
			k = end - 1
		case isASCIILetter(c):
			letter = true
		}
	}
	if !glob || !letter {
		return false
	}
	segs[n] = p[start:]
next:
	for _, file := range systemFiles {
		if len(file) != n+1 {
			continue
		}
		// The last segment, which holds a written letter, rules out most
		// files, so it is matched first.
		for i := n; i >= 0; i-- {
			if !globSegment(segs[i], file[i]) {
				continue next
			}
		}
		return true
	}
	return false
}

// globBracket reads the bracket expression at p[k] == '['. It returns the
// index past its "]" (or -1 when it is not closed), whether it matches the
// byte c, and whether it names a letter: not negated, with a letter listed
// on its own. "!" or "^" negates, a "]" listed first is a member, "x-y" is a
// range and "/" is dropped.
func globBracket(p string, k int, c byte) (end int, matches, named bool) {
	j := k + 1
	negated := j < len(p) && (p[j] == '!' || p[j] == '^')
	if negated {
		j++
	}
	found := false
	first := j
	for j < len(p) {
		lo := p[j]
		switch {
		case lo == ']' && j != first:
			return j + 1, found != negated, named && !negated
		case lo == '/':
			j++
		case j+2 < len(p) && p[j+1] == '-' && p[j+2] != ']':
			found = found || lo <= c && c <= p[j+2]
			j += 3
		default:
			found = found || lo == c
			named = named || isASCIILetter(lo)
			j++
		}
	}
	return -1, false, false
}

// globSegment reports whether the glob pat matches the whole of name: "?" is
// any byte, "*" any run of bytes and "[...]" one byte of the class. Only the
// last "*" is ever retried, so the work is at most len(name) passes over
// pat, and both are short (maxGlobToken, a systemFiles segment).
func globSegment(pat, name string) bool {
	p, i := 0, 0
	star, mark := -1, 0 // the last "*" in pat, and where in name it ends
	for i < len(name) {
		if p < len(pat) {
			switch pat[p] {
			case '*':
				star, mark = p, i
				p++
				continue
			case '?':
				p++
				i++
				continue
			case '[':
				if end, ok, _ := globBracket(pat, p, name[i]); end >= 0 && ok {
					p = end
					i++
					continue
				}
			default:
				if pat[p] == name[i] {
					p++
					i++
					continue
				}
			}
		}
		if star < 0 {
			return false
		}
		mark++
		p, i = star+1, mark
	}
	for p < len(pat) && pat[p] == '*' {
		p++
	}
	return p == len(pat)
}

// --- chained Windows FOR loop ---

// Bounds of the parts of a FOR loop after the operator. They keep the work
// per operator constant, so hasChainedFor is linear.
const (
	maxForGap      = 256 // blanks between two parts
	maxForSwitches = 4   // /D, /L, /R, /F
	maxForOption   = 256 // a quoted option string, or a path
	maxForVar      = 16  // the variable name
	maxForSet      = 512 // the bytes inside "(...)"
)

// hasChainedFor reports whether s holds a Windows FOR loop chained to
// another command: "&", "|" or ";" (so also "&&" and "||"), blanks, "for",
// optional /D, /L, /R and /F switches, each with an optional quoted option
// string or path, a "%" or "%%" variable, "in", "(...)" and the word "do",
// in any letter case. The same loop with no operator before it, as in a
// batch snippet, does not match.
//
// The blanks after an operator are skipped once, and everything after "for"
// is bounded by the constants above: linear in len(s).
func hasChainedFor(s string) bool {
	if strings.IndexByte(s, '%') < 0 || strings.IndexByte(s, '(') < 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != '&' && c != '|' && c != ';' {
			continue
		}
		j := skipBlanks(s, i+1)
		if hasPrefixFold(s[j:], "for") && forLoopAt(s, j+3) {
			return true
		}
		i = j - 1
	}
	return false
}

// forLoopAt reports whether the rest of a FOR loop starts at s[j], just past
// the word "for": switches, then forBodyAt.
func forLoopAt(s string, j int) bool {
	if j >= len(s) || s[j] != ' ' && s[j] != '\t' && s[j] != '/' {
		return false
	}
	j = skipForGap(s, j)
	for n := 0; n < maxForSwitches && forSwitchAt(s, j); n++ {
		j = skipForGap(s, j+2)
		switch {
		case j >= len(s) || s[j] == '/':
		case s[j] == '"':
			rest := s[j+1 : min(len(s), j+2+maxForOption)]
			q := strings.IndexByte(rest, '"')
			if q < 0 {
				return false
			}
			j = skipForGap(s, j+q+2)
		case forBodyAt(s, j):
			return true
		default: // a path, such as /R's directory, before the variable
			e := j
			for e < len(s) && e-j <= maxForOption && s[e] != ' ' && s[e] != '\t' {
				e++
			}
			j = skipForGap(s, e)
		}
	}
	return forBodyAt(s, j)
}

// forSwitchAt reports whether a FOR switch starts at s[j]: /D, /L, /R or /F,
// followed by a blank, a quote or the end of s.
func forSwitchAt(s string, j int) bool {
	if j+1 >= len(s) || s[j] != '/' || strings.IndexByte("dlrf", s[j+1]|0x20) < 0 {
		return false
	}
	return j+2 == len(s) || s[j+2] == ' ' || s[j+2] == '\t' || s[j+2] == '"'
}

// forBodyAt reports whether s[j:] is a loop's variable, "in", set and "do":
// "%" or "%%", 1 to maxForVar bytes of letters, digits, "_", "~", "@", "["
// and "]", blanks, "in", "(", then a ")" within maxForSet bytes that is
// followed (after blanks) by the word "do". Any ")" in that stretch may
// close the set, so a set holding a command with parentheses is read.
func forBodyAt(s string, j int) bool {
	if j >= len(s) || s[j] != '%' {
		return false
	}
	if j++; j < len(s) && s[j] == '%' {
		j++
	}
	k := j
	for k < len(s) && k-j <= maxForVar && isForVarByte(s[k]) {
		k++
	}
	if k == j || k-j > maxForVar {
		return false
	}
	in := skipForGap(s, k)
	if in == k || !hasPrefixFold(s[in:], "in") {
		return false
	}
	open := skipForGap(s, in+2)
	if open >= len(s) || s[open] != '(' {
		return false
	}
	end := min(len(s), open+2+maxForSet)
	for q := open + 1; ; {
		n := strings.IndexByte(s[q:end], ')')
		if n < 0 {
			return false
		}
		q += n + 1
		if forDoAt(s, q) {
			return true
		}
	}
}

// forDoAt reports whether the word "do" follows s[j:] after blanks.
func forDoAt(s string, j int) bool {
	j = skipForGap(s, j)
	return j+1 < len(s) && s[j]|0x20 == 'd' && s[j+1]|0x20 == 'o' && (j+2 == len(s) || !isIdentByte(s[j+2]))
}

func isForVarByte(c byte) bool {
	return isIdentByte(c) || c == '~' || c == '@' || c == '[' || c == ']'
}

// skipForGap is skipBlanks over at most maxForGap blanks.
func skipForGap(s string, j int) int {
	for end := j + maxForGap; j < end && j < len(s) && (s[j] == ' ' || s[j] == '\t'); {
		j++
	}
	return j
}
