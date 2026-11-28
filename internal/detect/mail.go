package detect

import "strings"

// This file reads the SMTP, POP3 and IMAP commands an attacker adds after a
// line break to a value that a handler copies into a mail session
// (AEG-CRLF-001; see isCRLF). Command names are matched in upper case, as
// written, and a command must start its line after nothing but blanks, so a
// quoted ("> RETR 1") or prefixed ("C: RETR 1") transcript is clear. Where a
// command's name alone would flag ordinary text (a product or flight code
// followed by a word, a shouted heading, a sentence about a command), the
// rest of the line must have the command's own syntax. The accepted false
// positives and misses are listed in docs/threat-model.md.
//
// Every function here reads forward within one line, and each line is read
// from one start, so a scan is linear in the value's length.

// maxIMAPTag is the longest IMAP command tag read before STORE.
const maxIMAPTag = 8

// mailCommandAt reports whether a mail command starts at s[i], the first
// byte after a line break and its blanks:
//
//   - "MAIL FROM:", optional blanks and "<";
//   - "RCPT TO:", optional blanks and an address (see recipientAt);
//   - "EHLO" or "HELO" and a host that ends the line (see greetingHost);
//   - "AUTH" and PLAIN, LOGIN, CRAM-MD5 or XOAUTH2, then the end of the line,
//     after at most one base64 initial response (see isInitialResponse);
//   - "RETR n" and "TOP n n" with nothing else on the line;
//   - an IMAP tag (one letter and three digits) and a command with its
//     arguments (see imapCommandAt);
//   - a tag of at most maxIMAPTag letters and digits and "STORE" (see
//     storeAt).
func mailCommandAt(s string, i int) bool {
	if strings.HasPrefix(s[i:], "MAIL FROM:") {
		k := skipBlanks(s, i+len("MAIL FROM:"))
		return k < len(s) && s[k] == '<'
	}
	if strings.HasPrefix(s[i:], "RCPT TO:") {
		return recipientAt(s, skipBlanks(s, i+len("RCPT TO:")))
	}
	e := alnumEnd(s, i)
	k := skipBlanks(s, e)
	if e == i || k == e {
		return false // no word, or nothing after it on the line
	}
	switch word := s[i:e]; word {
	case "EHLO", "HELO":
		return greetingHost(s, k)
	case "AUTH":
		return authAt(s, k)
	case "RETR":
		n := digitRun(s, k)
		return n > k && lineEnds(s, n)
	case "TOP":
		n := digitRun(s, k)
		m := skipBlanks(s, n)
		end := digitRun(s, m)
		return n > k && m > n && end > m && lineEnds(s, end)
	default:
		return taggedCommandAt(s, word, k)
	}
}

// recipientAt reports whether an address starts at s[k]: an optional "<",
// then "local@domain" without blanks, or "<local>" ("<root>"). The text after
// the address is not read.
func recipientAt(s string, k int) bool {
	angle := k < len(s) && s[k] == '<'
	if angle {
		k++
	}
	n := k
	for n < len(s) && s[n] > ' ' && s[n] != '<' && s[n] != '>' && s[n] != '@' {
		n++
	}
	if n == k || n >= len(s) {
		return false
	}
	if s[n] == '>' {
		return angle
	}
	if s[n] != '@' || n+1 >= len(s) {
		return false
	}
	c := s[n+1]
	return isASCIILetter(c) || isDigit(c) || c == '['
}

// greetingHost reports whether s[k:] is the argument of EHLO or HELO and ends
// the line: an address literal in brackets, "localhost", or a name of
// letters, digits, '-' and '_' with at least one dot between two of them
// ("mail.example.com", "192.0.2.1"). A single word ("HELO everyone") is not
// a host here.
func greetingHost(s string, k int) bool {
	if k < len(s) && s[k] == '[' {
		n := k + 1
		for n < len(s) && (isAlnum(s[n]) || s[n] == '.' || s[n] == ':') {
			n++
		}
		return n > k+1 && n < len(s) && s[n] == ']' && lineEnds(s, n+1)
	}
	n := k
	for n < len(s) && (isIdentByte(s[n]) || s[n] == '-' || s[n] == '.') {
		n++
	}
	if !lineEnds(s, n) {
		return false
	}
	host := strings.TrimSuffix(s[k:n], ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	return strings.IndexByte(host, '.') > 0 && !strings.HasSuffix(host, ".") && !strings.Contains(host, "..")
}

// authAt reports whether s[k:] is a listed AUTH mechanism followed by the end
// of the line, or by one base64 initial response and the end of the line.
func authAt(s string, k int) bool {
	n := saslEnd(s, k)
	switch s[k:n] {
	case "PLAIN", "LOGIN", "CRAM-MD5", "XOAUTH2":
		return initialResponseEnds(s, n)
	}
	return false
}

// isMechanism reports whether name is a SASL mechanism an IMAP server
// offers.
func isMechanism(name string) bool {
	switch name {
	case "PLAIN", "LOGIN", "CRAM-MD5", "DIGEST-MD5", "XOAUTH2", "OAUTHBEARER", "GSSAPI", "NTLM", "EXTERNAL",
		"ANONYMOUS", "SCRAM-SHA-1", "SCRAM-SHA-256":
		return true
	}
	return false
}

// isShouted reports whether w is a word of upper-case letters only, as in a
// shouted heading ("A101 LOGIN PAGE ERROR").
func isShouted(w string) bool {
	for i := 0; i < len(w); i++ {
		if w[i] < 'A' || w[i] > 'Z' {
			return false
		}
	}
	return w != ""
}

// saslEnd returns the end of the SASL mechanism name at s[k]: upper-case
// letters, digits, '-' and '_'.
func saslEnd(s string, k int) int {
	for k < len(s) && (s[k] >= 'A' && s[k] <= 'Z' || isDigit(s[k]) || s[k] == '-' || s[k] == '_') {
		k++
	}
	return k
}

// initialResponseEnds reports whether the line ends at s[n], or after blanks
// and one initial response (see isInitialResponse).
func initialResponseEnds(s string, n int) bool {
	if lineEnds(s, n) {
		return true
	}
	k := skipBlanks(s, n)
	if k == n {
		return false
	}
	e := k
	for e < len(s) && (isBase64Byte(s[e]) || s[e] == '=') {
		e++
	}
	return isInitialResponse(s[k:e]) && lineEnds(s, e)
}

// isInitialResponse reports whether tok, a run of base64 bytes, is "=" (an
// empty response) or reads as padded base64: a length that is a multiple of
// four, and not letters of one case only, as a word is ("AUTH LOGIN failed",
// "AUTH LOGIN DISABLED").
func isInitialResponse(tok string) bool {
	if tok == "=" {
		return true
	}
	if tok == "" || len(tok)%4 != 0 {
		return false
	}
	lower, upper := true, true
	for i := 0; i < len(tok); i++ {
		lower = lower && tok[i] >= 'a' && tok[i] <= 'z'
		upper = upper && tok[i] >= 'A' && tok[i] <= 'Z'
	}
	return !lower && !upper
}

// taggedCommandAt reports whether tag, followed by blanks, and the word at
// s[k] are an IMAP command: any command of imapCommandAt after a tag of one
// letter and three digits, STORE after any tag of at most maxIMAPTag letters
// and digits.
func taggedCommandAt(s, tag string, k int) bool {
	e := alnumEnd(s, k)
	command := s[k:e]
	if len(tag) == 4 && isASCIILetter(tag[0]) && digitRun(tag, 1) == 4 {
		if command == "UID" {
			return uidCommandAt(s, e)
		}
		if command != "STORE" {
			return imapCommandAt(s, command, e)
		}
	}
	return command == "STORE" && len(tag) <= maxIMAPTag && storeAt(s, e, strings.ContainsAny(tag, "0123456789"))
}

// uidCommandAt reports whether s[e:], just past "UID", is one of the commands
// UID prefixes, with its arguments.
func uidCommandAt(s string, e int) bool {
	k := skipBlanks(s, e)
	if k == e {
		return false
	}
	n := alnumEnd(s, k)
	switch command := s[k:n]; command {
	case "FETCH", "COPY", "SEARCH":
		return imapCommandAt(s, command, n)
	case "STORE":
		return storeAt(s, n, true)
	case "MOVE":
		return imapCommandAt(s, "COPY", n)
	case "EXPUNGE":
		a := skipBlanks(s, n)
		end := sequenceSetEnd(s, a)
		return a > n && end > a && lineEnds(s, end)
	}
	return false
}

// imapCommandAt reports whether s[e:], just past the command name, holds the
// arguments the command takes:
//
//   - LOGIN: a user and a password that end the line and are not both
//     upper-case words (see isShouted), or a "{n}" literal;
//   - AUTHENTICATE: a SASL mechanism (see isMechanism), then as
//     initialResponseEnds;
//   - SELECT: INBOX (with an optional subfolder) or a quoted mailbox, then
//     the end of the line;
//   - COPY: a message set and a mailbox as for SELECT;
//   - FETCH: a message set and an item list or name (see fetchItemAt);
//   - APPEND: a mailbox, on a line that ends in a "{n}" or "{n+}" literal;
//   - SEARCH: see searchAt;
//   - LIST: a quoted reference and a mailbox pattern that end the line.
func imapCommandAt(s, command string, e int) bool {
	k := skipBlanks(s, e)
	if k == e || k >= len(s) {
		return false
	}
	switch command {
	case "LOGIN":
		n := imapArgEnd(s, k)
		if n > k && s[k] == '{' && s[n-1] == '}' && lineEnds(s, n) {
			return true
		}
		p := skipBlanks(s, n)
		end := imapArgEnd(s, p)
		return n > k && p > n && end > p && lineEnds(s, end) &&
			!(isShouted(s[k:n]) && isShouted(s[p:end]))
	case "AUTHENTICATE":
		n := saslEnd(s, k)
		return isMechanism(s[k:n]) && initialResponseEnds(s, n)
	case "SELECT":
		return mailboxEndsLine(s, k)
	case "COPY":
		n := sequenceSetEnd(s, k)
		p := skipBlanks(s, n)
		return n > k && p > n && mailboxEndsLine(s, p)
	case "FETCH":
		n := sequenceSetEnd(s, k)
		p := skipBlanks(s, n)
		return n > k && p > n && fetchItemAt(s, p)
	case "APPEND":
		n := imapArgEnd(s, k)
		return n > k && skipBlanks(s, n) > n && endsInLiteral(s, n)
	case "SEARCH":
		return searchAt(s, k)
	case "LIST":
		if s[k] != '"' {
			return false
		}
		n := imapArgEnd(s, k)
		p := skipBlanks(s, n)
		end := imapArgEnd(s, p)
		return n > k && p > n && end > p && lineEnds(s, end)
	}
	return false
}

// storeAt reports whether s[e:], just past "STORE", is a message set followed
// by the FLAGS item ("+FLAGS", "-FLAGS.SILENT", "FLAGS"), or, with alone set,
// by the end of the line. A tag without a digit does not set alone: "WE STORE
// 5" is a shouted sentence.
func storeAt(s string, e int, alone bool) bool {
	k := skipBlanks(s, e)
	n := sequenceSetEnd(s, k)
	if k == e || n == k {
		return false
	}
	if lineEnds(s, n) {
		return alone
	}
	p := skipBlanks(s, n)
	if p == n {
		return false
	}
	if p < len(s) && (s[p] == '+' || s[p] == '-') {
		p++
	}
	return s[p:alnumEnd(s, p)] == "FLAGS"
}

// sequenceSetEnd returns the end of the IMAP message set at s[k] (digits,
// ':', ',' and '*', starting with a digit or '*'), or k.
func sequenceSetEnd(s string, k int) int {
	if k >= len(s) || !isDigit(s[k]) && s[k] != '*' {
		return k
	}
	for k < len(s) && (isDigit(s[k]) || s[k] == ':' || s[k] == ',' || s[k] == '*') {
		k++
	}
	return k
}

// imapArgEnd returns the end of the argument at s[k]: a quoted string closed
// on the same line, or a run of bytes without a blank, control byte or quote.
// It returns k when there is none.
func imapArgEnd(s string, k int) int {
	if k < len(s) && s[k] == '"' {
		for n := k + 1; n < len(s) && s[n] != '\r' && s[n] != '\n'; n++ {
			if s[n] == '"' {
				return n + 1
			}
		}
		return k
	}
	n := k
	for n < len(s) && s[n] > ' ' && s[n] != '"' {
		n++
	}
	return n
}

// mailboxEndsLine reports whether s[k:] is INBOX (any case), alone or with a
// "/" or "." subfolder, or a quoted name, and then the end of the line.
func mailboxEndsLine(s string, k int) bool {
	n := imapArgEnd(s, k)
	if n == k || !lineEnds(s, n) {
		return false
	}
	if s[k] == '"' {
		return true
	}
	name := s[k:n]
	return hasPrefixFold(name, "inbox") && (len(name) == 5 || name[5] == '/' || name[5] == '.')
}

// fetchItemAt reports whether s[k:] is a FETCH item list ("(...") or one
// data item name that ends the line or is followed by "[" or "."
// ("BODY[HEADER]", "RFC822.SIZE").
func fetchItemAt(s string, k int) bool {
	if k < len(s) && s[k] == '(' {
		return true
	}
	n := alnumEnd(s, k)
	switch s[k:n] {
	case "ALL", "FAST", "FULL", "BODY", "BODYSTRUCTURE", "ENVELOPE", "FLAGS", "INTERNALDATE", "RFC822", "UID":
		return lineEnds(s, n) || s[n] == '[' || s[n] == '.'
	}
	return false
}

// endsInLiteral reports whether the line holding s[k:] ends in "{n}" or
// "{n+}", blanks aside.
func endsInLiteral(s string, k int) bool {
	end := len(s)
	if n := strings.IndexAny(s[k:], "\r\n"); n >= 0 {
		end = k + n
	}
	for end > k && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	if end == k || s[end-1] != '}' {
		return false
	}
	end--
	if end > k && s[end-1] == '+' {
		end--
	}
	d := end
	for d > k && isDigit(s[d-1]) {
		d--
	}
	return d < end && d > k && s[d-1] == '{'
}

// searchKind says what must follow an IMAP SEARCH key.
type searchKind uint8

const (
	notSearchKey searchKind = iota
	// searchFlag takes no argument: the line ends, or another key follows.
	searchFlag
	// searchPrefix is NOT or OR: another key follows.
	searchPrefix
	// searchValue takes an argument that is not a shouted word (see
	// isShouted): "SEARCH ON HOLD" is a heading.
	searchValue
)

func searchKeyKind(key string) searchKind {
	switch key {
	case "ALL", "ANSWERED", "DELETED", "DRAFT", "FLAGGED", "NEW", "OLD", "RECENT", "SEEN", "UNANSWERED",
		"UNDELETED", "UNDRAFT", "UNFLAGGED", "UNSEEN":
		return searchFlag
	case "NOT", "OR":
		return searchPrefix
	case "BCC", "BEFORE", "BODY", "CC", "CHARSET", "FROM", "HEADER", "KEYWORD", "LARGER", "ON", "SENTBEFORE",
		"SENTON", "SENTSINCE", "SINCE", "SMALLER", "SUBJECT", "TEXT", "TO", "UID", "UNKEYWORD":
		return searchValue
	}
	return notSearchKey
}

// searchAt reports whether s[k:] starts IMAP search criteria: a key with what
// it needs after it (see searchKind). Only the first key, and the key or
// argument after it where one must follow, are read, so "SEARCH AND RESCUE"
// and "SEARCH ALL AREAS" are clear.
func searchAt(s string, k int) bool {
	n := alnumEnd(s, k)
	kind := searchKeyKind(s[k:n])
	if kind == notSearchKey {
		return false
	}
	if kind == searchFlag && lineEnds(s, n) {
		return true
	}
	p := skipBlanks(s, n)
	if p == n || lineEnds(s, p) {
		return false
	}
	if kind == searchValue {
		return !isShouted(s[p:imapArgEnd(s, p)])
	}
	return searchKeyKind(s[p:alnumEnd(s, p)]) != notSearchKey
}

// lineEnds reports whether only blanks stand between s[k] and the next line
// break or the end of s.
func lineEnds(s string, k int) bool {
	k = skipBlanks(s, k)
	return k == len(s) || s[k] == '\r' || s[k] == '\n'
}

// alnumEnd returns the end of the run of ASCII letters and digits at s[k].
func alnumEnd(s string, k int) int {
	for k < len(s) && isAlnum(s[k]) {
		k++
	}
	return k
}

// digitRun returns the end of the run of digits at s[k].
func digitRun(s string, k int) int {
	for k < len(s) && isDigit(s[k]) {
		k++
	}
	return k
}

func isAlnum(c byte) bool { return isASCIILetter(c) || isDigit(c) }
