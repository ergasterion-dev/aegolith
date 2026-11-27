package cases

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// callbackHost replaces public hosts. The .invalid names never resolve.
const callbackHost = "callback.invalid"

const (
	// maxDecodeLayers bounds how many layers of encoding and lookup nesting
	// are looked through.
	maxDecodeLayers = 10
	// maxRewritePasses bounds the passes taken to reach a stable result.
	maxRewritePasses = 8
	// maxNameBytes is the longest DNS name. Hosts split over lines, and user
	// info before a host written without slashes or holding characters only
	// browsers accept, are followed no further.
	maxNameBytes = 255
)

// RewriteCallbacks returns s with every public callback host replaced by
// callback.invalid, so that nothing sent later can make a server contact a
// public host. It looks at the host of a scheme://host URL, of a
// protocol-relative //host.tld and of a JNDI lookup, with slashes or
// backslashes, also when they are percent encoded (more than once), written
// as \/, \u, \x or HTML character references, in full-width characters, split
// by tabs or line breaks, or built from Log4j lower, upper, date and default
// value lookups. Only the bytes that spell the host change.
//
// A host stays only if it is provably local: a loopback, private, link-local
// or unspecified address, localhost, or a name ending .invalid, .test or
// .local. Every reading of an IPv4 address with leading zeros (octal and
// decimal) must be local. Anything else after a scheme, including a single
// label and a name only a lookup can supply, is replaced.
//
// Left unchanged, by design or as known limits: a host outside a URL (a bare
// name or address in a command or header, a mail address); after // without
// a scheme, in file: URLs and with fewer than two slashes, a single label, an
// address shorter than four parts and a name ending like a file (.php, .js,
// .conf and so on); the authority of php:, data:, phar:, javascript: and
// similar URLs that open no connection; an IPv6 address without brackets;
// anything inside base64, more than ten layers of encoding or an encoding not
// listed above, including overlong UTF-8; and a host after user info that
// holds ?, or that holds a space, double quote, angle bracket or backtick and
// either runs past 255 bytes or follows fewer than two slashes.
func RewriteCallbacks(s string) string {
	for range maxRewritePasses {
		out := rewritePass(s)
		if out == s {
			break
		}
		s = out
	}
	return s
}

// span is a range of bytes of the string being rewritten.
type span struct{ from, to int }

// view is one reading of the string: as written, or with some layers of
// encoding removed. src[i] is the range text[i] was decoded from.
type view struct {
	text string
	src  []span
}

// rewritePass looks for public hosts in every view of s and replaces them.
func rewritePass(s string) string {
	v := view{text: s, src: make([]span, len(s))}
	for i := range v.src {
		v.src[i] = span{i, i + 1}
	}
	var hosts [][]span
	for layer := 0; ; layer++ {
		sc := scanner{view: v}
		var next view
		if layer < maxDecodeLayers {
			next, sc.starts, sc.escaped = v.decode()
		}
		sc.scan()
		hosts = append(hosts, sc.hosts...)
		// Every transformation shortens the text or changes it.
		if layer >= maxDecodeLayers || next.text == v.text {
			break
		}
		v = next
	}
	return replaceHosts(s, hosts)
}

// replaceHosts writes callbackHost over each host, given as the ranges of s
// that spell it. Findings of one host in several views overlap and are
// replaced once. Bytes inside a host that do not spell it, such as the
// wrapping of a lookup, are kept.
func replaceHosts(s string, hosts [][]span) string {
	if len(hosts) == 0 {
		return s
	}
	marked := make([]bool, len(s))
	hulls := make([]span, 0, len(hosts))
	for _, host := range hosts {
		hull := host[0]
		for _, r := range host {
			hull.from, hull.to = min(hull.from, r.from), max(hull.to, r.to)
			for i := r.from; i < r.to; i++ {
				marked[i] = true
			}
		}
		hulls = append(hulls, hull)
	}
	slices.SortFunc(hulls, func(a, b span) int { return cmp.Compare(a.from, b.from) })

	var b strings.Builder
	done := 0
	for i := 0; i < len(hulls); {
		group := hulls[i]
		for i++; i < len(hulls) && hulls[i].from < group.to; i++ {
			group.to = max(group.to, hulls[i].to)
		}
		b.WriteString(s[done:group.from])
		written := false
		for k := group.from; k < group.to; k++ {
			switch {
			case !marked[k]:
				b.WriteByte(s[k])
			case !written:
				b.WriteString(callbackHost)
				written = true
			}
		}
		done = group.to
	}
	b.WriteString(s[done:])
	return b.String()
}

// transformation is one decoding step: n bytes become out, or, for a lookup,
// the n bytes become their own part [keep.from, keep.to).
type transformation struct {
	n      int
	out    string
	lookup bool
	keep   span
}

// decode removes one layer of encoding from v. starts marks the bytes of v at
// which something was decoded, and escaped the bytes consumed by a decoding
// other than a lookup.
func (v view) decode() (next view, starts, escaped []bool) {
	starts, escaped = make([]bool, len(v.text)), make([]bool, len(v.text))
	text := make([]byte, 0, len(v.text))
	src := make([]span, 0, len(v.src))
	for i := 0; i < len(v.text); {
		t, ok := transformAt(v.text, i)
		if !ok {
			text, src = append(text, v.text[i]), append(src, v.src[i])
			i++
			continue
		}
		starts[i] = true
		if t.lookup {
			text = append(text, v.text[i+t.keep.from:i+t.keep.to]...)
			src = append(src, v.src[i+t.keep.from:i+t.keep.to]...)
		} else {
			from := span{v.src[i].from, v.src[i+t.n-1].to}
			for k := range len(t.out) {
				text, src = append(text, t.out[k]), append(src, from)
			}
			for k := i; k < i+t.n; k++ {
				escaped[k] = true
			}
		}
		i += t.n
	}
	return view{text: string(text), src: src}, starts, escaped
}

// transformAt returns the decoding that starts at s[i], if any.
func transformAt(s string, i int) (transformation, bool) {
	rest := s[i:]
	switch rest[0] {
	case '%':
		if len(rest) >= 6 && (rest[1] == 'u' || rest[1] == 'U') {
			if r, ok := hexRune(rest[2:6]); ok {
				return transformation{n: 6, out: string(r)}, true
			}
		}
		if len(rest) >= 3 {
			if r, ok := hexRune(rest[1:3]); ok {
				return transformation{n: 3, out: string([]byte{byte(r)})}, true
			}
		}
	case '\\':
		switch {
		case len(rest) >= 2 && rest[1] == '/':
			return transformation{n: 2, out: "/"}, true
		case len(rest) >= 6 && rest[1] == 'u':
			if r, ok := hexRune(rest[2:6]); ok {
				return transformation{n: 6, out: string(r)}, true
			}
		case len(rest) >= 4 && rest[1] == 'x':
			if r, ok := hexRune(rest[2:4]); ok {
				return transformation{n: 4, out: string([]byte{byte(r)})}, true
			}
		}
	case '&':
		return entity(rest)
	case '$':
		return lookup(rest)
	default:
		if rest[0] >= utf8.RuneSelf {
			r, n := utf8.DecodeRuneInString(rest)
			switch {
			case r >= '！' && r <= '～': // full-width forms of ASCII
				return transformation{n: n, out: string(r - '！' + '!')}, true
			case r == '。' || r == '｡': // ideographic full stops
				return transformation{n: n, out: "."}, true
			}
		}
	}
	return transformation{}, false
}

func hexRune(s string) (rune, bool) {
	n, err := strconv.ParseUint(s, 16, 32)
	return rune(n), err == nil
}

// namedEntities are the HTML character references that spell URL syntax.
var namedEntities = map[string]string{
	"&colon;": ":", "&sol;": "/", "&bsol;": `\`, "&period;": ".", "&commat;": "@",
	"&num;": "#", "&amp;": "&", "&Tab;": "\t", "&NewLine;": "\n",
}

// entity reads the HTML character reference that starts rest.
func entity(rest string) (transformation, bool) {
	if !strings.HasPrefix(rest, "&#") {
		for name, out := range namedEntities {
			if strings.HasPrefix(rest, name) {
				return transformation{n: len(name), out: out}, true
			}
		}
		return transformation{}, false
	}
	i, base := 2, 10
	if i < len(rest) && (rest[i] == 'x' || rest[i] == 'X') {
		i, base = i+1, 16
	}
	first, r := i, rune(0)
	for ; i < len(rest) && r <= unicode.MaxRune; i++ {
		d, err := strconv.ParseUint(rest[i:i+1], base, 8)
		if err != nil {
			break
		}
		r = r*rune(base) + rune(d)
	}
	if i == first || r > unicode.MaxRune {
		return transformation{}, false
	}
	if i < len(rest) && rest[i] == ';' {
		i++
	}
	return transformation{n: i, out: string(r)}, true
}

// lookup reads an innermost Log4j lookup whose value its text gives: lower,
// upper, a quoted date, or any lookup with a default value. A jndi lookup is
// never replaced by part of itself: it is what has to stay visible.
func lookup(rest string) (transformation, bool) {
	if !strings.HasPrefix(rest, "${") {
		return transformation{}, false
	}
	end := 2
	for ; end < len(rest) && rest[end] != '}'; end++ {
		if strings.HasPrefix(rest[end:], "${") {
			return transformation{}, false // not innermost
		}
	}
	if end == len(rest) {
		return transformation{}, false
	}
	body := rest[2:end]
	value := func(from, to int) (transformation, bool) {
		return transformation{n: end + 1, lookup: true, keep: span{2 + from, 2 + to}}, true
	}
	switch {
	case hasPrefixFold(body, "jndi:"):
		return transformation{}, false
	case hasPrefixFold(body, "lower:"), hasPrefixFold(body, "upper:"):
		return value(len("lower:"), len(body))
	}
	if i := strings.Index(body, ":-"); i >= 0 {
		return value(i+len(":-"), len(body))
	}
	if hasPrefixFold(body, "date:'") && len(body) > len("date:'") && strings.HasSuffix(body, "'") {
		return value(len("date:'"), len(body)-1)
	}
	return transformation{}, false
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// Schemes that change how a URL's host is read, in lower case.
var (
	// noConnection URLs name files, wrappers or code, never a server.
	noConnection = set("php data expect phar zip glob zlib compress.zlib compress.bzip2 rar ogg javascript vbscript")
	// pathLike URLs usually name a local path; only a public-looking host is
	// replaced.
	pathLike = set("file jar classpath resource")
	// manySlashes schemes take the host after any number of slashes; for
	// other schemes a third slash means the host is empty.
	manySlashes = set("http https ws wss ftp")
	// slashOptional schemes may be followed by a host with one slash or none.
	slashOptional = set("http https ws wss ftp ldap ldaps rmi dns iiop nis nds gopher dict tftp sftp ssh smb telnet")
	// fileExtensions are name endings that are not top-level domains.
	fileExtensions = set("php php3 php4 php5 php7 phtml js mjs css html htm shtml xhtml ini conf cfg cnf config " +
		"inc asp aspx ashx asmx jsp jspx cgi png jpg jpeg gif svg bmp webp txt xml json yml yaml log bak swp old " +
		"exe dll sys dat bat cmd pdf doc docx csv sql db env properties war jar class")
)

func set(words string) map[string]bool {
	m := make(map[string]bool)
	for _, w := range strings.Fields(words) {
		m[w] = true
	}
	return m
}

// scanner finds the public hosts of one view.
type scanner struct {
	view
	// starts and escaped are what decode reports for the view; nil for the
	// last view.
	starts, escaped []bool
	// braceEnd[i] is the end of the ${...} opening at i; closes marks the }
	// that ends one.
	braceEnd map[int]int
	closes   map[int]bool
	hosts    [][]span
}

func (s *scanner) matchBraces() {
	s.braceEnd, s.closes = map[int]int{}, map[int]bool{}
	var open []int
	for i := 0; i < len(s.text); i++ {
		switch {
		case strings.HasPrefix(s.text[i:], "${"):
			open = append(open, i)
			i++
		case s.text[i] == '}' && len(open) > 0:
			s.braceEnd[open[len(open)-1]] = i + 1
			s.closes[i] = true
			open = open[:len(open)-1]
		}
	}
}

func (s *scanner) scan() {
	s.matchBraces()
	// corba is set inside the address list of a corbaloc or corbaname URL.
	corba := false
	for i := 0; i < len(s.text); {
		c := s.text[i]
		if isSlash(c) {
			corba = false
			end, count := s.slashRun(i)
			if count >= 2 {
				s.separator(i, end, count)
			}
			i = end
			continue
		}
		if corba && (c == '#' || s.endsAuthority(i)) {
			corba = false
		}
		if c == ':' {
			scheme := strings.ToLower(s.text[s.schemeStart(i):i])
			if scheme == "corbaloc" || scheme == "corbaname" {
				corba = true
			}
			if slashOptional[scheme] {
				s.withoutSlashes(i + 1)
			}
		}
		if corba && (c == ':' || c == '@' || c == ',') {
			s.host(i+1, len(s.text), false)
		}
		i++
	}
}

func isSlash(c byte) bool { return c == '/' || c == '\\' }

// slashRun reads the slashes and backslashes starting at i, which may have
// tabs and line breaks between them. It returns the index after the last one
// and their number.
func (s *scanner) slashRun(i int) (end, count int) {
	for k := i; k < len(s.text); k++ {
		switch c := s.text[k]; {
		case isSlash(c):
			end, count = k+1, count+1
		case c != '\t' && c != '\r' && c != '\n':
			return end, count
		}
	}
	return end, count
}

// schemeStart returns where the scheme ending before the colon at i starts,
// or i when there is none.
func (s *scanner) schemeStart(i int) int {
	k := i
	for k > 0 && isSchemeByte(s.text[k-1]) {
		k--
	}
	for k < i && !isLetter(s.text[k]) {
		k++
	}
	return k
}

func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

func isSchemeByte(c byte) bool {
	return isLetter(c) || '0' <= c && c <= '9' || c == '+' || c == '.' || c == '-'
}

// separator judges the host after the run of count slashes at [i, end).
func (s *scanner) separator(i, end, count int) {
	scheme := ""
	colon := i - 1
	for colon >= 0 && s.text[colon] == '\t' {
		colon--
	}
	if colon >= 0 && s.text[colon] == ':' {
		start := s.schemeStart(colon)
		if colon-start > 1 { // a single letter is a drive
			scheme = strings.ToLower(s.text[start:colon])
		}
		// Not schemes: a host replaced by an earlier pass, and what may be
		// only the end of one, after a lookup or encoded text. A later view
		// reads the whole scheme.
		partial := start > 0 && (s.closes[start-1] && !slashOptional[scheme] ||
			s.escaped != nil && s.escaped[start-1])
		if partial || strings.Contains(scheme, callbackHost) {
			scheme = ""
		}
	}
	if noConnection[scheme] || scheme == "file" && count == 3 {
		return
	}
	strict := scheme != "" && !pathLike[scheme] && (count == 2 || manySlashes[scheme])
	stop := s.authority(end, strict)
	// A DNS URL asks its server for the name in the path.
	if scheme == "dns" && stop < len(s.text) && s.text[stop] == '/' {
		s.host(stop+1, len(s.text), false)
	}
}

// withoutSlashes judges the host of a URL written with one slash or none,
// starting after the scheme's colon.
func (s *scanner) withoutSlashes(i int) {
	if i < len(s.text) && isSlash(s.text[i]) {
		end, count := s.slashRun(i)
		if count >= 2 {
			return // separator judges it
		}
		i = end
	}
	s.host(i, len(s.text), false)
	// The host may follow user info.
	end := i
	for end < len(s.text) && end-i < maxNameBytes && !s.endsAuthority(end) {
		end++
	}
	if k := strings.LastIndexByte(s.text[i:end], '@'); k >= 0 {
		s.host(i+k+1, len(s.text), false)
	}
}

// endsAuthority reports whether the byte at k cannot be part of a URL's
// authority. A single backslash can: parsers disagree about it.
func (s *scanner) endsAuthority(k int) bool {
	switch c := s.text[k]; c {
	case '\t', '\r', '\n':
		return false // parsers drop them; host decides
	case '/', '?', ' ', '"', '<', '>', '`', 0x7f:
		return true
	case '\\':
		_, count := s.slashRun(k)
		return count >= 2
	case '}':
		return s.closes[k] // of a lookup around the URL
	default:
		return c < ' '
	}
}

// authority judges every host the authority starting at i could be read to
// name, and returns where it ends. With strict, the host proper (after the
// last @ and before any #) is replaced unless local. The other candidates,
// which only some parsers connect to, are replaced if they look public.
func (s *scanner) authority(i int, strict bool) (end int) {
	end = i
	for end < len(s.text) {
		if past, ok := s.braceEnd[end]; ok {
			end = past
			continue
		}
		if s.endsAuthority(end) {
			break
		}
		end++
	}
	hash := end
	if k := strings.IndexByte(s.text[i:end], '#'); k >= 0 {
		hash = i + k
	}
	proper := i
	if k := strings.LastIndexByte(s.text[i:hash], '@'); k >= 0 {
		proper = i + k + 1
	}
	for k := i; k <= end; k++ {
		if k == i || s.text[k-1] == '@' || s.text[k-1] == '#' {
			s.host(k, end, strict && k == proper)
		}
	}
	// No user info follows a fragment, and a space straight after the slashes
	// of a URL without a scheme starts a comment.
	comment := !strict && end == i && end < len(s.text) && s.text[end] == ' '
	if hash == end && !comment {
		s.browserUserInfo(i, end)
	}
	return end
}

// browserUserInfo judges the hosts after user info holding characters that end
// an authority above but that browsers accept in user info: space, double
// quote, angle brackets and backtick. From end, where the authority starting
// at i stopped, any @ before a path, query or fragment and within maxNameBytes
// of i may close such user info. The text may as well be prose, so only a host
// that looks public is replaced.
func (s *scanner) browserUserInfo(i, end int) {
	for k := end; k < len(s.text) && k-i < maxNameBytes; k++ {
		if past, ok := s.braceEnd[k]; ok {
			k = past - 1
			continue
		}
		switch c := s.text[k]; {
		case strings.IndexByte(" \"<>`", c) >= 0:
		case c == '#' || s.endsAuthority(k):
			return
		case c == '@':
			s.host(k+1, len(s.text), false)
		}
	}
}

// host reads the host starting at i and, if it has to be replaced, records
// it. With strict that is any host that is not local; otherwise only one that
// looks public.
func (s *scanner) host(i, limit int, strict bool) {
	for i < limit && s.text[i] == '.' {
		i++
	}
	end := i
	if i < limit && s.text[i] == '[' {
		k := strings.IndexByte(s.text[i:min(limit, i+maxNameBytes)], ']')
		if k < 0 {
			return
		}
		end = i + k + 1
	}
	end = s.name(end, limit)
	if end == i {
		return
	}
	end = s.joinLines(i, end, limit)
	// A host that runs into something encoded is read in a later view.
	if s.starts != nil && slices.Contains(s.starts[i:min(end+1, len(s.starts))], true) {
		return
	}
	h := s.text[i:end]
	if isLocal(h) || !strict && !looksPublic(h) {
		return
	}
	s.hosts = append(s.hosts, s.src[i:end])
}

// joinLines extends the host at [i, end) over the line breaks and tabs that
// URL parsers drop from inside a name. Later lines belong to it if they add
// labels, or finish a name such as evil.c that is neither local nor complete.
// The latter test keeps the line after a host, as in an injected header.
func (s *scanner) joinLines(i, end, limit int) int {
	for cursor := end; cursor-i <= maxNameBytes; {
		k := cursor
		for k < limit && isDropped(rune(s.text[k])) {
			k++
		}
		next := s.name(k, limit)
		if k == cursor || next == k {
			break
		}
		head := s.text[i:end]
		unfinished := strings.Contains(head, ".") && !isLocal(head) && !looksPublic(head)
		if unfinished || strings.Contains(s.text[k:next], ".") {
			end = next
		}
		cursor = next
	}
	return end
}

// isDropped reports whether URL parsers remove r wherever it is.
func isDropped(r rune) bool { return r == '\t' || r == '\r' || r == '\n' }

// name returns the end of the run of host name characters and ${...} lookups
// starting at i.
func (s *scanner) name(i, limit int) int {
	for i < limit {
		if past, ok := s.braceEnd[i]; ok && past <= limit {
			i = past
			continue
		}
		r, n := utf8.DecodeRuneInString(s.text[i:])
		switch {
		case r < utf8.RuneSelf && (isSchemeByte(byte(r)) && r != '+' || r == '_'):
		// URL parsers map some symbols to letters and drop some invisible
		// characters, so only spaces and punctuation end a name.
		case r >= utf8.RuneSelf && r != utf8.RuneError && !unicode.IsSpace(r) && !unicode.IsPunct(r):
		default:
			return i
		}
		i += n
	}
	return i
}

// normalise returns host as a resolver would compare it.
func normalise(host string) string {
	host = strings.Map(func(r rune) rune {
		if isDropped(r) {
			return -1
		}
		return r
	}, host)
	return strings.TrimRight(lowerASCII(host), ".")
}

// isLocal reports whether host is certain not to be a public host.
func isLocal(host string) bool {
	name := normalise(host)
	if inner, ok := strings.CutPrefix(name, "["); ok {
		inner, ok = strings.CutSuffix(inner, "]")
		addr, err := netip.ParseAddr(inner)
		return ok && err == nil && localAddr(addr)
	}
	if readings, _ := parseIPv4(name); len(readings) > 0 {
		return !slices.ContainsFunc(readings, func(a netip.Addr) bool { return !localAddr(a) })
	}
	return name == "" || name == "localhost" || strings.HasSuffix(name, ".invalid") ||
		strings.HasSuffix(name, ".test") || strings.HasSuffix(name, ".local")
}

func localAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified()
}

// looksPublic reports whether host, found where it may not be a host at all,
// reads as a public one: an address or a name with a top-level domain.
func looksPublic(host string) bool {
	if isLocal(host) {
		return false
	}
	name := normalise(host)
	if inner, ok := strings.CutPrefix(name, "["); ok {
		inner, _, _ = strings.Cut(inner, "]")
		_, err := netip.ParseAddr(inner)
		return err == nil
	}
	if readings, parts := parseIPv4(name); len(readings) > 0 {
		// A small or short number is more often just a number.
		return parts == 4 || parts == 1 && (strings.HasPrefix(name, "0x") || readings[0].As4()[0] != 0)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 || slices.Contains(labels, "") {
		return false
	}
	last := labels[len(labels)-1]
	if strings.Contains(last, "${") {
		return true
	}
	return utf8.RuneCountInString(last) >= 2 && strings.IndexFunc(last, unicode.IsLetter) >= 0 && !fileExtensions[last]
}

// parseIPv4 reads name as inet_aton and URL parsers do: one to four numbers,
// decimal, octal (leading 0) or hexadecimal (0x), the last filling the
// remaining bytes. Some libraries read a leading 0 as decimal, so both
// readings are returned. It also returns the number of parts.
func parseIPv4(name string) (readings []netip.Addr, parts int) {
	fields := strings.SplitN(name, ".", 5)
	if len(fields) > 4 {
		return nil, 0
	}
	for _, leadingZeroBase := range []int{8, 10} {
		var value uint64
		ok := true
		for i, f := range fields {
			base := 10
			switch {
			case strings.HasPrefix(f, "0x"):
				base, f = 16, f[2:]
				if f == "" {
					f = "0"
				}
			case len(f) > 1 && f[0] == '0':
				base = leadingZeroBase
			}
			n, err := strconv.ParseUint(f, base, 64)
			// The last part fills every byte not yet given.
			width := 1
			if i == len(fields)-1 {
				width = 4 - i
			}
			if err != nil || n >= 1<<(8*width) {
				ok = false
				break
			}
			value = value<<(8*width) | n
		}
		if ok {
			readings = append(readings, netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}))
		}
	}
	return readings, len(fields)
}

// NamesPublicHost reports whether s could name a host that is not provably
// local, anywhere in it and not only in a URL: RewriteCallbacks would change
// it, or a view of it that RewriteCallbacks reads (with the same layers of
// encoding and lookups removed) holds a bare name or address that looks
// public. That covers a name with a top-level domain (also in a mail address
// or after a command), a public IPv4 address in any notation inet_aton reads,
// with or without a port, and a public IPv6 address, bracketed or bare.
//
// It refuses much that is not a host, such as document.cookie, table.column
// or a large number, which reads as an IPv4 address. Known limits, by design:
// a host assembled when the payload runs (concatenated strings, variables,
// character codes), one inside base64 or another encoding RewriteCallbacks
// does not read, a host split by spaces or line breaks, and a name with a
// top-level domain of one letter or one that looks like a file extension.
func NamesPublicHost(s string) bool {
	if RewriteCallbacks(s) != s {
		return true
	}
	v := view{text: s, src: make([]span, len(s))}
	for layer := 0; ; layer++ {
		if bareHost(v.text) {
			return true
		}
		if layer >= maxDecodeLayers {
			return false
		}
		next, _, _ := v.decode()
		if next.text == v.text {
			return false
		}
		v = next
	}
}

// bareHost reports whether text holds a name or address that looks public.
// Names end at any punctuation but ".", "-" and "_", so a lookup's braces and
// colons split it.
func bareHost(text string) bool {
	sc := scanner{view: view{text: text}}
	for i := 0; i < len(text); {
		if text[i] == '[' {
			if k := strings.IndexByte(text[i:min(len(text), i+maxNameBytes)], ']'); k > 0 && looksPublic(text[i:i+k+1]) {
				return true
			}
		}
		if end := addressToken(text, i); end > i {
			if addr, err := netip.ParseAddr(strings.TrimRight(text[i:end], ":.")); err == nil && addr.Is6() && !localAddr(addr) {
				return true
			}
		}
		end := sc.name(i, len(text))
		if end == i {
			i++
			continue
		}
		if looksPublic(strings.TrimLeft(text[i:end], ".")) {
			return true
		}
		i = end
	}
	return false
}

// addressToken returns the end of the run of ASCII letters, digits, ":" and
// "." starting at i, or i if the run does not start there.
func addressToken(text string, i int) int {
	isAddrByte := func(c byte) bool { return isLetter(c) || '0' <= c && c <= '9' || c == ':' || c == '.' }
	if i > 0 && isAddrByte(text[i-1]) {
		return i
	}
	end := i
	for end < len(text) && isAddrByte(text[end]) {
		end++
	}
	return end
}
