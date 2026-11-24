package detect

import (
	"net/netip"
	"strings"

	"github.com/ergasterion-dev/aegolith/internal/model"
	"github.com/ergasterion-dev/aegolith/internal/normalize"
)

// The file and URL detectors look for what a path or URL value would make
// the backend open or fetch: a directory traversal or system file (LFI), a
// remote or wrapper URL (RFI), or a URL into the cloud metadata service or
// the private network (SSRF). Like the injection detectors they check the
// value and, when one percent-decoding pass changes it, the decoded value,
// and every scan is linear in the value's length.

// LFI reports whether v reaches for a local file: a traversal sequence
// (../ or ..\, with the dots and separator raw or percent-encoded) or a NUL
// byte (AEG-LFI-001), or the name of a sensitive system file
// (AEG-LFI-002). Ellipses in prose ("Wait.../ok", "and so on..") do not
// count: the dots must be exactly two, after a separator or at the start.
func LFI(v string) (Hit, bool) {
	if valueOrDecoded(v, isTraversal) {
		return Hit{RuleID: "AEG-LFI-001", Category: model.CatLFI, Severity: model.SeverityHigh}, true
	}
	if valueOrDecoded(v, hasSensitiveFile) {
		return Hit{RuleID: "AEG-LFI-002", Category: model.CatLFI, Severity: model.SeverityHigh}, true
	}
	return Hit{}, false
}

// RFI reports whether v, after leading whitespace, is a URL a file include
// or fetch would follow somewhere it should not (AEG-RFI-001): a file:,
// php://, gopher://, dict://, ldap://, expect:// or jar:<scheme>: URL, a
// data:text/html URL, or an http(s) URL ending in '?' (the classic remote
// include that turns the appended local suffix into a query string). The
// scheme must be followed by its URL syntax, so "File: invoice.pdf" or
// "LDAP: is it supported?" stay clear.
func RFI(v string) (Hit, bool) {
	if valueOrDecoded(v, isRemoteInclude) {
		return Hit{RuleID: "AEG-RFI-001", Category: model.CatRFI, Severity: model.SeverityHigh}, true
	}
	return Hit{}, false
}

// SSRF reports whether v holds a URL (scheme then "://") whose host is a
// cloud metadata endpoint (AEG-SSRF-001) or a loopback, private or
// link-local address or localhost (AEG-SSRF-002). Hosts are compared after
// lower-casing, dropping userinfo, port and a trailing dot; numeric hosts
// are read the way inet_aton does (127.1, 2130706433, 0x7f000001,
// 0177.0.0.1) and bracketed IPv6 hosts as IPv6, IPv4-mapped included. An
// address outside a URL ("router at 192.168.1.1") does not count.
func SSRF(v string) (Hit, bool) {
	rule := ssrfRule(v)
	if rule != ssrfMetadata {
		if d, _ := normalize.DecodeValue(v); d != v {
			rule = max(rule, ssrfRule(d))
		}
	}
	switch rule {
	case ssrfMetadata:
		return Hit{RuleID: "AEG-SSRF-001", Category: model.CatSSRF, Severity: model.SeverityCritical}, true
	case ssrfInternal:
		return Hit{RuleID: "AEG-SSRF-002", Category: model.CatSSRF, Severity: model.SeverityHigh}, true
	}
	return Hit{}, false
}

// XXE reports whether an XML body declares a document type with an
// external identifier (SYSTEM or PUBLIC inside the <!DOCTYPE declaration)
// or an entity (<!ENTITY anywhere after it): AEG-XXE-001. The body is
// matched as sent; it is not percent-decoded.
func XXE(body string) (Hit, bool) {
	if isXXE(body) {
		return Hit{RuleID: "AEG-XXE-001", Category: model.CatXXE, Severity: model.SeverityHigh}, true
	}
	return Hit{}, false
}

// --- local file inclusion ---

// isTraversal finds a NUL byte (raw, or a literal %00 left after decoding)
// or a traversal: two dot tokens ('.' or %2e) followed by a separator token
// ('/', '\', %2f or %5c), or ending the value right after a separator
// ("/static/.."). The first dot must start the value or follow a byte that
// is neither alphanumeric nor a dot, or an encoded separator.
func isTraversal(s string) bool {
	if strings.IndexByte(s, 0) >= 0 || strings.Contains(s, "%00") {
		return true
	}
	for i := 0; i < len(s); i++ {
		n := dotAt(s, i)
		if n == 0 {
			continue
		}
		if i > 0 && !(isTraversalBoundary(s[i-1]) || i >= 3 && sepAt(s, i-3) == 3) {
			continue
		}
		m := dotAt(s, i+n)
		if m == 0 {
			continue
		}
		k := i + n + m
		if sepAt(s, k) > 0 {
			return true
		}
		if k == len(s) && i > 0 && (s[i-1] == '/' || s[i-1] == '\\' || i >= 3 && sepAt(s, i-3) == 3) {
			return true
		}
	}
	return false
}

// isTraversalBoundary reports whether a dot after c may start a traversal.
// A byte of a multi-byte UTF-8 character (>= 0x80) is a letter of another
// script, like an ASCII letter: "दूध../ब्रेड" is a word followed by an
// ellipsis, not a traversal.
func isTraversalBoundary(c byte) bool {
	return c != '.' && c < 0x80 && !isIdentByte(c) || c == '_'
}

// dotAt returns the length of a dot token at s[i] ('.' or %2e in any case),
// or 0.
func dotAt(s string, i int) int {
	switch {
	case i >= len(s):
		return 0
	case s[i] == '.':
		return 1
	case hasPrefixFold(s[i:], "%2e"):
		return 3
	}
	return 0
}

// sepAt returns the length of a path separator token at s[i] ('/', '\',
// %2f or %5c in any case), or 0.
func sepAt(s string, i int) int {
	switch {
	case i >= len(s):
		return 0
	case s[i] == '/' || s[i] == '\\':
		return 1
	case hasPrefixFold(s[i:], "%2f") || hasPrefixFold(s[i:], "%5c"):
		return 3
	}
	return 0
}

// hasSensitiveFile finds a sensitive system file name (any case): Unix
// password files, /proc/self/, a Kubernetes service account token, or the
// Windows win.ini / boot.ini after a path separator.
func hasSensitiveFile(s string) bool {
	for _, p := range [...]string{"/etc/passwd", "/etc/shadow", "/proc/self/", "serviceaccount/token"} {
		if indexFold(s, p) >= 0 {
			return true
		}
	}
	for _, name := range [...]string{"win.ini", "boot.ini"} {
		for off := 0; ; {
			n := indexFold(s[off:], name)
			if n < 0 {
				break
			}
			at := off + n
			if at > 0 && (s[at-1] == '/' || s[at-1] == '\\') {
				return true
			}
			off = at + 1
		}
	}
	return false
}

// --- remote file inclusion ---

func isRemoteInclude(s string) bool {
	i := 0
	for i < len(s) && s[i] <= ' ' {
		i++
	}
	s = s[i:]
	switch {
	case hasPrefixFold(s, "file:"):
		return len(s) > 5 && (s[5] == '/' || s[5] == '\\')
	case hasPrefixFold(s, "php://"), hasPrefixFold(s, "gopher://"), hasPrefixFold(s, "dict://"),
		hasPrefixFold(s, "ldap://"), hasPrefixFold(s, "expect://"), hasPrefixFold(s, "data:text/html"):
		return true
	case hasPrefixFold(s, "jar:"):
		j := 4
		for j < len(s) && isASCIILetter(s[j]) {
			j++
		}
		return j > 4 && j < len(s) && s[j] == ':'
	case hasPrefixFold(s, "http://"), hasPrefixFold(s, "https://"):
		return len(s) > len("http://") && s[len(s)-1] == '?' && strings.IndexAny(s, " \t\r\n") < 0
	}
	return false
}

// --- server-side request forgery ---

const (
	ssrfNone = iota
	ssrfInternal
	ssrfMetadata
)

// ssrfRule classifies the host of every URL in s and returns the worst
// class found. Each authority scan stops at the first '/', and every later
// "://" contains one, so no scan reaches past the next "://": every byte is
// read a bounded number of times, linear overall.
func ssrfRule(s string) int {
	worst := ssrfNone
	for off := 0; ; {
		n := strings.Index(s[off:], "://")
		if n < 0 {
			return worst
		}
		at := off + n
		off = at + 3
		if at == 0 || !isIdentByte(s[at-1]) && s[at-1] != '+' && s[at-1] != '-' && s[at-1] != '.' {
			continue // no scheme before "://"
		}
		end := off
		for end < len(s) && !isAuthorityEnd(s[end]) {
			end++
		}
		switch hostClass(urlHost(s[off:end])) {
		case ssrfMetadata:
			return ssrfMetadata
		case ssrfInternal:
			worst = ssrfInternal
		}
		// The next search resumes right after this "://", not at the end
		// of the authority: in "http://ok.example,http://169.254.169.254/"
		// the first authority runs into the second URL's scheme.
	}
}

// isAuthorityEnd reports whether c ends a URL authority (or the URL).
func isAuthorityEnd(c byte) bool {
	switch c {
	case '/', '?', '#', '\\', ' ', '\t', '\r', '\n', '"', '\'', '<', '>', '`':
		return true
	}
	return false
}

// urlHost returns the host of an authority: after the last '@', without the
// port, without a trailing dot. A bracketed IPv6 host keeps its brackets.
func urlHost(auth string) string {
	if i := strings.LastIndexByte(auth, '@'); i >= 0 {
		auth = auth[i+1:]
	}
	if strings.HasPrefix(auth, "[") {
		if i := strings.IndexByte(auth, ']'); i >= 0 {
			return auth[:i+1]
		}
		return auth
	}
	if i := strings.IndexByte(auth, ':'); i >= 0 {
		auth = auth[:i]
	}
	return strings.TrimSuffix(auth, ".")
}

// hostClass classifies a URL host.
func hostClass(host string) int {
	switch {
	case host == "":
		return ssrfNone
	case strings.EqualFold(host, "metadata.google.internal"):
		return ssrfMetadata
	case strings.EqualFold(host, "localhost") ||
		len(host) > len(".localhost") && hasPrefixFold(host[len(host)-len(".localhost"):], ".localhost"):
		return ssrfInternal
	}
	var addr netip.Addr
	if host[0] == '[' {
		a, err := netip.ParseAddr(strings.TrimSuffix(host[1:], "]"))
		if err != nil {
			return ssrfNone
		}
		addr = a.Unmap()
	} else {
		ip, ok := parseInetAton(host)
		if !ok {
			return ssrfNone
		}
		addr = netip.AddrFrom4([4]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)})
	}
	switch {
	case addr == metadataAWSv4 || addr == metadataAlibaba || addr == metadataAWSv6:
		return ssrfMetadata
	case addr.IsLoopback(), addr.IsPrivate(), addr.IsLinkLocalUnicast(), addr.IsUnspecified(),
		addr.Is4() && addr.As4()[0] == 0:
		return ssrfInternal
	}
	return ssrfNone
}

// Cloud metadata endpoints (AWS/Azure/GCP/OCI on 169.254.169.254, Alibaba
// on 100.100.100.200, AWS IPv6 on fd00:ec2::254).
var (
	metadataAWSv4   = netip.AddrFrom4([4]byte{169, 254, 169, 254})
	metadataAlibaba = netip.AddrFrom4([4]byte{100, 100, 100, 200})
	metadataAWSv6   = netip.MustParseAddr("fd00:ec2::254")
)

// parseInetAton parses an IPv4 host the way inet_aton (and so most HTTP
// clients' resolvers) does: one to four dot-separated parts, each decimal,
// octal (leading 0) or hex (0x), the last part filling the remaining
// bytes. "127.1", "2130706433", "0x7f000001" and "0177.0.0.1" are all
// 127.0.0.1. Anything else, including a host name, is not an address.
func parseInetAton(host string) (uint32, bool) {
	var parts [4]uint64
	n := 0
	for i := 0; ; {
		if n == 4 || i >= len(host) {
			return 0, false
		}
		v, end, ok := parseInetPart(host, i)
		if !ok {
			return 0, false
		}
		parts[n] = v
		n++
		if end == len(host) {
			break
		}
		if host[end] != '.' {
			return 0, false
		}
		i = end + 1
	}
	var ip uint64
	for k := 0; k < n-1; k++ {
		if parts[k] > 0xff {
			return 0, false
		}
		ip |= parts[k] << (24 - 8*k)
	}
	last := parts[n-1]
	if last >= 1<<(8*(5-n)) {
		return 0, false
	}
	return uint32(ip | last), true
}

// parseInetPart parses one inet_aton number at host[i], stopping at '.' or
// the end. Values are capped well above 32 bits so they cannot overflow.
func parseInetPart(host string, i int) (v uint64, end int, ok bool) {
	base := uint64(10)
	if strings.HasPrefix(host[i:], "0x") || strings.HasPrefix(host[i:], "0X") {
		base = 16
		i += 2
	} else if i+1 < len(host) && host[i] == '0' && host[i+1] != '.' {
		base = 8
		i++
	}
	start := i
	for ; i < len(host) && host[i] != '.'; i++ {
		d := uint64(unhexDigit(host[i]))
		if d >= base {
			return 0, i, false
		}
		v = v*base + d
		if v > 1<<40 {
			return 0, i, false
		}
	}
	return v, i, i > start
}

// unhexDigit returns the value of a hex digit, or 255.
func unhexDigit(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 255
}

// --- XML external entities ---

func isXXE(body string) bool {
	i := indexFold(body, "<!doctype")
	if i < 0 {
		return false
	}
	rest := body[i+len("<!doctype"):]
	decl := rest
	if end := strings.IndexAny(decl, ">["); end >= 0 {
		decl = decl[:end]
	}
	return hasWordFold(decl, "system") || hasWordFold(decl, "public") || indexFold(rest, "<!entity") >= 0
}

// hasWordFold reports whether the lower-case ASCII word w appears in s
// (any case) with no identifier byte on either side.
func hasWordFold(s, w string) bool {
	for off := 0; ; {
		n := indexFold(s[off:], w)
		if n < 0 {
			return false
		}
		at := off + n
		end := at + len(w)
		if (at == 0 || !isIdentByte(s[at-1])) && (end == len(s) || !isIdentByte(s[end])) {
			return true
		}
		off = at + 1
	}
}
