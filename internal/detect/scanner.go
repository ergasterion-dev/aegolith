package detect

import (
	"strings"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

// UserAgent reports whether ua names a known attack scanner as a whole word
// (any case, not part of a longer word: "nmapper" does not count):
// AEG-SCANNER-001.
func UserAgent(ua string) (Hit, bool) {
	for _, tok := range [...]string{
		"sqlmap", "nikto", "nuclei", "masscan", "nmap", "zgrab", "wpscan", "dirbuster",
		"gobuster", "ffuf", "acunetix", "nessus", "openvas", "wfuzz", "feroxbuster", "hydra",
	} {
		if hasLetterWordFold(ua, tok) {
			return Hit{RuleID: "AEG-SCANNER-001", Category: model.CatScanner, Severity: model.SeverityMedium}, true
		}
	}
	if indexFold(ua, "fuzz faster u fool") >= 0 {
		return Hit{RuleID: "AEG-SCANNER-001", Category: model.CatScanner, Severity: model.SeverityMedium}, true
	}
	return Hit{}, false
}

// hasLetterWordFold reports whether the lower-case word w appears in s (any
// case) with no ASCII letter on either side. Digits and punctuation are
// boundaries, so "Nikto/2.5.0" and "acunetix-wvs" match.
func hasLetterWordFold(s, w string) bool {
	for off := 0; ; {
		n := indexFold(s[off:], w)
		if n < 0 {
			return false
		}
		at := off + n
		end := at + len(w)
		if (at == 0 || !isASCIILetter(s[at-1])) && (end == len(s) || !isASCIILetter(s[end])) {
			return true
		}
		off = at + 1
	}
}

// ProbePath reports whether the decoded URL path p is a well-known scanner
// probe (AEG-SCANNER-002: WordPress, phpMyAdmin, dotfiles, Spring actuator,
// Apache server-status) or asks for a backup, editor or PHP file by the
// last segment's extension (AEG-SCANNER-003). A Go API serves none of
// these, so a request for one is reconnaissance. Matching ignores case.
// Query strings are not part of p.
func ProbePath(p string) (Hit, bool) { return ProbePathExcept(p, nil) }

// ProbePathExcept is ProbePath, except that a match whose text the caller
// excuses does not count. Every match is reported to excused as the byte
// range [start, end) of p that the rule read: the probe name (".git",
// "actuator/env", ".env") or, for AEG-SCANNER-003, the whole last segment.
// The range never includes the '/' before or after it. A path can hold
// several matches; the first one not excused is the result, so excusing
// one leaves the others reported. A nil excused excuses nothing. The
// engine excuses a match that lies wholly in literal segments of the
// declared route the request matched (see engine.checkProbeAndAgent).
func ProbePathExcept(p string, excused func(start, end int) bool) (Hit, bool) {
	keep := func(start, end int) bool { return excused == nil || !excused(start, end) }
	if probeMatch(p, keep) {
		return Hit{RuleID: "AEG-SCANNER-002", Category: model.CatScanner, Severity: model.SeverityMedium}, true
	}
	if seg := strings.LastIndexByte(p, '/') + 1; isBackupFile(p[seg:]) && keep(seg, len(p)) {
		return Hit{RuleID: "AEG-SCANNER-003", Category: model.CatScanner, Severity: model.SeverityMedium}, true
	}
	return Hit{}, false
}

// probeMatch reports whether p holds a probe name whose range keep accepts.
// The dotfile directories and files (/.env, /.git/, /.aws/, /.ssh/) and
// /wp-login.php match at the start of any path segment (a '/' precedes the
// name), so "/api/v1/.env" counts as well as "/.env": no API names a route
// that way. /wp-admin, /phpmyadmin, /server-status and /actuator match at
// the start of the path only, since an API may have its own
// "/api/server-status" or "/api/v1/devices/actuator/5" route. Below the
// first segment, actuator counts only when a known Spring Boot endpoint
// follows it ("/api/v1/actuator/env"; see actuatorEndpoint). Names that
// are directories end in '/' and match as plain prefixes; the others must
// be followed by the end of the path, '/' or '.' ("/.env.production"), so
// "/wp-admins-are-us" stays clear. One pass over the '/' positions, with a
// fixed number of names tried at each and keep called at most once per
// name tried: linear in len(p) when keep costs at most the length of the
// range it is given.
func probeMatch(p string, keep func(start, end int) bool) bool {
	for i := 0; i < len(p); i++ {
		if p[i] != '/' {
			continue
		}
		rest := p[i:]
		for _, pre := range [...]string{"/.git/", "/.aws/", "/.ssh/"} {
			if hasPrefixFold(rest, pre) && keep(i+1, i+len(pre)-1) {
				return true
			}
		}
		if hasPrefixFold(rest, "/wp-login.php") && keep(i+1, i+len("/wp-login.php")) {
			return true
		}
		if namedSegment(rest, "/.env") && keep(i+1, i+len("/.env")) {
			return true
		}
		if i == 0 {
			for _, pre := range [...]string{"/wp-admin", "/phpmyadmin", "/actuator", "/server-status"} {
				if namedSegment(rest, pre) && keep(1, len(pre)) {
					return true
				}
			}
			continue
		}
		if hasPrefixFold(rest, "/actuator/") {
			if n := actuatorEndpoint(rest[len("/actuator/"):]); n > 0 && keep(i+1, i+len("/actuator/")+n) {
				return true
			}
		}
	}
	return false
}

// namedSegment reports whether rest starts with pre (case-insensitively)
// followed by the end, '/' or '.'.
func namedSegment(rest, pre string) bool {
	return hasPrefixFold(rest, pre) && (len(rest) == len(pre) || rest[len(pre)] == '/' || rest[len(pre)] == '.')
}

// actuatorEndpoint returns the length of the Spring Boot actuator endpoint
// that rest, the text after "/actuator/", starts with when the end of the
// path or '/' follows it, or 0.
func actuatorEndpoint(rest string) int {
	for _, ep := range [...]string{"env", "heapdump", "mappings", "configprops", "beans", "threaddump", "loggers",
		"jolokia", "gateway", "health", "info", "metrics", "prometheus"} {
		if hasPrefixFold(rest, ep) && (len(rest) == len(ep) || rest[len(ep)] == '/') {
			return len(ep)
		}
	}
	return 0
}

// isBackupFile reports whether seg, the last path segment, ends in a
// backup or editor suffix (.bak .old .orig .swp .save ~) or .php.
func isBackupFile(seg string) bool {
	if strings.HasSuffix(seg, "~") {
		return true
	}
	for _, ext := range [...]string{".bak", ".old", ".orig", ".swp", ".save", ".php"} {
		if len(seg) > len(ext) && hasPrefixFold(seg[len(seg)-len(ext):], ext) {
			return true
		}
	}
	return false
}
