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
func ProbePath(p string) (Hit, bool) {
	if isProbePrefix(p) {
		return Hit{RuleID: "AEG-SCANNER-002", Category: model.CatScanner, Severity: model.SeverityMedium}, true
	}
	if isBackupFile(p) {
		return Hit{RuleID: "AEG-SCANNER-003", Category: model.CatScanner, Severity: model.SeverityMedium}, true
	}
	return Hit{}, false
}

// isProbePrefix matches the probe names. The dotfile directories and files
// (/.env, /.git/, /.aws/, /.ssh/) and /wp-login.php match at the start of
// any path segment (a '/' precedes the name), so "/api/v1/.env" counts as
// well as "/.env": no API names a route that way. /wp-admin, /phpmyadmin,
// /server-status and /actuator match at the start of the path only, since
// an API may have its own "/api/server-status" or "/api/v1/devices/actuator/5"
// route. Below the first segment, actuator counts only when a known Spring
// Boot endpoint follows it ("/api/v1/actuator/env"; see actuatorEndpoint).
// Names that are directories end in '/' and match as plain prefixes; the
// others must be followed by the end of the path, '/' or '.'
// ("/.env.production"), so "/wp-admins-are-us" stays clear. One pass over
// the '/' positions, with a fixed number of names tried at each: linear in
// len(p).
func isProbePrefix(p string) bool {
	for i := 0; i < len(p); i++ {
		if p[i] != '/' {
			continue
		}
		rest := p[i:]
		for _, pre := range [...]string{"/.git/", "/.aws/", "/.ssh/", "/wp-login.php"} {
			if hasPrefixFold(rest, pre) {
				return true
			}
		}
		if namedSegment(rest, "/.env") {
			return true
		}
		if i == 0 {
			for _, pre := range [...]string{"/wp-admin", "/phpmyadmin", "/actuator", "/server-status"} {
				if namedSegment(rest, pre) {
					return true
				}
			}
			continue
		}
		if hasPrefixFold(rest, "/actuator/") && actuatorEndpoint(rest[len("/actuator/"):]) {
			return true
		}
	}
	return false
}

// namedSegment reports whether rest starts with pre (case-insensitively)
// followed by the end, '/' or '.'.
func namedSegment(rest, pre string) bool {
	return hasPrefixFold(rest, pre) && (len(rest) == len(pre) || rest[len(pre)] == '/' || rest[len(pre)] == '.')
}

// actuatorEndpoint reports whether rest, the text after "/actuator/", starts
// with a Spring Boot actuator endpoint followed by the end of the path or
// '/'.
func actuatorEndpoint(rest string) bool {
	for _, ep := range [...]string{"env", "heapdump", "mappings", "configprops", "beans", "threaddump", "loggers",
		"jolokia", "gateway", "health", "info", "metrics", "prometheus"} {
		if hasPrefixFold(rest, ep) && (len(rest) == len(ep) || rest[len(ep)] == '/') {
			return true
		}
	}
	return false
}

// isBackupFile reports whether the last path segment ends in a backup or
// editor suffix (.bak .old .orig .swp .save ~) or .php.
func isBackupFile(p string) bool {
	seg := p[strings.LastIndexByte(p, '/')+1:]
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
