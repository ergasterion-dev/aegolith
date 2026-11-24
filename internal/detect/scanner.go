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
		"gobuster", "ffuf", "acunetix", "nessus", "openvas",
	} {
		if hasLetterWordFold(ua, tok) {
			return Hit{RuleID: "AEG-SCANNER-001", Category: model.CatScanner, Severity: model.SeverityMedium}, true
		}
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

// isProbePrefix matches the probe prefixes. Those naming a directory end in
// '/' and match as plain prefixes; the others must be followed by the end
// of the path, '/' or '.' ("/.env.production"), so "/wp-admins-are-us"
// stays clear.
func isProbePrefix(p string) bool {
	for _, pre := range [...]string{"/.git/", "/.aws/", "/.ssh/", "/wp-login.php"} {
		if hasPrefixFold(p, pre) {
			return true
		}
	}
	for _, pre := range [...]string{"/wp-admin", "/phpmyadmin", "/.env", "/actuator", "/server-status"} {
		if hasPrefixFold(p, pre) && (len(p) == len(pre) || p[len(pre)] == '/' || p[len(pre)] == '.') {
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
