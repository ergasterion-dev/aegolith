package detect

import (
	"strings"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

// UserAgent reports whether ua names a known attack scanner as a whole word
// (any case, not part of a longer word: "nmapper" does not count):
// AEG-SCANNER-001. "qualys was" is matched as one phrase, and "vega" only
// when a '/' follows it ("Vega/1.0"; "Vega" alone is a common product and
// place name).
func UserAgent(ua string) (Hit, bool) {
	for _, tok := range [...]string{
		"sqlmap", "nikto", "nuclei", "masscan", "nmap", "zgrab", "wpscan", "dirbuster",
		"gobuster", "ffuf", "acunetix", "nessus", "openvas", "wfuzz", "feroxbuster", "hydra",
		// alpha.6: CRS 3.3 scanner names missed by the external validation.
		"commix", "netsparker", "arachni", "w3af", "webinspect", "havij", "sqlninja",
		"whatweb", "detectify", "jorgee", "zmeu", "paros", "qualys was",
	} {
		if hasLetterWordFold(ua, tok) {
			return Hit{RuleID: "AEG-SCANNER-001", Category: model.CatScanner, Severity: model.SeverityMedium}, true
		}
	}
	if indexFold(ua, "fuzz faster u fool") >= 0 || hasLetterWordBeforeFold(ua, "vega", '/') {
		return Hit{RuleID: "AEG-SCANNER-001", Category: model.CatScanner, Severity: model.SeverityMedium}, true
	}
	return Hit{}, false
}

// hasLetterWordBeforeFold reports whether the lower-case word w appears in
// s (any case) with no ASCII letter before it and the byte next right
// after it.
func hasLetterWordBeforeFold(s, w string, next byte) bool {
	for off := 0; ; {
		n := indexFold(s[off:], w)
		if n < 0 {
			return false
		}
		at := off + n
		end := at + len(w)
		if (at == 0 || !isASCIILetter(s[at-1])) && end < len(s) && s[end] == next {
			return true
		}
		off = at + 1
	}
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
	if first := rootSegment(p); isRootDump(first) && keep(1, 1+len(first)) {
		return Hit{RuleID: "AEG-SCANNER-003", Category: model.CatScanner, Severity: model.SeverityMedium}, true
	}
	return Hit{}, false
}

// rootSegment returns the first segment of p ("" when p does not start
// with '/').
func rootSegment(p string) string {
	if p == "" || p[0] != '/' {
		return ""
	}
	if n := strings.IndexByte(p[1:], '/'); n >= 0 {
		return p[1 : 1+n]
	}
	return p[1:]
}

// isRootDump reports whether seg, the first path segment, names a SQL dump
// (".sql" followed by the end or another extension: "backup.sql",
// "users.sql.gz", ".sql"), a SQLite file (".sqlite", ".sqlite3") or an
// archive (".zip", ".rar", ".7z", ".tar", ".tgz", ".gz", ".bz2", ".xz",
// and so ".tar.gz"). An API serves none of these at its root; deeper in
// the path they are ordinary export or download names
// ("/api/v1/exports/orders.sql") and stay clear. Case is ignored.
//
// A compressed web or text file is not an archive: ".gz", ".bz2" or ".xz"
// right after one of webTypes ("/sitemap.xml.gz", "/main.js.gz") is
// clear, unless an earlier extension is ".sql" (above) or another archive
// (".tar", ".zip", ...: "/backup.tar.xml.gz"). Only the extension right
// before the compression counts: "/main.js.map.gz" is flagged.
func isRootDump(seg string) bool {
	for i := 0; i+4 <= len(seg); i++ {
		if seg[i] == '.' && hasPrefixFold(seg[i:], ".sql") && (i+4 == len(seg) || seg[i+4] == '.') {
			return true
		}
	}
	for _, ext := range [...]string{".sqlite", ".sqlite3", ".zip", ".rar", ".7z", ".tar", ".tgz", ".gz", ".bz2", ".xz"} {
		if len(seg) >= len(ext) && hasPrefixFold(seg[len(seg)-len(ext):], ext) {
			if (ext == ".gz" || ext == ".bz2" || ext == ".xz") && compressedWebFile(seg[:len(seg)-len(ext)]) {
				return false
			}
			return true
		}
	}
	return false
}

// webTypes are the extensions of files a site serves precompressed.
var webTypes = [...]string{
	"xml", "txt", "html", "htm", "js", "mjs", "css", "json", "ndjson", "svg", "wasm", "csv",
	"rss", "webmanifest", "ico", "woff", "woff2",
}

// compressedWebFile reports whether name, a file name without its
// compression extension, ends in one of webTypes and holds no archive
// extension before it (a '.' followed by an archive name and another '.').
func compressedWebFile(name string) bool {
	dot := strings.LastIndexByte(name, '.')
	if dot < 0 {
		return false
	}
	inner, web := name[dot+1:], false
	for _, w := range webTypes {
		if len(inner) == len(w) && hasPrefixFold(inner, w) {
			web = true
		}
	}
	if !web {
		return false
	}
	for i := 0; i < dot; i++ {
		if name[i] != '.' {
			continue
		}
		for _, a := range [...]string{"tar.", "tgz.", "zip.", "rar.", "7z.", "gz.", "bz2.", "xz.", "sqlite.", "sqlite3."} {
			if hasPrefixFold(name[i+1:], a) {
				return false
			}
		}
	}
	return true
}

// probeMatch reports whether p holds a probe name whose range keep accepts.
// The dotfile directories and files (/.env, /.git/, /.aws/, /.ssh/), the
// version-control directories as whole segments (.git, .svn, .hg, .bzr;
// from alpha.6) and /wp-login.php match at the start of any path segment
// (a '/' precedes the name), so "/api/v1/.env" counts as well as "/.env":
// no API names a route that way. "/.gitignore" and "/.github/" do not
// match: the name must end at the end, '/' or '.'. The rootNames and the
// .ht* server files and .git-credentials (matched as prefixes, so
// "/.htaccess-dev" counts) match at the start of the path only, since an
// API may have its own "/api/server-status" or
// "/api/v1/devices/actuator/5" route, or serve a repository's
// ".htaccess" deeper in the path. Below the
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
		for _, pre := range [...]string{"/.env", "/.git", "/.svn", "/.hg", "/.bzr"} {
			if namedSegment(rest, pre) && keep(i+1, i+len(pre)) {
				return true
			}
		}
		if i == 0 {
			// A root name's range runs to the end of the path: what follows
			// it (an actuator endpoint, a wp-admin page) is part of the
			// probe, so a declared "/actuator/:ep" or "/wp-admin/*" does
			// not excuse it.
			for _, pre := range rootNames {
				if namedSegment(rest, pre) && keep(1, len(p)) {
					return true
				}
			}
			for _, pre := range [...]string{"/.htaccess", "/.htpasswd", "/.htdigest", "/.htgroup", "/.htusers", "/.git-credentials"} {
				if hasPrefixFold(rest, pre) && keep(1, len(p)) {
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

// rootNames match as the first segment only (followed by the end, '/' or
// '.'): admin and status pages an API may also have below its prefix, and
// secret files (shell histories, registry and cloud credentials, private
// keys) and the settings of AI coding assistants, which are ordinary file
// names in a repository browser or a key store deeper in the path
// ("/api/v1/repos/1/files/.npmrc", "/api/v1/keys/id_rsa",
// "/repo/files/.claude/x").
var rootNames = [...]string{
	"/wp-admin", "/phpmyadmin", "/actuator", "/server-status",
	"/.npmrc", "/.netrc", "/.pgpass", "/.ds_store", "/.s3cfg", "/.dockercfg", "/.docker", "/.kube",
	"/.bash_history", "/.zsh_history", "/.mysql_history", "/.psql_history",
	"/id_rsa", "/id_dsa", "/id_ecdsa", "/id_ed25519",
	"/.claude", "/.cursor", "/.cursorignore", "/.continue", "/.windsurf", "/.zed", "/.roo", "/.kiro",
	"/.junie", "/.opencode", "/.plandex", "/.rovodev", "/.a0proj",
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
