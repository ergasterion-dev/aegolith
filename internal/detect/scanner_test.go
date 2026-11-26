package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

// Real customer user agents, package-level so that ScanText's tests run
// them through the combined scan too.
var legitUserAgents = []string{
	"okhttp/4.12.0",
	"ExampleCo/1.4.2 (iPhone; iOS 18.1; Scale/3.00)",
	"Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
	"Dart/3.5 (dart:io)",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
}

// Legitimate API paths, package-level for the same reason.
var legitPaths = []string{
	"/api/v1/orders/4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b",
	"/api/v1/vendors/12/products",
	"/api/v1/products/search",
	"/",
	"/api/v1/old-orders",
	"/api/v1/environments",
	"/api/v1/actuators-guide",
	"/api/v1/files/report.pdf",
	"/api/v1/env",
	"/wp-admins-are-us",
	"/api/v1/users/me/save",
}

func TestUserAgent(t *testing.T) {
	want := Hit{RuleID: "AEG-SCANNER-001", Category: model.CatScanner, Severity: model.SeverityMedium}
	assertHits(t, "UserAgent", UserAgent, want, []string{
		"sqlmap/1.8.4#stable (https://sqlmap.org)",
		"Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)",
		"Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
		"masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
		// Beyond the brief.
		"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
		"zgrab/0.x",
		"WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)",
		"DirBuster-1.0-RC1",
		"gobuster/3.6",
		"Fuzz Faster U Fool v2.1.0 (ffuf)",
		"Mozilla/5.0 acunetix-wvs",
		"Nessus SOAP",
		"OpenVAS-VT",
	})
	assertNoHits(t, "UserAgent", UserAgent, append([]string{
		"nmapper/1.0",
		"Nucleic Acid Lab app",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	}, legitUserAgents...))
}

func TestProbePath(t *testing.T) {
	probe := Hit{RuleID: "AEG-SCANNER-002", Category: model.CatScanner, Severity: model.SeverityMedium}
	assertHits(t, "ProbePath", ProbePath, probe, []string{
		"/wp-admin/admin-ajax.php",
		"/phpmyadmin/index.php",
		"/actuator/env",
		"/.env",
		"/.git/config",
		// Beyond the brief.
		"/wp-admin",
		"/wp-login.php",
		"/phpMyAdmin/",
		"/.env.production",
		"/actuator",
		"/server-status",
		"/.aws/credentials",
		"/.ssh/id_rsa",
	})
	backup := Hit{RuleID: "AEG-SCANNER-003", Category: model.CatScanner, Severity: model.SeverityMedium}
	assertHits(t, "ProbePath", ProbePath, backup, []string{
		"/config.php.bak",
		// Beyond the brief.
		"/index.php",
		"/api/v1/x.PHP",
		"/app/settings.old",
		"/web.config.orig",
		"/.index.html.swp",
		"/db.yml.save",
		"/config.yml~",
	})
	assertNoHits(t, "ProbePath", ProbePath, legitPaths)
}

func TestProbePathUnderPrefix(t *testing.T) {
	probe := Hit{RuleID: "AEG-SCANNER-002", Category: model.CatScanner, Severity: model.SeverityMedium}
	assertHits(t, "ProbePath", ProbePath, probe, []string{
		"/api/v1/.env",
		"/api/v1/.git/config",
		"/api/v1/actuator/env",
		"/api/v1/.aws/credentials",
		"/api/v1/.ssh/id_rsa",
		"/api/v1/wp-login.php",
		"/api/v1/.env.production",
		"/api/v1/Actuator/HeapDump",
		"/api/v1/actuator/jolokia/list",
	})
	// Only dot names, wp-login.php and actuator with a known endpoint match
	// below the first segment; the other names are root-only.
	assertNoHits(t, "ProbePath", ProbePath, []string{
		"/api/v1/devices/actuator/5",
		"/api/v1/devices/actuator",
		"/api/v1/devices/actuator/envelope",
		"/api/server-status",
		"/api/v1/wp-admin/x",
		"/a/b/wp-admin/x",
		"/api/v1/phpMyAdmin/",
		"/api/v1/environment",
		"/api/v1/actuators-list",
		"/api/v1/orders/envelope",
		"/api/v1/wp-admins-are-us",
		"/api/v1/orders/server-statuses",
	})
	// A PHP file under such a directory is still reconnaissance by its
	// extension.
	backup := Hit{RuleID: "AEG-SCANNER-003", Category: model.CatScanner, Severity: model.SeverityMedium}
	assertHits(t, "ProbePath", ProbePath, backup, []string{"/api/v1/wp-admin/install.php"})
}

func TestUserAgentFuzzers(t *testing.T) {
	want := Hit{RuleID: "AEG-SCANNER-001", Category: model.CatScanner, Severity: model.SeverityMedium}
	assertHits(t, "UserAgent", UserAgent, want, []string{
		"Fuzz Faster U Fool v2.1.0-dev",
		"Wfuzz/3.1.0",
		"feroxbuster/2.10.4",
		"Hydra",
	})
	assertNoHits(t, "UserAgent", UserAgent, append([]string{
		"Hydration/1.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
	}, legitUserAgents...))
}

// TestProbePathExcept: each match is offered as the range the rule read;
// excusing one leaves the others reported.
func TestProbePathExcept(t *testing.T) {
	const p = "/api/v1/vault/.env/actuator/env"
	var got []string
	all := func(start, end int) bool { got = append(got, p[start:end]); return true }
	if _, ok := ProbePathExcept(p, all); ok {
		t.Fatal("all excused, still a hit")
	}
	if strings.Join(got, ",") != ".env,actuator/env" {
		t.Fatalf("ranges %q", got)
	}
	onlyActuator := func(start, end int) bool { return p[start:end] == "actuator/env" }
	if h, ok := ProbePathExcept(p, onlyActuator); !ok || h.RuleID != "AEG-SCANNER-002" {
		t.Fatalf(".env not reported: %v %v", h, ok)
	}
	for path, want := range map[string]string{
		"/.git/config":      ".git",
		"/actuator":         "actuator",
		"/wp-login.php":     "wp-login.php",
		"/a/b/config.php~":  "config.php~",
		"/api/v1/x.php.bak": "x.php.bak",
	} {
		var r []string
		ProbePathExcept(path, func(s, e int) bool { r = append(r, path[s:e]); return true })
		if len(r) == 0 || r[len(r)-1] != want {
			t.Errorf("%q: ranges %q, want last %q", path, r, want)
		}
	}
}

// TestProbePathAlpha6: VCS directories as whole segments at any depth;
// secret dotfiles, private keys, SQL dumps, SQLite files and archives as
// the first segment only (they are legitimate file names deeper in a tree:
// an export, a repository browser, a key name).
func TestProbePathAlpha6(t *testing.T) {
	probe := Hit{RuleID: "AEG-SCANNER-002", Category: model.CatScanner, Severity: model.SeverityMedium}
	assertHits(t, "ProbePath", ProbePath, probe, []string{
		"/.git", "/.git/", "/.GIT", "/api/v1/.git", "/x/.git.bak",
		"/.svn", "/.svn/entries", "/.SVN/wc.db", "/api/v1/.svn/entries",
		"/.hg", "/.hg/dirstate", "/a/.hg/store/data/",
		"/.bzr", "/.bzr/README",
		"/.git-credentials",
		"/.htpasswd", "/.htaccess", "/.htdigest", "/.htgroup", "/.htusers",
		"/.htaccess.bak1", "/.htaccess-dev", "/.htpasswds", "/.HTACCESS",
		"/.npmrc", "/.netrc", "/.pgpass", "/.DS_Store", "/.ds_store",
		"/.bash_history", "/.zsh_history", "/.mysql_history", "/.psql_history",
		"/.s3cfg", "/.dockercfg", "/.docker/config.json", "/.kube/config",
		"/id_rsa", "/id_rsa.pub", "/id_dsa", "/id_dsa.ppk", "/id_ecdsa", "/id_ed25519",
	})
	backup := Hit{RuleID: "AEG-SCANNER-003", Category: model.CatScanner, Severity: model.SeverityMedium}
	assertHits(t, "ProbePath", ProbePath, backup, []string{
		"/backup.sql", "/backup2026.sql", "/Dump.sql", "/db.sql", "/.sql", "/users.sql.gz", "/.sql.bz2", "/dump.sql.zip",
		"/db.sqlite", "/data.sqlite3",
		"/backup2026.zip", "/backup.zip", "/backup.tar.gz", "/backup.tgz", "/dump.7z", "/site.rar",
		"/backups.tar.bz2", "/.zip", "/1.tar", "/localhost.tar.xz", "/www.ZIP", "/error_log.gz",
	})
	assertNoHits(t, "ProbePath", ProbePath, []string{
		// The brief's near misses.
		"/.gitignore", "/.github/", "/.github/workflows/x.yml", "/docs/git-guide", "/api/v1/sql-reports",
		// Other dot names that are not secrets or VCS metadata.
		"/.well-known/openid-configuration", "/.well-known/security.txt", "/.gitattributes", "/.gitlab-ci.yml",
		"/.hgignore", "/.svnignore", "/.github", "/.html", "/.httpd", "/.npmignore", "/.dsstore-guide",
		"/api/v1/gitlab", "/api/v1/git/commits", "/api/v1/svn-mirror", "/hg-docs", "/bzr2git",
		// Secret and archive names deeper in a tree: exports, repository
		// browsers, key names.
		"/api/v1/exports/orders.sql", "/api/v1/exports/backup.sql", "/api/v1/backups/backup2026.zip",
		"/api/v1/reports/2026.tar.gz", "/api/v1/downloads/site.zip", "/api/v1/files/db.sqlite",
		"/api/v1/keys/id_rsa", "/api/v1/repos/1/files/.htaccess", "/api/v1/repos/1/files/.npmrc",
		"/api/v1/files/.DS_Store", "/api/v1/repos/1/files/.netrc",
		// Root names that only look alike.
		"/sql", "/backup", "/backups/", "/mysql", "/sqlite-guide", "/id_rsa_guide", "/ids", "/.sqlfluff",
		"/data.sqlx", "/archive", "/zip-codes", "/gz", "/robots.txt", "/openapi.json", "/favicon.ico",
		"/api/v1/orders.zip", "/v1/exports.tar.gz",
		// Compressed web and text files at the root (sitemaps,
		// precompressed assets).
		"/sitemap.xml.gz", "/sitemap_index.xml.gz", "/index.html.gz", "/main.js.gz", "/robots.txt.gz",
		"/export.csv.gz", "/app.css.br", "/data.json.xz", "/logo.svg.gz", "/app.wasm.gz", "/SITEMAP.XML.GZ",
		"/feed.xml.bz2",
	})
	// Still dumps or archives: a compressed archive or SQL name, or a
	// web extension that is not the one right before the compression.
	assertHits(t, "ProbePath", ProbePath, backup, []string{
		"/x.sql.json.gz", "/backup.tar.xml.gz", "/backup.zip.json.gz", "/x.json.tar.gz", "/x.xml.gz.gz",
		"/backup.json.zip", "/x.html.tar", "/sitemap.xml.7z", "/sitemap.xml.rar", "/error_log.gz", "/.gz",
		"/main.js.map.gz", "/release-1.2.3.zip", "/v1.2.tar",
	})
}

func TestUserAgentAlpha6(t *testing.T) {
	want := Hit{RuleID: "AEG-SCANNER-001", Category: model.CatScanner, Severity: model.SeverityMedium}
	assertHits(t, "UserAgent", UserAgent, want, []string{
		"commix/v3.9-stable (https://commixproject.com)",
		"Mozilla/5.0 (compatible; Netsparker)",
		"Arachni/v1.6.1",
		"w3af.org", "w3af.sf.net", "Mozilla/4.0 (compatible; w3af.sourceforge.net)",
		"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; HP WebInspect)",
		"Havij",
		"sqlninja",
		"WhatWeb/0.5.5",
		"Mozilla/5.0 (compatible; Detectify) +https://detectify.com/bot/x",
		"Mozilla/5.0 Jorgee",
		"ZmEu",
		"paros",
		"Paros/3.2.13",
		"vega/", "Vega/1.0",
		"qualys was", "Mozilla/5.0 (Qualys WAS)",
	})
	assertNoHits(t, "UserAgent", UserAgent, append([]string{
		// Longer words that contain the names.
		"Commixer/1.0", "Parosol/2.0", "Vegan Recipes/4.1 CFNetwork/1410.0.3 Darwin/22.6.0",
		"Vegas Guide/2.0", "Mozilla/5.0 (Linux; Android 14; Vegas)", "Arachnid/1.0",
		"WhatWebsite/1.0", "Detectifying/1.0", "qualys washer", "Qualysis WAS",
		// A name without the '/' that the CRS entry has.
		"Vega", "Vega Lite", "Mozilla/5.0 (Vega)",
	}, legitUserAgents...))
}

// TestProbePathAndUserAgentLinear runs ProbePath (with an excuse that reads
// every range it is given, as the engine's does) and UserAgent on long
// repetitions of every name they try, the way TestScanTextLinear does:
// over 8x the time for 4x the input, three times in a row, fails.
func TestProbePathAndUserAgentLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("wall-clock bound; skipped under -short")
	}
	reading := func(p string) func() {
		return func() {
			ProbePathExcept(p, func(s, e int) bool {
				n := 0
				for i := s; i < e; i++ {
					n += int(p[i])
				}
				return n >= 0
			})
		}
	}
	paths := map[string]string{
		"git":        "/.git",
		"git-dir":    "/.git/",
		"svn":        "/.svn/x",
		"ht":         "/.htaccess",
		"actuator":   "/actuator/env",
		"actuator-x": "/actuator/",
		"env":        "/.env.",
		"slashes":    "/",
	}
	// One long first segment: the root dump scan reads it once.
	roots := map[string]string{"sql": ".sql", "sql-almost": ".sq", "dots": "."}
	agents := map[string]string{"vega": "vega", "vega-x": "vega ", "paro": "paro", "qualys": "qualys wa", "nmap": "nmapnmap"}
	const small, medium, large = 64 << 10, 256 << 10, 1 << 20
	limit := wallLimit(2*time.Second, 20*time.Second)
	check := func(name string, mk func(n int) func()) {
		s, m, l := mk(small), mk(medium), mk(large)
		grow := func() bool {
			ds, dm := bestOf(5, s), bestOf(5, m)
			return ds > 500*time.Microsecond && dm > 8*ds
		}
		if raceSlowdown == 1 && grow() && grow() && grow() {
			t.Errorf("%s: super-linear", name)
		}
		if d := bestOf(3, l); d > limit {
			t.Errorf("%s: %v on %d bytes, want under %v", name, d, large, limit)
		}
	}
	for name, unit := range paths {
		check("path "+name, func(n int) func() { return reading(strings.Repeat(unit, n/len(unit))) })
	}
	for name, unit := range roots {
		check("root "+name, func(n int) func() { return reading("/" + strings.Repeat(unit, n/len(unit))) })
	}
	for name, unit := range agents {
		check("ua "+name, func(n int) func() {
			ua := strings.Repeat(unit, n/len(unit))
			return func() { UserAgent(ua) }
		})
	}
}

// TestProbePathRootCompressedWebTypes covers the web types added after the
// alpha.6 final review: precompressed modules, feeds, manifests, icons and
// fonts at the root are clear; SQL and archive names before them are not.
func TestProbePathRootCompressedWebTypes(t *testing.T) {
	backup := Hit{RuleID: "AEG-SCANNER-003", Category: model.CatScanner, Severity: model.SeverityMedium}
	assertNoHits(t, "ProbePath", ProbePath, []string{
		"/app.mjs.gz", "/index.htm.gz", "/feed.rss.gz", "/site.webmanifest.br", "/events.ndjson.gz",
		"/favicon.ico.gz", "/font.woff.gz", "/font.woff2.br", "/APP.MJS.GZ", "/feed.rss.xz", "/icons.ico.bz2",
	})
	assertHits(t, "ProbePath", ProbePath, backup, []string{
		"/x.sql.mjs.gz", "/backup.tar.rss.gz", "/backup.zip.woff2.gz", "/x.mjs.tar.gz", "/x.ico.gz.gz",
		"/font.woff2.zip", "/x.htm.tar", "/feed.rss.7z", "/app.mjs.map.gz", "/x.mjsx.gz", "/x.woff3.gz",
	})
}
