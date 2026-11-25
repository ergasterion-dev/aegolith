package detect

import (
	"testing"

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
