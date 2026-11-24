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
