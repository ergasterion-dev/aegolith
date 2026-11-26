package fiberv2

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/ergasterion-dev/aegolith"
	"github.com/gofiber/fiber/v2"
)

// declaredHealth is the one route template whose literal segments should be
// excused from the scanner path rules.
const declaredHealth = "/api/v1/stores/:id/actuator/health"

// Each handler answers with its own status, so a status says which handler a
// request reached.
const (
	reachedDeclared  = http.StatusOK                   // 200
	reachedActuator  = http.StatusCreated              // 201
	reachedTwoParams = http.StatusAccepted             // 202
	reachedWPAdmin   = http.StatusNonAuthoritativeInfo // 203
	reachedCatchAll  = 299
)

func scannerRouteApp(appCfg fiber.Config, mw ...fiber.Handler) *fiber.App {
	appCfg.DisableStartupMessage = true
	app := fiber.New(appCfg)
	for _, h := range mw {
		app.Use(h)
	}
	status := func(code int) fiber.Handler {
		return func(c *fiber.Ctx) error { return c.SendStatus(code) }
	}
	app.Get(declaredHealth, status(reachedDeclared))
	app.Get("/api/v1/stores/:a/:b/actuator/health", status(reachedTwoParams))
	app.Get("/actuator/:ep", status(reachedActuator))
	app.Get("/wp-admin/*", status(reachedWPAdmin))
	app.All("/*", status(reachedCatchAll))
	return app
}

// TestFiberDeclaredRouteScannerPath: behind the middleware, a request for a
// declared route is not refused for a probe name its template spells
// literally. For this test's routes (no template ends in '/', and the
// declared handler is registered first), each listed form that a Fiber app
// could send to another handler, and each listed probe name that arrives in a
// parameter or wildcard, is still refused by a scanner path rule. The claim
// does not extend to other route sets.
func TestFiberDeclaredRouteScannerPath(t *testing.T) {
	configs := []struct {
		name          string
		cfg           fiber.Config
		caseSensitive bool
	}{
		{"default", fiber.Config{}, false},
		{"StrictRouting", fiber.Config{StrictRouting: true}, false},
		{"UnescapePath", fiber.Config{UnescapePath: true}, false},
		{"CaseSensitive", fiber.Config{CaseSensitive: true}, true},
	}

	const (
		base  = "/api/v1/stores/42/actuator/health"
		upper = "/API/V1/Stores/42/Actuator/Health"
	)
	excused := []struct{ method, path string }{
		{"GET", base},
		{"HEAD", base},
		{"GET", base + "?verbose=1"},
	}
	blocked := []struct{ method, path, rule string }{
		// A trailing slash the template does not have.
		{"GET", base + "/", "AEG-SCANNER-002"},
		{"GET", base + "//", "AEG-SCANNER-002"},
		// An encoded slash in a parameter.
		{"GET", "/api/v1/stores/a%2Fb/actuator/health", "AEG-SCANNER-002"},
		{"GET", "/api/v1/stores/a%2fb/actuator/health", "AEG-SCANNER-002"},
		// An encoded or duplicated literal is not the declared route.
		{"GET", "/api/v1/stores/42/actuator/%68ealth", "AEG-SCANNER-002"},
		{"GET", "/api/v1//stores/42/actuator/health", "AEG-SCANNER-002"},
		// Undeclared route, endpoint or method.
		{"GET", "/api/v1/devices/42/actuator/health", "AEG-SCANNER-002"},
		{"GET", "/api/v1/stores/42/actuator/env", "AEG-SCANNER-002"},
		{"POST", base, "AEG-SCANNER-002"},
		// A probe name in a parameter.
		{"GET", "/api/v1/stores/.env/actuator/health", "AEG-SCANNER-002"},
		// A root probe name followed by a parameter or wildcard.
		{"GET", "/actuator/env", "AEG-SCANNER-002"},
		{"GET", "/actuator/heapdump", "AEG-SCANNER-002"},
		{"GET", "/wp-admin/setup-config", "AEG-SCANNER-002"},
	}

	for _, c := range configs {
		t.Run(c.name, func(t *testing.T) {
			var rawPath string
			var rules []string
			fw := newFW(t, aegolith.Config{
				Mode: aegolith.ModeEnforce,
				Routes: []aegolith.Route{
					{Method: "GET", Path: declaredHealth},
					{Method: "GET", Path: "/actuator/:ep"},
					{Method: "GET", Path: "/wp-admin/*"},
				},
			})
			app := scannerRouteApp(c.cfg, New(Config{
				Firewall: fw,
				OnDecision: func(r *aegolith.Request, d aegolith.Decision) {
					rawPath = r.RawPath
					for _, m := range d.Matches {
						rules = append(rules, m.RuleID)
					}
				},
			}))
			bare := scannerRouteApp(c.cfg)

			wantAllowed := func(t *testing.T, method, path string) {
				t.Helper()
				rawPath, rules = "", nil
				code, _, _ := do(t, app, httptest.NewRequest(method, path, nil))
				if code != reachedDeclared {
					t.Errorf("%s %s: status %d (rules %v), want %d from the declared handler", method, path, code, rules, reachedDeclared)
				}
				for _, id := range rules {
					if id == "AEG-SCANNER-002" || id == "AEG-SCANNER-003" {
						t.Errorf("%s %s: scanner path rule %s reported on a declared route", method, path, id)
					}
				}
			}
			wantBlocked := func(t *testing.T, method, path, rule string) {
				t.Helper()
				rawPath, rules = "", nil
				code, _, _ := do(t, app, httptest.NewRequest(method, path, nil))
				if code != http.StatusForbidden || !slices.Contains(rules, rule) {
					unprotected, _, _ := do(t, bare, httptest.NewRequest(method, path, nil))
					t.Errorf("%s %s: status %d rules %v, want 403 with %s (without the middleware: %d)", method, path, code, rules, rule, unprotected)
					return
				}
				// The engine must have judged the path as sent.
				if rawPath != path {
					t.Errorf("%s %s: engine saw raw path %q", method, path, rawPath)
				}
			}

			for _, tc := range excused {
				wantAllowed(t, tc.method, tc.path)
			}
			for _, tc := range blocked {
				wantBlocked(t, tc.method, tc.path, tc.rule)
			}
			// Letter case follows the app's router.
			if c.caseSensitive {
				wantBlocked(t, "GET", upper, "AEG-SCANNER-002")
			} else {
				wantAllowed(t, "GET", upper)
			}

			// A scanner user agent is refused on the declared route too.
			rules = nil
			req := httptest.NewRequest("GET", base, nil)
			req.Header.Set("User-Agent", "sqlmap/1.8")
			if code, _, _ := do(t, app, req); code != http.StatusForbidden || !slices.Equal(rules, []string{"AEG-SCANNER-001"}) {
				t.Errorf("scanner user agent on the declared route: status %d rules %v, want 403 with only AEG-SCANNER-001", code, rules)
			}

			// The premise of the refusals: without the middleware these
			// forms reach a handler, on some configurations not the
			// declared one.
			slashHandler := reachedDeclared
			if c.cfg.StrictRouting {
				slashHandler = reachedCatchAll
			}
			encodedHandler := reachedDeclared
			if c.cfg.UnescapePath {
				encodedHandler = reachedTwoParams
			}
			for _, tc := range []struct {
				path string
				want int
			}{
				{base, reachedDeclared},
				{base + "/", slashHandler},
				{"/api/v1/stores/a%2Fb/actuator/health", encodedHandler},
				{"/actuator/env", reachedActuator},
				{"/wp-admin/setup-config", reachedWPAdmin},
			} {
				if code, _, _ := do(t, bare, httptest.NewRequest("GET", tc.path, nil)); code != tc.want {
					t.Errorf("without the middleware GET %s: status %d, want %d", tc.path, code, tc.want)
				}
			}
		})
	}
}
