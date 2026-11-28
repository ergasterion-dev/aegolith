package engine

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/internal/model"
	"github.com/ergasterion-dev/aegolith/internal/policy"
)

// scannerRules lists the AEG-SCANNER-* rule IDs among d's matches.
func scannerRules(d model.Decision) []string {
	var ids []string
	for _, m := range d.Matches {
		if strings.HasPrefix(m.RuleID, "AEG-SCANNER-") {
			ids = append(ids, m.RuleID)
		}
	}
	return ids
}

// TestDeclaredRouteScannerPath: a scanner path rule is not raised when the
// text it matched lies wholly in literal segments of the declared route the
// request matched. Text in a parameter or wildcard segment, an undeclared
// route or an undeclared method is still judged.
func TestDeclaredRouteScannerPath(t *testing.T) {
	var routes []policy.Route
	for _, ep := range []string{"health", "info", "metrics", "env"} {
		routes = append(routes, policy.Route{Method: "GET", Path: "/api/v1/stores/:id/actuator/" + ep})
	}
	routes = append(routes,
		policy.Route{Method: "GET", Path: "/api/v1/shops/:id/actuator/:ep"},
		// Overlapping templates: the literal wins for health only.
		policy.Route{Method: "GET", Path: "/api/v1/branches/:id/actuator/health"},
		policy.Route{Method: "GET", Path: "/api/v1/branches/:id/actuator/:ep"},
		policy.Route{Method: "GET", Path: "/api/v1/stores/:id/actuator/env/*"},
		policy.Route{Method: "GET", Path: "/api/v1/stores/:id/actuator/health/:file"},
		policy.Route{Method: "GET", Path: "/api/v1/vault/:x/actuator/env"},
		policy.Route{Method: "GET", Path: "/api/v1/files/*"},
		policy.Route{Method: "GET", Path: "/actuator/:ep"},
		policy.Route{Method: "GET", Path: "/actuator/health"},
		policy.Route{Method: "GET", Path: "/wp-admin/*"},
		policy.Route{Method: "GET", Path: "/:slug"},
		policy.Route{Method: "GET", Path: "/:a/:b"},
		policy.Route{Method: "GET", Path: "/*"},
	)
	e := newEngine(t, Options{Mode: model.ModeMonitor, FailOpen: true, Routes: routes, UnknownRoute: model.ActionMonitor})
	generic := newEngine(t, Options{Mode: model.ModeMonitor, FailOpen: true})
	do := func(e *Engine, method, path string, fold bool) model.Decision {
		return e.Inspect(&model.Request{Method: method, RawPath: path, Header: http.Header{}, CaseInsensitiveRoutes: fold})
	}

	for _, tc := range []struct {
		method, path string
		fold         bool
	}{
		{"GET", "/api/v1/stores/1/actuator/health", false},
		{"GET", "/api/v1/stores/1/actuator/info", false},
		{"GET", "/api/v1/stores/1/actuator/metrics", false},
		{"GET", "/api/v1/stores/1/actuator/env", false},
		{"HEAD", "/api/v1/stores/1/actuator/health", false}, // HEAD falls back to GET, as the router
		{"GET", "/API/V1/Stores/1/Actuator/Health", true},   // folding router: the same handler
		{"GET", "/api/v1/branches/1/actuator/health", false},
		{"GET", "/api/v1/stores/1/actuator/env/x", false}, // literal prefix, harmless wildcard rest
		// A double-encoded slash stays one segment on every router.
		{"GET", "/api/v1/stores/x%252Fy/actuator/health", false},
		// A root probe name declared wholly literally.
		{"GET", "/actuator/health", false},
		// A dot segment as the parameter is the router's view too (the
		// protocol rule AEG-PROTO-005 refuses it anyway).
		{"GET", "/api/v1/stores/../actuator/env", false},
	} {
		if ids := scannerRules(do(e, tc.method, tc.path, tc.fold)); len(ids) != 0 {
			t.Errorf("declared %s %q: %v", tc.method, tc.path, ids)
		}
		// Without a policy the same path is a probe.
		if len(scannerRules(do(generic, tc.method, tc.path, tc.fold))) == 0 {
			t.Errorf("generic %s %q: not flagged", tc.method, tc.path)
		}
	}

	for _, tc := range []struct {
		method, path string
		fold         bool
		want         string
	}{
		{"GET", "/api/v1/devices/1/actuator/health", false, "AEG-SCANNER-002"}, // undeclared route
		{"POST", "/api/v1/stores/1/actuator/env", false, "AEG-SCANNER-002"},    // undeclared method
		{"GET", "/api/v1/shops/1/actuator/env", false, "AEG-SCANNER-002"},      // endpoint in a parameter
		{"GET", "/api/v1/branches/1/actuator/env", false, "AEG-SCANNER-002"},   // overlap: param route
		{"GET", "/API/v1/stores/1/actuator/health", false, "AEG-SCANNER-002"},  // case-sensitive router: unrouted
		{"GET", "/api/v1/stores/1/actuator/%65nv", false, "AEG-SCANNER-002"},   // encoded literal: unrouted
		{"GET", "/api/v1//stores/1/actuator/env", false, "AEG-SCANNER-002"},    // duplicate slash: unrouted
		{"GET", "/api/v1/stores/1/actuator/env/.git/config", false, "AEG-SCANNER-002"},
		{"GET", "/api/v1/stores/1/actuator/env/.env", false, "AEG-SCANNER-002"},
		{"GET", "/api/v1/stores/x%2F.env/actuator/health", false, "AEG-SCANNER-002"}, // %2F in a parameter
		{"GET", "/api/v1/stores/x%2Factuator%2Fenv/actuator/health", false, "AEG-SCANNER-002"},
		{"GET", "/api/v1/vault/.env/actuator/env", false, "AEG-SCANNER-002"},                 // second match in a parameter
		{"GET", "/api/v1/stores/1/actuator/health/config.php.bak", false, "AEG-SCANNER-003"}, // backup file in a parameter
		{"GET", "/api/v1/files/.git/config", false, "AEG-SCANNER-002"},                       // wildcard
		{"GET", "/.env", false, "AEG-SCANNER-002"},                                           // /:slug
		{"GET", "/actuator/env", false, "AEG-SCANNER-002"},                                   // /:a/:b
		{"GET", "/wp-admin/install.php", false, "AEG-SCANNER-002"},                           // /:a/:b
		{"GET", "/x/y/.git/config", false, "AEG-SCANNER-002"},
		// A root probe name runs to the end of the path: a parameter or
		// wildcard after it is part of the match.
		{"GET", "/actuator/env", false, "AEG-SCANNER-002"},
		{"GET", "/actuator/heapdump", false, "AEG-SCANNER-002"},
		{"GET", "/actuator/jolokia", false, "AEG-SCANNER-002"},
		{"GET", "/wp-admin/setup-config", false, "AEG-SCANNER-002"},
		{"GET", "/wp-admin/", false, "AEG-SCANNER-002"},
		// A trailing slash the template does not have: ServeMux and Fiber
		// StrictRouting send it to another handler.
		{"GET", "/api/v1/stores/7/actuator/health/", false, "AEG-SCANNER-002"},
		{"GET", "/actuator/health/", false, "AEG-SCANNER-002"},
		// %2F in a parameter: Fiber UnescapePath routes it elsewhere.
		{"GET", "/api/v1/stores/a%2Fb/actuator/health", false, "AEG-SCANNER-002"},
		{"GET", "/api/v1/stores/a%2fb/actuator/health", false, "AEG-SCANNER-002"},
		{"GET", "/api/v1/stores/1%2Factuator/actuator/health", false, "AEG-SCANNER-002"},                    // /*
		{"GET", "/api/v1/stores/1/actuator/env/x/../../../../../../actuator/env", false, "AEG-SCANNER-002"}, // wildcard rest
	} {
		ids := scannerRules(do(e, tc.method, tc.path, tc.fold))
		found := false
		for _, id := range ids {
			found = found || id == tc.want
		}
		if !found {
			t.Errorf("%s %q: want %s, got %v", tc.method, tc.path, tc.want, ids)
		}
	}

	// Scanner user agents are never excused by a declared route.
	d := e.Inspect(&model.Request{Method: "GET", RawPath: "/api/v1/stores/1/actuator/health",
		Header: http.Header{"User-Agent": {"sqlmap/1.8"}}})
	if ids := scannerRules(d); len(ids) != 1 || ids[0] != "AEG-SCANNER-001" {
		t.Errorf("scanner UA on a declared route: %v", ids)
	}
}

// TestDeclaredLiteralMapping: a raw path whose per-segment decoding does
// not rebuild the decoded path excuses nothing.
func TestDeclaredLiteralMapping(t *testing.T) {
	e := newEngine(t, Options{Mode: model.ModeMonitor, FailOpen: true,
		Routes: []policy.Route{{Method: "GET", Path: "/api/v1/stores/:id/actuator/env"}}})
	s := &state{e: e, req: model.Request{Method: "GET", RawPath: "/api/v1/stores/1/actuator/env"}}
	s.path = "/api/v1/stores/1/actuator/envX" // not what the raw path decodes to
	s.matchRoute()
	if !s.routed {
		t.Fatal("not routed")
	}
	if ex := s.declaredLiteral(); ex != nil && ex(len("/api/v1/stores/1/"), len("/api/v1/stores/1/actuator/env")) {
		t.Fatal("excused a range of a path that does not match the raw path")
	}
}

// TestDeclaredRouteAcceptedMisses pins the accepted-miss list in the
// checkProbeAndAgent comment: each probe below is a probe-path match on a
// generic engine and is not reported once the route is declared.
func TestDeclaredRouteAcceptedMisses(t *testing.T) {
	routes := []policy.Route{{Method: "GET", Path: "/api/v1/stores/:id/actuator/health"}}
	declared := newEngine(t, Options{Mode: model.ModeMonitor, FailOpen: true, Routes: routes, UnknownRoute: model.ActionMonitor})
	folded := newEngine(t, Options{Mode: model.ModeMonitor, FailOpen: true, Routes: routes, UnknownRoute: model.ActionMonitor, CaseInsensitiveRoutes: true})
	rootLit := newEngine(t, Options{Mode: model.ModeMonitor, FailOpen: true, UnknownRoute: model.ActionMonitor,
		Routes: []policy.Route{{Method: "GET", Path: "/actuator/health"}}})
	generic := newEngine(t, Options{Mode: model.ModeMonitor, FailOpen: true})
	for _, tc := range []struct {
		name, method, path string
		e                  *Engine
	}{
		{"1. literal segments", "GET", "/api/v1/stores/7/actuator/health", declared},
		{"2. HEAD for GET", "HEAD", "/api/v1/stores/7/actuator/health", declared},
		{"2. folded case", "GET", "/API/V1/Stores/7/Actuator/Health", folded},
		{"1. root name, wholly literal", "GET", "/actuator/health", rootLit},
	} {
		req := func() *model.Request {
			return &model.Request{Method: tc.method, RawPath: tc.path, Header: http.Header{}}
		}
		if len(scannerRules(generic.Inspect(req()))) == 0 {
			t.Errorf("%s: %q is not a probe on a generic engine", tc.name, tc.path)
		}
		if ids := scannerRules(tc.e.Inspect(req())); len(ids) != 0 {
			t.Errorf("%s: %q still reported %v: the accepted-miss list is out of date", tc.name, tc.path, ids)
		}
	}
}

// TestSlashTemplateRequestedWithoutSlash: a template that ends in '/'
// excuses its literal text only when the request ends in '/' too, since
// ServeMux and Fiber StrictRouting can send the slashless form to another
// handler. The template "/" is not affected.
func TestSlashTemplateRequestedWithoutSlash(t *testing.T) {
	e := newEngine(t, Options{Mode: model.ModeMonitor, FailOpen: true, UnknownRoute: model.ActionMonitor, Routes: []policy.Route{
		{Method: "GET", Path: "/"},
		{Method: "GET", Path: "/actuator/health/"},
		{Method: "GET", Path: "/api/v1/hubs/:id/actuator/health/"},
	}})
	for _, base := range []string{"/actuator/health", "/api/v1/hubs/7/actuator/health"} {
		for _, tc := range []struct {
			method, path string
			fold, probe  bool
		}{
			{"GET", base, false, true},
			{"HEAD", base, false, true},
			{"GET", strings.ToUpper(base), true, true},
			{"GET", base + "/", false, false},
			{"HEAD", base + "/", false, false},
			{"GET", strings.ToUpper(base) + "/", true, false},
		} {
			ids := scannerRules(e.Inspect(&model.Request{Method: tc.method, RawPath: tc.path,
				Header: http.Header{}, CaseInsensitiveRoutes: tc.fold}))
			if got := len(ids) != 0; got != tc.probe {
				t.Errorf("%s %q: scanner rules %v, want reported %t", tc.method, tc.path, ids, tc.probe)
			}
		}
	}

	s := &state{e: e, req: model.Request{Method: "GET", RawPath: "/"}, path: "/"}
	s.matchRoute()
	if !s.routed || s.declaredLiteral() == nil {
		t.Errorf(`template "/", request "/": routed %t, excuse missing`, s.routed)
	}
	if ids := scannerRules(e.Inspect(&model.Request{Method: "GET", RawPath: "/", Header: http.Header{}})); len(ids) != 0 {
		t.Errorf(`template "/", request "/": %v`, ids)
	}
}

// TestDeclaredRouteNotExcused pins the forms that the accepted-miss list
// says excuse nothing: a trailing slash on only one of the template and the
// request, and %2F (any case) in a parameter or wildcard segment.
func TestDeclaredRouteNotExcused(t *testing.T) {
	e := newEngine(t, Options{Mode: model.ModeMonitor, FailOpen: true, UnknownRoute: model.ActionMonitor, Routes: []policy.Route{
		{Method: "GET", Path: "/api/v1/stores/:id/actuator/health"},
		{Method: "GET", Path: "/api/v1/shops/*"},
		{Method: "GET", Path: "/api/v1/hubs/:id/actuator/health/"},
	}})
	for _, p := range []string{
		"/api/v1/stores/7/actuator/health/",
		"/api/v1/stores/a%2Fb/actuator/health",
		"/api/v1/stores/a%2fb/actuator/health",
		"/api/v1/stores/%2F/actuator/health",
		"/api/v1/shops/x%2F/actuator/env",
	} {
		if len(scannerRules(e.Inspect(&model.Request{Method: "GET", RawPath: p, Header: http.Header{}}))) == 0 {
			t.Errorf("%q: excused", p)
		}
	}
	// A template that ends in '/' itself keeps the trailing-slash form.
	if ids := scannerRules(e.Inspect(&model.Request{Method: "GET", RawPath: "/api/v1/hubs/7/actuator/health/", Header: http.Header{}})); len(ids) != 0 {
		t.Errorf("template with a trailing slash: %v", ids)
	}
}

// TestDeclaredRouteAssistantConfig: an AI-assistant name is excused as the
// other root names are, only when the declared route spells the whole path
// literally.
func TestDeclaredRouteAssistantConfig(t *testing.T) {
	e := newEngine(t, Options{Mode: model.ModeMonitor, FailOpen: true, UnknownRoute: model.ActionMonitor, Routes: []policy.Route{
		{Method: "GET", Path: "/.continue"},
		{Method: "GET", Path: "/.zed/status"},
		{Method: "GET", Path: "/.claude/:file"},
		{Method: "GET", Path: "/:slug"},
	}})
	for path, want := range map[string]bool{
		"/.continue":             false,
		"/.zed/status":           false,
		"/.claude/settings.json": true, // the name runs into a parameter
		"/.cursor":               true, // /:slug
		"/.zed/other":            true, // undeclared
		"/.continue/":            true, // a slash the template does not have
	} {
		d := e.Inspect(&model.Request{Method: "GET", RawPath: path, Header: http.Header{}})
		if ids := scannerRules(d); (len(ids) == 1 && ids[0] == "AEG-SCANNER-002") != want || !want && len(ids) != 0 {
			t.Errorf("%q: %v, want flagged %v", path, ids, want)
		}
	}
}
