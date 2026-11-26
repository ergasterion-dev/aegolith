package httpwaf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ergasterion-dev/aegolith"
)

// TestDeclaredActuatorRouteThroughServeMux: a declared customer route named
// .../actuator/health reaches its ServeMux handler; the same name on an
// undeclared path is refused. A dot segment sent as the parameter matches
// the route, so the scanner rules excuse the literal actuator/health, but
// the protocol rule for dot segments (AEG-PROTO-005) refuses it before
// ServeMux could redirect to the cleaned path; that path is refused too.
func TestDeclaredActuatorRouteThroughServeMux(t *testing.T) {
	fw := newFW(t, aegolith.Config{Mode: aegolith.ModeEnforce, Routes: []aegolith.Route{
		{Method: "GET", Path: "/api/v1/stores/:id/actuator/health"},
	}})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/stores/{id}/actuator/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	h := Middleware(fw, Options{})(mux)
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/api/v1/stores/42/actuator/health", http.StatusOK},
		{"/api/v1/devices/42/actuator/health", http.StatusForbidden},
		{"/api/v1/stores/42/actuator/env", http.StatusForbidden},
		{"/api/v1/stores/42/.git/config", http.StatusForbidden},
		{"/api/v1/stores/../actuator/health", http.StatusForbidden},
		{"/api/v1/stores/%2e%2e/actuator/health", http.StatusForbidden},
		{"/api/v1/actuator/health", http.StatusForbidden},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d", tc.path, rec.Code, tc.want)
		}
	}
}
