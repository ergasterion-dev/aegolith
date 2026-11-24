package httpwaf_test

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/ergasterion-dev/aegolith"
	"github.com/ergasterion-dev/aegolith/httpwaf"
)

// Wrap any http.Handler. This example enforces; in production set
// Mode: aegolith.ModeMonitor first, so nothing is blocked and the slog hook
// only logs what would have been.
func ExampleMiddleware() {
	fw, err := aegolith.New(aegolith.Config{Mode: aegolith.ModeEnforce})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/products/search", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	// httpwaf.SlogHook(slog.Default()) is a ready OnDecision hook.
	handler := httpwaf.Middleware(fw, httpwaf.Options{
		OnDecision: httpwaf.SlogHook(slog.Default()),
	})(mux)

	for _, q := range []string{"red shoes", "1' OR '1'='1"} {
		req := httptest.NewRequest("GET", "/api/v1/products/search?q="+url.QueryEscape(q), nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		fmt.Println(rec.Code)
	}
	// Output:
	// 200
	// 403
}
