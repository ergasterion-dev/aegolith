package fiberv2_test

import (
	"fmt"
	"log"
	"log/slog"
	"net/http/httptest"
	"net/url"

	"github.com/ergasterion-dev/aegolith"
	"github.com/ergasterion-dev/aegolith/adapters/fiberv2"
	"github.com/ergasterion-dev/aegolith/httpwaf"
	"github.com/gofiber/fiber/v2"
)

// Use the middleware first, before your routes. This example enforces; in
// production set Mode: aegolith.ModeMonitor first.
func ExampleNew() {
	fw, err := aegolith.New(aegolith.Config{Mode: aegolith.ModeEnforce})
	if err != nil {
		log.Fatal(err) // invalid configuration is reported at startup
	}

	app := fiber.New()
	app.Use(fiberv2.New(fiberv2.Config{
		Firewall:   fw,
		OnDecision: httpwaf.SlogHook(slog.Default()),
		Next:       func(c *fiber.Ctx) bool { return c.Path() == "/healthz" },
	}))
	app.Get("/api/v1/products/search", func(c *fiber.Ctx) error { return c.SendString("ok") })

	for _, q := range []string{"red shoes", "1' OR '1'='1"} {
		resp, err := app.Test(httptest.NewRequest("GET", "/api/v1/products/search?q="+url.QueryEscape(q), nil))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(resp.StatusCode)
	}
	// Output:
	// 200
	// 403
}
