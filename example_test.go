package aegolith_test

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ergasterion-dev/aegolith"
)

// A firewall in monitor mode: attacks are reported, never blocked. Run this
// first in production, read the decisions, then switch to enforce.
func ExampleNew() {
	fw, err := aegolith.New(aegolith.Config{Mode: aegolith.ModeMonitor})
	if err != nil {
		log.Fatal(err) // invalid configuration is reported at startup
	}

	d := fw.Inspect(&aegolith.Request{
		Method:   "GET",
		RawPath:  "/api/v1/products/search",
		RawQuery: "q=1%27+OR+%271%27%3D%271",
		Header:   http.Header{},
	})

	fmt.Println(d.Action, d.Monitored)
	for _, m := range d.Matches {
		fmt.Println(m.RuleID, m.Category, m.Field, m.Action)
	}
	// Output:
	// allow true
	// AEG-SQLI-001 sqli query.q block
}

// Route policies describe the API: typed fields are validated by type and
// skip the heavy detectors, text fields get the full detector set.
func ExampleConfig_routes() {
	unknownFieldsBlock := aegolith.ActionBlock
	fw, err := aegolith.New(aegolith.Config{
		Mode: aegolith.ModeEnforce,
		Routes: []aegolith.Route{{
			Method: "POST",
			Path:   "/api/v1/cart/items",
			Body: map[string]aegolith.Field{
				"product_id": {Type: aegolith.TypeUUID},
				"qty":        {Type: aegolith.TypeInt, Min: ptr(1), Max: ptr(99)},
				"note":       {Type: aegolith.TypeText, MaxLen: 500},
			},
			UnknownFields: &unknownFieldsBlock,
		}},
		Exclusions: []aegolith.Exclusion{{
			Rule:  "AEG-SQLI-*",
			Route: "GET /api/v1/products/search",
			Field: "query.q",
		}},
	})
	if err != nil {
		log.Fatal(err)
	}

	cart := func(body string) aegolith.Decision {
		return fw.Inspect(&aegolith.Request{
			Method:  "POST",
			RawPath: "/api/v1/cart/items",
			Header:  http.Header{"Content-Type": {"application/json"}},
			Body:    []byte(body),
		})
	}

	fmt.Println(cart(`{"product_id":"3f2b8c1e-5d4a-4e6b-9c7d-1a2b3c4d5e6f","qty":2,"note":"Gate code 1234 & leave at door"}`).Action)
	fmt.Println(cart(`{"product_id":"1' OR '1'='1","qty":2}`).Action) // not a UUID
	// Output:
	// allow
	// block
}

// The same structure loads from a JSON file.
func ExampleLoadConfig() {
	dir, err := os.MkdirTemp("", "aegolith-example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "aegolith.json")
	if err := os.WriteFile(path, []byte(exampleConfigJSON), 0o600); err != nil {
		log.Fatal(err)
	}

	cfg, err := aegolith.LoadConfig(path)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := aegolith.New(cfg); err != nil {
		log.Fatal(err)
	}
	fmt.Println(cfg.Mode, len(cfg.Routes))
	// Output: monitor 2
}

// exampleConfigJSON is the file shown in the README ("Route policies").
const exampleConfigJSON = `{
  "mode": "monitor",
  "unknown_route": "monitor",
  "unknown_fields": "monitor",
  "inspect_headers": ["X-Api-Version"],
  "routes": [
    {
      "method": "GET",
      "path": "/api/v1/products/:id",
      "path_params": { "id": { "type": "uuid" } }
    },
    {
      "method": "POST",
      "path": "/api/v1/cart/items",
      "unknown_fields": "block",
      "body": {
        "product_id": { "type": "uuid" },
        "qty": { "type": "int", "min": 1, "max": 99 },
        "note": { "type": "text", "max_len": 500 }
      }
    }
  ],
  "exclusions": [
    { "rule": "AEG-SQLI-*", "route": "GET /api/v1/products/search", "field": "query.q" }
  ],
  "rule_actions": { "AEG-SCANNER-*": "monitor" }
}`

func ptr(f float64) *float64 { return &f }
