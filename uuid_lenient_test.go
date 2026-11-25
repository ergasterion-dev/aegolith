package aegolith_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith"
)

const (
	tcanon = "4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b"
	thex32 = "4b8e2f1a9c3d4e5f8a7b1c2d3e4f5a6b"
)

// uuidRoutes declares the same id under the strict and the lenient type,
// as a path param, a query value and a JSON body field.
func uuidRoutes(typ string) []aegolith.Route {
	return []aegolith.Route{
		{Method: "GET", Path: "/api/v1/orders/:id", PathParams: map[string]aegolith.Field{"id": {Type: typ}},
			Query: map[string]aegolith.Field{"ref": {Type: typ}}},
		{Method: "POST", Path: "/api/v1/cart/items", Body: map[string]aegolith.Field{"product_id": {Type: typ}}},
	}
}

// nonCanonical are the encodings github.com/google/uuid's Parse accepts on
// top of the canonical form, as they appear raw, in a path segment
// (braces percent-encoded) and as a JSON string.
var nonCanonical = []struct{ raw, path string }{
	{thex32, thex32},
	{strings.ToUpper(thex32), strings.ToUpper(thex32)},
	{"{" + tcanon + "}", "%7B" + tcanon + "%7D"},
	{"urn:uuid:" + tcanon, "urn:uuid:" + tcanon},
	{"URN:UUID:" + strings.ToUpper(tcanon), "URN:UUID:" + strings.ToUpper(tcanon)},
}

func TestInspectUUIDLenientAcceptsParseForms(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Routes: uuidRoutes(aegolith.TypeUUIDLenient)})
	for _, v := range append([]struct{ raw, path string }{{tcanon, tcanon}}, nonCanonical...) {
		for _, r := range []*aegolith.Request{
			get("/api/v1/orders/" + v.path),
			get("/api/v1/orders/" + tcanon + "?ref=" + v.path),
			postJSON("/api/v1/cart/items", `{"product_id":"`+v.raw+`"}`),
		} {
			if d := fw.Inspect(r); len(d.Matches) != 0 || d.Action != aegolith.ActionAllow {
				t.Errorf("%s %s?%s: %v (%v)", r.Method, r.RawPath, r.RawQuery, d.Action, ruleIDs(d))
			}
		}
	}
}

// TestInspectUUIDStrictUnchanged: the strict type still blocks every form
// uuid_lenient adds, in enforce mode, at every location.
func TestInspectUUIDStrictUnchanged(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Routes: uuidRoutes(aegolith.TypeUUID)})
	if d := fw.Inspect(get("/api/v1/orders/" + tcanon + "?ref=" + strings.ToUpper(tcanon))); len(d.Matches) != 0 {
		t.Fatalf("canonical: %v", ruleIDs(d))
	}
	for _, v := range nonCanonical {
		for field, r := range map[string]*aegolith.Request{
			"path.id":         get("/api/v1/orders/" + v.path),
			"query.ref":       get("/api/v1/orders/" + tcanon + "?ref=" + v.path),
			"body.product_id": postJSON("/api/v1/cart/items", `{"product_id":"`+v.raw+`"}`),
		} {
			d := fw.Inspect(r)
			mustHave(t, d, "AEG-SCHEMA-001", field)
			if d.Action != aegolith.ActionBlock {
				t.Errorf("%s %q: action %v, want block", field, v.raw, d.Action)
			}
		}
	}
}

func TestInspectUUIDLenientBlocksPayloads(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Routes: uuidRoutes(aegolith.TypeUUIDLenient)})
	for field, r := range map[string]*aegolith.Request{
		"path.id":         get("/api/v1/orders/1%27%20OR%20%271%27%3D%271"),
		"query.ref":       get("/api/v1/orders/" + tcanon + "?ref=%7B%27%20OR%201%3D1%20--%20-----------------------%7D"),
		"body.product_id": postJSON("/api/v1/cart/items", `{"product_id":"urn:uuid:' OR 1=1 -- -----------------------"}`),
	} {
		d := fw.Inspect(r)
		mustHave(t, d, "AEG-SCHEMA-001", field)
		if d.Action != aegolith.ActionBlock {
			t.Errorf("%s: action %v, want block", field, d.Action)
		}
	}
	for _, body := range []string{
		`{"product_id":"(` + tcanon + `)"}`,
		`{"product_id":"{` + tcanon + `"}`,
		`{"product_id":"` + thex32 + `\u0000"}`,
		`{"product_id":" ` + thex32 + `"}`,
		`{"product_id":4}`,
	} {
		mustHave(t, fw.Inspect(postJSON("/api/v1/cart/items", body)), "AEG-SCHEMA-001", "body.product_id")
	}
}

func TestLoadConfigUUIDLenient(t *testing.T) {
	dir := t.TempDir()
	load := func(name, typ string) (aegolith.Config, error) {
		t.Helper()
		path := filepath.Join(dir, name+".json")
		doc := `{"routes":[{"method":"GET","path":"/api/v1/orders/:id",
			"path_params":{"id":{"type":"` + typ + `"}},
			"query":{"ref":{"type":"` + typ + `"}}},
			{"method":"POST","path":"/api/v1/cart/items","body":{"product_id":{"type":"` + typ + `"}}}]}`
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return aegolith.LoadConfig(path)
	}
	cfg, err := load("lenient", "uuid_lenient")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Routes[0].PathParams["id"].Type != aegolith.TypeUUIDLenient {
		t.Fatalf("loaded %+v", cfg.Routes[0])
	}
	fw := mustNew(t, cfg)
	if d := fw.Inspect(get("/api/v1/orders/" + thex32 + "?ref=urn:uuid:" + tcanon)); len(d.Matches) != 0 {
		t.Fatalf("lenient from config: %v", ruleIDs(d))
	}
	for _, typ := range []string{"uuid-lenient", "UUID_LENIENT", "uuid_loose", "uuid_lenient ", "lenient_uuid", "guid"} {
		cfg, err := load("bad", typ)
		if err != nil {
			t.Fatalf("%q: LoadConfig: %v", typ, err)
		}
		_, err = aegolith.New(cfg)
		if err == nil || !strings.Contains(err.Error(), "unknown type") {
			t.Errorf("%q: New err = %v, want unknown type", typ, err)
		}
	}
}
