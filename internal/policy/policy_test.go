package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

func f64(v float64) *float64 { return &v }

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name   string
		routes []Route
		want   string // substring of the error; "" means no error
	}{
		{"ok", []Route{{Method: "GET", Path: "/a/:id", PathParams: map[string]FieldSpec{"id": {Type: "uuid"}}}}, ""},
		{"empty table", nil, ""},
		{"duplicate", []Route{{Method: "GET", Path: "/a"}, {Method: "get", Path: "/a"}}, "duplicate"},
		{"same path other method", []Route{{Method: "GET", Path: "/a"}, {Method: "POST", Path: "/a"}}, ""},
		{"unknown type", []Route{{Method: "POST", Path: "/a", Body: map[string]FieldSpec{"x": {Type: "integer"}}}}, "unknown type"},
		{"empty type", []Route{{Method: "GET", Path: "/a", Query: map[string]FieldSpec{"x": {}}}}, "unknown type"},
		{"bad pattern", []Route{{Method: "GET", Path: "/a", Query: map[string]FieldSpec{"x": {Type: "string", Pattern: "a("}}}}, "pattern"},
		{"min > max", []Route{{Method: "GET", Path: "/a", Query: map[string]FieldSpec{"x": {Type: "int", Min: f64(10), Max: f64(1)}}}}, "min"},
		{"min == max ok", []Route{{Method: "GET", Path: "/a", Query: map[string]FieldSpec{"x": {Type: "int", Min: f64(3), Max: f64(3)}}}}, ""},
		{"negative max_len", []Route{{Method: "GET", Path: "/a", Query: map[string]FieldSpec{"x": {Type: "text", MaxLen: -1}}}}, "max_len"},
		{"enum without values", []Route{{Method: "GET", Path: "/a", Query: map[string]FieldSpec{"x": {Type: "enum"}}}}, "enum"},
		{"missing method", []Route{{Path: "/a"}}, "method"},
		{"relative path", []Route{{Method: "GET", Path: "a/b"}}, "path"},
		{"star not last", []Route{{Method: "GET", Path: "/a/*/b"}}, "path"},
		{"empty param name", []Route{{Method: "GET", Path: "/a/:"}}, "path"},
		{"duplicate differing only in param name", []Route{{Method: "GET", Path: "/a/:id"}, {Method: "GET", Path: "/a/:x"}}, "duplicate"},
		{"duplicate wildcard", []Route{{Method: "GET", Path: "/s/*"}, {Method: "GET", Path: "/s/*"}}, "duplicate"},
		{"duplicate param name in one path", []Route{{Method: "GET", Path: "/a/:id/b/:id"}}, "duplicate param"},
		{"path param not in path", []Route{{Method: "GET", Path: "/a", PathParams: map[string]FieldSpec{"id": {Type: "int"}}}}, "path param"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Compile(tt.routes)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestMatchPrecedence(t *testing.T) {
	tbl, err := Compile([]Route{
		{Method: "GET", Path: "/api/v1/products/:id"},
		{Method: "GET", Path: "/api/v1/products/search"},
		{Method: "GET", Path: "/x"},
		{Method: "GET", Path: "/static/*"},
		{Method: "POST", Path: "/api/v1/cart/items"},
		{Method: "GET", Path: "/api/v1/orders/:id/items/:item"},
		{Method: "GET", Path: "/api/v1/orders/latest/items/summary"},
		{Method: "GET", Path: "/"},
		{Method: "GET", Path: "/u/:user"},
		{Method: "GET", Path: "/u/:uid/posts/:post"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		method, path string
		wantOK       bool
		wantKey      string
		wantParams   map[string]string
	}{
		{"GET", "/api/v1/products/search", true, "GET /api/v1/products/search", nil},
		{"GET", "/api/v1/products/4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b", true, "GET /api/v1/products/:id", map[string]string{"id": "4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b"}},
		{"HEAD", "/x", true, "GET /x", nil},
		{"head", "/x", true, "GET /x", nil},
		{"GET", "/static/a/b", true, "GET /static/*", map[string]string{"*": "a/b"}},
		{"GET", "/static/", true, "GET /static/*", map[string]string{"*": ""}},
		{"POST", "/api/v1/cart/items", true, "POST /api/v1/cart/items", nil},
		{"POST", "/api/v1/cart/items/", true, "POST /api/v1/cart/items", nil},
		// a literal that dead-ends must fall back to the param branch
		{"GET", "/api/v1/orders/latest/items/7", true, "GET /api/v1/orders/:id/items/:item", map[string]string{"id": "latest", "item": "7"}},
		{"GET", "/api/v1/orders/latest/items/summary", true, "GET /api/v1/orders/latest/items/summary", nil},
		{"GET", "/", true, "GET /", nil},
		{"GET", "/u/ali", true, "GET /u/:user", map[string]string{"user": "ali"}},
		{"GET", "/u/7/posts/9", true, "GET /u/:uid/posts/:post", map[string]string{"uid": "7", "post": "9"}},
		{"GET", "/nope", false, "", nil},
		{"POST", "/x", false, "", nil},
		{"DELETE", "/api/v1/products/1", false, "", nil},
		{"GET", "/api/v1/products", false, "", nil},
		{"GET", "/api/v1/products//", false, "", nil},
		{"GET", "/api/v1/products/1/extra", false, "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			m, ok := tbl.Match(tt.method, tt.path)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (key %q)", ok, tt.wantOK, m.Key)
			}
			if !ok {
				if m.Route != nil {
					t.Fatalf("no match but Route set")
				}
				return
			}
			if m.Key != tt.wantKey {
				t.Fatalf("key = %q, want %q", m.Key, tt.wantKey)
			}
			if len(m.Params) != len(tt.wantParams) {
				t.Fatalf("params = %v, want %v", m.Params, tt.wantParams)
			}
			for k, v := range tt.wantParams {
				if m.Params[k] != v {
					t.Fatalf("param %q = %q, want %q", k, m.Params[k], v)
				}
			}
		})
	}
}

func TestMatchNilTable(t *testing.T) {
	var tbl *Table
	if _, ok := tbl.Match("GET", "/"); ok {
		t.Fatal("nil table matched")
	}
}

func TestCompileCopiesRoutes(t *testing.T) {
	routes := []Route{{Method: "POST", Path: "/a", Body: map[string]FieldSpec{"qty": {Type: "int"}}}}
	tbl, err := Compile(routes)
	if err != nil {
		t.Fatal(err)
	}
	routes[0].Body["qty"] = FieldSpec{Type: "text"}
	routes[0].Path = "/b"
	m, ok := tbl.Match("POST", "/a")
	if !ok {
		t.Fatal("no match")
	}
	if s, _ := m.Field(model.LocBody, "qty"); s.Type != "int" {
		t.Fatalf("table aliased caller's map: type %q", s.Type)
	}
}

func TestMatchedField(t *testing.T) {
	tbl, err := Compile([]Route{{
		Method:     "POST",
		Path:       "/api/v1/cart/:cart/items",
		PathParams: map[string]FieldSpec{"cart": {Type: "uuid"}},
		Query:      map[string]FieldSpec{"dry": {Type: "bool"}},
		Body:       map[string]FieldSpec{"items[].sku": {Type: "string", Pattern: "[A-Z0-9-]{3,20}"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := tbl.Match("POST", "/api/v1/cart/abc/items")
	if !ok {
		t.Fatal("no match")
	}
	for _, c := range []struct {
		loc  model.Location
		name string
		want string
	}{
		{model.LocPath, "cart", "uuid"},
		{model.LocQuery, "dry", "bool"},
		{model.LocBody, "items[].sku", "string"},
		{model.LocBody, "cart", ""},
		{model.LocHeader, "dry", ""},
		{model.LocCookie, "cart", ""},
	} {
		s, ok := m.Field(c.loc, c.name)
		if ok != (c.want != "") || s.Type != c.want {
			t.Errorf("Field(%s,%s) = %q,%v; want %q", c.loc, c.name, s.Type, ok, c.want)
		}
	}
	// The compiled pattern is used through Field.
	s, _ := m.Field(model.LocBody, "items[].sku")
	if !Validate(s, "AB-12", true) || Validate(s, "ab-12", true) {
		t.Fatal("compiled pattern not applied")
	}
	if _, ok := (Matched{}).Field(model.LocBody, "x"); ok {
		t.Fatal("zero Matched returned a field")
	}
}

func TestRouteJSON(t *testing.T) {
	const doc = `{"method":"POST","path":"/api/v1/cart/items",
	  "body":{"product_id":{"type":"uuid"},"qty":{"type":"int","min":1,"max":99},"note":{"type":"text","max_len":500}},
	  "unknown_fields":"block"}`
	var r Route
	if err := json.Unmarshal([]byte(doc), &r); err != nil {
		t.Fatal(err)
	}
	if r.UnknownFields == nil || *r.UnknownFields != model.ActionBlock {
		t.Fatalf("unknown_fields = %v", r.UnknownFields)
	}
	if q := r.Body["qty"]; q.Type != "int" || *q.Min != 1 || *q.Max != 99 {
		t.Fatalf("qty = %+v", q)
	}
	if r.Body["note"].MaxLen != 500 {
		t.Fatalf("note = %+v", r.Body["note"])
	}
	if _, err := Compile([]Route{r}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateTypes(t *testing.T) {
	type c struct {
		value    string
		isString bool
		want     bool
	}
	qty := FieldSpec{Type: "int", Min: f64(1), Max: f64(99)}
	price := FieldSpec{Type: "number", Min: f64(0), Max: f64(1000)}
	tests := []struct {
		name  string
		spec  FieldSpec
		cases []c
	}{
		{"uuid", FieldSpec{Type: "uuid"}, []c{
			{"4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b", true, true},
			{"4B8E2F1A-9C3D-4E5F-8A7B-1C2D3E4F5A6B", true, true},
			{"1' OR '1'='1", true, false},
			{"4b8e2f1a9c3d4e5f8a7b1c2d3e4f5a6b", true, false},
			{"4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6g", true, false},
			{"{4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b}", true, false},
			{"4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b ", true, false},
			{"", true, false},
		}},
		{"int", qty, []c{
			{"2", false, true},
			{"2", true, true},
			{"1", false, true},
			{"99", true, true},
			{"0", false, false},
			{"100", false, false},
			{"2.5", false, false},
			{"2.5", true, false},
			{"-1", false, false},
			{"1e1", false, false},
			{"two", true, false},
			{" 2", true, false},
			{"+2", true, false},
			{"0x2", true, false},
			{"2; DROP TABLE x", true, false},
			{"99999999999999999999999", true, false},
			{"", true, false},
		}},
		{"int unbounded", FieldSpec{Type: "int"}, []c{
			{"-42", false, true},
			{"9223372036854775807", true, true},
			{"-", true, false},
		}},
		{"number", price, []c{
			{"12.99", false, true},
			{"12.99", true, true},
			{"0", false, true},
			{"1e2", false, true},
			{"-0.01", false, false},
			{"1000.01", false, false},
			{"NaN", true, false},
			{"Inf", true, false},
			{"0x1p-2", true, false},
			{"1_0", true, false},
			{"12.", true, false},
			{".5", true, false},
			{"1e", true, false},
			{"", true, false},
		}},
		{"bool", FieldSpec{Type: "bool"}, []c{
			{"true", false, true},
			{"false", false, true},
			{"true", true, true},
			{"1", true, true},
			{"0", true, true},
			{"FALSE", true, true},
			{"1", false, false},
			{"yes", true, false},
			{"true'--", true, false},
		}},
		{"enum", FieldSpec{Type: "enum", Enum: []string{"asc", "desc"}}, []c{
			{"asc", true, true},
			{"desc", true, true},
			{"ASC", true, false},
			{"asc;", true, false},
			{"", true, false},
		}},
		{"string", FieldSpec{Type: "string", MaxLen: 5, Pattern: "[a-z]+"}, []c{
			{"abc", true, true},
			{"abcde", true, true},
			{"abcdef", true, false},
			{"ab1", true, false},
			{"xabc1", true, false},
			{"", true, false},
		}},
		{"string runes", FieldSpec{Type: "string", MaxLen: 3}, []c{
			{"اردو", true, false},
			{"हिं", true, true},
			{"", true, true},
		}},
		{"text", FieldSpec{Type: "text", MaxLen: 10}, []c{
			{"milk & bread", true, false},
			{"milk&bread", true, true},
			{"' OR 1=1--", true, true},
		}},
		{"text unlimited", FieldSpec{Type: "text"}, []c{
			{strings.Repeat("a", 100000), true, true},
		}},
		{"email", FieldSpec{Type: "email"}, []c{
			{"a.b+tag@example.com", true, true},
			{"user@localhost", true, true},
			{"no-at.example.com", true, false},
			{"a@b@example.com", true, false},
			{"a b@example.com", true, false},
			{"a@example.com\r\nBcc: x@y.z", true, false},
			{"@example.com", true, false},
			{"a@", true, false},
			{strings.Repeat("a", 250) + "@b.co", true, false},
			{"", true, false},
		}},
		{"phone", FieldSpec{Type: "phone"}, []c{
			{"+91 9000000000", true, true},
			{"+1-555-123-4567", true, true},
			{"5551234", true, true},
			{"9000000000", false, true},
			{"9999999999; cat /etc/passwd", true, false},
			{"123456", true, false},
			{"1234567890123456", true, false},
			{"++911234567", true, false},
			{"91+1234567", true, false},
			{"(555) 123-4567", true, false},
			{"+", true, false},
			{"", true, false},
		}},
		{"url", FieldSpec{Type: "url"}, []c{
			{"https://cdn.example.com/img/a.png", true, true},
			{"http://169.254.169.254/", true, true},
			{"HTTPS://example.com", true, true},
			{"file:///etc/passwd", true, false},
			{"gopher://x/", true, false},
			{"javascript:alert(1)", true, false},
			{"/relative/path", true, false},
			{"//example.com/x", true, false},
			{"http://", true, false},
			{"http:///x", true, false},
			{"http://exa mple.com/", true, false},
			{"https://example.com/\r\nX: y", true, false},
			{"https://example.com/" + strings.Repeat("a", 3000), true, false},
			{"", true, false},
		}},
		{"unknown type", FieldSpec{Type: "integer"}, []c{
			{"1", false, false},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, cs := range tt.cases {
				if got := Validate(tt.spec, cs.value, cs.isString); got != cs.want {
					v := cs.value
					if len(v) > 40 {
						v = v[:40] + "..."
					}
					t.Errorf("Validate(%q, isString=%v) = %v, want %v", v, cs.isString, got, cs.want)
				}
			}
		})
	}
}

func TestValidateLinearTime(t *testing.T) {
	// Every validator must stay fast on large adversarial input.
	big := strings.Repeat("1", 1<<20)
	for _, typ := range []string{"uuid", "int", "number", "bool", "email", "phone", "url"} {
		if Validate(FieldSpec{Type: typ}, big, true) {
			t.Errorf("%s accepted a 1 MiB value", typ)
		}
	}
	s := FieldSpec{Type: "string", Pattern: "(a+)+b"}
	if Validate(s, strings.Repeat("a", 1<<16), true) {
		t.Error("pattern should not match")
	}
}
