// Package policy holds the declared API surface: a route table matched by
// method and path template, and the typed field specs used to validate
// path parameters, query values and JSON body values.
package policy

import (
	"fmt"
	"strings"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

// Route declares one endpoint. Path is a template of literal segments,
// ":name" parameters and an optional trailing "*" that matches the rest of
// the path (zero or more segments). Body keys are normalize.WalkJSON paths
// such as "address.line1" or "items[].sku". UnknownFields is the action for
// inputs the route does not declare; nil leaves it to the engine default.
type Route struct {
	Method        string               `json:"method"`
	Path          string               `json:"path"`
	PathParams    map[string]FieldSpec `json:"path_params,omitempty"`
	Query         map[string]FieldSpec `json:"query,omitempty"`
	Body          map[string]FieldSpec `json:"body,omitempty"`
	UnknownFields *model.Action        `json:"unknown_fields,omitempty"`
}

// Table is a compiled, immutable route table, safe for concurrent use.
//
// It holds two tries per method: byMethod, the table as compiled (literal
// segments case-sensitive, or folded for CompileFold), and foldByMethod,
// the same routes with literal segments folded to ASCII lower case, used
// when a caller asks MatchFold to fold on a case-sensitive table. For a
// CompileFold table both are the same trie.
type Table struct {
	byMethod     map[string]*node
	foldByMethod map[string]*node
	fold         bool // literal segments match regardless of ASCII case
}

// node is one segment position in a method's route trie.
type node struct {
	literal  map[string]*node // lower-cased in a folded trie
	param    *node            // any non-empty segment
	wildcard *entry           // route whose template ends in "*" at this position
	end      *entry           // route whose template ends exactly here
}

type entry struct {
	route  *Route
	key    string
	params []string // param names in template order
}

// Matched is the result of a successful Table.Match.
type Matched struct {
	Route  *Route
	Key    string            // "METHOD /template", e.g. "POST /api/v1/cart/items"
	Params map[string]string // path parameter values; "*" holds the wildcard rest
}

// Compile validates routes and builds a case-sensitive table. The table
// keeps its own copy of every route, so later changes to routes do not
// affect it.
func Compile(routes []Route) (*Table, error) {
	return compile(routes, false)
}

// CompileFold is Compile for a server that routes case-insensitively:
// literal segments are folded to ASCII lower case, so "/API/v1" matches the
// template "/api/v1". Parameter values keep their case. Two templates that
// differ only in the case of their literal segments are duplicates.
func CompileFold(routes []Route) (*Table, error) {
	return compile(routes, true)
}

func compile(routes []Route, fold bool) (*Table, error) {
	t := &Table{byMethod: map[string]*node{}, fold: fold}
	if fold {
		t.foldByMethod = t.byMethod
	} else {
		t.foldByMethod = map[string]*node{}
	}
	for i := range routes {
		r, err := compileRoute(routes[i])
		if err != nil {
			return nil, fmt.Errorf("policy: route %d (%s %s): %w", i, routes[i].Method, routes[i].Path, err)
		}
		if err := insert(t.byMethod, r, fold); err != nil {
			return nil, fmt.Errorf("policy: route %d (%s %s): %w", i, routes[i].Method, routes[i].Path, err)
		}
		if !fold {
			// Templates that differ only in letter case are distinct
			// here but collide in the folded view: the first declared
			// keeps the slot, deterministically.
			_ = insert(t.foldByMethod, r, true)
		}
	}
	return t, nil
}

func compileRoute(in Route) (*Route, error) {
	r := in
	r.Method = strings.ToUpper(strings.TrimSpace(in.Method))
	if r.Method == "" {
		return nil, fmt.Errorf("missing method")
	}
	segs, err := templateSegments(in.Path)
	if err != nil {
		return nil, err
	}
	params := map[string]bool{}
	for _, s := range segs {
		if strings.HasPrefix(s, ":") {
			if params[s[1:]] {
				return nil, fmt.Errorf("path: duplicate param %q", s[1:])
			}
			params[s[1:]] = true
		}
	}
	for name := range in.PathParams {
		if !params[name] {
			return nil, fmt.Errorf("path param %q is not in the path", name)
		}
	}
	if in.UnknownFields != nil {
		a := *in.UnknownFields
		r.UnknownFields = &a
	}
	for _, f := range []struct {
		loc string
		in  map[string]FieldSpec
		out *map[string]FieldSpec
	}{
		{"path", in.PathParams, &r.PathParams},
		{"query", in.Query, &r.Query},
		{"body", in.Body, &r.Body},
	} {
		if f.in == nil {
			continue
		}
		m := make(map[string]FieldSpec, len(f.in))
		for name, spec := range f.in {
			c, err := spec.compile()
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", f.loc, name, err)
			}
			m[name] = c
		}
		*f.out = m
	}
	return &r, nil
}

// templateSegments splits and checks a route template.
func templateSegments(p string) ([]string, error) {
	if !strings.HasPrefix(p, "/") {
		return nil, fmt.Errorf("path %q must start with /", p)
	}
	segs := splitPath(p)
	for i, s := range segs {
		switch {
		case s == "*":
			if i != len(segs)-1 {
				return nil, fmt.Errorf("path %q: * must be the last segment", p)
			}
		case strings.Contains(s, "*"):
			return nil, fmt.Errorf("path %q: * must be a whole segment", p)
		case s == ":":
			return nil, fmt.Errorf("path %q: empty param name", p)
		case s == "" && len(segs) > 0:
			return nil, fmt.Errorf("path %q: empty segment", p)
		}
	}
	return segs, nil
}

// splitPath turns "/a/b/" into ["a","b"] and "/" into []. One trailing
// slash is ignored so "/x/" matches "/x"; inner empty segments are kept.
func splitPath(p string) []string {
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// insert adds r to the trie of its method in byMethod, folding literal
// segments to ASCII lower case when fold is set. A route that ends where
// another already ends is a duplicate; the trie is then left unchanged
// apart from empty interior nodes.
func insert(byMethod map[string]*node, r *Route, fold bool) error {
	root := byMethod[r.Method]
	if root == nil {
		root = &node{}
		byMethod[r.Method] = root
	}
	e := &entry{route: r, key: r.Method + " " + r.Path}
	n := root
	for _, s := range splitPath(r.Path) {
		if s[0] == ':' {
			e.params = append(e.params, s[1:])
		}
		switch {
		case s == "*":
			if n.wildcard != nil {
				return fmt.Errorf("duplicate route (same as %s)", n.wildcard.key)
			}
			n.wildcard = e
			return nil
		case s[0] == ':':
			if n.param == nil {
				n.param = &node{}
			}
			n = n.param
		default:
			if fold {
				s = asciiLower(s)
			}
			if n.literal == nil {
				n.literal = map[string]*node{}
			}
			c := n.literal[s]
			if c == nil {
				c = &node{}
				n.literal[s] = c
			}
			n = c
		}
	}
	if n.end != nil {
		return fmt.Errorf("duplicate route (same as %s)", n.end.key)
	}
	n.end = e
	return nil
}

// Match finds the route for method and path. The engine passes the raw
// (still percent-escaped) path and decodes parameter values afterwards, so
// an encoded "/" (%2F) can neither split a segment nor forge one.
// At each segment a literal beats a parameter, which beats a trailing "*";
// a branch that dead-ends falls back to the next option. HEAD requests
// match GET routes when no HEAD route matches. Literal segments match
// case-insensitively when the table was built with CompileFold.
func (t *Table) Match(method, path string) (Matched, bool) {
	if t == nil {
		return Matched{}, false
	}
	return t.MatchFold(method, path, t.fold)
}

// MatchFold is Match with literal-segment case folding chosen per call; a
// table built with CompileFold always folds. When folding, matching is
// exactly as on a CompileFold table: literal segments compare after ASCII
// lower-casing, the most specific template wins (literal, then param, then
// wildcard, segment by segment), and of templates that differ only in
// letter case the first declared wins. Parameter values and the wildcard
// rest keep their case.
func (t *Table) MatchFold(method, path string, fold bool) (Matched, bool) {
	if t == nil {
		return Matched{}, false
	}
	fold = fold || t.fold
	method = strings.ToUpper(method)
	segs := splitPath(path)
	if m, ok := t.matchMethod(method, segs, fold); ok {
		return m, true
	}
	if method == "HEAD" {
		return t.matchMethod("GET", segs, fold)
	}
	return Matched{}, false
}

func (t *Table) matchMethod(method string, segs []string, fold bool) (Matched, bool) {
	tries := t.byMethod
	if fold {
		tries = t.foldByMethod
	}
	root := tries[method]
	if root == nil {
		return Matched{}, false
	}
	var bound []string // param values in template order
	e, rest := root.find(segs, 0, fold, &bound)
	if e == nil {
		return Matched{}, false
	}
	m := Matched{Route: e.route, Key: e.key}
	if len(e.params) > 0 || rest >= 0 {
		m.Params = make(map[string]string, len(e.params)+1)
		for i, n := range e.params {
			m.Params[n] = bound[i]
		}
		if rest >= 0 {
			m.Params["*"] = strings.Join(segs[rest:], "/")
		}
	}
	return m, true
}

// find walks the trie depth-first, preferring literal, then param, then
// wildcard. Each trie node is visited at most once (every node has one
// parent and is entered only from it), so the cost is bounded by the table
// size, not exponential in the path. It returns the entry and the index of
// the first segment the wildcard consumed (-1 if none).
func (n *node) find(segs []string, i int, fold bool, bound *[]string) (*entry, int) {
	if i == len(segs) {
		if n.end != nil {
			return n.end, -1
		}
		if n.wildcard != nil {
			return n.wildcard, i
		}
		return nil, -1
	}
	s := segs[i]
	lit := s
	if fold {
		lit = asciiLower(s)
	}
	if c := n.literal[lit]; c != nil {
		if e, r := c.find(segs, i+1, fold, bound); e != nil {
			return e, r
		}
	}
	if n.param != nil && s != "" {
		*bound = append(*bound, s)
		if e, r := n.param.find(segs, i+1, fold, bound); e != nil {
			return e, r
		}
		*bound = (*bound)[:len(*bound)-1]
	}
	if n.wildcard != nil {
		return n.wildcard, i
	}
	return nil, -1
}

// Segments splits a request path into segments exactly as Match does: one
// leading and one trailing '/' are dropped, inner empty segments are kept,
// and percent escapes are left as they are. Segment i of the result is the
// one that Matched.Literal(i) describes.
func Segments(path string) []string { return splitPath(path) }

// Literal reports whether segment i of the matched path (as Segments splits
// it) was matched by a literal segment of the route template, rather than
// by a ":name" parameter or the trailing "*". A literal segment equals the
// template's text (up to ASCII case when folding), so the route's author
// wrote it.
func (m Matched) Literal(i int) bool {
	if m.Route == nil || i < 0 {
		return false
	}
	segs := splitPath(m.Route.Path)
	if i >= len(segs) {
		return false
	}
	s := segs[i]
	return s != "*" && s[0] != ':'
}

// asciiLower lower-cases ASCII letters only, as Fiber's router does; other
// bytes (UTF-8, percent escapes) are left alone.
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// Field returns the spec declared for a path param, query value or body
// value of the matched route.
func (m Matched) Field(loc model.Location, name string) (FieldSpec, bool) {
	if m.Route == nil {
		return FieldSpec{}, false
	}
	var specs map[string]FieldSpec
	switch loc {
	case model.LocPath:
		specs = m.Route.PathParams
	case model.LocQuery:
		specs = m.Route.Query
	case model.LocBody:
		specs = m.Route.Body
	default:
		return FieldSpec{}, false
	}
	s, ok := specs[name]
	return s, ok
}
