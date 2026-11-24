// Package engine runs Aegolith's inspection pipeline (spec §5.2): protocol
// checks, path and user-agent rules, route policy, input inspection, then
// rule-action overrides, exclusions and the mode decide the verdict.
//
// An Engine is immutable after New and safe for concurrent use; all
// per-request state lives in a state value owned by one Inspect call.
package engine

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/ergasterion-dev/aegolith/internal/model"
	"github.com/ergasterion-dev/aegolith/internal/policy"
	"github.com/ergasterion-dev/aegolith/internal/protocol"
)

// Exclusion drops matches whose rule, route key and field all match. Rule
// is a rule ID, an ID prefix ending in "*", or a category name. Route is a
// route key ("METHOD /template" for a matched route, "METHOD /decoded/path"
// otherwise). Field is a match field such as "query.q". Route and Field
// accept a trailing "*" as a prefix wildcard; "" or "*" match anything.
type Exclusion struct {
	Rule, Route, Field string
}

// Options is the fully resolved engine configuration: every limit is
// positive and every action has its default filled in.
type Options struct {
	Mode                model.Mode
	AllowedMethods      []string
	AllowedContentTypes []string
	AllowXML            bool
	Limits              model.Limits
	Routes              []policy.Route
	UnknownRoute        model.Action
	UnknownFields       model.Action
	Exclusions          []Exclusion
	RuleActions         map[string]model.Action
	InspectHeaders      []string
	FailOpen            bool
}

type prefixAction struct {
	prefix string
	action model.Action
}

// Engine is a compiled, immutable pipeline.
type Engine struct {
	mode           model.Mode
	proto          protocol.Config
	lim            model.Limits
	table          *policy.Table // nil when no routes are configured
	unknownRoute   model.Action
	unknownFields  model.Action
	exclusions     []Exclusion
	ruleExact      map[string]model.Action
	rulePrefix     []prefixAction // longest prefix first
	ruleCategory   map[model.Category]model.Action
	inspectHeaders []string // canonical header names
	failOpen       bool

	// testHook, when set, runs at the start of every inspection inside the
	// recover guard. Tests use it to inject panics.
	testHook func(*model.Request)
}

var categories = []model.Category{
	model.CatSQLi, model.CatXSS, model.CatCmdi, model.CatCodei, model.CatLDAP, model.CatSSTI,
	model.CatJNDI, model.CatCRLF, model.CatLFI, model.CatRFI, model.CatSSRF, model.CatXXE,
	model.CatNoSQLi, model.CatProtoPollute, model.CatSession, model.CatScanner,
	model.CatProtocol, model.CatSchema, model.CatRoute,
}

func validAction(a model.Action) bool { return a >= model.ActionAllow && a <= model.ActionMonitor }

// rulePattern normalizes and checks a rule selector: "*", a rule ID or ID
// prefix (AEG-..., upper-cased), or a category name (lower-cased).
func rulePattern(p string) (string, error) {
	p = strings.TrimSpace(p)
	switch {
	case p == "":
		return "", errors.New("empty rule")
	case p == "*":
		return p, nil
	case strings.HasPrefix(strings.ToUpper(p), "AEG-"):
		return strings.ToUpper(p), nil
	case slices.Contains(categories, model.Category(strings.ToLower(p))):
		return strings.ToLower(p), nil
	}
	return "", fmt.Errorf("rule %q is not a rule ID (AEG-...), ID prefix ending in * or category", p)
}

// New validates o and compiles the route table and rule selectors.
func New(o Options) (*Engine, error) {
	if o.Mode != model.ModeEnforce && o.Mode != model.ModeMonitor {
		return nil, fmt.Errorf("invalid mode %d", int(o.Mode))
	}
	if !validAction(o.UnknownRoute) || !validAction(o.UnknownFields) {
		return nil, errors.New("invalid unknown_route or unknown_fields action")
	}
	if o.Limits.MaxBodyBytes <= 0 || o.Limits.MaxDepth <= 0 || o.Limits.MaxFields <= 0 || o.Limits.MaxValueLen <= 0 {
		return nil, fmt.Errorf("limits must be positive: %+v", o.Limits)
	}
	e := &Engine{
		mode:          o.Mode,
		lim:           o.Limits,
		unknownRoute:  o.UnknownRoute,
		unknownFields: o.UnknownFields,
		failOpen:      o.FailOpen,
		proto: protocol.Config{
			AllowedMethods:      slices.Clone(o.AllowedMethods),
			AllowedContentTypes: slices.Clone(o.AllowedContentTypes),
			Limits:              o.Limits,
			AllowXML:            o.AllowXML,
		},
	}
	if len(o.Routes) > 0 {
		t, err := policy.Compile(o.Routes)
		if err != nil {
			return nil, err
		}
		e.table = t
	}
	for i, x := range o.Exclusions {
		r, err := rulePattern(x.Rule)
		if err != nil {
			return nil, fmt.Errorf("exclusion %d: %w", i, err)
		}
		route, err := routePattern(x.Route)
		if err != nil {
			return nil, fmt.Errorf("exclusion %d: %w", i, err)
		}
		field, err := fieldPattern(x.Field)
		if err != nil {
			return nil, fmt.Errorf("exclusion %d: %w", i, err)
		}
		e.exclusions = append(e.exclusions, Exclusion{Rule: r, Route: route, Field: field})
	}
	e.ruleExact = map[string]model.Action{}
	e.ruleCategory = map[model.Category]model.Action{}
	// Sorted keys keep compilation deterministic.
	for _, k := range slices.Sorted(maps.Keys(o.RuleActions)) {
		a := o.RuleActions[k]
		if !validAction(a) {
			return nil, fmt.Errorf("rule_actions[%q]: invalid action %d", k, int(a))
		}
		p, err := rulePattern(k)
		if err != nil {
			return nil, fmt.Errorf("rule_actions: %w", err)
		}
		switch {
		case strings.HasSuffix(p, "*"):
			e.rulePrefix = append(e.rulePrefix, prefixAction{prefix: strings.TrimSuffix(p, "*"), action: a})
		case strings.HasPrefix(p, "AEG-"):
			e.ruleExact[p] = a
		default:
			e.ruleCategory[model.Category(p)] = a
		}
	}
	slices.SortStableFunc(e.rulePrefix, func(a, b prefixAction) int { return len(b.prefix) - len(a.prefix) })
	for _, h := range o.InspectHeaders {
		if strings.TrimSpace(h) == "" {
			return nil, errors.New("inspect_headers: empty header name")
		}
		e.inspectHeaders = append(e.inspectHeaders, http.CanonicalHeaderKey(strings.TrimSpace(h)))
	}
	return e, nil
}

// routePattern checks an exclusion route: "", "*", or "METHOD /path" (the
// method is upper-cased; the path may end in "*").
func routePattern(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "*" {
		return p, nil
	}
	method, path, ok := strings.Cut(p, " ")
	if !ok || method == "" || !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("route %q must be \"METHOD /path\", \"*\" or empty", p)
	}
	return strings.ToUpper(method) + " " + path, nil
}

var fieldLocations = []string{"path", "query", "body", "form", "header", "cookie", "method"}

// fieldPattern checks an exclusion field: "", "*", or a match field such as
// "query.q" (header names are lower-cased, as in matches).
func fieldPattern(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "*" {
		return p, nil
	}
	loc, _, _ := strings.Cut(strings.TrimSuffix(p, "*"), ".")
	if !slices.Contains(fieldLocations, loc) {
		return "", fmt.Errorf("field %q must start with one of %s", p, strings.Join(fieldLocations, ", "))
	}
	if loc == "header" {
		p = strings.ToLower(p)
	}
	return p, nil
}

// matchPattern reports whether v matches pat: "" and "*" match anything, a
// trailing "*" matches by prefix, anything else must be equal.
func matchPattern(pat, v string) bool {
	switch {
	case pat == "" || pat == "*":
		return true
	case strings.HasSuffix(pat, "*"):
		return strings.HasPrefix(v, pat[:len(pat)-1])
	}
	return pat == v
}

// ruleAction returns the configured override for a rule: exact rule ID
// first, then the longest matching ID prefix, then the category.
func (e *Engine) ruleAction(id string, cat model.Category) (model.Action, bool) {
	if a, ok := e.ruleExact[id]; ok {
		return a, true
	}
	for _, p := range e.rulePrefix {
		if strings.HasPrefix(id, p.prefix) {
			return p.action, true
		}
	}
	a, ok := e.ruleCategory[cat]
	return a, ok
}

func (e *Engine) excluded(m model.Match, routeKey string) bool {
	for _, x := range e.exclusions {
		if (matchPattern(x.Rule, m.RuleID) || x.Rule == string(m.Category)) &&
			matchPattern(x.Route, routeKey) && matchPattern(x.Field, m.Field) {
			return true
		}
	}
	return false
}
