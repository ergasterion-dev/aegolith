package aegolith

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ergasterion-dev/aegolith/internal/engine"
	"github.com/ergasterion-dev/aegolith/internal/model"
)

// Exclusion drops matches for one rule selector on one route and field,
// for known false positives. All three parts must match.
type Exclusion struct {
	// Rule is a rule ID ("AEG-SQLI-001"), an ID prefix ending in "*"
	// ("AEG-SQLI-*", or "*" for every rule) or a category name ("sqli").
	Rule string `json:"rule"`
	// Route is a route key: "METHOD /template" as declared in Routes
	// ("POST /api/v1/cart/items"); for a request that matched no route it
	// is the method, a space and the percent-decoded path. A trailing "*"
	// matches by prefix; "*" or "" matches every route.
	Route string `json:"route"`
	// Field is a match field: "path", "path.<param>", "query.<key>",
	// "body.<json path>", "form.<key>", "header.<lowercase name>" or
	// "cookie.<name>". A trailing "*" matches by prefix; "*" or "" matches
	// every field.
	Field string `json:"field"`
}

// Config configures a Firewall. Zero values mean the defaults noted on each
// field, so Config{} is a working generic configuration.
type Config struct {
	// Mode is ModeEnforce (default: block on any blocking match) or
	// ModeMonitor (never block; report matches with Monitored set).
	Mode Mode `json:"mode"`
	// AllowedMethods defaults to GET HEAD POST PUT PATCH DELETE OPTIONS.
	AllowedMethods []string `json:"allowed_methods,omitempty"`
	// AllowedContentTypes (media types, for requests with a body) defaults
	// to application/json, application/x-www-form-urlencoded and
	// multipart/form-data.
	AllowedContentTypes []string `json:"allowed_content_types,omitempty"`
	// AllowXML also allows application/xml and text/xml bodies and runs
	// the XXE rule on them.
	AllowXML bool `json:"allow_xml,omitempty"`
	// Limits bound the work per request; each zero field takes its default
	// (see DefaultLimits). Negative values are rejected. MaxValueLen is
	// rounded down to an even number, minimum 2.
	Limits Limits `json:"limits"`
	// Routes declare the API surface. With no routes every input is
	// untyped and gets every detector.
	Routes []Route `json:"routes,omitempty"`
	// CaseInsensitiveRoutes matches the literal segments of route templates
	// regardless of ASCII case ("/API/v1/cart" matches "/api/v1/cart");
	// parameter values keep their case. Set it when the server routes
	// case-insensitively, otherwise a case variant of a path reaches the
	// handler but is treated as an unknown route and escapes the route's
	// typed fields and unknown-field action. Default false (net/http, chi
	// and gorilla are case-sensitive). The Fiber adapter turns it on per
	// request unless fiber.Config.CaseSensitive is set. Two templates that
	// differ only in letter case are then duplicates and rejected by New.
	CaseInsensitiveRoutes bool `json:"case_insensitive_routes,omitempty"`
	// UnknownRoute is the action for a request matching no route when
	// Routes is set. Default (and the zero value, ActionAllow): monitor, so
	// it cannot be set to allow here; LoadConfig rejects an explicit
	// "allow". Use RuleActions{"AEG-ROUTE-001": allow} to silence it.
	UnknownRoute Action `json:"unknown_route"`
	// UnknownFields is the action for a query, form or JSON field a matched
	// route does not declare, unless the route sets its own. Default (and
	// the zero value, ActionAllow): monitor; LoadConfig rejects an explicit
	// "allow" (use RuleActions{"AEG-SCHEMA-002": allow}). Undeclared values
	// are still scanned.
	UnknownFields Action `json:"unknown_fields"`
	// Exclusions drop matches for known false positives.
	Exclusions []Exclusion `json:"exclusions,omitempty"`
	// RuleActions override the action of matches by rule ID, ID prefix
	// ending in "*" or category name (exact ID beats the longest prefix,
	// which beats the category). Allow drops the match.
	RuleActions map[string]Action `json:"rule_actions,omitempty"`
	// InspectHeaders lists extra request headers whose values are scanned
	// (User-Agent and Referer always are).
	InspectHeaders []string `json:"inspect_headers,omitempty"`
	// FailOpen decides an internal error: allow the request (nil or true,
	// the default) or block it (false). Decision.Err is set either way.
	FailOpen *bool `json:"fail_open,omitempty"`
}

// LoadConfig reads a JSON configuration file. Unknown keys, unknown enum
// values and trailing data are errors. The result still goes through New's
// validation.
func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("aegolith: load config: %w", err)
	}
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("aegolith: config %s: %w", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("aegolith: config %s: trailing data after the JSON object", path)
	}
	// "allow" is the zero Action, which these two fields read as their
	// monitor default, so an explicit "allow" would silently mean monitor.
	var explicit struct {
		UnknownRoute  *Action `json:"unknown_route"`
		UnknownFields *Action `json:"unknown_fields"`
	}
	if err := json.Unmarshal(b, &explicit); err != nil {
		return Config{}, fmt.Errorf("aegolith: config %s: %w", path, err)
	}
	if explicit.UnknownRoute != nil && *explicit.UnknownRoute == ActionAllow {
		return Config{}, fmt.Errorf(`aegolith: config %s: "unknown_route": "allow" is not supported (it would mean monitor); use "rule_actions": {"AEG-ROUTE-001": "allow"} to silence unknown routes`, path)
	}
	if explicit.UnknownFields != nil && *explicit.UnknownFields == ActionAllow {
		return Config{}, fmt.Errorf(`aegolith: config %s: "unknown_fields": "allow" is not supported (it would mean monitor); use "rule_actions": {"AEG-SCHEMA-002": "allow"} to silence undeclared fields`, path)
	}
	return cfg, nil
}

// options resolves defaults and returns the engine configuration.
func (c Config) options() (engine.Options, error) {
	lim, err := resolveLimits(c.Limits)
	if err != nil {
		return engine.Options{}, err
	}
	methods := make([]string, 0, len(c.AllowedMethods))
	for _, m := range c.AllowedMethods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" {
			return engine.Options{}, errors.New("allowed_methods: empty method")
		}
		methods = append(methods, m)
	}
	for _, ct := range c.AllowedContentTypes {
		if strings.TrimSpace(ct) == "" {
			return engine.Options{}, errors.New("allowed_content_types: empty media type")
		}
	}
	o := engine.Options{
		Mode:                  c.Mode,
		AllowedMethods:        methods,
		AllowedContentTypes:   c.AllowedContentTypes,
		AllowXML:              c.AllowXML,
		Limits:                lim,
		Routes:                c.Routes,
		CaseInsensitiveRoutes: c.CaseInsensitiveRoutes,
		UnknownRoute:          orMonitor(c.UnknownRoute),
		UnknownFields:         orMonitor(c.UnknownFields),
		RuleActions:           c.RuleActions,
		InspectHeaders:        c.InspectHeaders,
		FailOpen:              c.FailOpen == nil || *c.FailOpen,
	}
	for _, x := range c.Exclusions {
		o.Exclusions = append(o.Exclusions, engine.Exclusion{Rule: x.Rule, Route: x.Route, Field: x.Field})
	}
	return o, nil
}

// orMonitor maps the zero value (allow) to the monitor default.
func orMonitor(a Action) Action {
	if a == model.ActionAllow {
		return model.ActionMonitor
	}
	return a
}

func resolveLimits(l Limits) (Limits, error) {
	if l.MaxBodyBytes < 0 || l.MaxDepth < 0 || l.MaxFields < 0 || l.MaxValueLen < 0 {
		return Limits{}, fmt.Errorf("limits must not be negative: %+v", l)
	}
	d := model.DefaultLimits()
	if l.MaxBodyBytes == 0 {
		l.MaxBodyBytes = d.MaxBodyBytes
	}
	if l.MaxDepth == 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxFields == 0 {
		l.MaxFields = d.MaxFields
	}
	if l.MaxValueLen == 0 {
		l.MaxValueLen = d.MaxValueLen
	}
	// A long value is scanned in windows of MaxValueLen bytes that start
	// every MaxValueLen/2 bytes. Rounding down to an even number (minimum 2)
	// keeps the step exactly half a window, so every byte is scanned at most
	// twice, which the per-request scan budget relies on.
	l.MaxValueLen = max(l.MaxValueLen&^1, 2)
	return l, nil
}
