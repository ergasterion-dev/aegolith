// Package protocol implements the HTTP-level checks that run before any
// content inspection: method, content type, body size, control characters,
// path traversal, request smuggling and double encoding.
package protocol

import (
	"maps"
	"mime"
	"slices"
	"strings"

	"github.com/ergasterion-dev/aegolith/internal/model"
	"github.com/ergasterion-dev/aegolith/internal/normalize"
)

// DefaultMethods are used when Config.AllowedMethods is empty.
var DefaultMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

// DefaultContentTypes are used when Config.AllowedContentTypes is empty.
var DefaultContentTypes = []string{"application/json", "application/x-www-form-urlencoded", "multipart/form-data"}

// Config tunes the protocol checks. Empty allow-lists mean the defaults; a
// non-positive Limits.MaxBodyBytes means the default body limit.
type Config struct {
	AllowedMethods      []string
	AllowedContentTypes []string
	Limits              model.Limits
	AllowXML            bool
}

// Check runs every protocol rule against r and returns at most one match
// per rule.
func Check(r *model.Request, cfg Config) []model.Match {
	var out []model.Match
	add := func(id string, sev model.Severity, act model.Action, loc model.Location, field, val string) {
		out = append(out, model.Match{
			RuleID: id, Category: model.CatProtocol, Severity: sev,
			Location: loc, Field: field, Snippet: model.Redact(val), Action: act,
		})
	}

	methods := cfg.AllowedMethods
	if len(methods) == 0 {
		methods = DefaultMethods
	}
	if !slices.Contains(methods, r.Method) {
		add("AEG-PROTO-001", model.SeverityMedium, model.ActionBlock, model.LocMethod, "method", r.Method)
	}

	if len(r.Body) > 0 {
		ct := r.Header.Get("Content-Type")
		if !contentTypeAllowed(ct, cfg) {
			add("AEG-PROTO-002", model.SeverityMedium, model.ActionBlock, model.LocHeader, "header.content-type", ct)
		}
	}

	maxBody := cfg.Limits.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = model.DefaultLimits().MaxBodyBytes
	}
	if int64(len(r.Body)) > maxBody {
		add("AEG-PROTO-003", model.SeverityLow, model.ActionMonitor, model.LocBody, "body", "")
	}

	decoded, double := normalize.DecodeValue(r.RawPath)
	if hasCtl(r.RawPath) || hasCtl(decoded) {
		add("AEG-PROTO-004", model.SeverityHigh, model.ActionBlock, model.LocPath, "path", r.RawPath)
	} else {
		// Sorted keys: with control characters in several headers, the
		// reported one must not depend on map iteration order.
		for _, name := range slices.Sorted(maps.Keys(r.Header)) {
			if vals := r.Header[name]; anyCtl(vals) {
				add("AEG-PROTO-004", model.SeverityHigh, model.ActionBlock, model.LocHeader, "header."+strings.ToLower(name), strings.Join(vals, ","))
				break
			}
		}
	}

	if hasTraversal(r.RawPath) {
		add("AEG-PROTO-005", model.SeverityHigh, model.ActionBlock, model.LocPath, "path", r.RawPath)
	}

	if te := r.Header.Values("Transfer-Encoding"); len(te) > 0 {
		bad := len(r.Header.Values("Content-Length")) > 0
		for _, v := range te {
			if v != "chunked" {
				bad = true
			}
		}
		if bad {
			add("AEG-PROTO-006", model.SeverityHigh, model.ActionBlock, model.LocHeader, "header.transfer-encoding", strings.Join(te, ","))
		}
	}

	if double {
		add("AEG-PROTO-007", model.SeverityHigh, model.ActionBlock, model.LocPath, "path", r.RawPath)
	}
	return out
}

func contentTypeAllowed(ct string, cfg Config) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		// Tolerate unparsable parameters but still require a media type.
		mt = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	}
	if mt == "" {
		return false
	}
	if cfg.AllowXML && (mt == "application/xml" || mt == "text/xml") {
		return true
	}
	allowed := cfg.AllowedContentTypes
	if len(allowed) == 0 {
		allowed = DefaultContentTypes
	}
	for _, a := range allowed {
		if strings.EqualFold(a, mt) {
			return true
		}
	}
	return false
}

func hasCtl(s string) bool { return strings.ContainsAny(s, "\r\n\x00") }

func anyCtl(vals []string) bool {
	for _, v := range vals {
		if hasCtl(v) {
			return true
		}
	}
	return false
}

// hasTraversal reports ../ or ..\ (or a path ending in /.. or \..) in the
// raw path or in its once- or twice-decoded forms, which covers %2e%2e%2f,
// ..%2f, %2e%2e/, ..%5c and %252e%252e%252f (case-insensitive).
func hasTraversal(raw string) bool {
	s := strings.ToLower(raw)
	for i := 0; i < 3; i++ {
		if strings.Contains(s, "../") || strings.Contains(s, "..\\") ||
			strings.HasSuffix(s, "/..") || strings.HasSuffix(s, "\\..") {
			return true
		}
		next, _ := normalize.DecodeValue(s)
		if next == s {
			break
		}
		s = next
	}
	return false
}
