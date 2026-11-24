package httpwaf

import (
	"context"
	"log/slog"

	"github.com/ergasterion-dev/aegolith"
)

const (
	maxPathLen  = 256
	maxFieldLen = 128
	maxErrLen   = 128
	// maxSnippetLen matches model.Redact's cap; maxTokenLen bounds short
	// identifiers (method, rule ID, category, location).
	maxSnippetLen = 64
	maxTokenLen   = 64
)

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// clean truncates s and replaces control and non-ASCII bytes with '?'.
func clean(s string, n int) string {
	b := []byte(clip(s, n))
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	return string(b)
}

// SlogHook returns an Options.OnDecision hook that logs to l (slog.Default
// when nil): Warn for a blocked request, Info for a monitored one, nothing
// for a clean allow, and Error for a decision that only carries an internal
// error (fail-open fault).
//
// Attributes (spec 5.6): method, path (the escaped path without the query,
// clipped to 256 bytes), route (the matched route key, empty for an unknown
// route), rules, categories, locations, fields (clipped to 128 bytes),
// snippets (the engine's already-redacted values, at most 64 bytes),
// latency (Decision.Duration) and, when set, error. Every string goes
// through clean, so control and non-ASCII bytes are logged as '?'. No raw
// request data beyond the path is added.
func SlogHook(l *slog.Logger) func(*aegolith.Request, aegolith.Decision) {
	return func(r *aegolith.Request, d aegolith.Decision) {
		l := l
		if l == nil {
			l = slog.Default()
		}
		var level slog.Level
		var msg string
		switch {
		case d.Err != nil && d.Action != aegolith.ActionBlock && !d.Monitored:
			level, msg = slog.LevelError, "aegolith: internal error"
		case d.Action == aegolith.ActionBlock:
			level, msg = slog.LevelWarn, "aegolith: request blocked"
		case d.Monitored:
			level, msg = slog.LevelInfo, "aegolith: request monitored"
		default:
			return
		}
		rules := make([]string, 0, len(d.Matches))
		cats := make([]string, 0, len(d.Matches))
		locs := make([]string, 0, len(d.Matches))
		fields := make([]string, 0, len(d.Matches))
		snips := make([]string, 0, len(d.Matches))
		for _, m := range d.Matches {
			rules = append(rules, clean(m.RuleID, maxTokenLen))
			cats = append(cats, clean(string(m.Category), maxTokenLen))
			locs = append(locs, clean(string(m.Location), maxTokenLen))
			fields = append(fields, clean(m.Field, maxFieldLen))
			snips = append(snips, clean(m.Snippet, maxSnippetLen))
		}
		attrs := []slog.Attr{
			slog.String("method", clean(r.Method, maxTokenLen)),
			slog.String("path", clean(r.RawPath, maxPathLen)),
			slog.String("route", clean(d.Route, maxPathLen)),
			slog.Any("rules", rules),
			slog.Any("categories", cats),
			slog.Any("locations", locs),
			slog.Any("fields", fields),
			slog.Any("snippets", snips),
			slog.Duration("latency", d.Duration),
		}
		if d.Err != nil {
			attrs = append(attrs, slog.String("error", clean(d.Err.Error(), maxErrLen)))
		}
		l.LogAttrs(context.Background(), level, msg, attrs...)
	}
}
