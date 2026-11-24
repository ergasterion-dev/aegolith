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
// error (fail-open fault). The path is the escaped path without the query,
// clipped to 256 bytes; fields are clipped to 128. Snippets are the engine's already-redacted values
// (at most 64 bytes); no raw request data is added.
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
		fields := make([]string, 0, len(d.Matches))
		snips := make([]string, 0, len(d.Matches))
		for _, m := range d.Matches {
			rules = append(rules, m.RuleID)
			cats = append(cats, string(m.Category))
			fields = append(fields, clip(m.Field, maxFieldLen))
			snips = append(snips, m.Snippet)
		}
		attrs := []slog.Attr{
			slog.String("method", r.Method),
			slog.String("path", clip(r.RawPath, maxPathLen)),
			slog.Any("rules", rules),
			slog.Any("categories", cats),
			slog.Any("fields", fields),
			slog.Any("snippets", snips),
		}
		if d.Err != nil {
			attrs = append(attrs, slog.String("error", clean(d.Err.Error(), maxErrLen)))
		}
		l.LogAttrs(context.Background(), level, msg, attrs...)
	}
}
