package httpwaf

import (
	"context"
	"log/slog"

	"github.com/ergasterion-dev/aegolith"
)

// SlogHook returns an Options.OnDecision hook that logs to l (slog.Default
// when nil): Warn for a blocked request, Info for a monitored one, nothing
// for a clean allow. Snippets are the engine's already-redacted values
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
			fields = append(fields, m.Field)
			snips = append(snips, m.Snippet)
		}
		l.LogAttrs(context.Background(), level, msg,
			slog.String("method", r.Method),
			slog.String("path", r.RawPath),
			slog.Any("rules", rules),
			slog.Any("categories", cats),
			slog.Any("fields", fields),
			slog.Any("snippets", snips),
		)
	}
}
