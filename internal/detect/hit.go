// Package detect holds Aegolith's attack detectors. Every detector is a pure
// function of a single value: no global mutable state, safe for concurrent
// use.
package detect

import (
	"github.com/ergasterion-dev/aegolith/internal/model"
	"github.com/ergasterion-dev/aegolith/internal/normalize"
)

// Hit is one detector finding before the engine attaches the request
// location, field name, redacted snippet and action.
type Hit struct {
	RuleID   string
	Category model.Category
	Severity model.Severity
}

// valueOrDecoded runs match on v and, when one percent-decoding pass changes
// it, on the decoded value.
func valueOrDecoded(v string, match func(string) bool) bool {
	if match(v) {
		return true
	}
	d, _ := normalize.DecodeValue(v)
	return d != v && match(d)
}
