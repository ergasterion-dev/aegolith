// Package detect holds Pylolith's attack detectors. Every detector is a pure
// function of a single value: no global mutable state, safe for concurrent
// use.
package detect

import "github.com/ergasterion-dev/pylolith/internal/model"

// Hit is one detector finding before the engine attaches the request
// location, field name, redacted snippet and action.
type Hit struct {
	RuleID   string
	Category model.Category
	Severity model.Severity
}
