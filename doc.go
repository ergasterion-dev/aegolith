// Package aegolith is an API-aware web application firewall library for Go.
//
// Build a Firewall with New (or LoadConfig then New) and call Inspect for
// each request. Inspect runs protocol checks, route-typed validation of
// declared fields and targeted attack detectors on free-text inputs, then
// applies rule-action overrides, exclusions and the mode. It never panics.
package aegolith
