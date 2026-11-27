package aegolith

import (
	"errors"
	"fmt"

	"github.com/ergasterion-dev/aegolith/internal/engine"
	"github.com/ergasterion-dev/aegolith/internal/model"
	"github.com/ergasterion-dev/aegolith/internal/policy"
)

// Types shared with the internal packages.
type (
	// Request is the transport-independent request the adapters build.
	Request = model.Request
	// Decision is the verdict of Inspect.
	Decision = model.Decision
	// Match is one rule hit; its Snippet is always redacted.
	Match = model.Match
	// Action is allow, block or monitor.
	Action = model.Action
	// Mode is enforce or monitor.
	Mode = model.Mode
	// Severity ranks a match.
	Severity = model.Severity
	// Category groups rules by attack class.
	Category = model.Category
	// Location is the part of the request a match came from.
	Location = model.Location
	// Limits bound the work done per request.
	Limits = model.Limits
	// Route declares one endpoint: method, path template and typed fields.
	Route = policy.Route
	// Field declares the type of one path parameter, query value or body
	// value.
	Field = policy.FieldSpec
)

// Actions.
const (
	ActionAllow   = model.ActionAllow
	ActionBlock   = model.ActionBlock
	ActionMonitor = model.ActionMonitor
)

// Modes.
const (
	ModeEnforce = model.ModeEnforce
	ModeMonitor = model.ModeMonitor
)

// Severities.
const (
	SeverityLow      = model.SeverityLow
	SeverityMedium   = model.SeverityMedium
	SeverityHigh     = model.SeverityHigh
	SeverityCritical = model.SeverityCritical
)

// Locations.
const (
	LocMethod   = model.LocMethod
	LocPath     = model.LocPath
	LocQuery    = model.LocQuery
	LocHeader   = model.LocHeader
	LocCookie   = model.LocCookie
	LocBody     = model.LocBody
	LocProtocol = model.LocProtocol
)

// Categories.
const (
	CatSQLi         = model.CatSQLi
	CatXSS          = model.CatXSS
	CatCmdi         = model.CatCmdi
	CatCodei        = model.CatCodei
	CatLDAP         = model.CatLDAP
	CatSSTI         = model.CatSSTI
	CatJNDI         = model.CatJNDI
	CatCRLF         = model.CatCRLF
	CatLFI          = model.CatLFI
	CatRFI          = model.CatRFI
	CatSSRF         = model.CatSSRF
	CatXXE          = model.CatXXE
	CatNoSQLi       = model.CatNoSQLi
	CatProtoPollute = model.CatProtoPollute
	CatSession      = model.CatSession
	CatScanner      = model.CatScanner
	CatProtocol     = model.CatProtocol
	CatSchema       = model.CatSchema
	CatRoute        = model.CatRoute
)

// Field types for Field.Type.
const (
	TypeUUID   = policy.TypeUUID
	TypeInt    = policy.TypeInt
	TypeNumber = policy.TypeNumber
	TypeBool   = policy.TypeBool
	TypeEnum   = policy.TypeEnum
	TypeString = policy.TypeString
	TypeText   = policy.TypeText
	TypeEmail  = policy.TypeEmail
	TypePhone  = policy.TypePhone
	TypeURL    = policy.TypeURL

	// TypeUUIDLenient ("uuid_lenient") accepts the canonical form plus the
	// forms Go's github.com/google/uuid Parse also takes: 32 hex digits,
	// braces and a "urn:uuid:" prefix. Declare it only where the handler
	// parses the id that leniently; TypeUUID stays canonical-only.
	TypeUUIDLenient = policy.TypeUUIDLenient

	// TypeBase64 ("base64") is text sent as base64 in the standard alphabet
	// ('+' and '/'), padded or not, CR and LF ignored. The detectors judge
	// the decoded value as they judge a TypeText value; MaxLen bounds the
	// encoded one.
	TypeBase64 = policy.TypeBase64

	// TypeBase64URL ("base64url") is TypeBase64 in the URL-safe alphabet
	// ('-' and '_'). Declare it only where the handler decodes with a
	// URL-safe decoder.
	TypeBase64URL = policy.TypeBase64URL
)

// DefaultLimits returns the default inspection limits: 1 MiB body, JSON
// depth 32, 1,000 fields and 8 KiB scanned per value.
func DefaultLimits() Limits { return model.DefaultLimits() }

// Firewall inspects requests. It is immutable and safe for concurrent use.
type Firewall struct {
	eng      *engine.Engine
	limits   Limits
	failOpen bool
}

// New validates cfg and builds a Firewall. Invalid routes, field types,
// actions, rule selectors, exclusions or limits are reported here, at
// startup, rather than at request time. The Firewall keeps its own copy of
// everything in cfg.
func New(cfg Config) (*Firewall, error) {
	o, err := cfg.options()
	if err != nil {
		return nil, fmt.Errorf("aegolith: %w", err)
	}
	eng, err := engine.New(o)
	if err != nil {
		return nil, fmt.Errorf("aegolith: %w", err)
	}
	return &Firewall{eng: eng, limits: o.Limits, failOpen: o.FailOpen}, nil
}

// Limits returns the resolved inspection limits (defaults applied). Adapters
// use MaxBodyBytes to bound how much of a request body they buffer. A nil
// Firewall returns DefaultLimits.
func (f *Firewall) Limits() Limits {
	if f == nil {
		return DefaultLimits()
	}
	return f.limits
}

// FailOpen reports whether an internal error allows the request (true, the
// default) or blocks it. A nil Firewall fails open.
func (f *Firewall) FailOpen() bool { return f == nil || f.failOpen }

// Inspect returns the decision for r. It never panics: an internal error
// yields Decision.Err set and Action allow (fail open, the default) or
// block (Config.FailOpen false). A nil Firewall allows with Err set.
func (f *Firewall) Inspect(r *Request) Decision {
	if f == nil || f.eng == nil {
		return Decision{Action: ActionAllow, Err: errors.New("aegolith: nil Firewall")}
	}
	return f.eng.Inspect(r)
}
