package remote

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/run"
)

// Why a payload or case is not sent. None repeats a value.
const (
	ReasonNoPayload  = "the case has no payload to place"
	ReasonPlacement  = "the case's placement is not query, header or json"
	ReasonNoEntry    = "no allow entry has a placement of the case's kind"
	ReasonPublicHost = "the payload could name a public host"
	// ReasonInternalHost has no override: a target that fetches what a
	// payload names would read its own metadata service or link-local hosts.
	ReasonInternalHost = "the payload could name a link-local or cloud metadata address"
	ReasonHeaderValue  = "the payload cannot be sent as a header value"
	ReasonNotUTF8      = "the payload is not valid UTF-8, which a JSON string needs"
	ReasonConflict     = "every placement of the payload is a request another case expects otherwise"
)

// PlacedEncoder is the encoder of a placed case: the decoded payload is sent
// as it is, whatever encoding the source gave it. It is the name GoTestWAF
// gives the same thing, so a report counts both in one row.
const PlacedEncoder = "Plain"

// Refusal is a payload of a case that is not placed, and why. Payload is nil
// for a case without one.
type Refusal struct {
	Payload []byte
	Reason  string
}

// Place returns the requests remote mode sends for c: each payload of c, one
// at a time, in every placement slot of the allow-list of the same kind as
// c's placement (query, header or json), at the entry's method and path byte
// for byte. Nothing else of c is sent: not its path, query, headers or body.
// A query payload is percent-encoded as case lines encode a query; a header
// payload is the header value; a JSON payload is the body {"name": payload}
// with Content-Type application/json.
//
// Each placed request is a case of its own, with the usual ID and c's source
// references, category, expectation and placement, the one payload and the
// encoder PlacedEncoder, as the payload is sent decoded. The payloads that are not placed are returned with the reason;
// a case without a payload is refused as a whole. A payload that could name
// a link-local or cloud metadata address (see cases.NamesInternalHost) or a
// public host (see cases.NamesPublicHost) is never placed. Loopback and
// private addresses are placed.
//
// t must be valid.
func Place(c cases.Case, t Target) (placed []cases.Case, refused []Refusal) {
	refuseAll := func(reason string) []Refusal {
		if len(c.Payloads) == 0 {
			return []Refusal{{Reason: reason}}
		}
		out := make([]Refusal, 0, len(c.Payloads))
		for _, p := range c.Payloads {
			out = append(out, Refusal{Payload: p, Reason: reason})
		}
		return out
	}
	switch {
	case len(c.Payloads) == 0:
		return nil, refuseAll(ReasonNoPayload)
	case c.Placement != PlaceQuery && c.Placement != PlaceHeader && c.Placement != PlaceJSON:
		return nil, refuseAll(ReasonPlacement)
	}
	type slot struct {
		entry Entry
		place placement
	}
	var slots []slot
	for _, e := range t.Allow {
		for _, p := range e.placements() {
			if p.kind == c.Placement {
				slots = append(slots, slot{e, p})
			}
		}
	}
	if len(slots) == 0 {
		return nil, refuseAll(ReasonNoEntry)
	}
	for _, payload := range c.Payloads {
		if reason := payloadRefusal(c.Placement, payload); reason != "" {
			refused = append(refused, Refusal{Payload: payload, Reason: reason})
			continue
		}
		for _, s := range slots {
			p, err := request(c, s.entry, s.place, payload)
			if err != nil {
				// The checks above make this unreachable; refuse rather
				// than send something else.
				refused = append(refused, Refusal{Payload: payload, Reason: "the request cannot be built"})
				break
			}
			placed = append(placed, p)
		}
	}
	return placed, refused
}

// payloadRefusal says why payload cannot be placed as kind, or "".
func payloadRefusal(kind string, payload []byte) string {
	switch {
	// First, so that these payloads are counted under their own reason.
	case cases.NamesInternalHost(string(payload)):
		return ReasonInternalHost
	case cases.NamesPublicHost(string(payload)):
		return ReasonPublicHost
	case kind == PlaceHeader && !validHeaderValue(string(payload)):
		return ReasonHeaderValue
	case kind == PlaceJSON && !utf8.Valid(payload):
		return ReasonNotUTF8
	}
	return ""
}

// request builds the case that sends payload in place p of entry e, with the
// descriptive fields of c.
func request(c cases.Case, e Entry, p placement, payload []byte) (cases.Case, error) {
	l := cases.Line{
		Name: "placed", Category: c.Category, Method: e.Method, Path: e.Path,
		Headers: map[string]string{}, Source: "placed", SourceCaseID: "placed",
		Expected: c.Expected, Placement: c.Placement, Encoder: PlacedEncoder,
	}
	values := map[placement]string{p: string(payload)}
	if err := fill(&l, values); err != nil {
		return cases.Case{}, err
	}
	out, err := cases.FromLine(l)
	if err != nil {
		return cases.Case{}, err
	}
	out.Sources = slices.Clone(c.Sources)
	out.Payloads = [][]byte{bytes.Clone(payload)}
	return out, nil
}

// fill puts each value into its placement of l: query pairs, header values
// and one JSON object holding every json placement.
func fill(l *cases.Line, values map[placement]string) error {
	body := map[string]string{}
	for _, p := range slices.SortedFunc(maps.Keys(values), func(a, b placement) int {
		return strings.Compare(a.kind+":"+a.name, b.kind+":"+b.name)
	}) {
		switch p.kind {
		case PlaceQuery:
			l.Query = append(l.Query, []string{p.name, values[p]})
		case PlaceHeader:
			l.Headers[p.name] = values[p]
		case PlaceJSON:
			body[p.name] = values[p]
		}
	}
	if len(body) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return err
	}
	l.Body = strings.TrimSuffix(buf.String(), "\n")
	l.ContentType = "application/json"
	return nil
}

// Plan is what a remote run sends and what it writes about the cases it does
// not send. Its lines, read back and merged, are Send and NotSent again, and
// Conflicts once more conflict, so a report on them counts every case.
type Plan struct {
	// Send holds the merged placed requests, ordered by ID.
	Send []cases.Case
	// NotSent holds the merged cases and payloads that are not sent; Reasons
	// gives why, by case ID.
	NotSent []cases.Case
	Reasons map[string]string
	// Conflicts holds the cases that send one request and disagree on what
	// to expect. None of them is sent.
	Conflicts []cases.Case
	// Refused counts the payloads Place refused, by reason.
	Refused map[string]int
}

// Prepare places every payload of originals (merged cases) and merges the
// placed requests. Payloads that are not placed, and payloads whose every
// placement conflicts, are kept as the original case with those payloads, to
// be reported as not sent. inputConflicts, the cases left out when the
// originals were merged, are written as they are.
//
// It fails rather than let a report on its lines name a held-out case: every
// source reference of a held-out original must belong to a held-out case of
// the lines, which holds because every payload of every original is in them.
func Prepare(originals, inputConflicts []cases.Case, t Target) (Plan, error) {
	plan := Plan{Reasons: map[string]string{}, Refused: map[string]int{}}
	type payloadKey struct {
		original int
		payload  string
	}
	placedBy := map[payloadKey][]string{} // placed IDs of each payload
	reasonOf := map[payloadKey]string{}
	var placed []cases.Case
	for i, o := range originals {
		ps, refused := Place(o, t)
		for _, p := range ps {
			k := payloadKey{i, string(p.Payloads[0])}
			placedBy[k] = append(placedBy[k], p.ID)
		}
		placed = append(placed, ps...)
		for _, r := range refused {
			reasonOf[payloadKey{i, string(r.Payload)}] = r.Reason
			plan.Refused[r.Reason]++
		}
	}
	_, conflicts := cases.Merge(placed)
	conflicting := map[string]bool{}
	for _, c := range conflicts {
		conflicting[c.ID] = true
	}
	placedIDs := map[string]bool{}
	for _, p := range placed {
		placedIDs[p.ID] = true
	}

	all := slices.Clone(placed)
	unsentReasons := map[string][]string{}
	for i, o := range originals {
		var left [][]byte
		var reasons []string
		if len(o.Payloads) == 0 {
			reasons = append(reasons, reasonOf[payloadKey{i, ""}])
		}
		for _, p := range o.Payloads {
			k := payloadKey{i, string(p)}
			if slices.ContainsFunc(placedBy[k], func(id string) bool { return !conflicting[id] }) {
				continue
			}
			reason := reasonOf[k]
			if reason == "" {
				reason = ReasonConflict
			}
			left, reasons = append(left, p), append(reasons, reason)
		}
		if len(reasons) == 0 {
			continue
		}
		unsent := o
		unsent.Payloads = left
		all = append(all, unsent)
		unsentReasons[o.ID] = append(unsentReasons[o.ID], reasons...)
	}
	all = append(all, inputConflicts...)

	merged, conflicts := cases.Merge(all)
	plan.Conflicts = conflicts
	for _, c := range merged {
		if placedIDs[c.ID] {
			plan.Send = append(plan.Send, c)
			continue
		}
		reasons := slices.Clone(unsentReasons[c.ID])
		slices.Sort(reasons)
		plan.NotSent = append(plan.NotSent, c)
		plan.Reasons[c.ID] = cmp.Or(strings.Join(slices.Compact(reasons), "; "), "the case is not a placed request")
	}
	slices.SortFunc(plan.Send, func(a, b cases.Case) int { return strings.Compare(a.ID, b.ID) })

	hidden := map[cases.SourceRef]bool{}
	for _, c := range merged {
		if cases.Split(c) == cases.SplitHeldOut {
			for _, ref := range c.Sources {
				hidden[ref] = true
			}
		}
	}
	for _, o := range originals {
		if cases.Split(o) == cases.SplitHeldOut && slices.ContainsFunc(o.Sources, func(r cases.SourceRef) bool { return !hidden[r] }) {
			return Plan{}, errors.New("the placed cases would let a report name a held-out case; nothing is sent")
		}
	}
	return plan, nil
}

// Lines returns the case lines of the plan: every case to send, every case
// not sent and every conflicting case.
func (p Plan) Lines() []cases.Line {
	var out []cases.Line
	for _, group := range [][]cases.Case{p.Send, p.NotSent, p.Conflicts} {
		for _, c := range group {
			out = append(out, cases.Lines(c)...)
		}
	}
	return out
}

// NotSentResults returns a not-sent result, with its reason, for each case of
// NotSent.
func (p Plan) NotSentResults() []run.Result {
	out := make([]run.Result, 0, len(p.NotSent))
	for _, c := range p.NotSent {
		out = append(out, run.Result{CaseID: c.ID, Outcome: run.NotSent, Reason: p.Reasons[c.ID]})
	}
	return out
}
