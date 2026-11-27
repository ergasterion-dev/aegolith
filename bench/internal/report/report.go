// Package report turns cases and their results into counts, a Markdown and
// JSON report, and a comparison with an earlier report.
//
// A report holds no request values or payloads. It names single cases only
// from the development and baseline sets: held-out cases appear in counts
// alone.
package report

import (
	"cmp"
	"maps"
	"slices"
	"time"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/run"
)

// Meta says what a report was made from.
type Meta struct {
	Commit  string // the Aegolith commit
	Created time.Time
	Sources []SourceInfo
	// Environment describes the machine, the tools and the settings of the run.
	Environment []Field `json:",omitempty"`
	// Input counts the case lines the report was made from.
	Input *Input `json:",omitempty"`
	// Generated describes the generated legitimate requests among them.
	Generated *Generated `json:",omitempty"`
}

// SourceInfo describes one source of cases. An empty field was not recorded.
type SourceInfo struct {
	Name, Repo, Commit, License string
	Included                    bool
	Note                        string
}

// Counts is the number of cases per outcome. Sent counts every case but those
// that were not sent.
type Counts struct{ Sent, Blocked, Flagged, RouteOnly, Passed, Rejected, Unknown, NotSent int }

// TotalSource is the Source of the rows that count each case once, whatever
// its sources and category. No case has an empty source.
const TotalSource = ""

// Row counts the cases of one source, category, split and expectation. A case
// with several sources is counted in a row of each of them, so only the rows
// of TotalSource, which have no category, add up to the number of cases.
type Row struct {
	Source, Category, Split string
	Expected                cases.Expected
	Counts                  Counts
}

// Config holds the results of one configuration of the target.
type Config struct {
	Name string
	Rows []Row
	// Payloads is the number of distinct attack payloads, over all splits,
	// that the firewall judged in at least one case; PayloadsAny of them were
	// blocked or flagged in at least one such case, PayloadsAll in every one.
	PayloadsAny, PayloadsAll, Payloads int
	// FlaggedLegit lists the legitimate cases blocked or flagged, and Missed
	// the attacks neither blocked nor flagged, of the development and baseline
	// sets.
	FlaggedLegit []Listed
	Missed       []Listed
	// NotSentReasons counts, over all splits and expectations, why cases were
	// not sent.
	NotSentReasons []ReasonCount `json:",omitempty"`
}

// Listed names one case. SourceCaseID is empty when each name the case has is
// also the name of a held-out case.
type Listed struct {
	CaseID, Source, SourceCaseID, Category string
	Rules                                  []string
}

// Report is what is written as report.json and rendered as report.md.
type Report struct {
	Meta    Meta
	Configs []Config
	// Load is the result of a load run, if one was made. It enters no count
	// and no rate of Configs.
	Load *run.LoadResult `json:",omitempty"`
}

// BuildConfig counts the results rs of the cases cs.
//
// The cases are merged first (see cases.Merge), so that one request is counted
// once and is held out if any of its sources makes it so; requests whose
// sources disagree on what to expect are left out. A case without a result
// counts as not sent, only the first result of a case counts, and a result of
// no case is ignored.
func BuildConfig(name string, cs []cases.Case, rs []run.Result) Config {
	merged, _ := cases.Merge(cs)
	results := make(map[string]run.Result, len(rs))
	for _, r := range rs {
		if _, ok := results[r.CaseID]; !ok {
			results[r.CaseID] = r
		}
	}
	hidden := heldOutRefs(merged)

	out := Config{Name: name}
	rows := map[rowKey]Counts{}
	payloads := map[string]placements{}
	notSent := map[string]int{}
	for _, c := range merged {
		r, ok := results[c.ID]
		if !ok {
			r.Outcome, r.Reason = run.NotSent, "no result for the case"
		}
		if r.Outcome == run.NotSent {
			notSent[cmp.Or(r.Reason, notRecorded)]++
		}
		split := cases.Split(c)
		one := countOf(r.Outcome)
		count := func(k rowKey) {
			sum := rows[k]
			sum.add(one)
			rows[k] = sum
		}
		count(rowKey{source: TotalSource, split: split, expected: c.Expected})
		for _, source := range sourceNames(c) {
			count(rowKey{source, c.Category, split, c.Expected})
		}

		judged, detected := one.judged() > 0, one.detected() > 0
		if c.Expected == cases.Attack && judged {
			for _, p := range c.Payloads {
				seen := payloads[string(p)]
				seen.any = seen.any || detected
				seen.undetected = seen.undetected || !detected
				payloads[string(p)] = seen
			}
		}

		// Only these two sets may be listed.
		if split != cases.SplitDev && split != cases.SplitBaseline {
			continue
		}
		switch {
		case c.Expected == cases.Attack && judged && !detected:
			out.Missed = append(out.Missed, listed(c, r, hidden))
		case c.Expected == cases.Legit && detected:
			out.FlaggedLegit = append(out.FlaggedLegit, listed(c, r, hidden))
		}
	}

	for _, k := range slices.SortedFunc(maps.Keys(rows), compareRows) {
		out.Rows = append(out.Rows, Row{
			Source: k.source, Category: k.category, Split: k.split, Expected: k.expected, Counts: rows[k],
		})
	}
	out.NotSentReasons = reasonCounts(notSent)
	out.Payloads = len(payloads)
	for _, seen := range payloads {
		if seen.any {
			out.PayloadsAny++
		}
		if !seen.undetected {
			out.PayloadsAll++
		}
	}
	slices.SortFunc(out.Missed, compareListed)
	slices.SortFunc(out.FlaggedLegit, compareListed)
	return out
}

// placements says what happened to the judged cases of one payload.
type placements struct{ any, undetected bool }

type rowKey struct {
	source, category, split string
	expected                cases.Expected
}

func compareRows(a, b rowKey) int {
	return cmp.Or(
		cmp.Compare(a.source, b.source),
		cmp.Compare(a.category, b.category),
		cmp.Compare(a.split, b.split),
		cmp.Compare(a.expected, b.expected),
	)
}

// sourceNames returns the distinct sources of a merged case.
func sourceNames(c cases.Case) []string {
	names := make([]string, 0, len(c.Sources))
	for _, ref := range c.Sources {
		names = append(names, ref.Source)
	}
	// Merge sorts the references by source.
	return slices.Compact(names)
}

// heldOutRefs returns every name a source gives to a held-out case.
func heldOutRefs(cs []cases.Case) map[cases.SourceRef]bool {
	out := map[cases.SourceRef]bool{}
	for _, c := range cs {
		if cases.Split(c) == cases.SplitHeldOut {
			for _, ref := range c.Sources {
				out[ref] = true
			}
		}
	}
	return out
}

// listed names c by the first of its source references that no held-out case
// shares; a source need not give each of its requests a name of its own.
func listed(c cases.Case, r run.Result, hidden map[cases.SourceRef]bool) Listed {
	l := Listed{CaseID: c.ID, Category: c.Category, Rules: slices.Clone(r.Rules)}
	if i := slices.IndexFunc(c.Sources, func(ref cases.SourceRef) bool { return !hidden[ref] }); i >= 0 {
		l.Source, l.SourceCaseID = c.Sources[i].Source, c.Sources[i].CaseID
	} else if len(c.Sources) > 0 {
		l.Source = c.Sources[0].Source
	}
	return l
}

func compareListed(a, b Listed) int {
	return cmp.Or(
		cmp.Compare(a.Source, b.Source),
		cmp.Compare(a.SourceCaseID, b.SourceCaseID),
		cmp.Compare(a.CaseID, b.CaseID),
	)
}

// countOf is the count of one case. An outcome this package does not know is
// unknown.
func countOf(o run.Outcome) Counts {
	c := Counts{Sent: 1}
	switch o {
	case run.Blocked:
		c.Blocked = 1
	case run.Flagged:
		c.Flagged = 1
	case run.RouteOnly:
		c.RouteOnly = 1
	case run.Passed:
		c.Passed = 1
	case run.Rejected:
		c.Rejected = 1
	case run.NotSent:
		c.Sent, c.NotSent = 0, 1
	default:
		c.Unknown = 1
	}
	return c
}

func (c *Counts) add(o Counts) {
	c.Sent += o.Sent
	c.Blocked += o.Blocked
	c.Flagged += o.Flagged
	c.RouteOnly += o.RouteOnly
	c.Passed += o.Passed
	c.Rejected += o.Rejected
	c.Unknown += o.Unknown
	c.NotSent += o.NotSent
}

// detected is the number of cases blocked or flagged.
func (c Counts) detected() int { return c.Blocked + c.Flagged }

// judged is the number of cases the firewall decided about, the denominator of
// every rate: rejected, unknown and unsent cases say nothing about it.
func (c Counts) judged() int { return c.detected() + c.RouteOnly + c.Passed }

// DetectionRate is the share of judged cases that were blocked or flagged, 0
// when none was judged. For legitimate cases it is the false positive rate.
func (c Counts) DetectionRate() float64 { return share(c.detected(), c.judged()) }

// share is n of all, 0 when all is 0.
func share(n, all int) float64 {
	if all == 0 {
		return 0
	}
	return float64(n) / float64(all)
}
