package report

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

// Field is one named value of the description of a run, such as the processor
// of the machine.
type Field struct{ Name, Value string }

// Input counts what went into a report, before anything was merged.
type Input struct {
	// Lines is the number of case lines read, Distinct the number of requests
	// counted after identical requests were merged.
	Lines, Distinct int
	Sources         []SourceInput
	// Conflicts counts the requests left out because the lines that send them
	// disagree on what to expect, by the sources of those lines.
	Conflicts []Conflict
}

// SourceInput counts the case lines of one source.
type SourceInput struct {
	Source                  string
	Lines                   int
	Attack, Legit, NearMiss int
	// NoPayload counts the lines that name no payload, Conflicting those left
	// out as conflicting.
	NoPayload, Conflicting int
	// Base64Attack counts the attack lines whose encoder is a base64 one.
	Base64Attack int `json:",omitempty"`
	// Skipped is the number of source cases the importer left out, and nil
	// when that was not recorded.
	Skipped     *int          `json:",omitempty"`
	SkipReasons []ReasonCount `json:",omitempty"`
}

// ReasonCount is the number of cases left out for one reason.
type ReasonCount struct {
	Reason string
	Count  int
}

// base64Encoders are the encoder names that write a payload in base64.
var base64Encoders = []string{"Base64", "Base64Flat"}

// Conflict counts the conflicting requests whose lines come from one set of
// sources.
type Conflict struct {
	Sources         []string
	Requests, Lines int
}

// CountInput counts the cases cs, which are the case lines as read: not
// merged.
func CountInput(cs []cases.Case) Input {
	merged, conflicts := cases.Merge(cs)
	in := Input{Lines: len(cs), Distinct: len(merged)}
	bySource := map[string]*SourceInput{}
	source := func(name string) *SourceInput {
		if bySource[name] == nil {
			bySource[name] = &SourceInput{Source: name}
		}
		return bySource[name]
	}
	for _, c := range cs {
		for _, name := range sourceNames(c) {
			s := source(name)
			s.Lines++
			switch c.Expected {
			case cases.Attack:
				s.Attack++
				if slices.Contains(base64Encoders, c.Encoder) {
					s.Base64Attack++
				}
			case cases.Legit:
				s.Legit++
			case cases.NearMiss:
				s.NearMiss++
			}
			if len(c.Payloads) == 0 {
				s.NoPayload++
			}
		}
	}

	type group struct {
		lines   int
		sources []string
	}
	requests := map[string]*group{}
	for _, c := range conflicts {
		g := requests[c.ID]
		if g == nil {
			g = &group{}
			requests[c.ID] = g
		}
		g.lines++
		for _, name := range sourceNames(c) {
			source(name).Conflicting++
			g.sources = append(g.sources, name)
		}
	}
	sets := map[string]*Conflict{}
	for _, g := range requests {
		slices.Sort(g.sources)
		names := slices.Compact(g.sources)
		key := strings.Join(names, "\x00")
		if sets[key] == nil {
			sets[key] = &Conflict{Sources: names}
		}
		sets[key].Requests++
		sets[key].Lines += g.lines
	}
	for _, key := range slices.Sorted(maps.Keys(sets)) {
		in.Conflicts = append(in.Conflicts, *sets[key])
	}
	for _, name := range slices.Sorted(maps.Keys(bySource)) {
		in.Sources = append(in.Sources, *bySource[name])
	}
	return in
}

// AddSkips records the source cases the importer of a source left out, one
// reason for each; none records that it left none out.
func (in *Input) AddSkips(source string, reasons []string) {
	i, found := slices.BinarySearchFunc(in.Sources, source, func(s SourceInput, name string) int {
		return cmp.Compare(s.Source, name)
	})
	if !found {
		in.Sources = slices.Insert(in.Sources, i, SourceInput{Source: source})
	}
	skipped := len(reasons)
	in.Sources[i].Skipped = &skipped
	count := map[string]int{}
	for _, r := range reasons {
		count[r]++
	}
	in.Sources[i].SkipReasons = reasonCounts(count)
}

// reasonCounts orders the counts of reasons, the commonest first.
func reasonCounts(count map[string]int) (out []ReasonCount) {
	for _, r := range slices.SortedFunc(maps.Keys(count), func(a, b string) int {
		return cmp.Or(cmp.Compare(count[b], count[a]), cmp.Compare(a, b))
	}) {
		out = append(out, ReasonCount{r, count[r]})
	}
	return out
}

// Generated describes a generated set of legitimate requests and what it was
// built from.
type Generated struct {
	Seed int64
	N    int
	// Templates, Lists and Entries are the sizes of the generator's material,
	// TemplatesUsed and EntriesUsed what went into at least one line.
	Templates, Lists, Entries  int
	TemplatesUsed, EntriesUsed int
	Categories                 []GeneratedCategory
	// Cores counts the word lists of pasted code that hold the pasted text
	// itself, if the generator names them.
	Cores []GeneratedList `json:",omitempty"`
}

// GeneratedList counts the entries of one word list, those that went into a
// line, and the lines that hold one.
type GeneratedList struct {
	Name                 string
	Entries, Used, Lines int
}

// GeneratedCategory counts the lines of one category and what went into them.
type GeneratedCategory struct {
	Name                                string
	Lines, NearMiss, Templates, Entries int
}
