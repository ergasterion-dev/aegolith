package report

import (
	"cmp"
	"maps"
	"slices"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

// Variant counts the cases that one source writes in one way: with one encoder,
// or with its payload in one place. Value is "" where the source names none.
type Variant struct {
	Source, Value, Split string
	Expected             cases.Expected
	Counts               Counts
}

// spelling is one way in which a source writes a request.
type spelling struct{ source, value string }

// variants counts cases by how their sources write them.
type variants struct {
	of func(cases.Case) string
	// ways holds the ways in which the case lines write each request.
	ways   map[string]map[spelling]bool
	counts map[variantKey]Counts
}

type variantKey struct {
	way      spelling
	split    string
	expected cases.Expected
}

// newVariants reads the value that of gives from the case lines cs, which are
// not merged: a merged case keeps the value of one line alone.
func newVariants(cs []cases.Case, of func(cases.Case) string) variants {
	v := variants{of: of, ways: map[string]map[spelling]bool{}, counts: map[variantKey]Counts{}}
	for _, c := range cs {
		if v.ways[c.ID] == nil {
			v.ways[c.ID] = map[spelling]bool{}
		}
		for _, source := range sourceNames(c) {
			v.ways[c.ID][spelling{source, v.of(c)}] = true
		}
	}
	return v
}

// add counts the merged case c once under each way it is written.
func (v variants) add(c cases.Case, split string, one Counts) {
	for way := range v.ways[c.ID] {
		k := variantKey{way, split, c.Expected}
		sum := v.counts[k]
		sum.add(one)
		v.counts[k] = sum
	}
}

// rows returns the counts of the sources that name a value for at least one of
// their cases; the others have nothing to compare.
func (v variants) rows() (out []Variant) {
	named := map[string]bool{}
	for k := range v.counts {
		if k.way.value != "" {
			named[k.way.source] = true
		}
	}
	for _, k := range slices.SortedFunc(maps.Keys(v.counts), func(a, b variantKey) int {
		return cmp.Or(
			cmp.Compare(a.way.source, b.way.source),
			cmp.Compare(a.way.value, b.way.value),
			cmp.Compare(a.split, b.split),
			cmp.Compare(a.expected, b.expected),
		)
	}) {
		if named[k.way.source] {
			out = append(out, Variant{k.way.source, k.way.value, k.split, k.expected, v.counts[k]})
		}
	}
	return out
}
