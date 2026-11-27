package report

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/run"
)

// unwrapped returns text with every run of blanks and line breaks as one
// blank, so that a phrase is found wherever a line of prose breaks.
func unwrapped(text string) string { return strings.Join(strings.Fields(text), " ") }

// section returns the part of md from the heading up to the next heading of
// the same or a higher level.
func section(t *testing.T, md, heading string) string {
	t.Helper()
	_, rest, found := strings.Cut(md, "\n"+heading+"\n")
	if !found {
		t.Fatalf("no heading %q in:\n%s", heading, md)
	}
	level := len(heading) - len(strings.TrimLeft(heading, "#"))
	var out []string
	for _, line := range strings.Split(rest, "\n") {
		if hashes := len(line) - len(strings.TrimLeft(line, "#")); hashes > 0 && hashes <= level {
			break
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func TestCountInput(t *testing.T) {
	t.Parallel()
	cs := []cases.Case{
		newCase(t, "alpha", "a1", cases.Attack, "q=1", "p1"),
		newCase(t, "alpha", "a2", cases.Legit, "q=2", ""),
		// alpha disagrees with itself on one request, twice over.
		newCase(t, "alpha", "a3", cases.Attack, "q=3", "p3"),
		newCase(t, "alpha", "a4", cases.NearMiss, "q=3", ""),
		newCase(t, "alpha", "a5", cases.Attack, "q=4", "p4"),
		newCase(t, "alpha", "a6", cases.NearMiss, "q=4", "p4"),
		// The two sources disagree, and agree on another request.
		newCase(t, "alpha", "a7", cases.Attack, "q=5", "p5"),
		newCase(t, "beta", "b1", cases.Legit, "q=5", "p5"),
		newCase(t, "beta", "b2", cases.Attack, "q=1", ""),
	}

	in := CountInput(cs)
	in.AddSkips("alpha", []string{"too long", "not sent", "not sent"})
	in.AddSkips("beta", nil)
	in.AddSkips("gamma", []string{"too long"})

	three, none, one := 3, 0, 1
	want := Input{
		Lines: 9,
		// q=1, once, and q=2.
		Distinct: 2,
		Sources: []SourceInput{
			{Source: "alpha", Lines: 7, Attack: 4, Legit: 1, NearMiss: 2, NoPayload: 2, Conflicting: 5,
				Skipped:     &three,
				SkipReasons: []ReasonCount{{"not sent", 2}, {"too long", 1}}},
			{Source: "beta", Lines: 2, Attack: 1, Legit: 1, NoPayload: 1, Conflicting: 1, Skipped: &none},
			{Source: "gamma", Skipped: &one, SkipReasons: []ReasonCount{{"too long", 1}}},
		},
		Conflicts: []Conflict{
			{Sources: []string{"alpha"}, Requests: 2, Lines: 4},
			{Sources: []string{"alpha", "beta"}, Requests: 1, Lines: 2},
		},
	}
	if !reflect.DeepEqual(in, want) {
		got, _ := json.MarshalIndent(in, "", " ")
		t.Errorf("input = %s", got)
	}

	md := Report{Meta: Meta{Input: &in}}.Markdown()
	s := section(t, md, "## Input")
	contains(t, unwrapped(s),
		"as import or remote wrote it", "9 case lines were read.",
		"2 distinct requests are counted",
		"6 lines (3 requests) are left out",
		"| alpha | 7 | 4 | 1 | 2 | 2 | 5 | 3 |",
		"| beta | 2 | 1 | 1 | 0 | 1 | 1 | 0 |",
		"| gamma | 0 | 0 | 0 | 0 | 0 | 0 | 1 |",
		"| all | 9 | 5 | 2 | 2 | 3 | 6 | 4 |",
		"| alpha | 2 | 4 |", "| alpha, beta | 1 | 2 |",
		"| alpha | not sent | 2 |", "| gamma | too long | 1 |")
	for _, name := range []string{"a1", "b1", "p1", "p3", "q=1"} {
		if strings.Contains(s, name) {
			t.Errorf("the input counts name %q:\n%s", name, s)
		}
	}

	// Without a skip list the number is not known, and neither is the total.
	unknown := CountInput(cs[:1])
	contains(t, section(t, Report{Meta: Meta{Input: &unknown}}.Markdown(), "## Input"),
		"| alpha | 1 | 1 | 0 | 0 | 0 | 0 | not recorded |",
		"| all | 1 | 1 | 0 | 0 | 0 | 0 | not recorded |",
		"0 lines (0 requests) are left out")
}

func TestEnvironmentAndSourceNotes(t *testing.T) {
	t.Parallel()
	r := Report{Meta: Meta{
		Commit:      "abc (with uncommitted changes)",
		Environment: []Field{{"CPU", "Some | CPU"}, {"Load average at start", "1.0 2.0 3.0"}},
		Sources: []SourceInfo{
			{Name: "crs", Repo: "host/org/crs", Commit: "c0ffee", License: "Apache-2.0", Included: true, Note: "pinned"},
			{Name: "gotestwaf", Included: false, Note: "not among the case files"},
		},
	}}
	md := r.Markdown()
	contains(t, md, "- Aegolith commit: abc (with uncommitted changes)")
	contains(t, section(t, md, "## Run environment"), `| CPU | Some \| CPU |`, "| Load average at start | 1.0 2.0 3.0 |")
	s := section(t, md, "## Sources")
	contains(t, unwrapped(s), "| Source | Repository | Commit | Licence | Included | Note |",
		"| crs | host/org/crs | c0ffee | Apache-2.0 | yes | pinned |",
		"a test file belongs to one rule", "paranoia level", "the importer does not filter by level",
		"category protocol", "need not be a working exploit", "only a fragment",
		"split by its case ID", "heuristic")
	for _, unsupported := range []string{"ask for more", "paranoia-level-1", "expected to be lower"} {
		if strings.Contains(unwrapped(s), unsupported) {
			t.Errorf("the CRS note still implies what the data does not show (%q):\n%s", unsupported, s)
		}
	}
	if strings.Contains(s, "false-positive") {
		t.Errorf("a source that is not included is described:\n%s", s)
	}
	r.Meta.Sources[1].Included = true
	contains(t, section(t, r.Markdown(), "## Sources"), "false-positive")

	if md := (Report{}).Markdown(); strings.Contains(md, "## Run environment") || strings.Contains(md, "## Input") ||
		strings.Contains(md, "## Generated") {
		t.Errorf("a report without these says it has them:\n%s", md)
	}
}

func TestGeneratedSection(t *testing.T) {
	t.Parallel()
	g := Generated{
		Seed: 9, N: 40, Templates: 321, Lists: 311, Entries: 4166, TemplatesUsed: 30, EntriesUsed: 70,
		Categories: []GeneratedCategory{
			{Name: "names", Lines: 30, Templates: 20, Entries: 50},
			{Name: "pasted-code", Lines: 6, NearMiss: 1, Templates: 6, Entries: 12},
			{Name: "punctuation-prose", Lines: 4, Templates: 4, Entries: 9},
		},
		Cores: []GeneratedList{
			{Name: "code-error", Entries: 54, Used: 5, Lines: 4},
			{Name: "code-shell", Entries: 53, Used: 2, Lines: 3},
		},
	}
	s := section(t, Report{Meta: Meta{Generated: &g}}.Markdown(), "## Generated legitimate traffic")
	contains(t, unwrapped(s),
		"Seed 9, 40 lines",
		"321 templates and 4166 entries in 311 word lists",
		"| names | 30 | 75.0% | 0 | 20 | 50 |",
		"| pasted-code | 6 | 15.0% | 1 | 6 | 12 |",
		"| all | 40 | 100.0% | 1 | 30 | 70 |",
		"punctuation-prose and pasted-code are 25.0% of the lines",
		"not independent",
		"not a measurement of real traffic",
		"/etc/passwd or /etc/shadow",
		"after one replay",
		"no native review", "loopback")
	cores := section(t, Report{Meta: Meta{Generated: &g}}.Markdown(), "### Core snippets of pasted code")
	contains(t, unwrapped(cores), "7 of the 107 entries of 2 word lists",
		"| code-error | 54 | 5 | 4 |", "| code-shell | 53 | 2 | 3 |", "| all | 107 | 7 | |",
		"one line may hold several")
	g.Cores = nil
	if md := (Report{Meta: Meta{Generated: &g}}).Markdown(); strings.Contains(md, "Core snippets") {
		t.Errorf("no core lists, yet:\n%s", md)
	}
}

// The false positive rate is shown for each source and category, held out,
// development and all, and a near-miss never enters it.
func TestFalsePositivesBySourceAndCategory(t *testing.T) {
	t.Parallel()
	withCategory := func(cs []cases.Case, category string) []cases.Case {
		out := slices.Clone(cs)
		for i := range out {
			out[i].Category = category
		}
		return out
	}
	held := withCategory(inSplit(t, cases.SplitHeldOut, "h", cases.Legit, 4), "names")
	dev := withCategory(inSplit(t, cases.SplitDev, "d", cases.Legit, 8)[4:], "reviews")
	near := withCategory(inSplit(t, cases.SplitHeldOut, "n", cases.NearMiss, 10)[8:], "names")
	own := newCase(t, cases.SourceBaseline, "legit/own", cases.Legit, "q=own", "")
	rs := slices.Concat(
		answered(held[:1], run.Blocked), answered(held[1:2], run.Flagged), answered(held[2:3], run.Passed),
		answered(held[3:], run.Rejected), answered(dev, run.Passed), answered(near[:1], run.Blocked),
		answered(near[1:], run.Passed), answered([]cases.Case{own}, run.Blocked))

	cfg := BuildConfig("none", slices.Concat(held, dev, near, []cases.Case{own}), rs)
	md := Report{Configs: []Config{cfg}}.Markdown()

	s := section(t, md, "### False positives by source and category")
	contains(t, s,
		"| Source | Category | Held-out | Development | All splits |",
		"| baseline | sqli | n/a | n/a | 100.0% (1 of 1) |",
		"| baseline | (all categories) | n/a | n/a | 100.0% (1 of 1) |",
		"| third | names | 66.7% (2 of 3) | n/a | 66.7% (2 of 3) |",
		"| third | reviews | n/a | 0.0% (0 of 4) | 0.0% (0 of 4) |",
		"| third | (all categories) | 66.7% (2 of 3) | 0.0% (0 of 4) | 28.6% (2 of 7) |",
		"| (all sources) | (all categories) | 66.7% (2 of 3) | 0.0% (0 of 4) | 37.5% (3 of 8) |")
	n := section(t, md, "### Near-miss requests blocked or flagged, by source and category")
	contains(t, n,
		"| third | names | 50.0% (1 of 2) | n/a | 50.0% (1 of 2) |",
		"| (all sources) | (all categories) | 50.0% (1 of 2) | n/a | 50.0% (1 of 2) |")
	if strings.Contains(n, "reviews") || strings.Contains(n, "baseline") {
		t.Errorf("the near-miss table holds legitimate requests:\n%s", n)
	}
	headline := section(t, md, "### Headline (held-out)")
	contains(t, headline, "- False positive rate (blocked or flagged): 66.7% (2 of 3 legitimate requests)",
		"by source and category")

	// A configuration without near-misses says so.
	none := Report{Configs: []Config{BuildConfig("none", []cases.Case{own}, nil)}}.Markdown()
	contains(t, section(t, none, "### Near-miss requests blocked or flagged, by source and category"), "No cases.")
}

func TestExplanationStatesTheSplit(t *testing.T) {
	t.Parallel()
	contains(t, unwrapped(Report{}.Markdown()),
		"SHA-256", "30%", "unsalted", "not a secret", "generated traffic included",
		"a rule whose action is monitor")
}

// A report of a load run alone says nothing about rates it does not hold.
func TestLoadOnlyReport(t *testing.T) {
	t.Parallel()
	md := Report{Load: loadResult()}.Markdown()
	if strings.Contains(md, "rates above") || strings.Contains(md, "## Configuration") {
		t.Errorf("a load report speaks of rates it does not hold:\n%s", md)
	}
	contains(t, unwrapped(md), "enters no detection or false positive rate")
}

// The report says why cases were not sent, without naming them.
func TestNotSentReasons(t *testing.T) {
	t.Parallel()
	cs := inSplit(t, cases.SplitHeldOut, "ns", cases.Attack, 4)
	rs := []run.Result{
		{CaseID: cs[0].ID, Outcome: run.NotSent, Reason: "cannot frame"},
		{CaseID: cs[1].ID, Outcome: run.NotSent, Reason: "cannot frame"},
		{CaseID: cs[2].ID, Outcome: run.Passed, Reason: "a remark on a sent case"},
		// cs[3] has no result.
	}
	cfg := BuildConfig("none", cs, rs)
	want := []ReasonCount{{"cannot frame", 2}, {"no result for the case", 1}}
	if !slices.Equal(cfg.NotSentReasons, want) {
		t.Errorf("reasons %+v, want %+v", cfg.NotSentReasons, want)
	}
	md := Report{Configs: []Config{cfg}}.Markdown()
	s := section(t, md, "### Why cases were not sent")
	contains(t, s, "| cannot frame | 2 |", "| no result for the case | 1 |")
	contains(t, unwrapped(s), "says nothing about the firewall")
	if strings.Contains(s, cs[0].ID[:12]) || strings.Contains(md, "a remark") {
		t.Errorf("unexpected text:\n%s", md)
	}
	all := Report{Configs: []Config{BuildConfig("none", cs[2:3], rs)}}.Markdown()
	if strings.Contains(all, "### Why cases were not sent") {
		t.Errorf("every case was sent:\n%s", all)
	}
}
