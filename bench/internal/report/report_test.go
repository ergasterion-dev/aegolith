package report

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/run"
)

// newCase builds the case of one request. query tells requests apart.
func newCase(t *testing.T, source, id string, expected cases.Expected, query, payload string) cases.Case {
	t.Helper()
	c, err := cases.FromLine(cases.Line{
		Name: id, Category: "sqli", Method: "GET", Path: "/x", RawQuery: query,
		Source: source, SourceCaseID: id, Expected: expected, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// payloads returns n distinct payloads that put a third-party case in split.
func payloads(t *testing.T, split string, n int) []string {
	t.Helper()
	var out []string
	for i := 0; len(out) < n; i++ {
		p := fmt.Sprintf("secret-payload-%d", i)
		if cases.Split(newCase(t, "third", "x", cases.Attack, "q=x", p)) == split {
			out = append(out, p)
		}
	}
	return out
}

// inSplit returns n third-party cases of one split, named prefix-0 onwards.
func inSplit(t *testing.T, split, prefix string, expected cases.Expected, n int) []cases.Case {
	t.Helper()
	var out []cases.Case
	for i, p := range payloads(t, split, n) {
		id := fmt.Sprintf("%s-%d", prefix, i)
		out = append(out, newCase(t, "third", id, expected, "q="+id, p))
	}
	return out
}

// answered gives every case the same outcome.
func answered(cs []cases.Case, o run.Outcome, rules ...string) []run.Result {
	var out []run.Result
	for _, c := range cs {
		out = append(out, run.Result{CaseID: c.ID, Outcome: o, Rules: rules})
	}
	return out
}

// total returns the counts of the cases of one split and expectation, each
// case counted once.
func total(c Config, split string, expected cases.Expected) Counts {
	return countsOf(c, TotalSource, split, expected)
}

func countsOf(c Config, source, split string, expected cases.Expected) Counts {
	var out Counts
	for _, r := range c.Rows {
		if r.Source == source && r.Split == split && r.Expected == expected {
			out.add(r.Counts)
		}
	}
	return out
}

func asJSON(t *testing.T, r Report) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func contains(t *testing.T, text string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in:\n%s", want, text)
		}
	}
}

func TestRatesExcludeRejectedAndUnknown(t *testing.T) {
	t.Parallel()
	cs := inSplit(t, cases.SplitHeldOut, "a", cases.Attack, 17)
	var rs []run.Result
	rs = append(rs, answered(cs[:6], run.Blocked)...)
	rs = append(rs, answered(cs[6:8], run.Passed)...)
	rs = append(rs, answered(cs[8:13], run.Rejected)...)
	rs = append(rs, answered(cs[13:16], run.Unknown)...)
	rs = append(rs, answered(cs[16:], run.NotSent)...)

	cfg := BuildConfig("none", cs, rs)

	got := total(cfg, cases.SplitHeldOut, cases.Attack)
	want := Counts{Sent: 16, Blocked: 6, Passed: 2, Rejected: 5, Unknown: 3, NotSent: 1, Matched: Matched{Other: 6}}
	if got != want {
		t.Errorf("counts = %+v, want %+v", got, want)
	}
	if rate := got.DetectionRate(); rate != 0.75 {
		t.Errorf("detection rate = %v, want 0.75", rate)
	}
	contains(t, Report{Configs: []Config{cfg}}.Markdown(),
		"- Blocked rate: 75.0% (6 of 8 attacks)",
		"- Detection rate (blocked or flagged): 75.0% (6 of 8 attacks)",
		"- False positive rate (blocked or flagged): n/a (no legitimate request judged)",
		"- Attacks outside the rates: 5 rejected, 3 unknown, 1 not sent")
}

func TestHeadlineCountsFlaggedAndRouteOnly(t *testing.T) {
	t.Parallel()
	attacks := inSplit(t, cases.SplitHeldOut, "a", cases.Attack, 4)
	legit := inSplit(t, cases.SplitHeldOut, "l", cases.Legit, 8)[4:]
	// Development cases must not reach the headline.
	dev := inSplit(t, cases.SplitDev, "d", cases.Attack, 3)
	var rs []run.Result
	for i, o := range []run.Outcome{run.Blocked, run.Flagged, run.RouteOnly, run.Passed} {
		rs = append(rs, answered(attacks[i:i+1], o)...)
		rs = append(rs, answered(legit[i:i+1], o)...)
	}
	rs = append(rs, answered(dev, run.Blocked)...)

	md := Report{Configs: []Config{BuildConfig("none", slices.Concat(attacks, legit, dev), rs)}}.Markdown()

	contains(t, md,
		"- Blocked rate: 25.0% (1 of 4 attacks)",
		"- Detection rate (blocked or flagged): 50.0% (2 of 4 attacks)",
		"- False positive rate (blocked or flagged): 50.0% (2 of 4 legitimate requests)",
		"unsalted", "not a secret")
}

func TestRateOfNothingIsZero(t *testing.T) {
	t.Parallel()
	if rate := (Counts{Sent: 2, Rejected: 1, Unknown: 1}).DetectionRate(); rate != 0 {
		t.Errorf("rate = %v, want 0", rate)
	}
}

func TestCaseWithoutResultIsNotSent(t *testing.T) {
	t.Parallel()
	cs := inSplit(t, cases.SplitDev, "a", cases.Attack, 3)
	rs := []run.Result{
		{CaseID: cs[0].ID, Outcome: run.Blocked},
		{CaseID: cs[0].ID, Outcome: run.Passed},              // a repeat changes nothing
		{CaseID: cs[1].ID, Outcome: run.Outcome("whatever")}, // not an outcome
		{CaseID: "no-such-case", Outcome: run.Blocked},
	}
	got := total(BuildConfig("none", cs, rs), cases.SplitDev, cases.Attack)
	want := Counts{Sent: 2, Blocked: 1, Unknown: 1, NotSent: 1, Matched: Matched{Other: 1}}
	if got != want {
		t.Errorf("counts = %+v, want %+v", got, want)
	}
}

func TestListsHoldDevAndBaselineOnly(t *testing.T) {
	t.Parallel()
	dev := inSplit(t, cases.SplitDev, "dev-attack", cases.Attack, 4)
	base := newCase(t, cases.SourceBaseline, "attack/own", cases.Attack, "q=own", "")
	legit := inSplit(t, cases.SplitDev, "dev-legit", cases.Legit, 8)[4:]
	var rs []run.Result
	for i, o := range []run.Outcome{run.Blocked, run.RouteOnly, run.Passed, run.Rejected} {
		rs = append(rs, answered(dev[i:i+1], o, "AEG-ROUTE-001")...)
	}
	for i, o := range []run.Outcome{run.Blocked, run.Flagged, run.RouteOnly, run.Passed} {
		rs = append(rs, answered(legit[i:i+1], o, "AEG-SQLI-001")...)
	}
	rs = append(rs, answered([]cases.Case{base}, run.Passed)...)

	cfg := BuildConfig("none", slices.Concat(dev, legit, []cases.Case{base}), rs)

	names := func(ls []Listed) []string {
		var out []string
		for _, l := range ls {
			out = append(out, l.Source+" "+l.SourceCaseID)
		}
		return out
	}
	wantMissed := []string{"baseline attack/own", "third dev-attack-1", "third dev-attack-2"}
	if got := names(cfg.Missed); !slices.Equal(got, wantMissed) {
		t.Errorf("missed = %v, want %v", got, wantMissed)
	}
	wantFlagged := []string{"third dev-legit-4", "third dev-legit-5"}
	if got := names(cfg.FlaggedLegit); !slices.Equal(got, wantFlagged) {
		t.Errorf("flagged legit = %v, want %v", got, wantFlagged)
	}
	if first := cfg.FlaggedLegit[0]; first.CaseID != legit[0].ID || first.Category != "sqli" ||
		!slices.Equal(first.Rules, []string{"AEG-SQLI-001"}) {
		t.Errorf("flagged legit entry = %+v", first)
	}
	md := Report{Configs: []Config{cfg}}.Markdown()
	contains(t, md, "dev-attack-1", "dev-legit-4", "attack/own", base.ID[:12], "AEG-SQLI-001")
	for _, secret := range []string{"secret-payload", "q=own", "q=dev"} {
		if strings.Contains(md, secret) || strings.Contains(asJSON(t, Report{Configs: []Config{cfg}}), secret) {
			t.Errorf("the report repeats the request value %q", secret)
		}
	}
}

func TestHeldOutNeverListed(t *testing.T) {
	t.Parallel()
	held := payloads(t, cases.SplitHeldOut, 4)
	devP := payloads(t, cases.SplitDev, 2)

	attack := newCase(t, "third", "held-attack", cases.Attack, "q=1", held[0])
	legit := newCase(t, "third", "held-legit", cases.Legit, "q=2", held[1])
	// One request, three sources: only one of them knows the held-out
	// payload, and none of their names for it may show.
	shared := []cases.Case{
		newCase(t, cases.SourceBaseline, "held-in-baseline", cases.Attack, "q=3", ""),
		newCase(t, "alpha", "held-in-alpha", cases.Attack, "q=3", devP[0]),
		newCase(t, "third", "held-in-third", cases.Attack, "q=3", held[2]),
	}
	// A source that gives a held-out and a development request one name.
	twin := newCase(t, "third", "twin-name", cases.Attack, "q=4", held[3])
	devTwin := newCase(t, "third", "twin-name", cases.Attack, "q=5", devP[1])

	cs := slices.Concat([]cases.Case{attack, legit}, shared, []cases.Case{twin, devTwin})
	hidden := []cases.Case{attack, legit, shared[0], twin}
	var rs []run.Result
	rs = append(rs, answered([]cases.Case{attack, shared[0], twin, devTwin}, run.Passed, "AEG-ROUTE-001")...)
	rs = append(rs, answered([]cases.Case{legit}, run.Blocked, "AEG-SQLI-001")...)

	cfg := BuildConfig("none", cs, rs)

	if got := total(cfg, cases.SplitHeldOut, cases.Attack).Passed; got != 3 {
		t.Errorf("held-out attacks passed = %d, want 3", got)
	}
	if len(cfg.Missed) != 1 || cfg.Missed[0].CaseID != devTwin.ID || len(cfg.FlaggedLegit) != 0 {
		t.Fatalf("missed = %+v, flagged = %+v; want the development case only", cfg.Missed, cfg.FlaggedLegit)
	}
	if l := cfg.Missed[0]; l.Source != "third" || l.SourceCaseID != "" {
		t.Errorf("entry = %+v, want a source without the name it shares with a held-out case", l)
	}

	// The previous report knew the baseline case before a third-party source
	// held it out, so it listed it.
	before := BuildConfig("none", shared[:1], answered(shared[:1], run.Passed))
	if len(before.Missed) != 1 {
		t.Fatalf("previous missed = %+v, want the baseline case", before.Missed)
	}
	r := Report{Configs: []Config{cfg}}
	outputs := map[string]string{
		"markdown":             r.Markdown(),
		"JSON":                 asJSON(t, r),
		"diff":                 Diff(Report{Configs: []Config{before}}, r),
		"diff against nothing": Diff(Report{}, r),
		"diff of a removal":    Diff(Report{Configs: []Config{before}}, Report{}),
	}
	names := []string{"held-attack", "held-legit", "held-in-", "twin-name", "secret-payload"}
	for _, c := range hidden {
		names = append(names, c.ID[:12])
	}
	for kind, out := range outputs {
		for _, name := range names {
			if strings.Contains(out, name) {
				t.Errorf("%s names the held-out %q:\n%s", kind, name, out)
			}
		}
	}
}

func TestNearMissNotInFalsePositiveRate(t *testing.T) {
	t.Parallel()
	held := inSplit(t, cases.SplitHeldOut, "l", cases.Legit, 4)
	near := inSplit(t, cases.SplitHeldOut, "n", cases.NearMiss, 7)[4:]
	devNear := inSplit(t, cases.SplitDev, "dn", cases.NearMiss, 2)
	rs := slices.Concat(answered(held, run.Passed), answered(near, run.Blocked), answered(devNear, run.Blocked))

	cfg := BuildConfig("none", slices.Concat(held, near, devNear), rs)

	if got := total(cfg, cases.SplitHeldOut, cases.Legit); got != (Counts{Sent: 4, Passed: 4}) {
		t.Errorf("legit counts = %+v, want four passed", got)
	}
	if got := total(cfg, cases.SplitHeldOut, cases.NearMiss); got != (Counts{Sent: 3, Blocked: 3, Matched: Matched{Other: 3}}) {
		t.Errorf("near-miss counts = %+v, want three blocked", got)
	}
	if len(cfg.FlaggedLegit) != 0 || len(cfg.Missed) != 0 {
		t.Errorf("flagged = %+v, missed = %+v; a near-miss is neither", cfg.FlaggedLegit, cfg.Missed)
	}
	contains(t, Report{Configs: []Config{cfg}}.Markdown(),
		"- False positive rate (blocked or flagged): 0.0% (0 of 4 legitimate requests)",
		"near-miss")
}

func TestMultiSourceCountedOnceInTotal(t *testing.T) {
	t.Parallel()
	p := payloads(t, cases.SplitDev, 1)[0]
	cs := []cases.Case{
		newCase(t, "alpha", "a-1", cases.Attack, "q=1", p),
		newCase(t, "alpha", "a-2", cases.Attack, "q=1", p),
		newCase(t, "beta", "b-1", cases.Attack, "q=1", p),
		newCase(t, cases.SourceBaseline, "attack/own", cases.Attack, "q=1", ""),
	}

	cfg := BuildConfig("none", cs, answered(cs[:1], run.Passed))

	one := Counts{Sent: 1, Passed: 1}
	for _, source := range []string{TotalSource, "alpha", "beta", cases.SourceBaseline} {
		if got := countsOf(cfg, source, cases.SplitDev, cases.Attack); got != one {
			t.Errorf("source %q: counts = %+v, want %+v", source, got, one)
		}
	}
	if len(cfg.Rows) != 4 {
		t.Errorf("%d rows, want one per source and one total: %+v", len(cfg.Rows), cfg.Rows)
	}
	if len(cfg.Missed) != 1 {
		t.Errorf("missed = %+v, want the case once", cfg.Missed)
	}
}

func TestPayloadAnyAll(t *testing.T) {
	t.Parallel()
	p := payloads(t, cases.SplitDev, 3)
	// at builds one placement of a payload and its outcome.
	type placement struct {
		query, payload string
		expected       cases.Expected
		outcome        run.Outcome
	}
	attack := func(query, payload string, o run.Outcome) placement {
		return placement{query, payload, cases.Attack, o}
	}
	tests := []struct {
		name               string
		placements         []placement
		payloads, any, all int
	}{
		{"one of two detected", []placement{attack("a", p[0], run.Blocked), attack("b", p[0], run.Passed)}, 1, 1, 0},
		{"route only is no detection", []placement{attack("a", p[0], run.Flagged), attack("b", p[0], run.RouteOnly)}, 1, 1, 0},
		{"both detected", []placement{attack("a", p[0], run.Blocked), attack("b", p[0], run.Flagged)}, 1, 1, 1},
		{"none detected", []placement{attack("a", p[0], run.Passed)}, 1, 0, 0},
		{"unjudged placements left out", []placement{
			attack("a", p[0], run.Blocked), attack("b", p[0], run.Rejected),
			attack("c", p[0], run.Unknown), attack("d", p[0], run.NotSent),
			attack("e", p[1], run.Rejected),
		}, 1, 1, 1},
		// One request that two sources give two payloads for.
		{"each payload of a case", []placement{
			attack("a", p[0], run.Blocked), attack("a", p[1], run.Blocked), attack("b", p[1], run.Passed),
		}, 2, 2, 1},
		{"only attacks", []placement{
			{"a", p[0], cases.Legit, run.Blocked}, {"b", p[1], cases.NearMiss, run.Blocked},
		}, 0, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var cs []cases.Case
			var rs []run.Result
			for i, pl := range tt.placements {
				c := newCase(t, fmt.Sprintf("s%d", i), "id", pl.expected, pl.query, pl.payload)
				cs = append(cs, c)
				rs = append(rs, run.Result{CaseID: c.ID, Outcome: pl.outcome})
			}
			got := BuildConfig("none", cs, rs)
			if got.Payloads != tt.payloads || got.PayloadsAny != tt.any || got.PayloadsAll != tt.all {
				t.Errorf("payloads %d, any %d, all %d; want %d, %d, %d",
					got.Payloads, got.PayloadsAny, got.PayloadsAll, tt.payloads, tt.any, tt.all)
			}
		})
	}
}

func TestDiffShowsRateChange(t *testing.T) {
	t.Parallel()
	attacks := inSplit(t, cases.SplitHeldOut, "a", cases.Attack, 4)
	dev := inSplit(t, cases.SplitDev, "dev", cases.Attack, 2)
	legit := inSplit(t, cases.SplitDev, "ok", cases.Legit, 4)[2:]
	cs := slices.Concat(attacks, dev, legit)
	report := func(commit string, rs ...[]run.Result) Report {
		return Report{
			Meta:    Meta{Commit: commit, Created: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
			Configs: []Config{BuildConfig("typed", cs, slices.Concat(rs...))},
		}
	}
	prev := report("old-commit",
		answered(attacks[:2], run.Blocked), answered(attacks[2:], run.Passed),
		answered(dev[:1], run.Passed), answered(dev[1:], run.Blocked), answered(legit, run.Passed))
	cur := report("new-commit",
		answered(attacks[:3], run.Blocked), answered(attacks[3:], run.Passed),
		answered(dev, run.Passed), answered(legit[:1], run.Blocked), answered(legit[1:], run.Passed))

	diff := Diff(prev, cur)

	contains(t, diff, "old-commit", "2026-01-02T03:04:05Z", "typed",
		"| Blocked rate | 50.0% (2 of 4) | 75.0% (3 of 4) | +25.0 points |",
		"| Detection rate | 50.0% (2 of 4) | 75.0% (3 of 4) | +25.0 points |",
		"| False positive rate | n/a | n/a | n/a |",
		"dev-1", "ok-2")
	if strings.Contains(diff, "dev-0") {
		t.Errorf("a case missed before is not newly missed:\n%s", diff)
	}
	contains(t, Diff(cur, prev), "-25.0 points")
	contains(t, Diff(cur, cur), "| Blocked rate | 75.0% (3 of 4) | 75.0% (3 of 4) | no change |")

	other := Report{Configs: []Config{{Name: "bare"}}}
	contains(t, Diff(other, cur), "Not in the previous report", "bare", "Only in the previous report")

	const warning = "The sources differ"
	if strings.Contains(diff, warning) {
		t.Errorf("the sources are the same:\n%s", diff)
	}
	moved := cur
	moved.Meta.Sources = []SourceInfo{{Name: "third", Commit: "newer", Included: true}}
	contains(t, Diff(prev, moved), warning)
}

// TestDiffWarnsOfChangedInput compares reports whose sources give other
// numbers of case lines at the same pinned versions: the case set changed.
func TestDiffWarnsOfChangedInput(t *testing.T) {
	t.Parallel()
	cs := inSplit(t, cases.SplitDev, "a", cases.Attack, 3)
	withInput := func(cs []cases.Case) Report {
		in := CountInput(cs)
		return Report{Meta: Meta{Input: &in}, Configs: []Config{BuildConfig("none", cs, answered(cs, run.Passed))}}
	}
	const warning = "The case lines differ"
	same := Diff(withInput(cs), withInput(cs))
	if strings.Contains(same, warning) {
		t.Errorf("the same input is reported as changed:\n%s", same)
	}
	fewer := Diff(withInput(cs), withInput(cs[:2]))
	contains(t, fewer, warning, "| third | 3 | 2 | 3 | 2 | 0 | 0 | 0 | 0 |")
	other := []cases.Case{cs[0]}
	other[0].Sources = []cases.SourceRef{{Source: "added", CaseID: "x"}}
	contains(t, Diff(withInput(cs[1:]), withInput(slices.Concat(cs[1:], other))), warning, "| added | 0 | 1 | 0 | 1 |")
	// A report without input counts cannot be compared.
	contains(t, Diff(Report{Configs: withInput(cs).Configs}, withInput(cs)), "does not count its case lines")
}

func TestMarkdownEscapesNames(t *testing.T) {
	t.Parallel()
	c := newCase(t, cases.SourceBaseline, "a|b\n# <script>`x`", cases.Attack, "q=1", "")
	r := Report{
		Meta:    Meta{Sources: []SourceInfo{{Name: "s|t", Included: false, Note: "no\nlicence"}}},
		Configs: []Config{BuildConfig("n\n## forged", []cases.Case{c}, answered([]cases.Case{c}, run.Passed))},
	}
	for _, md := range []string{r.Markdown(), Diff(Report{}, r)} {
		for _, raw := range []string{"a|b", "<script>", "\n## forged", "s|t", "\n# <"} {
			if strings.Contains(md, raw) {
				t.Errorf("%q is not escaped in:\n%s", raw, md)
			}
		}
	}
	contains(t, r.Markdown(), `a\|b`, "&lt;script&gt;", `s\|t`, "no licence", "not recorded")
}

// Rounding must not turn "all but one" into all, or "one" into none.
func TestPercentagesNeverRoundToAllOrNothing(t *testing.T) {
	t.Parallel()
	// report holds attacks of which detected were blocked, and legitimate
	// requests of which flagged were.
	report := func(detected, attacks, flagged, legit int) Report {
		row := func(source string, expected cases.Expected, blocked, all int) Row {
			return Row{Source: source, Split: cases.SplitHeldOut, Expected: expected,
				Counts: Counts{Sent: all, Blocked: blocked, Passed: all - blocked, Matched: Matched{Content: blocked}}}
		}
		return Report{Configs: []Config{{
			Name: "typed",
			Rows: []Row{
				row(TotalSource, cases.Attack, detected, attacks), row(TotalSource, cases.Legit, flagged, legit),
				row("third", cases.Attack, detected, attacks), row("third", cases.Legit, flagged, legit),
			},
			Payloads: attacks, PayloadsAny: detected, PayloadsAll: flagged,
		}}}
	}
	almost := report(2499, 2500, 1, 3000)
	exact := report(2500, 2500, 0, 3000)
	reversed := report(0, 2500, 3000, 3000)

	md := almost.Markdown()
	contains(t, md,
		"- Blocked rate: >99.9% (2499 of 2500 attacks)",
		"- Detection rate (blocked or flagged): >99.9% (2499 of 2500 attacks)",
		"- False positive rate (blocked or flagged): <0.1% (1 of 3000 legitimate requests)",
		"- Blocked or flagged in at least one placement: >99.9% (2499 of 2500)",
		"- Blocked or flagged in every judged placement: <0.1% (1 of 2500)",
		// The totals and both source tables; a cell is escaped.
		"| held-out | attack | 2500 | 2499 | 0 | 0 | 1 | 0 | 0 | 0 | &gt;99.9% | &gt;99.9% | &gt;99.9% | 2499 | 0 | 0 | 0 | 0 |",
		"| held-out | legit | 3000 | 1 | 0 | 0 | 2999 | 0 | 0 | 0 | &lt;0.1% | &lt;0.1% | &lt;0.1% | 1 | 0 | 0 | 0 | 0 |",
		"| third | held-out | attack | 2500 | 2499 | 0 | 0 | 1 | 0 | 0 | 0 | &gt;99.9% | &gt;99.9% | &gt;99.9% | 2499 | 0 | 0 | 0 | 0 |",
		"| third |  | held-out | legit | 3000 | 1 | 0 | 0 | 2999 | 0 | 0 | 0 | &lt;0.1% | &lt;0.1% | &lt;0.1% | 1 | 0 | 0 | 0 | 0 |")
	for _, wrong := range []string{"100.0%", " 0.0%"} {
		if strings.Contains(md, wrong) {
			t.Errorf("%q is shown for a rate that is not:\n%s", wrong, md)
		}
	}

	contains(t, exact.Markdown(),
		"- Blocked rate: 100.0% (2500 of 2500 attacks)",
		"- False positive rate (blocked or flagged): 0.0% (0 of 3000 legitimate requests)",
		"| held-out | attack | 2500 | 2500 | 0 | 0 | 0 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% | 2500 | 0 | 0 | 0 | 0 |",
		"| held-out | legit | 3000 | 0 | 0 | 0 | 3000 | 0 | 0 | 0 | 0.0% | 0.0% | 0.0% | 0 | 0 | 0 | 0 | 0 |")

	contains(t, Diff(exact, almost),
		"| Detection rate | 100.0% (2500 of 2500) | &gt;99.9% (2499 of 2500) | -&lt;0.1 points |",
		"| False positive rate | 0.0% (0 of 3000) | &lt;0.1% (1 of 3000) | +&lt;0.1 points |")
	contains(t, Diff(reversed, almost),
		"| Detection rate | 0.0% (0 of 2500) | &gt;99.9% (2499 of 2500) | +&gt;99.9 points |",
		"| False positive rate | 100.0% (3000 of 3000) | &lt;0.1% (1 of 3000) | -&gt;99.9 points |")
	contains(t, Diff(reversed, exact),
		"| Detection rate | 0.0% (0 of 2500) | 100.0% (2500 of 2500) | +100.0 points |",
		"| False positive rate | 100.0% (3000 of 3000) | 0.0% (0 of 3000) | -100.0 points |")
}

func TestPercentAtTheEdges(t *testing.T) {
	t.Parallel()
	tests := []struct {
		n, all int
		want   string
	}{
		{0, 0, "n/a"}, {0, 1, "0.0%"}, {1, 1, "100.0%"}, {0, 3000, "0.0%"}, {3000, 3000, "100.0%"},
		{1, 3000, "<0.1%"}, {2499, 2500, ">99.9%"}, {1, 1_000_000, "<0.1%"}, {999_999, 1_000_000, ">99.9%"},
		{1, 1000, "0.1%"}, {999, 1000, "99.9%"}, {3, 4, "75.0%"},
	}
	for _, tt := range tests {
		if got := percent(tt.n, tt.all); got != tt.want {
			t.Errorf("percent(%d, %d) = %q, want %q", tt.n, tt.all, got, tt.want)
		}
	}
}

func loadResult() *run.LoadResult {
	return &run.LoadResult{
		RPS: 500, Workers: 64, AttackShare: 0.1, Seed: 7, AttackCases: 230, LegitCases: 195, Excluded: 3,
		IDPrefix: "load-abc-", Sent: 29990, TransportErrors: 4, Attacks: 3010, Dropped: 10,
		ByStatus: map[int]int{403: 3000, 200: 26980, 400: 6},
		P50US:    180, P90US: 420, P99US: 1500, MaxUS: 2_340_000, MaxLagUS: 950,
		HeapStart: 3 << 20, HeapPeak: 9 << 20, HeapEnd: 5 << 20, MemAsked: true, MemPolls: 14, MemPollFailures: 1,
		Conflicting: 2,
		Duration:    time.Minute, AchievedRPS: 499.8333,
	}
}

func TestReportWithoutLoadIsUnchanged(t *testing.T) {
	t.Parallel()
	r := Report{Configs: []Config{BuildConfig("default", nil, nil)}}
	if md := r.Markdown(); strings.Contains(md, "Load") || strings.Contains(md, "round trip") {
		t.Errorf("a report without a load run mentions one:\n%s", md)
	}
	if js := asJSON(t, r); strings.Contains(js, "Load") {
		t.Errorf("report.json without a load run has a Load key: %s", js)
	}
	with := r
	with.Load = loadResult()
	if md := with.Markdown(); !strings.HasPrefix(md, r.Markdown()) {
		t.Error("the load section changes the report before it")
	}
	var back Report
	if err := json.Unmarshal([]byte(asJSON(t, with)), &back); err != nil {
		t.Fatal(err)
	}
	if back.Load == nil || back.Load.Sent != 29990 || back.Load.ByStatus[403] != 3000 || back.Load.Duration != time.Minute {
		t.Errorf("the load result does not survive report.json: %+v", back.Load)
	}
}

func TestLoadSection(t *testing.T) {
	t.Parallel()
	md := Report{Load: loadResult()}.Markdown()
	_, section, found := strings.Cut(md, "\n## Load\n")
	if !found {
		t.Fatalf("no load section in:\n%s", md)
	}
	contains(t, section,
		"asked 500 requests per second; 499.8 per second were sent and 499.8 per second answered over 1m0s",
		"counts requests that ended in a transport error",
		"and 2 because their sources disagree",
		"14 of 30000 scheduled requests are not in these figures",
		"64 workers",
		"10.0% asked (seed 7)",
		"3010 of 29990",
		"230 attack and 195 legitimate cases",
		"3 cases were left out before the run",
		"Sent: 29990 (29986 answered, 4 transport errors)",
		"Dropped: 10",
		"| 200 | 26980 |", "| 400 | 6 |", "| 403 | 3000 |",
		"p50 180 µs, p90 420 µs, p99 1.50 ms, max 2.34 s",
		"not the firewall's decision latency",
		"at most 0.8% above",
		"a request was sent at most 950 µs after its scheduled time",
		"start 3.0 MiB, peak 9.0 MiB, end 5.0 MiB, growth +2.0 MiB",
		"14 readings, 1 failed",
		"Firewall decision latency: not read",
	)
	// Statuses in order.
	if strings.Index(section, "| 200 |") > strings.Index(section, "| 403 |") {
		t.Error("the statuses are not sorted")
	}
	for _, not := range []string{"Interrupted", "interrupted", "refused", "load-abc-"} {
		if strings.Contains(section, not) {
			t.Errorf("a complete run says %q:\n%s", not, section)
		}
	}
}

func TestLoadSectionSaysWhatIsMissing(t *testing.T) {
	t.Parallel()
	l := loadResult()
	l.Interrupted, l.Cancelled, l.NotSent = true, 5, 2
	l.HeapStart, l.HeapPeak, l.HeapEnd, l.MemAsked, l.MemPolls, l.MemPollFailures = 0, 0, 0, false, 0, 0
	l.Decisions = &run.DecisionLatency{Records: 3000, Requests: 2990, Skipped: 2, Other: 7, Unreadable: 1, P50US: 12, P90US: 30, P99US: 61, MaxUS: 4100}
	md := Report{Load: l}.Markdown()
	contains(t, md,
		"The run was interrupted",
		"5 requests were in flight",
		"2 requests were refused by the client",
		"Target heap: not read (no admin URL was given)",
		"Firewall decision latency: p50 12 µs, p90 30 µs, p99 61 µs, max 4.10 ms over 3000 decision records "+
			"from 2990 requests; 29986 requests were answered",
		"21 of 30007 scheduled requests are not in these figures",
		"2 records of requests blocked because inspection failed",
		"7 records of other runs", "1 unreadable line",
	)

	// Readings without the flag are still readings.
	l.MemPolls, l.HeapStart, l.HeapPeak, l.HeapEnd = 3, 1<<20, 1<<20, 1<<20
	if md := (Report{Load: l}).Markdown(); strings.Contains(md, "no admin URL") || !strings.Contains(md, "3 readings") {
		t.Errorf("a result with readings says that no admin URL was given:\n%s", md)
	}

	// Every scheduled request answered: nothing is missing from the percentiles.
	l = loadResult()
	l.Sent, l.Dropped, l.TransportErrors = 30000, 0, 0
	if md := (Report{Load: l}).Markdown(); strings.Contains(md, "are not in these figures") {
		t.Errorf("a run with every request answered says some are missing:\n%s", md)
	}

	// A heap that shrank, and a reading that failed.
	l = loadResult()
	l.HeapStart, l.HeapEnd = 5<<20, 3<<20
	contains(t, Report{Load: l}.Markdown(), "growth -2.0 MiB")
	l.HeapEnd = 0
	contains(t, Report{Load: l}.Markdown(), "start 5.0 MiB, peak 9.0 MiB, end not read, growth n/a")

	// Nothing answered: no latency to show.
	l = loadResult()
	l.ByStatus, l.TransportErrors, l.P50US, l.P90US, l.P99US, l.MaxUS = nil, l.Sent, 0, 0, 0, 0
	contains(t, Report{Load: l}.Markdown(), "Client round trip: no request was answered", "No request was answered.")
	l.Decisions = &run.DecisionLatency{Skipped: 1}
	contains(t, Report{Load: l}.Markdown(), "Firewall decision latency: no decision record of this run has a latency")
}
