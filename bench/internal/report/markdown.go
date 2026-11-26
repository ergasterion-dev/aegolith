package report

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

// shortID is how much of a case ID the Markdown shows; report.json has all of
// it.
const shortID = 12

const notRecorded = "not recorded"

// explanation tells a reader how to read the numbers.
const explanation = `One case is one distinct request. Rates are over the cases the firewall judged
(blocked, flagged, route-only or passed); rejected, unknown and not-sent cases
are left out of them. Flagged means allowed with a content rule matching in
monitor mode. Route-only means that only route rules matched in monitor mode,
which is not counted as a detection. A near-miss resembles an attack without
being one and never enters the false positive rate.

Headline numbers use the held-out set. A third-party case is held out if an
unsalted hash of any of its decoded payloads (of its case ID if it has none)
falls in a fixed 30% range; the other third-party cases are the development
set. This is a reporting discipline, not a secret: anyone can compute which
cases are held out. Held-out cases are counted and never listed. Cases that
only the project's own corpus (baseline) provides are in neither set.
`

// Markdown renders the report.
func (r Report) Markdown() string {
	var b strings.Builder
	b.WriteString("# Aegolith WAF bench report\n\n")
	fmt.Fprintf(&b, "- Aegolith commit: %s\n- Created: %s\n\n",
		cell(orNotRecorded(r.Meta.Commit)), created(r.Meta.Created))
	b.WriteString(explanation)

	b.WriteString("\n## Sources\n\n")
	if len(r.Meta.Sources) == 0 {
		b.WriteString("None recorded.\n")
	} else {
		header(&b, "Source", "Commit", "Licence", "Included", "Note")
		for _, s := range r.Meta.Sources {
			included := "no"
			if s.Included {
				included = "yes"
			}
			row(&b, s.Name, orNotRecorded(s.Commit), orNotRecorded(s.License), included, s.Note)
		}
	}
	for _, c := range r.Configs {
		c.markdown(&b)
	}
	return b.String()
}

func (c Config) markdown(b *strings.Builder) {
	fmt.Fprintf(b, "\n## Configuration: %s\n", cell(c.Name))

	attacks, legit := c.heldOut(cases.Attack), c.heldOut(cases.Legit)
	b.WriteString("\n### Headline (held-out)\n\n")
	fmt.Fprintf(b, "- Blocked rate: %s\n", described(attacks.Blocked, attacks.judged(), "attack"))
	fmt.Fprintf(b, "- Detection rate (blocked or flagged): %s\n",
		described(attacks.detected(), attacks.judged(), "attack"))
	fmt.Fprintf(b, "- False positive rate (blocked or flagged): %s\n",
		described(legit.detected(), legit.judged(), "legitimate request"))
	fmt.Fprintf(b, "- Attacks outside the rates: %s\n", outside(attacks))
	fmt.Fprintf(b, "- Legitimate requests outside the rates: %s\n", outside(legit))

	b.WriteString("\n### Totals (each case counted once)\n\n")
	countTable(b, []string{"Split", "Expected"}, c.grouped(true, func(r Row) []string {
		return []string{r.Split, string(r.Expected)}
	}))
	b.WriteString("\nA case with several sources is counted under each of them below.\n")
	b.WriteString("\n### By source\n\n")
	countTable(b, []string{"Source", "Split", "Expected"}, c.grouped(false, func(r Row) []string {
		return []string{r.Source, r.Split, string(r.Expected)}
	}))
	b.WriteString("\n### By source and category\n\n")
	countTable(b, []string{"Source", "Category", "Split", "Expected"}, c.grouped(false, func(r Row) []string {
		return []string{r.Source, r.Category, r.Split, string(r.Expected)}
	}))

	b.WriteString("\n### Distinct attack payloads (all splits)\n\n")
	if c.Payloads == 0 {
		b.WriteString("No judged attack case carries a payload.\n")
	} else {
		fmt.Fprintf(b, "- Judged in at least one case: %d\n", c.Payloads)
		fmt.Fprintf(b, "- Blocked or flagged in at least one placement: %s\n", fraction(c.PayloadsAny, c.Payloads))
		fmt.Fprintf(b, "- Blocked or flagged in every judged placement: %s\n", fraction(c.PayloadsAll, c.Payloads))
	}

	b.WriteString("\n### Missed attacks (development and baseline)\n\n")
	listTable(b, c.Missed)
	b.WriteString("\n### Flagged legitimate requests (development and baseline)\n\n")
	listTable(b, c.FlaggedLegit)
}

// heldOut returns the held-out total of the cases with one expectation.
func (c Config) heldOut(expected cases.Expected) Counts {
	var out Counts
	for _, r := range c.Rows {
		if r.Source == TotalSource && r.Split == cases.SplitHeldOut && r.Expected == expected {
			out.add(r.Counts)
		}
	}
	return out
}

// group is one line of a count table.
type group struct {
	labels []string
	counts Counts
}

// grouped adds up the total rows, or the others, that have the same labels, in
// the order in which the labels first appear.
func (c Config) grouped(totals bool, labels func(Row) []string) []group {
	var out []group
	for _, r := range c.Rows {
		if (r.Source == TotalSource) != totals {
			continue
		}
		l := labels(r)
		i := slices.IndexFunc(out, func(g group) bool { return slices.Equal(g.labels, l) })
		if i < 0 {
			i = len(out)
			out = append(out, group{labels: l})
		}
		out[i].counts.add(r.Counts)
	}
	return out
}

func countTable(b *strings.Builder, labels []string, groups []group) {
	if len(groups) == 0 {
		b.WriteString("No cases.\n")
		return
	}
	header(b, append(slices.Clone(labels), "Sent", "Blocked", "Flagged", "Route only", "Passed",
		"Rejected", "Unknown", "Not sent", "Blocked rate", "Blocked or flagged rate")...)
	for _, g := range groups {
		n := g.counts
		cells := slices.Clone(g.labels)
		for _, v := range []int{n.Sent, n.Blocked, n.Flagged, n.RouteOnly, n.Passed, n.Rejected, n.Unknown, n.NotSent} {
			cells = append(cells, fmt.Sprint(v))
		}
		row(b, append(cells, percent(n.Blocked, n.judged()), percent(n.detected(), n.judged()))...)
	}
}

func listTable(b *strings.Builder, ls []Listed) {
	if len(ls) == 0 {
		b.WriteString("None.\n")
		return
	}
	header(b, "Case", "Source", "Source case", "Category", "Rules")
	for _, l := range ls {
		row(b, l.CaseID[:min(len(l.CaseID), shortID)], l.Source, l.SourceCaseID, l.Category,
			strings.Join(l.Rules, ", "))
	}
}

// Diff renders what changed from prev to cur, configuration by configuration.
// It names only cases that cur lists: a case prev lists may be held out by
// now.
func Diff(prev, cur Report) string {
	var b strings.Builder
	b.WriteString("## Changes since the previous report\n\n")
	fmt.Fprintf(&b, "Previous report: commit %s, created %s.\n",
		cell(orNotRecorded(prev.Meta.Commit)), created(prev.Meta.Created))
	if !slices.Equal(sourceVersions(prev), sourceVersions(cur)) {
		b.WriteString("The sources differ between the two reports, so the rates are not over the same cases.\n")
	}
	for _, c := range cur.Configs {
		fmt.Fprintf(&b, "\n### Configuration: %s\n\n", cell(c.Name))
		i := indexOf(prev.Configs, c.Name)
		if i < 0 {
			b.WriteString("Not in the previous report.\n")
			continue
		}
		diffConfig(&b, prev.Configs[i], c)
	}
	for _, c := range prev.Configs {
		if indexOf(cur.Configs, c.Name) < 0 {
			fmt.Fprintf(&b, "\n### Configuration: %s\n\nOnly in the previous report.\n", cell(c.Name))
		}
	}
	return b.String()
}

func indexOf(cs []Config, name string) int {
	return slices.IndexFunc(cs, func(c Config) bool { return c.Name == name })
}

func sourceVersions(r Report) []string {
	var out []string
	for _, s := range r.Meta.Sources {
		if s.Included {
			out = append(out, s.Name+"\x00"+s.Commit)
		}
	}
	slices.Sort(out)
	return out
}

func diffConfig(b *strings.Builder, prev, cur Config) {
	pa, ca := prev.heldOut(cases.Attack), cur.heldOut(cases.Attack)
	pl, cl := prev.heldOut(cases.Legit), cur.heldOut(cases.Legit)
	header(b, "Measure (held-out unless said)", "Previous", "Current", "Change")
	rate := func(name string, pn, pall, cn, call int) {
		change := "n/a"
		if pall > 0 && call > 0 {
			change = "no change"
			if before, after := share(pn, pall), share(cn, call); before != after {
				change = points(100 * (after - before))
			}
		}
		row(b, name, fraction(pn, pall), fraction(cn, call), change)
	}
	number := func(name string, p, c int) {
		change := "no change"
		if p != c {
			change = fmt.Sprintf("%+d", c-p)
		}
		row(b, name, fmt.Sprint(p), fmt.Sprint(c), change)
	}
	rate("Blocked rate", pa.Blocked, pa.judged(), ca.Blocked, ca.judged())
	rate("Detection rate", pa.detected(), pa.judged(), ca.detected(), ca.judged())
	rate("False positive rate", pl.detected(), pl.judged(), cl.detected(), cl.judged())
	number("Attacks rejected", pa.Rejected, ca.Rejected)
	number("Attacks unknown", pa.Unknown, ca.Unknown)
	number("Attacks not sent", pa.NotSent, ca.NotSent)
	number("Legitimate rejected", pl.Rejected, cl.Rejected)
	number("Legitimate unknown", pl.Unknown, cl.Unknown)
	number("Legitimate not sent", pl.NotSent, cl.NotSent)
	number("Attack payloads judged (all splits)", prev.Payloads, cur.Payloads)
	number("Payloads detected in any placement (all splits)", prev.PayloadsAny, cur.PayloadsAny)
	number("Payloads detected in every placement (all splits)", prev.PayloadsAll, cur.PayloadsAll)

	b.WriteString("\nMissed attacks the previous report did not list (development and baseline):\n\n")
	listTable(b, added(prev.Missed, cur.Missed))
	b.WriteString("\nFlagged legitimate requests the previous report did not list (development and baseline):\n\n")
	listTable(b, added(prev.FlaggedLegit, cur.FlaggedLegit))
}

// added returns the cases of cur that prev does not list.
func added(prev, cur []Listed) []Listed {
	before := make(map[string]bool, len(prev))
	for _, l := range prev {
		before[l.CaseID] = true
	}
	return slices.DeleteFunc(slices.Clone(cur), func(l Listed) bool { return before[l.CaseID] })
}

// percent is n of all as a percentage, or "n/a" when all is 0. It reads 0.0%
// only when n is 0 and 100.0% only when n is all.
func percent(n, all int) string {
	switch {
	case all == 0:
		return "n/a"
	case n == 0:
		return "0.0%"
	case n == all:
		return "100.0%"
	}
	return between(100*share(n, all)) + "%"
}

// points is a change between two rates that differ, in percentage points. It
// reads 100.0 only for a change from none to all or back.
func points(change float64) string {
	sign := "+"
	if change < 0 {
		sign = "-"
	}
	size := math.Abs(change)
	if size == 100 {
		return sign + "100.0 points"
	}
	return sign + between(size) + " points"
}

// between writes a number above 0 and below 100 with one decimal, as a bound
// where rounding would reach either end.
func between(v float64) string {
	switch s := fmt.Sprintf("%.1f", v); s {
	case "0.0":
		return "<0.1"
	case "100.0":
		return ">99.9"
	default:
		return s
	}
}

// fraction is percent with the numbers behind it.
func fraction(n, all int) string {
	if all == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%s (%d of %d)", percent(n, all), n, all)
}

// described is fraction for a headline, naming what was counted.
func described(n, all int, what string) string {
	if all == 0 {
		return fmt.Sprintf("n/a (no %s judged)", what)
	}
	return fmt.Sprintf("%s (%d of %d %ss)", percent(n, all), n, all, what)
}

func outside(c Counts) string {
	return fmt.Sprintf("%d rejected, %d unknown, %d not sent", c.Rejected, c.Unknown, c.NotSent)
}

func created(t time.Time) string {
	if t.IsZero() {
		return notRecorded
	}
	return t.UTC().Format(time.RFC3339)
}

func orNotRecorded(s string) string {
	if s == "" {
		return notRecorded
	}
	return s
}

func header(b *strings.Builder, names ...string) {
	row(b, names...)
	b.WriteString(strings.Repeat("|---", len(names)) + "|\n")
}

// row writes one table row, escaping every cell.
func row(b *strings.Builder, cells ...string) {
	b.WriteString("|")
	for _, c := range cells {
		b.WriteString(" " + cell(c) + " |")
	}
	b.WriteString("\n")
}

// markup replaces what Markdown or HTML would act on.
var markup = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`,
	"|", `\|`, "#", `\#`, "~", `\~`, "&", "&amp;", "<", "&lt;", ">", "&gt;",
)

// cell makes text from a source or a file safe to put on one line of
// Markdown.
func cell(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
	return markup.Replace(s)
}
