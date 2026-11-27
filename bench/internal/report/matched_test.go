package report

import (
	"slices"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/run"
)

// A detection is counted by the families of the rules that matched.
func TestDetectionsByWhatMatched(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		outcome run.Outcome
		rules   []string
		want    Matched
	}{
		{"content rule", run.Blocked, []string{"AEG-SQLI-001"}, Matched{Content: 1}},
		{"content with protocol", run.Blocked, []string{"AEG-PROTO-011", "AEG-XSS-001"}, Matched{Content: 1}},
		{"content with scanner and schema", run.Blocked,
			[]string{"AEG-SCANNER-001", "AEG-SCHEMA-002", "AEG-XXE-001"}, Matched{Content: 1}},
		{"protocol only", run.Blocked, []string{"AEG-PROTO-002"}, Matched{ProtocolOnly: 1}},
		{"protocol beside a route rule", run.Blocked, []string{"AEG-PROTO-002", "AEG-ROUTE-001"},
			Matched{ProtocolOnly: 1}},
		{"flagged by a limit rule", run.Flagged, []string{"AEG-PROTO-020", "AEG-ROUTE-001"},
			Matched{ProtocolOnly: 1}},
		{"schema only", run.Blocked, []string{"AEG-ROUTE-001", "AEG-SCHEMA-001"}, Matched{SchemaOnly: 1}},
		{"scanner only", run.Blocked, []string{"AEG-SCANNER-002"}, Matched{ScannerOnly: 1}},
		{"two other families", run.Flagged, []string{"AEG-PROTO-010", "AEG-SCHEMA-002"}, Matched{Other: 1}},
		{"route rule alone blocks", run.Blocked, []string{"AEG-ROUTE-001"}, Matched{Other: 1}},
		{"no rule", run.Blocked, nil, Matched{Other: 1}},
		{"a family this package does not know", run.Blocked, []string{"AEG-NEWKIND-001"}, Matched{Other: 1}},
		{"passed", run.Passed, nil, Matched{}},
		{"route only", run.RouteOnly, []string{"AEG-ROUTE-001"}, Matched{}},
		{"unknown", run.Unknown, []string{"AEG-SQLI-001"}, Matched{}},
		{"rejected", run.Rejected, nil, Matched{}},
	}
	for _, tt := range tests {
		for _, expected := range []cases.Expected{cases.Attack, cases.Legit, cases.NearMiss} {
			cs := inSplit(t, cases.SplitHeldOut, "m", expected, 1)
			cfg := BuildConfig("none", cs, answered(cs, tt.outcome, tt.rules...))
			for _, source := range []string{TotalSource, "third"} {
				if got := countsOf(cfg, source, cases.SplitHeldOut, expected).Matched; got != tt.want {
					t.Errorf("%s (%s, source %q): matched = %+v, want %+v", tt.name, expected, source, got, tt.want)
				}
			}
		}
	}
}

func TestMatchedPartsAddUpAndAreShown(t *testing.T) {
	t.Parallel()
	attacks := inSplit(t, cases.SplitHeldOut, "secret-attack", cases.Attack, 10)
	legit := inSplit(t, cases.SplitHeldOut, "secret-legit", cases.Legit, 30)[10:]
	var rs []run.Result
	rs = append(rs, answered(attacks[0:3], run.Blocked, "AEG-SQLI-001")...)
	rs = append(rs, answered(attacks[3:5], run.Blocked, "AEG-PROTO-002")...)
	rs = append(rs, answered(attacks[5:6], run.Blocked, "AEG-SCHEMA-001")...)
	rs = append(rs, answered(attacks[6:7], run.Blocked, "AEG-SCANNER-001")...)
	rs = append(rs, answered(attacks[7:8], run.Blocked)...)
	rs = append(rs, answered(attacks[8:], run.Passed)...)
	rs = append(rs, answered(legit[0:1], run.Blocked, "AEG-CMDI-001")...)
	rs = append(rs, answered(legit[1:4], run.Blocked, "AEG-SCHEMA-002")...)
	rs = append(rs, answered(legit[4:], run.Passed)...)

	cfg := BuildConfig("none", slices.Concat(attacks, legit), rs)

	for _, r := range cfg.Rows {
		m := r.Counts.Matched
		if sum := m.Content + m.ProtocolOnly + m.SchemaOnly + m.ScannerOnly + m.Other; sum != r.Counts.detected() {
			t.Errorf("row %+v: the parts add up to %d, not %d", r, sum, r.Counts.detected())
		}
	}
	md := Report{Configs: []Config{cfg}}.Markdown()
	contains(t, section(t, md, "### Headline (held-out)"),
		"- Detection rate (blocked or flagged): 80.0% (8 of 10 attacks)\n"+
			"  - What matched in those 8: a content rule in 3, protocol rules only in 2, schema rules only in 1, "+
			"scanner rules only in 1, anything else in 1\n"+
			"  - Detected with a content rule: 30.0% (3 of 10 attacks)\n",
		"- False positive rate (blocked or flagged): 20.0% (4 of 20 legitimate requests)\n"+
			"  - What matched in those 4: a content rule in 1, protocol rules only in 0, schema rules only in 3, "+
			"scanner rules only in 0, anything else in 0\n"+
			"  - Blocked or flagged with a content rule: 5.0% (1 of 20 legitimate requests)\n")
	const columns = "| Blocked rate | Blocked or flagged rate | Content rule rate | Content rule | Protocol only | " +
		"Schema only | Scanner only | Other |"
	const attackCells = " 10 | 8 | 0 | 0 | 2 | 0 | 0 | 0 | 80.0% | 80.0% | 30.0% | 3 | 2 | 1 | 1 | 1 |"
	for heading, row := range map[string]string{
		"### Totals (each case counted once)": "| held-out | attack |",
		"### By source":                       "| third | held-out | attack |",
		"### By source and category":          "| third | sqli | held-out | attack |",
	} {
		contains(t, section(t, md, heading), columns, row+attackCells)
	}
	// The report says what the five parts are, and what they cannot show.
	contains(t, unwrapped(md),
		"SQLI, XSS, CMDI, CODEI, LDAP, SSTI, JNDI, CRLF, LFI, RFI, SSRF, XXE, NOSQL, PPOLL or SESSION",
		"AEG-PROTO-*", "AEG-SCHEMA-*", "AEG-SCANNER-*",
		"the first blocking match ends the inspection",
		"does not say that no content rule would have matched")
	for _, name := range []string{"secret-attack", "secret-legit", "secret-payload"} {
		if strings.Contains(md, name) {
			t.Errorf("a held-out case is named (%q)", name)
		}
	}
}

// The rules behind protocol-only detections are counted, so that a reader sees
// how many are refusals of a content type.
func TestProtocolOnlyDetectionsByRule(t *testing.T) {
	t.Parallel()
	held := inSplit(t, cases.SplitHeldOut, "secret-held", cases.Attack, 4)
	dev := inSplit(t, cases.SplitDev, "d", cases.Attack, 2)
	legit := inSplit(t, cases.SplitDev, "l", cases.Legit, 3)[2:]
	rs := slices.Concat(
		answered(held[0:2], run.Blocked, "AEG-PROTO-002"),
		answered(held[2:3], run.Flagged, "AEG-PROTO-010", "AEG-PROTO-011", "AEG-ROUTE-001"),
		answered(held[3:], run.Blocked, "AEG-PROTO-002", "AEG-SQLI-001"), // a content rule: not counted here
		answered(dev[0:1], run.Blocked, "AEG-PROTO-002"),
		answered(dev[1:], run.Blocked, "AEG-PROTO-005"),
		answered(legit, run.Blocked, "AEG-PROTO-002"),
	)

	cfg := BuildConfig("none", slices.Concat(held, dev, legit), rs)

	md := Report{Configs: []Config{cfg}}.Markdown()
	got := section(t, md, "### Protocol-only detections by rule")
	contains(t, got,
		"| Rule | Expected | Held-out | Development | All splits |",
		"| AEG-PROTO-002 | attack | 2 | 1 | 3 |",
		"| AEG-PROTO-005 | attack | 0 | 1 | 1 |",
		"| AEG-PROTO-010 | attack | 1 | 0 | 1 |",
		"| AEG-PROTO-011 | attack | 1 | 0 | 1 |",
		"| AEG-PROTO-002 | legit | 0 | 1 | 1 |")
	for _, wrong := range []string{"AEG-SQLI", "AEG-ROUTE", "secret-"} {
		if strings.Contains(got, wrong) {
			t.Errorf("%q is in the table:\n%s", wrong, got)
		}
	}
	empty := BuildConfig("none", dev, answered(dev, run.Passed))
	contains(t, section(t, Report{Configs: []Config{empty}}.Markdown(), "### Protocol-only detections by rule"),
		"None.")
}
