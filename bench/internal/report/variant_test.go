package report

import (
	"slices"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/run"
)

// sourceCase returns a case as a source writes it with a placement and an
// encoder.
func sourceCase(t *testing.T, source, id, query, payload, placement, encoder string) cases.Case {
	t.Helper()
	c, err := cases.FromLine(cases.Line{
		Name: id, Category: "sqli", Method: "GET", Path: "/x", RawQuery: query,
		Source: source, SourceCaseID: id, Expected: cases.Attack, Payload: payload,
		Placement: placement, Encoder: encoder,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestResultsByEncoderAndPlacement(t *testing.T) {
	t.Parallel()
	p := payloads(t, cases.SplitHeldOut, 3)
	cs := []cases.Case{
		// One request that a source gives under two encoders counts under
		// each, and once under its placement.
		sourceCase(t, "enc", "secret-1", "q=1", p[0], "query", "Plain"),
		sourceCase(t, "enc", "secret-2", "q=1", p[0], "query", "URL"),
		sourceCase(t, "enc", "secret-3", "q=2", p[1], "header", "Base64Flat"),
		sourceCase(t, "enc", "secret-4", "q=3", p[2], "", "Plain"),
		// Another source of the same request has its own placement.
		sourceCase(t, "other", "secret-5", "q=2", p[1], "raw", ""),
		// A source with neither is in neither table.
		sourceCase(t, "bare", "secret-6", "q=4", p[0], "", ""),
	}
	rs := []run.Result{
		{CaseID: cs[0].ID, Outcome: run.Blocked, Rules: []string{"AEG-SQLI-001"}},
		{CaseID: cs[2].ID, Outcome: run.Passed},
		{CaseID: cs[3].ID, Outcome: run.Blocked, Rules: []string{"AEG-PROTO-002"}},
		{CaseID: cs[5].ID, Outcome: run.Passed},
	}

	cfg := BuildConfig("none", cs, rs)

	blocked := Counts{Sent: 1, Blocked: 1, Matched: Matched{Content: 1}}
	passed := Counts{Sent: 1, Passed: 1}
	refused := Counts{Sent: 1, Blocked: 1, Matched: Matched{ProtocolOnly: 1}}
	variant := func(source, value string, n Counts) Variant {
		return Variant{Source: source, Value: value, Split: cases.SplitHeldOut, Expected: cases.Attack, Counts: n}
	}
	encoders := []Variant{
		variant("enc", "Base64Flat", passed),
		variant("enc", "Plain", Counts{Sent: 2, Blocked: 2, Matched: Matched{Content: 1, ProtocolOnly: 1}}),
		variant("enc", "URL", blocked),
	}
	if !slices.Equal(cfg.Encoders, encoders) {
		t.Errorf("encoders = %+v, want %+v", cfg.Encoders, encoders)
	}
	placements := []Variant{
		variant("enc", "", refused),
		variant("enc", "header", passed),
		variant("enc", "query", blocked),
		variant("other", "raw", passed),
	}
	if !slices.Equal(cfg.Placements, placements) {
		t.Errorf("placements = %+v, want %+v", cfg.Placements, placements)
	}

	md := Report{Configs: []Config{cfg}}.Markdown()
	byEncoder := section(t, md, "### By source and encoder")
	contains(t, byEncoder,
		"| Source | Encoder | Split | Expected | Sent | Blocked |",
		"| enc | Plain | held-out | attack | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 100.0% | 100.0% | 50.0% | 1 | 1 | 0 | 0 | 0 |",
		"| enc | Base64Flat | held-out | attack | 1 | 0 | 0 | 0 | 1 |")
	contains(t, unwrapped(byEncoder), "counted under each")
	byPlacement := section(t, md, "### By source and placement")
	contains(t, byPlacement,
		"| Source | Placement | Split | Expected | Sent | Blocked |",
		"| enc | (none named) | held-out | attack | 1 | 1 |",
		"| other | raw | held-out | attack | 1 | 0 | 0 | 0 | 1 |")
	contains(t, unwrapped(byPlacement),
		"counted under each",
		"User-Agent", "Referer", "SSRF", "cookie", "inspect\\_headers", "X-Api-Version",
		"CR, LF and NUL", "Content-Type", "Transfer-Encoding")
	for _, s := range []string{byEncoder, byPlacement} {
		for _, wrong := range []string{"secret-", "| bare |"} {
			if strings.Contains(s, wrong) {
				t.Errorf("%q is in:\n%s", wrong, s)
			}
		}
	}

	plain := inSplit(t, cases.SplitDev, "d", cases.Attack, 1)
	none := Report{Configs: []Config{BuildConfig("none", plain, nil)}}.Markdown()
	contains(t, section(t, none, "### By source and encoder"), "No cases.")
	contains(t, section(t, none, "### By source and placement"), "No cases.")
}

// The report says where base64 is decoded, and how much of the source's
// attacks arrive that way, counted from the case lines.
func TestBase64ShareInSourceNote(t *testing.T) {
	t.Parallel()
	legit := sourceCase(t, "gotestwaf", "l", "q=9", "p9", "query", "Base64")
	legit.Expected = cases.Legit
	cs := []cases.Case{
		sourceCase(t, "gotestwaf", "a1", "q=1", "p1", "query", "Base64Flat"),
		sourceCase(t, "gotestwaf", "a2", "q=2", "p2", "query", "Base64"),
		sourceCase(t, "gotestwaf", "a3", "q=3", "p3", "query", "URL"),
		sourceCase(t, "gotestwaf", "a4", "q=4", "p4", "query", "Plain"),
		sourceCase(t, "gotestwaf", "a5", "q=4", "p4", "query", "URL"), // lines, not requests
		legit,
	}
	in := CountInput(cs)
	if got := in.Sources[0].Base64Attack; got != 2 {
		t.Errorf("base64 attack lines = %d, want 2", got)
	}
	sources := []SourceInfo{{Name: "gotestwaf", Included: true}}
	note := func(in *Input) string {
		return unwrapped(section(t, Report{Meta: Meta{Sources: sources, Input: in}}.Markdown(), "## Sources"))
	}
	contains(t, note(&in), "Aegolith decodes base64 only in a field a route declares base64 or base64url", "Base64 or Base64Flat",
		"40.0% (2 of 5) of the attack case lines read from this source use one of these two encoders.")
	for _, without := range []*Input{nil, {}} {
		s := note(without)
		contains(t, s, "Aegolith decodes base64 only in a field a route declares base64 or base64url")
		if strings.Contains(s, "attack case lines read from this source") {
			t.Errorf("a share is given without its lines:\n%s", s)
		}
	}
}
