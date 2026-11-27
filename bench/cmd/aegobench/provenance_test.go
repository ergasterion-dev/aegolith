package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/report"
	runner "github.com/ergasterion-dev/aegolith/bench/internal/run"
	"github.com/ergasterion-dev/aegolith/bench/internal/sources/legit"
)

const manifest = `[
 {"name": "crs", "repo": "host/org/crs", "commit": "c0ffee", "license": "Apache-2.0", "included": true, "note": "Release one."},
 {"name": "gotestwaf", "repo": "host/org/gtw", "commit": "beef", "license": "MIT", "included": true, "note": "Release two."},
 {"name": "other-set", "repo": "", "commit": "", "license": "", "included": false, "note": "Left out: no licence."}
]`

// provenance writes the inputs of a report over a baseline, a CRS and 30
// generated cases into dir and returns the arguments of report.
func provenance(t *testing.T, dir string) []string {
	t.Helper()
	path := func(name string) string { return filepath.Join(dir, name) }
	own := detectLine("own-case", "q=own", cases.Attack)
	own.Source = cases.SourceBaseline
	third := detectLine("third-case", "q=third", cases.Attack)
	third.Source = "crs"
	writeCases(t, path("baseline.jsonl"), own)
	writeCases(t, path("crs.jsonl"), third)
	writeCases(t, path("legit.jsonl"), legit.Generate(3, 30)...)
	merged, _, err := readCases([]string{path("baseline.jsonl")})
	if err != nil {
		t.Fatal(err)
	}
	writeText(t, path("results.jsonl"), `{"case_id":"`+merged[0].ID+`","outcome":"passed"}`+"\n")
	writeText(t, path("sources.json"), manifest)
	writeText(t, path("crs-skipped.jsonl"),
		`{"case_id":"hidden-skip","reason":"too long"}`+"\n"+`{"case_id":"hidden-skip-2","reason":"too long"}`+"\n")
	writeText(t, path("baseline-skipped.jsonl"), "")
	writeText(t, path("environment"), "Processor=Some CPU = fast\n\nGo=go1.99\n")
	return []string{
		"--cases", path("baseline.jsonl") + "," + path("crs.jsonl") + "," + path("legit.jsonl"),
		"--results", "none=" + path("results.jsonl"),
		"--sources", path("sources.json"),
		"--skipped", "baseline=" + path("baseline-skipped.jsonl") + ",crs=" + path("crs-skipped.jsonl"),
		"--environment", path("environment"),
		"--legit-seed", "3", "--legit-n", "30",
		"--out", path("out"),
	}
}

func TestReportRecordsProvenance(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if err := runReport(provenance(t, dir), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var r report.Report
	jsonText := readText(t, filepath.Join(dir, "out", "report.json"))
	if err := json.Unmarshal([]byte(jsonText), &r); err != nil {
		t.Fatal(err)
	}

	sources := map[string]report.SourceInfo{}
	var names []string
	for _, s := range r.Meta.Sources {
		sources[s.Name] = s
		names = append(names, s.Name)
	}
	if want := []string{"baseline", "crs", "generated-legit", "gotestwaf", "other-set"}; !slices.Equal(names, want) {
		t.Fatalf("sources %v, want %v", names, want)
	}
	if got, want := sources["crs"], (report.SourceInfo{Name: "crs", Repo: "host/org/crs", Commit: "c0ffee",
		License: "Apache-2.0", Included: true, Note: "Release one."}); got != want {
		t.Errorf("crs = %+v, want %+v", got, want)
	}
	for _, name := range []string{"baseline", "generated-legit"} {
		if s := sources[name]; !s.Included || s.Repo != "this repository" || s.License != "Apache-2.0" || s.Commit != "" {
			t.Errorf("%s = %+v", name, s)
		}
	}
	if s := sources["generated-legit"]; !strings.Contains(s.Note, "seed 3, 30 lines") {
		t.Errorf("generated note %q", s.Note)
	}
	if s := sources["gotestwaf"]; s.Included || s.Commit != "beef" || !strings.Contains(s.Note, "Not among the case files") {
		t.Errorf("gotestwaf = %+v", s)
	}
	if s := sources["other-set"]; s.Included || s.Note != "Left out: no licence." {
		t.Errorf("other-set = %+v", s)
	}

	wantEnv := []report.Field{{Name: "Processor", Value: "Some CPU = fast"}, {Name: "Go", Value: "go1.99"}}
	if !slices.Equal(r.Meta.Environment, wantEnv) {
		t.Errorf("environment %+v, want %+v", r.Meta.Environment, wantEnv)
	}
	if r.Meta.Input == nil || r.Meta.Input.Lines != 32 || len(r.Meta.Input.Sources) != 3 {
		t.Fatalf("input %+v", r.Meta.Input)
	}
	var skipped []int
	for _, s := range r.Meta.Input.Sources {
		if s.Skipped == nil {
			t.Fatalf("%s: skipped not recorded", s.Source)
		}
		skipped = append(skipped, *s.Skipped)
	}
	// baseline, crs, generated-legit.
	if want := []int{0, 2, 0}; !slices.Equal(skipped, want) {
		t.Errorf("skipped %v, want %v", skipped, want)
	}
	g := r.Meta.Generated
	if g == nil || g.Seed != 3 || g.N != 30 || g.Templates == 0 || g.Entries == 0 || g.EntriesUsed == 0 {
		t.Fatalf("generated %+v", g)
	}
	if len(g.Cores) == 0 || g.Cores[0].Name == "" || g.Cores[0].Entries == 0 {
		t.Errorf("core lists %+v", g.Cores)
	}
	lines := 0
	for _, c := range g.Categories {
		lines += c.Lines
	}
	if lines != 30 {
		t.Errorf("%d generated lines over the categories, want 30", lines)
	}
	md := readText(t, filepath.Join(dir, "out", "report.md"))
	for _, want := range []string{"## Run environment", "## Input", "## Generated legitimate traffic", "c0ffee",
		"| crs | too long | 2 |"} {
		if !strings.Contains(md, want) {
			t.Errorf("no %q in the report", want)
		}
	}
	for _, text := range []string{md, jsonText, stdout.String()} {
		for _, secret := range []string{"hidden-skip", "q=own", "q=third", dir} {
			if strings.Contains(text, secret) && !(secret == dir && text == stdout.String()) {
				t.Errorf("output holds %q", secret)
			}
		}
	}
}

// Without a seed and a size the report says that the generated set is not
// described.
func TestReportSaysWhenTheGeneratedSetIsNotDescribed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	args := provenance(t, dir)
	i := slices.Index(args, "--legit-seed")
	args = slices.Delete(args, i, i+4)
	var stdout, stderr bytes.Buffer
	if err := runReport(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	md := readText(t, filepath.Join(dir, "out", "report.md"))
	if strings.Contains(md, "## Generated legitimate traffic") || !strings.Contains(md, "not described: report was not given") {
		t.Errorf("unexpected report:\n%s", md)
	}
}

func TestReportRefusesProvenanceThatDoesNotFit(t *testing.T) {
	t.Parallel()
	// Each entry changes the arguments or a file of a good set of inputs.
	set := func(flag, value string) func(*testing.T, string, []string) []string {
		return func(_ *testing.T, _ string, args []string) []string {
			args[slices.Index(args, flag)+1] = value
			return args
		}
	}
	file := func(name, text string) func(*testing.T, string, []string) []string {
		return func(t *testing.T, dir string, args []string) []string {
			writeText(t, filepath.Join(dir, name), text)
			return args
		}
	}
	tests := map[string]func(*testing.T, string, []string) []string{
		"another seed":  set("--legit-seed", "4"),
		"a smaller set": set("--legit-n", "29"),
		"a larger set":  set("--legit-n", "31"),
		"too large":     set("--legit-n", "5000000"),
		"nothing generated": func(t *testing.T, dir string, args []string) []string {
			writeCases(t, filepath.Join(dir, "legit.jsonl"))
			return args
		},
		"no manifest":          set("--sources", "absent"),
		"manifest unknown key": file("sources.json", `[{"name":"crs","hidden-skip":1}]`),
		"manifest not a list":  file("sources.json", `{}`),
		"manifest trailing":    file("sources.json", manifest+"[]"),
		"manifest repeats":     file("sources.json", `[{"name":"crs"},{"name":"crs"}]`),
		"manifest empty name":  file("sources.json", `[{}]`),
		"no skip file":         set("--skipped", "crs=absent"),
		"broken skip file":     file("crs-skipped.jsonl", "hidden-skip\n"),
		"skip without reason":  file("crs-skipped.jsonl", `{"case_id":"hidden-skip"}`+"\n"),
		"skips of an unknown source": func(_ *testing.T, dir string, args []string) []string {
			args[slices.Index(args, "--skipped")+1] = "csr=" + filepath.Join(dir, "crs-skipped.jsonl")
			return args
		},
		"no environment":   set("--environment", "absent"),
		"environment line": file("environment", "hidden-skip\n"),
		"environment name": file("environment", "=hidden-skip\n"),
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			args := change(t, dir, provenance(t, dir))
			var stdout, stderr bytes.Buffer
			err := runReport(args, &stdout, &stderr)
			if err == nil || errors.Is(err, errUsage) {
				t.Fatalf("err = %v, want a failure", err)
			}
			if strings.Contains(err.Error(), "hidden-skip") {
				t.Errorf("err = %q repeats the file", err)
			}
			for _, name := range []string{"report.md", "report.json"} {
				if sameFile(filepath.Join(dir, "out", name), filepath.Join(dir, "out", name)) {
					t.Errorf("%s was written", name)
				}
			}
		})
	}
}

func TestReportRejectsBadProvenanceUsage(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	args := provenance(t, dir)
	with := func(flag, value string) []string {
		a := slices.Clone(args)
		a[slices.Index(a, flag)+1] = value
		return a
	}
	tests := map[string][]string{
		"skipped without source":   with("--skipped", filepath.Join(dir, "crs-skipped.jsonl")),
		"skipped empty file":       with("--skipped", "crs="),
		"skipped source twice":     with("--skipped", "crs=a,crs=b"),
		"negative size":            with("--legit-n", "-1"),
		"neither results nor load": slices.Delete(slices.Clone(args), 2, 4),
		"out over the manifest": func() []string {
			a := with("--sources", filepath.Join(dir, "report.md"))
			writeText(t, filepath.Join(dir, "report.md"), manifest)
			a[slices.Index(a, "--out")+1] = dir
			return a
		}(),
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := runReport(args, &stdout, &stderr); !errors.Is(err, errUsage) {
				t.Errorf("err = %v, want a usage error", err)
			}
		})
	}
}

// A load run alone can be reported, with the same provenance.
func TestReportOfALoadRunAlone(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	args := provenance(t, dir)
	load, err := json.Marshal(runner.LoadResult{
		Format: runner.LoadResultFormat, RPS: 5, Workers: 1, Duration: time.Second, Sent: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeText(t, filepath.Join(dir, "load.json"), string(load))
	args = slices.Delete(args, 2, 4) // --results
	args = append(args, "--load", filepath.Join(dir, "load.json"))
	var stdout, stderr bytes.Buffer
	if err := runReport(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	md := readText(t, filepath.Join(dir, "out", "report.md"))
	for _, want := range []string{"## Load", "## Run environment", "c0ffee"} {
		if !strings.Contains(md, want) {
			t.Errorf("no %q in the report", want)
		}
	}
	if strings.Contains(md, "## Configuration") || !strings.Contains(stdout.String(), "0 configurations") {
		t.Errorf("a load report holds a configuration:\n%s\n%s", stdout.String(), md)
	}
}
