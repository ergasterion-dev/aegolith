package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/remote"
	"github.com/ergasterion-dev/aegolith/bench/internal/report"
)

func writeText(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readText(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestReportFromDetect runs detect and report as an operator would.
func TestReportFromDetect(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first, second := filepath.Join(dir, "1.jsonl"), filepath.Join(dir, "2.jsonl")
	attack := detectLine("attack-case", "q=1%27%20OR%20%271%27%3D%271", cases.Attack)
	attack.Source = cases.SourceBaseline
	missed := detectLine("missed-case", "q=pears", cases.Attack)
	missed.Source = cases.SourceBaseline
	writeCases(t, first, attack, missed, detectLine("disputed", "q=plums", cases.Attack))
	writeCases(t, second, detectLine("legit-case", "q=apples", cases.Legit),
		detectLine("disputed-too", "q=plums", cases.Legit))
	access, decisions := filepath.Join(dir, "a.jsonl"), filepath.Join(dir, "d.jsonl")
	base := startTarget(t, access, decisions)
	results := filepath.Join(dir, "results.jsonl")
	list := first + "," + second
	var stdout, stderr bytes.Buffer
	if err := run([]string{"detect", "--cases", list, "--base", base, "--access", access,
		"--decisions", decisions, "--out", results}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "new", "out")
	args := []string{"report", "--cases", list, "--results", "none=" + results + ",again=" + results, "--out", out}
	stdout.Reset()
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"3 cases", "2 configurations", "2 conflicting"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("summary %q does not say %q", stdout.String(), want)
		}
	}
	jsonPath, mdPath := filepath.Join(out, "report.json"), filepath.Join(out, "report.md")
	var r report.Report
	if err := json.Unmarshal([]byte(readText(t, jsonPath)), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Configs) != 2 || r.Configs[0].Name != "none" || r.Configs[1].Name != "again" {
		t.Fatalf("configs = %+v, want none then again", r.Configs)
	}
	if got := r.Configs[0].Missed; len(got) != 1 || got[0].SourceCaseID != "missed-case" {
		t.Errorf("missed = %+v, want the missed baseline attack", got)
	}
	if r.Format != report.Format {
		t.Errorf("format %d, want %d", r.Format, report.Format)
	}
	if r.Meta.Commit == "" || r.Meta.Created.IsZero() {
		t.Errorf("meta = %+v, want a commit and a time", r.Meta)
	}
	var sources []string
	for _, s := range r.Meta.Sources {
		if !s.Included {
			t.Errorf("source %+v is not marked included", s)
		}
		sources = append(sources, s.Name)
	}
	if got := strings.Join(sources, " "); got != "baseline test" {
		t.Errorf("sources = %q, want baseline and test", got)
	}
	md := readText(t, mdPath)
	if !strings.Contains(md, "missed-case") || strings.Contains(md, "Changes since") {
		t.Errorf("unexpected report:\n%s", md)
	}
	for _, text := range []string{md, readText(t, jsonPath)} {
		for _, value := range []string{"pears", "apples", "%27"} {
			if strings.Contains(text, value) {
				t.Errorf("the report repeats the request value %q", value)
			}
		}
	}

	// A second run may compare with the report it replaces.
	if err := run(append(args, "--previous", jsonPath), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if md := readText(t, mdPath); !strings.Contains(md, "## Changes since the previous report") {
		t.Errorf("no comparison in:\n%s", md)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("%d files in the output directory, want 2", len(entries))
	}
}

func TestFailedReportLeavesOutputAlone(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := func(name string) string { return filepath.Join(dir, name) }
	good := path("good.jsonl")
	writeCases(t, good, detectLine("legit", "q=apples", cases.Legit))
	merged, _, err := readCases([]string{good})
	if err != nil {
		t.Fatal(err)
	}
	line := `{"case_id":"` + merged[0].ID + `","outcome":"passed"}` + "\n"
	writeText(t, path("results.jsonl"), line)
	writeText(t, path("repeated.jsonl"), line+line)
	writeText(t, path("foreign.jsonl"), line+`{"case_id":"hidden-case","outcome":"passed"}`+"\n")
	writeText(t, path("none.jsonl"), "")
	writeText(t, path("broken.jsonl"), "{")
	writeText(t, path("not-a-report.json"), "{}")
	writeText(t, path("unversioned.json"), `{"Meta":{},"Configs":[{"Name":"none"}]}`)
	writeText(t, path("other-version.json"), `{"Format":999,"Meta":{},"Configs":[{"Name":"none"}]}`)
	writeText(t, path("not-joined.jsonl"), `{"case_id":"`+merged[0].ID+`","request_id":"rt-0a1b2c3d-`+merged[0].ID+
		`","status":200,"outcome":"unknown","reason":"`+remote.ReasonNotJoined+`"}`+"\n")
	writeText(t, path("invalid.jsonl"),
		`{"name":"hidden-case","source":"test","source_case_id":"hidden-case"}`+"\n")
	out := path("out")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	jsonPath, mdPath := filepath.Join(out, "report.json"), filepath.Join(out, "report.md")
	writeText(t, jsonPath, "keep")
	writeText(t, mdPath, "keep")

	args := func(caseFile, results string, more ...string) []string {
		return append([]string{"--cases", caseFile, "--results", "none=" + results, "--out", out}, more...)
	}
	results := path("results.jsonl")
	tests := map[string][]string{
		"missing case file":         args(path("absent"), results),
		"invalid case":              args(path("invalid.jsonl"), results),
		"missing results":           args(good, path("absent")),
		"empty results":             args(good, path("none.jsonl")),
		"broken results":            args(good, path("broken.jsonl")),
		"repeated result":           args(good, path("repeated.jsonl")),
		"result of other case":      args(good, path("foreign.jsonl")),
		"missing previous":          args(good, results, "--previous", path("absent")),
		"broken previous":           args(good, results, "--previous", path("broken.jsonl")),
		"previous no report":        args(good, results, "--previous", path("not-a-report.json")),
		"previous unversioned":      args(good, results, "--previous", path("unversioned.json")),
		"previous of other version": args(good, results, "--previous", path("other-version.json")),
		"results not joined":        args(good, path("not-joined.jsonl")),
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := runReport(args, &stdout, &stderr)
			if err == nil || errors.Is(err, errUsage) {
				t.Fatalf("err = %v, want a failure", err)
			}
			hints := map[string]string{"results not joined": "aegobench join", "previous unversioned": "format version",
				"previous of other version": "format version"}
			if hint := hints[name]; hint != "" && !strings.Contains(err.Error(), hint) {
				t.Errorf("err = %q does not say %q", err, hint)
			}
			// An error must not single out a case, which may be held out.
			if msg := err.Error(); strings.Contains(msg, "hidden-case") || strings.Contains(msg, merged[0].ID) {
				t.Errorf("err = %q names a case", msg)
			}
			for _, p := range []string{jsonPath, mdPath} {
				if got := readText(t, p); got != "keep" {
					t.Errorf("%s = %q, want it untouched", filepath.Base(p), got)
				}
			}
		})
	}
}

func TestReportRejectsBadUsage(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.jsonl")
	writeCases(t, good, detectLine("legit", "q=apples", cases.Legit))
	results := filepath.Join(dir, "report.md") // would be overwritten with --out dir
	writeText(t, results, "keep")
	out := filepath.Join(dir, "out")
	args := func(cases, results, out string) []string {
		var a []string
		for _, kv := range [][2]string{{"--cases", cases}, {"--results", results}, {"--out", out}} {
			if kv[1] != "" {
				a = append(a, kv[0], kv[1])
			}
		}
		return a
	}
	tests := map[string][]string{
		"no cases":             args("", "a="+results, out),
		"empty case name":      args(good+",", "a="+results, out),
		"no results":           args(good, "", out),
		"results without name": args(good, results, out),
		"empty name":           args(good, "="+results, out),
		"empty file":           args(good, "a=", out),
		"empty entry":          args(good, "a="+results+",", out),
		"name used twice":      args(good, "a="+results+",a="+results, out),
		"no out":               args(good, "a="+results, ""),
		"extra argument":       append(args(good, "a="+results, out), "extra"),
		"out over the results": args(good, "a="+results, dir),
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := runReport(args, &stdout, &stderr); !errors.Is(err, errUsage) {
				t.Errorf("err = %v, want a usage error", err)
			}
			if got := readText(t, results); got != "keep" {
				t.Errorf("results = %q, want them untouched", got)
			}
		})
	}
}

func TestCommitFromBuildSettings(t *testing.T) {
	t.Parallel()
	setting := func(k, v string) debug.BuildSetting { return debug.BuildSetting{Key: k, Value: v} }
	tests := map[string]struct {
		settings []debug.BuildSetting
		want     string
	}{
		"not stamped": {nil, "unknown"},
		"clean":       {[]debug.BuildSetting{setting("vcs.revision", "abc"), setting("vcs.modified", "false")}, "abc"},
		"modified": {
			[]debug.BuildSetting{setting("vcs.revision", "abc"), setting("vcs.modified", "true")},
			"abc (with uncommitted changes)",
		},
	}
	for name, tt := range tests {
		if got := commitFrom(tt.settings); got != tt.want {
			t.Errorf("%s: commit = %q, want %q", name, got, tt.want)
		}
	}
}

// TestReportCountsEachEncoderOfARequest gives one request under two encoders
// of one source: the per-encoder and per-placement rows count it under each,
// as the report says, while every other count sees one case.
func TestReportCountsEachEncoderOfARequest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	plain := detectLine("one-plain", "q=1%27%20OR%20%271%27%3D%271", cases.Attack)
	plain.Encoder, plain.Placement, plain.Payload = "Plain", "query", "1' OR '1'='1"
	url := plain
	url.Name, url.SourceCaseID, url.Encoder, url.Placement = "one-url", "one-url", "URL", "header"
	caseFile := filepath.Join(dir, "cases.jsonl")
	writeCases(t, caseFile, plain, url)
	merged, _, err := readCases([]string{caseFile})
	if err != nil || len(merged) != 1 {
		t.Fatalf("fixture: %d merged cases, %v", len(merged), err)
	}
	results := filepath.Join(dir, "results.jsonl")
	writeText(t, results, `{"case_id":"`+merged[0].ID+`","status":403,"outcome":"blocked","rules":["AEG-SQLI-001"]}`+"\n")
	out := filepath.Join(dir, "out")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"report", "--cases", caseFile, "--results", "none=" + results, "--out", out}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var r report.Report
	if err := json.Unmarshal([]byte(readText(t, filepath.Join(out, "report.json"))), &r); err != nil {
		t.Fatal(err)
	}
	values := func(vs []report.Variant) map[string]int {
		m := map[string]int{}
		for _, v := range vs {
			m[v.Value] += v.Counts.Blocked
		}
		return m
	}
	if got := values(r.Configs[0].Encoders); got["Plain"] != 1 || got["URL"] != 1 || len(got) != 2 {
		t.Errorf("encoder rows count %v, want the request blocked under Plain and under URL", got)
	}
	if got := values(r.Configs[0].Placements); got["query"] != 1 || got["header"] != 1 || len(got) != 2 {
		t.Errorf("placement rows count %v, want the request blocked under query and under header", got)
	}
	for _, row := range r.Configs[0].Rows {
		if row.Source == report.TotalSource && row.Counts.Blocked != 1 {
			t.Errorf("total row %+v, want the request once", row)
		}
	}
}
