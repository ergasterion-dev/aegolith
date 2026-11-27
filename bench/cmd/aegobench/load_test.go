package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	runner "github.com/ergasterion-dev/aegolith/bench/internal/run"
	"github.com/ergasterion-dev/aegolith/bench/internal/target"
)

func readLoad(t *testing.T, path string) runner.LoadResult {
	t.Helper()
	var res runner.LoadResult
	if err := json.Unmarshal([]byte(readText(t, path)), &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// loadFixture writes a case file with one attack, one legitimate and one
// near-miss case and starts an enforcing target with its admin endpoints.
func loadFixture(t *testing.T) (dir, caseFile, base, admin, decisions string) {
	t.Helper()
	dir = t.TempDir()
	caseFile = filepath.Join(dir, "cases.jsonl")
	writeCases(t, caseFile,
		detectLine("attack-case", "q=1%27%20OR%20%271%27%3D%271", cases.Attack),
		detectLine("legit-case", "q=apples", cases.Legit),
		detectLine("near-case", "q=select%20a%20pear", cases.NearMiss))
	decisions = filepath.Join(dir, "d.jsonl")
	base = startTarget(t, filepath.Join(dir, "a.jsonl"), decisions)
	srv := httptest.NewServer(target.AdminHandler())
	t.Cleanup(srv.Close)
	return dir, caseFile, base, srv.URL, decisions
}

// TestLoadThenReport runs load and report as an operator would.
func TestLoadThenReport(t *testing.T) {
	t.Parallel()
	dir, caseFile, base, admin, decisions := loadFixture(t)
	// A second file that disputes the near-miss case and the attack.
	disputing := filepath.Join(dir, "disputing.jsonl")
	writeCases(t, disputing, detectLine("near-as-legit", "q=select%20a%20pear", cases.Legit),
		detectLine("another-attack", "q=2%27%20OR%20%272%27%3D%272", cases.Attack))
	caseFile += "," + disputing
	out := filepath.Join(dir, "new", "load.json")
	var stdout, stderr bytes.Buffer
	err := run([]string{"load", "--cases", caseFile, "--base", base, "--admin", admin, "--rps", "200",
		"--duration", "500ms", "--workers", "8", "--attack-share", "0.25", "--seed", "9",
		"--decisions", decisions, "--out", out}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	res := readLoad(t, out)
	if res.Format != runner.LoadResultFormat || !strings.Contains(readText(t, out), `"Format": 2`) {
		t.Errorf("format = %d, want %d written to the file", res.Format, runner.LoadResultFormat)
	}
	if res.Sent+res.Dropped != 100 || res.Sent == 0 || res.TransportErrors != 0 || res.Interrupted {
		t.Fatalf("result = %+v, want the 100 requests of the schedule", res)
	}
	if res.RPS != 200 || res.Workers != 8 || res.AttackShare != 0.25 || res.Seed != 9 ||
		res.AttackCases != 2 || res.LegitCases != 1 || res.Conflicting != 2 {
		t.Errorf("result does not say what was asked: %+v", res)
	}
	if res.Attacks == 0 || res.ByStatus[http.StatusForbidden] != res.Attacks || res.ByStatus[http.StatusOK] != res.Sent-res.Attacks {
		t.Errorf("by status = %v with %d attacks of %d", res.ByStatus, res.Attacks, res.Sent)
	}
	if res.HeapStart == 0 || res.HeapEnd == 0 || res.MemPolls != 2 || res.MemPollFailures != 0 {
		t.Errorf("heap %d to %d in %d polls, %d failed; want one at the start and one at the end",
			res.HeapStart, res.HeapEnd, res.MemPolls, res.MemPollFailures)
	}
	if d := res.Decisions; d == nil || d.Records != res.Attacks || d.Skipped != 0 || d.Other != 0 || d.MaxUS <= 0 {
		t.Errorf("decision latency = %+v, want it over the %d blocked attacks", d, res.Attacks)
	}
	for _, want := range []string{"sent ", "transport errors", "dropped", out} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("summary %q does not say %q", stdout.String(), want)
		}
	}

	// Load writes no detection results: report needs those of a detect run.
	results := filepath.Join(dir, "results.jsonl")
	if err := run([]string{"detect", "--cases", caseFile, "--base", base, "--access", filepath.Join(dir, "a.jsonl"),
		"--decisions", decisions, "--out", results}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	for _, r := range readResults(t, results) {
		if strings.HasPrefix(r.RequestID, "load-") {
			t.Errorf("a detection result has the request ID %q", r.RequestID)
		}
	}
	reportDir := filepath.Join(dir, "report")
	args := []string{"report", "--cases", caseFile, "--results", "default=" + results, "--out", reportDir}
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	without := readText(t, filepath.Join(reportDir, "report.md"))
	if strings.Contains(without, "## Load") {
		t.Error("a report without --load has a load section")
	}
	if err := run(append(args, "--load", out), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	with := readText(t, filepath.Join(reportDir, "report.md"))
	// The report before the load section differs only in its time.
	if !strings.Contains(with, "\n## Load\n") || !strings.Contains(with, "asked 200 requests per second") ||
		!strings.Contains(with, "decision records") || !strings.Contains(with, "Target heap: start ") ||
		!strings.Contains(with, "and 2 because their sources disagree") {
		t.Errorf("no load section in:\n%s", with)
	}
	if strings.Contains(with, "apples") || strings.Contains(with, "OR") {
		t.Error("the report repeats a request value")
	}
}

func TestLoadInterruptedWritesPartialResult(t *testing.T) {
	t.Parallel()
	dir, caseFile, _, _, _ := loadFixture(t)
	out := filepath.Join(dir, "load.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Interrupted by the fifth request, so that some were answered whatever
	// the machine is doing.
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		if requests.Add(1) == 5 {
			cancel()
		}
	}))
	t.Cleanup(srv.Close)
	var stdout, stderr bytes.Buffer
	err := runLoad(ctx, []string{"--cases", caseFile, "--base", srv.URL, "--rps", "100", "--duration", "1h",
		"--workers", "1", "--out", out}, &stdout, &stderr)
	if err == nil || errors.Is(err, errUsage) || !strings.Contains(err.Error(), "interrupted") {
		t.Errorf("err = %v, want it to say that the run was interrupted", err)
	}
	res := readLoad(t, out)
	// One worker: the four requests before the interrupt were answered.
	if !res.Interrupted || res.Sent < 4 || res.Sent > 5 || res.Sent+res.Cancelled != 5 || res.Duration >= time.Hour {
		t.Errorf("partial result = %+v, want the requests sent until the interrupt", res)
	}
	if !strings.Contains(stdout.String(), "interrupted") {
		t.Errorf("summary %q does not say that the run was interrupted", stdout.String())
	}
}

func TestFailedLoadLeavesOutputAlone(t *testing.T) {
	t.Parallel()
	dir, caseFile, base, _, decisions := loadFixture(t)
	onlyLegit := filepath.Join(dir, "legit.jsonl")
	writeCases(t, onlyLegit, detectLine("legit-case", "q=apples", cases.Legit))
	out := filepath.Join(dir, "load.json")
	tests := map[string][]string{
		"no attack case":         {"--cases", onlyLegit, "--base", base, "--rps", "10", "--duration", "1s", "--out", out},
		"missing case file":      {"--cases", filepath.Join(dir, "nope"), "--base", base, "--rps", "10", "--duration", "1s", "--out", out},
		"missing decision log":   {"--cases", caseFile, "--base", base, "--rps", "10", "--duration", "1s", "--decisions", filepath.Join(dir, "nope"), "--out", out},
		"shorter than a request": {"--cases", caseFile, "--base", base, "--rps", "1", "--duration", "10ms", "--decisions", decisions, "--out", out},
	}
	for name, args := range tests {
		writeText(t, out, "keep")
		var stdout, stderr bytes.Buffer
		if err := runLoad(context.Background(), args, &stdout, &stderr); err == nil {
			t.Errorf("%s: no error", name)
		}
		if got := readText(t, out); got != "keep" {
			t.Errorf("%s: output = %q, want it untouched", name, got)
		}
	}
}

func TestLoadRejectsBadUsage(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caseFile := filepath.Join(dir, "cases.jsonl")
	writeCases(t, caseFile, detectLine("attack-case", "q=1", cases.Attack), detectLine("legit-case", "q=2", cases.Legit))
	decisions := filepath.Join(dir, "d.jsonl")
	writeText(t, decisions, "")
	good := map[string]string{"--cases": caseFile, "--base": "http://127.0.0.1:1", "--rps": "10",
		"--duration": "1s", "--out": filepath.Join(dir, "load.json")}
	with := func(changes ...string) []string {
		flags := map[string]string{}
		for k, v := range good {
			flags[k] = v
		}
		for i := 0; i < len(changes); i += 2 {
			flags[changes[i]] = changes[i+1]
		}
		var args []string
		for k, v := range flags {
			if v != "" {
				args = append(args, k, v)
			}
		}
		return args
	}
	tests := map[string][]string{
		"no cases":               with("--cases", ""),
		"empty case name":        with("--cases", caseFile+","),
		"no base":                with("--base", ""),
		"base with a path":       with("--base", "http://127.0.0.1:1/x"),
		"base with a password":   with("--base", "http://u:p@127.0.0.1:1"),
		"base of another scheme": with("--base", "ftp://127.0.0.1"),
		"admin with a path":      with("--admin", "http://127.0.0.1:2/memstats"),
		"admin with a query":     with("--admin", "http://127.0.0.1:2?x=1"),
		"no rps":                 with("--rps", ""),
		"zero rps":               with("--rps", "0"),
		"rps too high":           with("--rps", "1000001"),
		"rps not a number":       with("--rps", "fast"),
		"no duration":            with("--duration", ""),
		"zero duration":          with("--duration", "0s"),
		"negative duration":      with("--duration", "-1s"),
		"duration not a time":    with("--duration", "60"),
		"zero workers":           with("--workers", "0"),
		"too many workers":       with("--workers", "65537"),
		"workers beyond memory":  with("--workers", "4611686018427387904"),
		"share above one":        with("--attack-share", "1.5"),
		"negative share":         with("--attack-share", "-0.1"),
		"share not a number":     with("--attack-share", "NaN"),
		"no out":                 with("--out", ""),
		"out over the cases":     with("--out", caseFile),
		"out over the decisions": with("--decisions", decisions, "--out", decisions),
		"extra argument":         append(with(), "extra"),
		"unknown flag":           append(with(), "--id-prefix", "x"),
	}
	for name, args := range tests {
		var stdout, stderr bytes.Buffer
		if err := runLoad(context.Background(), args, &stdout, &stderr); !errors.Is(err, errUsage) {
			t.Errorf("%s: err = %v, want a usage error", name, err)
		}
	}
}

// TestLoadSendsOnlyToLoopback: neither the target nor its admin endpoints may
// be on another machine.
func TestLoadSendsOnlyToLoopback(t *testing.T) {
	t.Parallel()
	parse := func(base, admin string) error {
		var stderr bytes.Buffer
		args := []string{"--cases", "c", "--base", base, "--rps", "1", "--duration", "1s", "--out", "o"}
		if admin != "" {
			args = append(args, "--admin", admin)
		}
		_, _, err := parseLoad(args, &stderr)
		if err != nil && strings.Contains(err.Error()+stderr.String(), "secret-host") {
			t.Errorf("%s, %s: the value is repeated: %v", base, admin, err)
		}
		return err
	}
	loopback := []string{"http://localhost", "http://LocalHost:8088", "https://127.0.0.1:8088",
		"http://127.255.0.9", "http://[::1]:8088"}
	for _, u := range loopback {
		if err := parse(u, ""); err != nil {
			t.Errorf("base %s: %v", u, err)
		}
		if err := parse("http://127.0.0.1:8088", u); err != nil {
			t.Errorf("admin %s: %v", u, err)
		}
	}
	for _, u := range []string{"http://secret-host.example.test:8088", "https://localhost.secret-host.example.test",
		"http://127.0.0.1.secret-host.example.test", "http://secret-host", "http://192.0.2.1:8088",
		"http://128.0.0.1", "http://0.0.0.0:8088", "http://[::]:8088", "http://[2001:db8::1]",
		"http://[::ffff:192.0.2.1]", "http://2130706433"} {
		for what, err := range map[string]error{"base": parse(u, ""), "admin": parse("http://127.0.0.1:8088", u)} {
			if !errors.Is(err, errUsage) {
				t.Errorf("%s %s: err = %v, want a usage error", what, u, err)
				continue
			}
			if strings.Contains(err.Error(), strings.SplitN(u, "//", 2)[1]) {
				t.Errorf("%s %s: the value is repeated: %v", what, u, err)
			}
		}
	}
}

func TestReportRejectsBadLoadFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caseFile := filepath.Join(dir, "cases.jsonl")
	writeCases(t, caseFile, detectLine("legit-case", "q=apples", cases.Legit))
	results := filepath.Join(dir, "results.jsonl")
	c, err := cases.FromLine(detectLine("legit-case", "q=apples", cases.Legit))
	if err != nil {
		t.Fatal(err)
	}
	writeText(t, results, `{"case_id":"`+c.ID+`","request_id":"r","status":200,"outcome":"passed","latency_us":1}`+"\n")
	out := filepath.Join(dir, "out")
	loadFile := filepath.Join(dir, "load.json")
	for name, content := range map[string]string{
		"not JSON":         "secret-value",
		"another object":   `{"Meta":{},"Configs":[]}`,
		"an empty object":  `{}`,
		"null":             `null`,
		"trailing data":    `{"Format":2,"RPS":1,"Workers":1,"Duration":1000000000}{}`,
		"a results line":   `{"case_id":"x","outcome":"passed"}`,
		"a negative count": `{"Format":2,"RPS":1,"Workers":1,"Duration":1000000000,"Sent":-1}`,
		// Written before the format had a version: fields added since would
		// read as zero and be reported as measured.
		"no format version":      `{"RPS":1,"Workers":1,"Duration":1000000000,"Sent":5,"MemPolls":14,"HeapStart":100}`,
		"another format version": `{"Format":1,"RPS":1,"Workers":1,"Duration":1000000000}`,
		"a later format version": `{"Format":3,"RPS":1,"Workers":1,"Duration":1000000000}`,
	} {
		writeText(t, loadFile, content)
		var stdout, stderr bytes.Buffer
		err := runReport([]string{"--cases", caseFile, "--results", "a=" + results, "--out", out, "--load", loadFile}, &stdout, &stderr)
		if err == nil {
			t.Errorf("%s: no error", name)
		} else if strings.Contains(err.Error(), "secret-value") {
			t.Errorf("%s: the error repeats the file: %v", name, err)
		} else if strings.Contains(name, "format version") && !strings.Contains(err.Error(), "run load again") {
			t.Errorf("%s: err = %v, want it to say to run load again", name, err)
		}
		if files, _ := filepath.Glob(filepath.Join(out, "*")); len(files) != 0 {
			t.Errorf("%s: a report was written: %v", name, files)
		}
	}
	// The current format is read.
	writeText(t, loadFile, `{"Format":2,"RPS":1,"Workers":1,"Duration":1000000000,"Sent":1}`)
	var stdout, stderr bytes.Buffer
	if err := runReport([]string{"--cases", caseFile, "--results", "a=" + results, "--out", out, "--load", loadFile}, &stdout, &stderr); err != nil {
		t.Errorf("a load result of the current format: %v", err)
	}
	if err := runReport([]string{"--cases", caseFile, "--results", "a=" + results, "--out", dir, "--load", filepath.Join(dir, "report.json")},
		&stdout, &stderr); err == nil {
		t.Error("a missing load file is no error")
	}
	writeText(t, filepath.Join(dir, "report.md"), "{}")
	if err := runReport([]string{"--cases", caseFile, "--results", "a=" + results, "--out", dir, "--load", filepath.Join(dir, "report.md")},
		&stdout, &stderr); !errors.Is(err, errUsage) {
		t.Errorf("err = %v, want a usage error for --out over the load file", err)
	}
}
