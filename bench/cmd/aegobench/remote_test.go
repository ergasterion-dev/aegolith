package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/remote"
	runner "github.com/ergasterion-dev/aegolith/bench/internal/run"
)

// remoteLine is an original case with a payload in the given placement.
func remoteLine(id, placement, payload string, expected cases.Expected) cases.Line {
	return cases.Line{
		Name: id, Category: "c", Method: "PUT", Path: "/orig/" + id, Headers: map[string]string{"Cookie": "a=b"},
		Source: "test", SourceCaseID: id, Expected: expected, Payload: payload, Placement: placement,
	}
}

// writeTargetFile writes a target file for a loopback server at base.
func writeTargetFile(t *testing.T, path, base string, edit func(*remote.Target)) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	target := remote.Target{
		BaseURL: "http://" + u.Host, RequestIDPrefix: "rt-", Mode: remote.ModeEnforce, HealthPath: "/health",
		MaxRPS: 50, StopStatuses: []int{429}, Headers: map[string]string{},
		Allow: []remote.Entry{
			{Method: "GET", Path: "/api/v1/products/search", Placements: []string{"query:q"}, BenignStatus: []int{200}},
			{Method: "POST", Path: "/api/v1/notes", Placements: []string{"json:note"}, BenignStatus: []int{200}},
		},
	}
	if edit != nil {
		edit(&target)
	}
	b, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	writeText(t, path, string(b))
	return u.Host
}

func TestRemoteThenJoinThenReport(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caseFile := filepath.Join(dir, "cases.jsonl")
	writeCases(t, caseFile,
		remoteLine("sqli", "query", "1' OR '1'='1", cases.Attack),
		remoteLine("note", "json", "Thanks for the quick delivery", cases.Legit),
		remoteLine("callback", "query", "curl abc.oastify.com", cases.Attack),
		remoteLine("path", "path", "../../etc/passwd", cases.Attack),
		remoteLine("bare", "query", "", cases.Attack))
	access, decisions := filepath.Join(dir, "a.jsonl"), filepath.Join(dir, "d.jsonl")
	base := startTarget(t, access, decisions)
	targetFile := filepath.Join(dir, "target.json")
	host := writeTargetFile(t, targetFile, base, nil)
	sent, placed := filepath.Join(dir, "sent.jsonl"), filepath.Join(dir, "placed.jsonl")

	var stdout, stderr bytes.Buffer
	err := run([]string{"remote", "--target", targetFile, "--confirm-host", host, "--rps", "50",
		"--cases", caseFile, "--out", sent, "--out-cases", placed}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("remote: %v\n%s", err, stderr.String())
	}
	for _, want := range []string{"2 to send", "2 sent", "3 cases not placed"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("remote summary %q does not say %q", stdout.String(), want)
		}
	}
	joined := filepath.Join(dir, "joined.jsonl")
	stdout.Reset()
	err = run([]string{"join", "--results", sent, "--access", access, "--decisions", decisions, "--out", joined}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if !strings.Contains(stdout.String(), "unreadable log lines: 0 access, 0 decision") {
		t.Errorf("join summary %q", stdout.String())
	}
	rs := readResults(t, joined)
	count := map[runner.Outcome]int{}
	for _, r := range rs {
		count[r.Outcome]++
	}
	if len(rs) != 5 || count[runner.Blocked] != 1 || count[runner.Passed] != 1 || count[runner.NotSent] != 3 {
		t.Errorf("joined outcomes %v", count)
	}

	out := filepath.Join(dir, "report")
	stdout.Reset()
	err = run([]string{"report", "--cases", placed, "--results", "remote=" + joined, "--out", out}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if !strings.Contains(stdout.String(), "5 cases") || strings.Contains(stdout.String(), "no result") {
		t.Errorf("report summary %q", stdout.String())
	}
}

// countingServer counts every request it gets.
func countingServer(t *testing.T, status int) (string, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &n
}

func TestRemoteRefusesBeforeSending(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base, hits := countingServer(t, http.StatusOK)
	caseFile := filepath.Join(dir, "cases.jsonl")
	writeCases(t, caseFile, remoteLine("sqli", "query", "1' OR '1'='1", cases.Attack))
	good := filepath.Join(dir, "target.json")
	host := writeTargetFile(t, good, base, nil)
	noAllow := filepath.Join(dir, "no-allow.json")
	writeTargetFile(t, noAllow, base, func(t *remote.Target) { t.Allow = nil })
	public := filepath.Join(dir, "public.json")
	writeTargetFile(t, public, base, func(t *remote.Target) { t.BaseURL = "http://waf.example.test" })
	out, outCases := filepath.Join(dir, "out.jsonl"), filepath.Join(dir, "placed.jsonl")
	writeText(t, outCases, "keep\n")
	blocked := filepath.Join(dir, "file")
	writeText(t, blocked, "")

	args := func(extra ...string) []string {
		a := map[string]string{"--target": good, "--confirm-host": host, "--rps": "5", "--cases": caseFile,
			"--out": out, "--out-cases": outCases}
		for i := 0; i < len(extra); i += 2 {
			if extra[i+1] == "" {
				delete(a, extra[i])
			} else {
				a[extra[i]] = extra[i+1]
			}
		}
		list := []string{"remote"}
		for k, v := range a {
			list = append(list, k, v)
		}
		return list
	}
	tests := map[string][]string{
		"no target":             args("--target", ""),
		"no confirm host":       args("--confirm-host", ""),
		"no rps":                args("--rps", ""),
		"rps zero":              args("--rps", "0"),
		"rps over the ceiling":  args("--rps", "51"),
		"no cases":              args("--cases", ""),
		"no out":                args("--out", ""),
		"no out cases":          args("--out-cases", ""),
		"limit zero":            args("--limit", "0"),
		"wrong host":            args("--confirm-host", "localhost"),
		"host without port":     args("--confirm-host", "127.0.0.1"),
		"empty allow-list":      args("--target", noAllow),
		"http to a public host": args("--target", public, "--confirm-host", "waf.example.test"),
		"out is out-cases":      args("--out", outCases),
		"out is a case file":    args("--out", caseFile),
		"out-cases is target":   args("--out-cases", good),
		"out is the stop file":  args("--stop-file", out),
		"out is the heartbeat":  args("--heartbeat-file", outCases),
		"out in a file":         args("--out", filepath.Join(blocked, "x.jsonl")),
		"out is a directory":    args("--out", dir),
	}
	for name, a := range tests {
		var stdout, stderr bytes.Buffer
		if err := run(a, &stdout, &stderr); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("%d requests were sent", n)
	}
	if readText(t, outCases) != "keep\n" {
		t.Error("a refused run changed an output file")
	}
}

func TestRemoteStopWritesFilesAndFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base, hits := countingServer(t, http.StatusBadGateway)
	caseFile := filepath.Join(dir, "cases.jsonl")
	writeCases(t, caseFile, remoteLine("a", "query", "1' OR '1'='1", cases.Attack), remoteLine("b", "query", "x", cases.Attack))
	targetFile := filepath.Join(dir, "target.json")
	host := writeTargetFile(t, targetFile, base, nil)
	out, outCases := filepath.Join(dir, "out.jsonl"), filepath.Join(dir, "placed.jsonl")
	var stdout, stderr bytes.Buffer
	err := run([]string{"remote", "--target", targetFile, "--confirm-host", host, "--rps", "5",
		"--cases", caseFile, "--out", out, "--out-cases", outCases}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("err %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("%d requests after a 502 health check", hits.Load())
	}
	rs := readResults(t, out)
	if len(rs) != 2 || rs[0].Outcome != runner.NotSent || rs[1].Outcome != runner.NotSent {
		t.Errorf("results %+v", rs)
	}
	if _, err := os.Stat(outCases); err != nil {
		t.Errorf("no case file: %v", err)
	}
}

func TestJoinRejectsBadUsage(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	results, access, decisions := filepath.Join(dir, "r.jsonl"), filepath.Join(dir, "a.jsonl"), filepath.Join(dir, "d.jsonl")
	writeText(t, results, `{"case_id":"x","request_id":"rt-x","status":200,"outcome":"unknown","latency_us":1}`+"\n")
	writeText(t, access, "")
	writeText(t, decisions, "")
	for name, args := range map[string][]string{
		"no results":         {"--access", access, "--decisions", decisions, "--out", filepath.Join(dir, "o")},
		"out is the results": {"--results", results, "--access", access, "--decisions", decisions, "--out", results},
		"out is a log":       {"--results", results, "--access", access, "--decisions", decisions, "--out", access},
	} {
		var stdout, stderr bytes.Buffer
		if err := run(append([]string{"join"}, args...), &stdout, &stderr); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A result with no access record is never passed.
	out := filepath.Join(dir, "out.jsonl")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"join", "--results", results, "--access", access, "--decisions", decisions, "--out", out}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if rs := readResults(t, out); len(rs) != 1 || rs[0].Outcome != runner.Unknown {
		t.Errorf("joined %+v", rs)
	}
}
