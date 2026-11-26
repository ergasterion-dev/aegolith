package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith"
	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/records"
	runner "github.com/ergasterion-dev/aegolith/bench/internal/run"
	"github.com/ergasterion-dev/aegolith/bench/internal/target"
)

func detectLine(id, rawQuery string, expected cases.Expected) cases.Line {
	return cases.Line{
		Name: id, Category: "c", Method: "GET", Path: "/x", RawQuery: rawQuery,
		Source: "test", SourceCaseID: id, Expected: expected,
	}
}

func writeCases(t *testing.T, path string, lines ...cases.Line) {
	t.Helper()
	if err := writeCaseFile(path, lines); err != nil {
		t.Fatal(err)
	}
}

func readResults(t *testing.T, path string) []runner.Result {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []runner.Result
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		var r runner.Result
		if err := dec.Decode(&r); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{`"case_id"`, `"request_id"`, `"status"`, `"outcome"`, `"latency_us"`} {
			if !strings.Contains(sc.Text(), key) {
				t.Errorf("line %q has no %s", sc.Text(), key)
			}
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// startTarget serves an enforcing target on loopback that writes its logs to
// the two files.
func startTarget(t *testing.T, accessPath, decisionsPath string) string {
	t.Helper()
	writer := func(path string) *records.Writer {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		})
		return records.NewWriter(f)
	}
	handler, err := target.Handler(target.Config{
		Mode: aegolith.ModeEnforce, Access: writer(accessPath), Decisions: writer(decisionsPath),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestDetectWritesJoinedResults(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first, second := filepath.Join(dir, "1.jsonl"), filepath.Join(dir, "2.jsonl")
	attack := detectLine("attack", "q=1%27%20OR%20%271%27%3D%271", cases.Attack)
	again := attack
	again.Source = "other"
	writeCases(t, first, attack, detectLine("disputed", "q=pears", cases.Attack))
	writeCases(t, second, again, detectLine("legit", "q=apples", cases.Legit),
		detectLine("disputed-too", "q=pears", cases.Legit))
	access, decisions := filepath.Join(dir, "a.jsonl"), filepath.Join(dir, "d.jsonl")
	base := startTarget(t, access, decisions)
	out := filepath.Join(dir, "new", "results.jsonl")

	var stdout, stderr bytes.Buffer
	err := run([]string{"detect", "--cases", first + "," + second, "--base", base, "--access", access,
		"--decisions", decisions, "--out", out}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}

	rs := readResults(t, out)
	if len(rs) != 2 {
		t.Fatalf("results = %+v, want the merged attack and the legitimate case", rs)
	}
	for i, want := range []runner.Outcome{runner.Blocked, runner.Passed} {
		r := rs[i]
		if r.Outcome != want || r.RequestID != "b0000000-"+r.CaseID || len(r.CaseID) != 64 {
			t.Errorf("result %d = %+v, want %s with the default prefix", i, r, want)
		}
	}
	if len(rs[0].Rules) == 0 {
		t.Error("the block names no rule")
	}
	summary := stdout.String()
	for _, want := range []string{"2 cases", "1 blocked", "1 passed", "2 conflicting"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary %q does not say %q", summary, want)
		}
	}
}

func TestFailedDetectLeavesOutputAlone(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good, empty := filepath.Join(dir, "good.jsonl"), filepath.Join(dir, "empty.jsonl")
	writeCases(t, good, detectLine("legit", "q=apples", cases.Legit))
	writeCases(t, empty)
	invalid := filepath.Join(dir, "invalid.jsonl")
	writeCases(t, invalid, cases.Line{Name: "n"})
	access, decisions := filepath.Join(dir, "a.jsonl"), filepath.Join(dir, "d.jsonl")
	base := startTarget(t, access, decisions)
	missing := filepath.Join(dir, "missing.jsonl")

	args := func(casesList, access, decisions, out string) []string {
		return []string{"--cases", casesList, "--base", base, "--access", access, "--decisions", decisions, "--out", out}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	out := filepath.Join(dir, "results.jsonl")
	tests := map[string]struct {
		ctx  context.Context
		args []string
	}{
		"missing case file":    {args: args(missing, access, decisions, out)},
		"no cases":             {args: args(empty, access, decisions, out)},
		"invalid case":         {args: args(invalid, access, decisions, out)},
		"missing access log":   {args: args(good, missing, decisions, out)},
		"missing decision log": {args: args(good, access, missing, out)},
		"interrupted":          {ctx: cancelled, args: args(good, access, decisions, out)},
	}
	if err := os.WriteFile(out, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := tt.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			var stdout, stderr bytes.Buffer
			err := runDetect(ctx, tt.args, &stdout, &stderr)
			if err == nil || errors.Is(err, errUsage) {
				t.Errorf("err = %v, want a failure", err)
			}
			if got, err := os.ReadFile(out); err != nil || string(got) != "keep" {
				t.Errorf("output = %q, %v; want it untouched", got, err)
			}
		})
	}
}

func TestDetectRejectsBadUsage(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.jsonl")
	writeCases(t, good, detectLine("legit", "q=apples", cases.Legit))
	access, decisions := filepath.Join(dir, "a.jsonl"), filepath.Join(dir, "d.jsonl")
	for _, p := range []string{access, decisions} {
		if err := os.WriteFile(p, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a request was sent")
	}))
	t.Cleanup(srv.Close)
	base := srv.URL
	out := filepath.Join(dir, "r.jsonl")

	full := map[string]string{"--cases": good, "--base": base, "--access": access, "--decisions": decisions, "--out": out}
	with := func(flag, value string) []string {
		var args []string
		for k, v := range full {
			if k != flag {
				args = append(args, k, v)
			}
		}
		if value != "" {
			args = append(args, flag, value)
		}
		return args
	}
	tests := map[string][]string{
		"no cases":              with("--cases", ""),
		"empty case name":       with("--cases", good+",,"+good),
		"no base":               with("--base", ""),
		"base without scheme":   with("--base", "127.0.0.1:1"),
		"base with other kind":  with("--base", "ftp://127.0.0.1:1"),
		"base without host":     with("--base", "http://"),
		"base with a path":      with("--base", base+"/api"),
		"base with a query":     with("--base", base+"?a=1"),
		"base with user info":   with("--base", strings.Replace(base, "//", "//user:hunter2@", 1)),
		"base that is no URL":   with("--base", "http://user:hunter2@[::1"),
		"no access":             with("--access", ""),
		"no decisions":          with("--decisions", ""),
		"no out":                with("--out", ""),
		"rate zero":             with("--rps", "0"),
		"negative rate":         with("--rps", "-1"),
		"long prefix":           with("--id-prefix", strings.Repeat("a", 65)),
		"bad prefix":            with("--id-prefix", "a b"),
		"extra argument":        append(with("", ""), "extra"),
		"out over the cases":    with("--out", good),
		"out over the access":   with("--out", access),
		"out over the decision": with("--out", decisions),
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := runDetect(context.Background(), args, &stdout, &stderr)
			if !errors.Is(err, errUsage) {
				t.Errorf("err = %v, want a usage error", err)
			}
			if err != nil && strings.Contains(err.Error()+stderr.String(), "hunter2") {
				t.Errorf("the password is repeated: %v", err)
			}
			for _, p := range []string{access, decisions} {
				if got, err := os.ReadFile(p); err != nil || string(got) != "keep" {
					t.Errorf("%s = %q, %v; want it untouched", filepath.Base(p), got, err)
				}
			}
		})
	}
}

func TestDetectSendsOnlyToLoopback(t *testing.T) {
	t.Parallel()
	parse := func(base string) error {
		var stderr bytes.Buffer
		_, _, err := parseDetect([]string{"--cases", "c", "--base", base, "--access", "a",
			"--decisions", "d", "--out", "o"}, &stderr)
		if err != nil && strings.Contains(err.Error()+stderr.String(), "secret-host") {
			t.Errorf("%s: the value is repeated: %v", base, err)
		}
		return err
	}
	for _, base := range []string{"http://localhost", "http://LocalHost:8088", "https://127.0.0.1:8088",
		"http://127.255.0.9", "http://[::1]:8088"} {
		if err := parse(base); err != nil {
			t.Errorf("%s: %v", base, err)
		}
	}
	for _, base := range []string{"http://secret-host.example.test:8088", "https://localhost.secret-host.example.test",
		"http://127.0.0.1.secret-host.example.test", "http://secret-host", "http://192.0.2.1:8088",
		"http://128.0.0.1", "http://0.0.0.0:8088", "http://[::]:8088", "http://[2001:db8::1]",
		"http://[::ffff:192.0.2.1]", "http://2130706433"} {
		err := parse(base)
		if !errors.Is(err, errUsage) {
			t.Errorf("%s: err = %v, want a usage error", base, err)
			continue
		}
		u := strings.SplitN(base, "//", 2)[1]
		if strings.Contains(err.Error(), u) {
			t.Errorf("%s: the value is repeated: %v", base, err)
		}
	}
}
