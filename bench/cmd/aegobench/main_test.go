package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/records"
)

const corpusDir = "../../../testdata/corpus"

func TestImportBaselineWritesCaseFile(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "new", "baseline.jsonl")
	var stdout, stderr bytes.Buffer
	args := []string{"import", "--source", "baseline", "--corpus", corpusDir, "--out", out}
	// The second run replaces the file the first one wrote.
	for range 2 {
		stdout.Reset()
		if err := run(args, &stdout, &stderr); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	lines, err := cases.ReadLines(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 425 {
		t.Errorf("%d lines, want 425", len(lines))
	}
	if got := stdout.String(); !strings.Contains(got, "425") {
		t.Errorf("summary %q does not give the count", got)
	}
	entries, err := os.ReadDir(filepath.Dir(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("%d files in the output directory, want 1", len(entries))
	}
}

func TestFailedImportLeavesOutputAlone(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "cases.jsonl")
	if err := os.WriteFile(out, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := run([]string{"import", "--source", "baseline", "--corpus", t.TempDir(), "--out", out}, &stdout, &stderr)
	if err == nil {
		t.Fatal("want an error for an empty corpus directory")
	}
	if errors.Is(err, errUsage) {
		t.Errorf("a failed import is not a usage error: %v", err)
	}
	got, readErr := os.ReadFile(out)
	if readErr != nil || string(got) != "keep" {
		t.Errorf("output = %q, %v; want it untouched", got, readErr)
	}
}

func TestRunRejectsBadUsage(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "x.jsonl")
	tests := map[string][]string{
		"no subcommand":      nil,
		"unknown subcommand": {"explode"},
		"unknown flag":       {"import", "--nope"},
		"extra argument":     {"import", "--source", "baseline", "--corpus", corpusDir, "--out", out, "extra"},
		"no source":          {"import", "--corpus", corpusDir, "--out", out},
		"unknown source":     {"import", "--source", "nope", "--corpus", corpusDir, "--out", out},
		"no corpus":          {"import", "--source", "baseline", "--out", out},
		"no out":             {"import", "--source", "baseline", "--corpus", corpusDir},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if err := run(args, &stdout, &stderr); !errors.Is(err, errUsage) {
				t.Errorf("err = %v, want a usage error", err)
			}
		})
	}
}

func TestHelpIsNotAnError(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}, {"import", "-h"}, {"target", "-h"}, {"detect", "-h"}, {"report", "-h"}} {
		var stdout, stderr bytes.Buffer
		if err := run(args, &stdout, &stderr); err != nil {
			t.Errorf("%v: %v", args, err)
		}
		want := "import"
		switch args[0] {
		case "target":
			want = "-decisions"
		case "detect":
			want = "-id-prefix"
		case "report":
			want = "-previous"
		}
		if !strings.Contains(stdout.String()+stderr.String(), want) {
			t.Errorf("%v: no usage text", args)
		}
	}
}

func TestTargetServesAndRecords(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "new")
	access, decisions := filepath.Join(dir, "access.jsonl"), filepath.Join(dir, "decisions.jsonl")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A log left by an earlier run is replaced, not appended to.
	if err := os.WriteFile(access, []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	read, write := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := runTarget(ctx, []string{"--addr", "127.0.0.1:0", "--admin-addr", "127.0.0.1:0",
			"--mode", "enforce", "--access", access, "--decisions", decisions}, write, io.Discard)
		write.CloseWithError(err)
		done <- err
	}()
	announced, err := bufio.NewReader(read).ReadString('\n')
	if err != nil {
		t.Fatalf("no start line: %v", err)
	}
	urls := regexp.MustCompile(`http://127\.0\.0\.1:[0-9]+`).FindAllString(announced, -1)
	if len(urls) != 2 {
		t.Fatalf("start line %q does not give both addresses", announced)
	}

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	status := func(url, id string) int {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Request-Id", id)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Error(err)
		}
		return resp.StatusCode
	}
	if got := status(urls[0]+"/x?q=1%27%20OR%20%271%27%3D%271", "t1"); got != http.StatusForbidden {
		t.Errorf("attack status %d, want 403", got)
	}
	if got := status(urls[1]+"/health", "t2"); got != http.StatusOK {
		t.Errorf("health status %d, want 200", got)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("target did not stop")
	}

	af, err := os.Open(access)
	if err != nil {
		t.Fatal(err)
	}
	defer af.Close()
	got, bad, err := records.ReadAccess(af)
	if err != nil || bad != 0 || len(got) != 1 || got["t1"].Path != "/x" {
		t.Errorf("access = %+v, bad %d, err %v; want only t1", got, bad, err)
	}
	df, err := os.Open(decisions)
	if err != nil {
		t.Fatal(err)
	}
	defer df.Close()
	ds, bad, err := records.ReadDecisions(df)
	if err != nil || bad != 0 || len(ds["t1"]) != 1 || ds["t1"][0].Action != "block" {
		t.Errorf("decisions = %+v, bad %d, err %v; want one block for t1", ds, bad, err)
	}
}

// A start that fails must not destroy the logs of an earlier, or still
// running, target.
func TestTargetFailedStartKeepsLogs(t *testing.T) {
	t.Parallel()
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Not deferred: the parallel subtests run after this function returns.
	t.Cleanup(func() {
		if err := taken.Close(); err != nil {
			t.Error(err)
		}
	})

	// Unlike a missing policy, this one fails after the logs are open.
	badPolicy := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badPolicy, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := map[string][]string{
		"port in use":       {"--addr", taken.Addr().String(), "--admin-addr", "127.0.0.1:0"},
		"admin port in use": {"--addr", "127.0.0.1:0", "--admin-addr", taken.Addr().String()},
		"missing policy":    {"--addr", "127.0.0.1:0", "--admin-addr", "127.0.0.1:0", "--policy", "none.json"},
		"invalid policy":    {"--addr", "127.0.0.1:0", "--admin-addr", "127.0.0.1:0", "--policy", badPolicy},
	}
	for name, extra := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			access, decisions := filepath.Join(dir, "a.jsonl"), filepath.Join(dir, "d.jsonl")
			for _, p := range []string{access, decisions} {
				if err := os.WriteFile(p, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			args := append([]string{"--mode", "monitor", "--access", access, "--decisions", decisions}, extra...)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := runTarget(ctx, args, io.Discard, io.Discard)
			if err == nil || errors.Is(err, errUsage) {
				t.Errorf("err = %v, want a start failure", err)
			}
			for _, p := range []string{access, decisions} {
				if got, err := os.ReadFile(p); err != nil || string(got) != "keep" {
					t.Errorf("%s = %q, %v; want it untouched", filepath.Base(p), got, err)
				}
			}
		})
	}
}

func TestTargetRejectsBadUsage(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	access, decisions := filepath.Join(dir, "a.jsonl"), filepath.Join(dir, "d.jsonl")
	policy := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policy, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	local := []string{"--addr", "127.0.0.1:0", "--admin-addr", "127.0.0.1:0"}
	tests := map[string][]string{
		"no mode":                 {"--access", access, "--decisions", decisions},
		"unknown mode":            {"--mode", "off", "--access", access, "--decisions", decisions},
		"no access":               {"--mode", "enforce", "--decisions", decisions},
		"no decisions":            {"--mode", "enforce", "--access", access},
		"extra argument":          {"--mode", "enforce", "--access", access, "--decisions", decisions, "extra"},
		"one file for both logs":  {"--mode", "enforce", "--access", access, "--decisions", access},
		"access over the policy":  {"--mode", "enforce", "--access", policy, "--decisions", decisions, "--policy", policy},
		"decisions on the policy": {"--mode", "enforce", "--access", access, "--decisions", policy, "--policy", policy},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			all := append(append([]string{}, local...), args...)
			if err := runTarget(ctx, all, io.Discard, io.Discard); !errors.Is(err, errUsage) {
				t.Errorf("err = %v, want a usage error", err)
			}
			if got, err := os.ReadFile(policy); err != nil || string(got) != "{}" {
				t.Errorf("policy = %q, %v; want it untouched", got, err)
			}
		})
	}
}
