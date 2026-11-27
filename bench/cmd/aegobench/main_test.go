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
	"slices"
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

func TestImportCRSWritesCasesAndCountsSkips(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "crs.jsonl")
	var stdout, stderr bytes.Buffer
	skipped := filepath.Join(filepath.Dir(out), "audit", "skipped.jsonl")
	args := []string{
		"import", "--source", "crs", "--root", "../../internal/sources/crs/testdata/tree",
		"--out", out, "--skipped", skipped,
	}
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	audit, err := os.ReadFile(skipped)
	if err != nil {
		t.Fatal(err)
	}
	auditLines := strings.Split(strings.TrimSuffix(string(audit), "\n"), "\n")
	if len(auditLines) != 7 {
		t.Errorf("%d lines in the skip file, want 7:\n%s", len(auditLines), audit)
	}
	if want := `{"case_id":"942100-3","reason":"request is given as raw or encoded bytes"}`; !slices.Contains(auditLines, want) {
		t.Errorf("the skip file lacks %s:\n%s", want, audit)
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
	if len(lines) != 4 {
		t.Errorf("%d lines, want 4", len(lines))
	}
	for _, l := range lines {
		if _, err := cases.FromLine(l); err != nil {
			t.Error(err)
		}
	}
	want := "wrote 4 cases from crs (2 attack, 0 legit, 2 near-miss) to " + out + "\n" +
		"skipped 7:\n" +
		"      1  HTTP version is not HTTP/1.1\n" +
		"      1  file holds no tests\n" +
		"      1  file is not valid YAML\n" +
		"      1  output requires no rule IDs and excludes none\n" +
		"      1  request is given as raw or encoded bytes\n" +
		"      1  response-phase rule: the attack is not in the request\n" +
		"      1  test has several stages\n"
	if got := stdout.String(); got != want {
		t.Errorf("summary:\n%s\nwant:\n%s", got, want)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr: %s", stderr.String())
	}
}

func TestImportGoTestWAFWritesCasesAndCountsSkips(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "gotestwaf.jsonl")
	skipped := filepath.Join(filepath.Dir(out), "skipped.jsonl")
	var stdout, stderr bytes.Buffer
	args := []string{
		"import", "--source", "gotestwaf", "--root", "../../internal/sources/gotestwaf/testdata/tree",
		"--out", out, "--skipped", skipped,
	}
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	audit, err := os.ReadFile(skipped)
	if err != nil {
		t.Fatal(err)
	}
	auditLines := strings.Split(strings.TrimSuffix(string(audit), "\n"), "\n")
	if want := `{"case_id":"attacks/odd/1/Rot13/XMLBody","reason":"encoder is not one of the tool's"}`; !slices.Contains(auditLines, want) {
		t.Errorf("the skip file lacks %s:\n%s", want, audit)
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
	for _, l := range lines {
		if _, err := cases.FromLine(l); err != nil {
			t.Error(err)
		}
	}
	want := "wrote 17 cases from gotestwaf (11 attack, 6 legit, 0 near-miss) to " + out + "\n" +
		"skipped 10:\n" +
		"      3  encoder is not one of the tool's\n" +
		"      2  GraphQL placeholder: the tool sends it only to a target that answers its GraphQL check\n" +
		"      1  file holds no payload, no encoder or no placeholder\n" +
		"      1  file is not YAML in the shape of a test case\n" +
		"      1  gRPC placeholder: the tool makes a gRPC call, not a plain HTTP request\n" +
		"      1  placeholder is not one of the tool's\n" +
		"      1  the tool cannot load this file: RawRequest needs a method that is a string\n"
	if got := stdout.String(); got != want {
		t.Errorf("summary:\n%s\nwant:\n%s", got, want)
	}
	if len(lines) != 17 || len(auditLines) != 10 || stderr.Len() != 0 {
		t.Errorf("%d lines, %d skips, stderr %q", len(lines), len(auditLines), stderr.String())
	}

	err = run([]string{"import", "--source", "gotestwaf", "--out", out}, &stdout, &stderr)
	if !errors.Is(err, errUsage) {
		t.Errorf("error %v, want a usage error without --root", err)
	}
	err = run([]string{"import", "--source", "gotestwaf", "--root", t.TempDir(), "--out", out}, &stdout, &stderr)
	if err == nil || errors.Is(err, errUsage) {
		t.Errorf("error %v, want a failed import for an empty tree", err)
	}
}

func TestImportCRSNeedsARoot(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "crs.jsonl")
	var stdout, stderr bytes.Buffer
	err := run([]string{"import", "--source", "crs", "--out", out}, &stdout, &stderr)
	if !errors.Is(err, errUsage) {
		t.Errorf("error %v, want a usage error", err)
	}
	err = run([]string{"import", "--source", "crs", "--root", t.TempDir(), "--out", out}, &stdout, &stderr)
	if err == nil || errors.Is(err, errUsage) {
		t.Errorf("error %v, want a failed import for a tree without tests", err)
	}
	if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the output exists after failed imports: %v", statErr)
	}
	const tree = "../../internal/sources/crs/testdata/tree"
	err = run([]string{"import", "--source", "crs", "--root", tree, "--out", out, "--skipped", out}, &stdout, &stderr)
	if !errors.Is(err, errUsage) {
		t.Errorf("error %v, want a usage error for one file given twice", err)
	}
	err = run([]string{"import", "--source", "baseline", "--corpus", corpusDir, "--out", out, "--skipped", out + ".skips"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if got, readErr := os.ReadFile(out + ".skips"); readErr != nil || len(got) != 0 {
		t.Errorf("skip file of a source without skips: %q, %v; want it empty", got, readErr)
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

func TestImportGeneratedLegitWritesCasesPerCategory(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "legit.jsonl")
	var stdout, stderr bytes.Buffer
	args := []string{"import", "--source", "generated-legit", "--seed", "7", "--n", "40", "--out", out}
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := cases.ReadLines(bytes.NewReader(first))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if _, err := cases.FromLine(l); err != nil {
			t.Error(err)
		}
	}
	want := "wrote 40 cases from generated-legit (0 attack, 40 legit, 0 near-miss) to " + out + "\n" +
		"by category:\n" +
		"      4  addresses\n" +
		"      8  code-like-prose\n" +
		"      4  names\n" +
		"      4  other-languages\n" +
		"      4  prices-and-quantities\n" +
		"      6  reviews\n" +
		"      6  support-messages\n" +
		"      4  urls-in-text\n"
	if got := stdout.String(); got != want {
		t.Errorf("summary:\n%s\nwant:\n%s", got, want)
	}
	if len(lines) != 40 || stderr.Len() != 0 {
		t.Errorf("%d lines, stderr %q", len(lines), stderr.String())
	}

	// The same seed and size write the same file; another seed does not.
	again := filepath.Join(filepath.Dir(out), "again.jsonl")
	args[len(args)-1] = again
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if second, err := os.ReadFile(again); err != nil || !bytes.Equal(first, second) {
		t.Errorf("a second run wrote a different file (error %v)", err)
	}
	if err := run([]string{"import", "--source", "generated-legit", "--seed", "8", "--n", "40", "--out", again}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if other, err := os.ReadFile(again); err != nil || bytes.Equal(first, other) {
		t.Errorf("another seed wrote the same file (error %v)", err)
	}
}

func TestImportGeneratedLegitNeedsASizeItCanReach(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "legit.jsonl")
	var stdout, stderr bytes.Buffer
	for _, n := range []string{"", "0", "-3"} {
		args := []string{"import", "--source", "generated-legit", "--out", out}
		if n != "" {
			args = append(args, "--n", n)
		}
		if err := run(args, &stdout, &stderr); !errors.Is(err, errUsage) {
			t.Errorf("--n %q: error %v, want a usage error", n, err)
		}
	}
	// More than the material holds: an error that says how many there are,
	// and no file with fewer cases than were asked for.
	err := run([]string{"import", "--source", "generated-legit", "--n", "5000000", "--out", out}, &stdout, &stderr)
	if err == nil || errors.Is(err, errUsage) || !strings.Contains(err.Error(), "distinct cases") {
		t.Errorf("error %v, want one that says how many distinct cases there are", err)
	}
	if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the output exists after failed imports: %v", statErr)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout after failed imports: %q", stdout.String())
	}
}
