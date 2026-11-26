package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
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
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}, {"import", "-h"}} {
		var stdout, stderr bytes.Buffer
		if err := run(args, &stdout, &stderr); err != nil {
			t.Errorf("%v: %v", args, err)
		}
		if !strings.Contains(stdout.String()+stderr.String(), "import") {
			t.Errorf("%v: no usage text", args)
		}
	}
}
