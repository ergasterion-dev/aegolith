package aegolith_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestFuzzQuickScriptHandlesSpaces runs scripts/fuzz-quick.sh against a
// throwaway repository whose module and package directories contain spaces,
// with GO pointing at a stub that records each invocation instead of
// fuzzing. Every Fuzz package must be found and run from the right module
// directory with the right package path.
func TestFuzzQuickScriptHandlesSpaces(t *testing.T) {
	for _, tool := range []string{"sh", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	script, err := filepath.Abs(filepath.Join("scripts", "fuzz-quick.sh"))
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	repo := filepath.Join(base, "repo with space")
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(repo, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const fuzzFile = "package p\n\nimport \"testing\"\n\nfunc FuzzX(f *testing.F) {}\n"
	write("go.mod", "module example.com/root\n")
	write("root_test.go", fuzzFile)
	write("pkg a/a_test.go", fuzzFile)
	write("pkg a/plain_test.go", "package p\n")
	write("sub mod/go.mod", "module example.com/sub\n")
	write("sub mod/inner dir/b_test.go", fuzzFile)

	logPath := filepath.Join(base, "go calls.log")
	stub := filepath.Join(base, "stub go")
	if err := os.WriteFile(stub, []byte(`#!/bin/sh
printf '%s|%s\n' "$(pwd)" "$*" >> "$STUB_LOG"
case "$*" in
"test -list"*) echo FuzzX; echo ok ;;
esac
`), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", "-q", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}

	cmd := exec.Command("sh", script)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "GO="+stub, "FUZZTIME=1x", "STUB_LOG="+logPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fuzz-quick.sh: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "fuzz-quick: 3 targets passed") {
		t.Fatalf("output:\n%s", out)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	// macOS temp dirs resolve through /private; compare against the real path.
	realRepo, err := filepath.EvalSymlinks(repo)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		dir, args, _ := strings.Cut(l, "|")
		if rd, err := filepath.EvalSymlinks(dir); err == nil {
			dir = rd
		}
		rel, err := filepath.Rel(realRepo, dir)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(args, "-fuzz") {
			got = append(got, rel+"|"+args)
		}
	}
	slices.Sort(got)
	want := []string{
		".|test -run ^$ -fuzz ^FuzzX$ -fuzztime 1x .",
		".|test -run ^$ -fuzz ^FuzzX$ -fuzztime 1x ./pkg a",
		"sub mod|test -run ^$ -fuzz ^FuzzX$ -fuzztime 1x ./inner dir",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("fuzz runs:\n%s\nwant:\n%s\nscript output:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"), out)
	}
}
