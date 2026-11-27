//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith/bench/internal/report"
)

const (
	runScript  = "../../scripts/run-local.sh"
	scriptFile = "../../sources.json"
)

// scriptVariables are what the script reads from its environment.
var scriptVariables = []string{"SOURCES", "OUT", "PREVIOUS", "POLICY", "DETECT_RPS", "LEGIT_SEED", "LEGIT_N",
	"DURATION", "RPS", "WORKERS", "ATTACK_SHARE", "LOAD_SEED"}

// scriptCommand runs the one-command script over the baseline only, which
// needs no network, writing into out. extra holds more NAME=value settings.
func scriptCommand(t *testing.T, mode, out string, extra ...string) *exec.Cmd {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	// Reading them makes a cached result depend on them.
	for _, name := range []string{runScript, scriptFile} {
		if _, err := os.ReadFile(name); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.CommandContext(t.Context(), bash, runScript, mode)
	// Not the settings of whoever runs the tests, and not the variables a git
	// hook sets, which would point git elsewhere.
	cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return strings.HasPrefix(name, "GIT_") || slices.Contains(scriptVariables, name)
	})
	cmd.Env = append(cmd.Env, "SOURCES=baseline", "OUT="+out)
	cmd.Env = append(cmd.Env, extra...)
	return cmd
}

// processGone fails the test unless the process whose ID the file holds has
// ended and been waited for.
func processGone(t *testing.T, pidFile string) {
	t.Helper()
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("no process ID: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		t.Fatalf("process ID %q", b)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Errorf("process %d of %s is still there (%v)", pid, filepath.Base(pidFile), err)
	}
}

func notThere(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s is there (%v)", filepath.Base(path), err)
	}
}

// TestMakeBenchSmoke runs what make bench-waf runs, over the baseline only.
func TestMakeBenchSmoke(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "out")
	output, err := scriptCommand(t, "waf", out, "DETECT_RPS=5000").CombinedOutput()
	if err != nil {
		t.Fatalf("the script failed: %v\n%s", err, output)
	}

	md := readText(t, filepath.Join(out, "report.md"))
	var r report.Report
	if err := json.Unmarshal([]byte(readText(t, filepath.Join(out, "report.json"))), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Configs) != 2 || r.Configs[0].Name != "no-policy" || r.Configs[1].Name != "example-policy" {
		t.Fatalf("configurations %+v", r.Configs)
	}
	// What the firewall decides is not this test's matter; that every case was
	// sent and has a known outcome is.
	for _, c := range r.Configs {
		cases, unknown := 0, 0
		for _, row := range c.Rows {
			if row.Source == report.TotalSource {
				cases, unknown = cases+row.Counts.Sent, unknown+row.Counts.Unknown
			}
		}
		if cases != 425 || unknown != 0 {
			t.Errorf("%s: %d cases sent, %d unknown; want 425 and 0", c.Name, cases, unknown)
		}
		processGone(t, filepath.Join(out, "runs", c.Name, "target.pid"))
	}
	environment := map[string]string{}
	for _, f := range r.Meta.Environment {
		environment[f.Name] = f.Value
	}
	for _, name := range []string{"CPU", "Logical processors", "Memory", "Operating system", "Go",
		"libinjection-go", "git", "Load average at start (1, 5, 15 min)", "Load average at end (1, 5, 15 min)",
		"Configuration no-policy", "Configuration example-policy"} {
		if v := environment[name]; v == "" || v == "unknown" {
			t.Errorf("environment %q is %q", name, v)
		}
	}
	if r.Meta.Input == nil || r.Meta.Input.Lines != 425 {
		t.Errorf("input %+v", r.Meta.Input)
	}
	// The commit the binary was built from is recorded.
	if head, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
		if commit := strings.TrimSpace(string(head)); !strings.HasPrefix(r.Meta.Commit, commit) {
			t.Errorf("commit %q, want %s", r.Meta.Commit, commit)
		}
	}
	// No local path.
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	local := []string{root, out, os.TempDir()}
	if home, err := os.UserHomeDir(); err == nil {
		local = append(local, home)
	}
	for _, path := range local {
		if path = strings.TrimSuffix(path, "/"); len(path) > 4 && strings.Contains(md, path) {
			t.Errorf("the report holds the local path %q", path)
		}
	}
}

// A run that fails stops the target it started and leaves no report, not even
// an earlier one.
func TestRunLocalStopsTargetOnFailure(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	writeText(t, filepath.Join(out, "report.md"), "stale")
	writeText(t, filepath.Join(out, "report.json"), "stale")
	// detect refuses this rate, after the target has started.
	output, err := scriptCommand(t, "waf", out, "DETECT_RPS=0").CombinedOutput()
	if err == nil {
		t.Fatalf("the script succeeded:\n%s", output)
	}
	if !bytes.Contains(output, []byte("--rps must be at least 1")) {
		t.Errorf("the failure is not that of detect:\n%s", output)
	}
	processGone(t, filepath.Join(out, "runs", "no-policy", "target.pid"))
	notThere(t, filepath.Join(out, "report.md"))
	notThere(t, filepath.Join(out, "report.json"))
}

func TestRunLocalRefusesBadSettings(t *testing.T) {
	t.Parallel()
	for name, settings := range map[string][]string{
		"unknown source":     {"SOURCES=baseline elsewhere"},
		"no source":          {"SOURCES= "},
		"source twice":       {"SOURCES=baseline,baseline"},
		"no previous report": {"PREVIOUS=absent.json"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out := filepath.Join(t.TempDir(), "out")
			output, err := scriptCommand(t, "waf", out, settings...).CombinedOutput()
			if err == nil {
				t.Fatalf("the script succeeded:\n%s", output)
			}
			notThere(t, filepath.Join(out, "runs"))
		})
	}
	if output, err := scriptCommand(t, "other", filepath.Join(t.TempDir(), "out")).CombinedOutput(); err == nil {
		t.Errorf("an unknown mode succeeded:\n%s", output)
	}
}

// An interrupted run stops the client and the target it started.
func TestRunLocalStopsWhatItStartedWhenInterrupted(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "out")
	run := filepath.Join(out, "runs", "no-policy")
	// At one request per second detection lasts minutes.
	cmd := scriptCommand(t, "waf", out, "DETECT_RPS=1")
	log, err := os.Create(filepath.Join(t.TempDir(), "script.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() { ended <- cmd.Wait() }()
	// The target's first access record shows that both processes are at work.
	// The wait has no bound of its own: a busy machine may take long to build.
	for {
		if info, err := os.Stat(filepath.Join(run, "access.jsonl")); err == nil && info.Size() > 0 {
			break
		}
		select {
		case err := <-ended:
			t.Fatalf("the script ended before it was interrupted: %v\n%s", err, readText(t, log.Name()))
		case <-time.After(20 * time.Millisecond):
		}
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := <-ended; err == nil {
		t.Errorf("the interrupted script succeeded:\n%s", readText(t, log.Name()))
	}
	processGone(t, filepath.Join(run, "target.pid"))
	processGone(t, filepath.Join(run, "detect.pid"))
	notThere(t, filepath.Join(out, "report.md"))
}

// The load mode writes its result and a report of it.
func TestRunLocalLoad(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "out")
	output, err := scriptCommand(t, "load", out, "DURATION=1s", "RPS=50").CombinedOutput()
	if err != nil {
		t.Fatalf("the script failed: %v\n%s", err, output)
	}
	var r report.Report
	if err := json.Unmarshal([]byte(readText(t, filepath.Join(out, "load", "report.json"))), &r); err != nil {
		t.Fatal(err)
	}
	l := r.Load
	// Whether each of the 50 scheduled requests was sent depends on the
	// machine; that each is accounted for does not.
	if l == nil || l.RPS != 50 || l.Sent+l.Dropped != 50 || l.Decisions == nil || !l.MemAsked || l.MemPolls < 1 {
		t.Errorf("load %+v", l)
	}
	if len(r.Configs) != 0 {
		t.Errorf("a load report holds detection configurations: %+v", r.Configs)
	}
	environment := map[string]string{}
	for _, f := range r.Meta.Environment {
		environment[f.Name] = f.Value
	}
	if environment["Target"] == "" || environment["Load average at end (1, 5, 15 min)"] == "" {
		t.Errorf("environment %q", environment)
	}
	processGone(t, filepath.Join(out, "load", "target.pid"))
}
