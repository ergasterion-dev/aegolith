package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/remote"
	runner "github.com/ergasterion-dev/aegolith/bench/internal/run"
)

// remoteOptions are the checked flags of the remote command.
type remoteOptions struct {
	target                  remote.Target
	targetFile, confirmHost string
	rps, limit              int
	caseFiles               []string
	out, outCases           string
	stopFile, heartbeatFile string
}

// parseRemote parses and checks the flags of remote and the target file;
// help reports that the user asked for the flag list. Nothing is sent and
// nothing written before it returns.
func parseRemote(args []string, stderr io.Writer) (o remoteOptions, help bool, err error) {
	fs := flag.NewFlagSet("aegobench remote", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.targetFile, "target", "", "target file: the deployment, its allow-list and its limits")
	fs.StringVar(&o.confirmHost, "confirm-host", "", "the host[:port] of the target file's base_url, typed again")
	fs.IntVar(&o.rps, "rps", 0, "requests per second, at most the target file's max_rps (required)")
	caseFiles := fs.String("cases", "", "case files to place, separated by commas")
	fs.StringVar(&o.out, "out", "", "results file to write, for join")
	fs.StringVar(&o.outCases, "out-cases", "", "case file to write: every placed request and every case not sent, for report")
	fs.StringVar(&o.stopFile, "stop-file", "", "file whose appearance stops the run (optional)")
	fs.StringVar(&o.heartbeatFile, "heartbeat-file", "", "file that must have been modified in the last 30 s (optional)")
	fs.IntVar(&o.limit, "limit", 200, "case requests to send at most")
	if help, err := parseFlags(fs, args); help || err != nil {
		return o, help, err
	}
	if o.targetFile == "" || o.confirmHost == "" || o.rps == 0 || *caseFiles == "" || o.out == "" || o.outCases == "" {
		return o, false, fmt.Errorf("%w: --target, --confirm-host, --rps, --cases, --out and --out-cases are required", errUsage)
	}
	if o.limit < 1 {
		return o, false, fmt.Errorf("%w: --limit must be at least 1", errUsage)
	}
	o.caseFiles = strings.Split(*caseFiles, ",")
	if slices.Contains(o.caseFiles, "") {
		return o, false, fmt.Errorf("%w: --cases holds an empty file name", errUsage)
	}
	if o.target, err = remote.LoadTarget(o.targetFile); err != nil {
		return o, false, err
	}
	if err := o.target.Validate(o.confirmHost, o.rps); err != nil {
		return o, false, fmt.Errorf("target file: %w", err)
	}

	inputs := append([]string{o.targetFile}, o.caseFiles...)
	for _, f := range []string{o.stopFile, o.heartbeatFile} {
		if f != "" {
			inputs = append(inputs, f)
		}
	}
	if samePath(o.out, o.outCases) {
		return o, false, fmt.Errorf("%w: --out and --out-cases must be different files", errUsage)
	}
	for _, out := range []string{o.out, o.outCases} {
		if slices.ContainsFunc(inputs, func(in string) bool { return samePath(in, out) }) {
			return o, false, fmt.Errorf("%w: --out and --out-cases must not be the target file, a case file, the stop file or the heartbeat file", errUsage)
		}
		if err := checkWritable(out); err != nil {
			return o, false, fmt.Errorf("cannot write %s: %w", out, err)
		}
	}
	return o, false, nil
}

// samePath reports whether a and b name one file, existing or not.
func samePath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b) || sameFile(a, b)
}

// checkWritable checks that writeFile can replace path: it is not a
// directory and a file can be created beside it. It creates the directory if
// needed, as writeFile does.
func checkWritable(path string) error {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return errors.New("it is a directory")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	return errors.Join(f.Close(), os.Remove(f.Name()))
}

// runRemote places the cases into the target's allow-list and sends them
// under its limits. It writes the case file before sending and the results
// after, also when the run stops early; a stop is then an error.
func runRemote(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	o, help, err := parseRemote(args, stderr)
	if help || err != nil {
		return err
	}
	var all []cases.Case
	for _, path := range o.caseFiles {
		cs, err := readCaseFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		all = append(all, cs...)
	}
	originals, inputConflicts := cases.Merge(all)
	if len(originals) == 0 {
		return errors.New("the case files hold no cases to use")
	}
	plan, err := remote.Prepare(originals, inputConflicts, o.target)
	if err != nil {
		return err
	}
	if err := writeCaseFile(o.outCases, plan.Lines()); err != nil {
		return fmt.Errorf("writing %s: %w", o.outCases, err)
	}

	sent, stop, err := remote.Run(ctx, remote.Options{
		Target: o.target, ConfirmHost: o.confirmHost, RPS: o.rps, Cases: plan.Send, Limit: o.limit,
		StopFile: o.stopFile, HeartbeatFile: o.heartbeatFile,
	})
	if err != nil {
		return err
	}
	results := append(sent, plan.NotSentResults()...)
	if err := writeResults(o.out, results); err != nil {
		return fmt.Errorf("writing %s: %w", o.out, err)
	}
	if err := summarizeRemote(stdout, o, plan, sent); err != nil {
		return err
	}
	if stop != "" {
		return fmt.Errorf("the remote run stopped: %s; the results and the case file were written", stop)
	}
	return nil
}

// summarizeRemote prints what was placed, sent and left out, and why.
func summarizeRemote(w io.Writer, o remoteOptions, plan remote.Plan, sent []runner.Result) error {
	var done, unsent int
	unsentWhy := map[string]int{}
	for _, r := range sent {
		if r.Outcome == runner.NotSent {
			unsent++
			reason, _, _ := strings.Cut(r.Reason, ": ")
			unsentWhy[reason]++
		} else {
			done++
		}
	}
	// Counted as report counts them: one per case line.
	conflicting := 0
	for _, c := range plan.Conflicts {
		conflicting += len(cases.Lines(c))
	}
	_, err := fmt.Fprintf(w, "placed requests: %d to send, %d sent, %d not sent\n"+
		"%d cases not placed (%d refusals); %d conflicting cases left out\n"+
		"wrote %s and %s\n",
		len(plan.Send), done, unsent,
		len(plan.NotSent), sum(plan.Refused), conflicting, o.out, o.outCases)
	if err != nil {
		return err
	}
	for _, counts := range []map[string]int{unsentWhy, plan.Refused} {
		for _, reason := range slices.SortedFunc(maps.Keys(counts), func(a, b string) int {
			return cmp.Or(cmp.Compare(counts[b], counts[a]), cmp.Compare(a, b))
		}) {
			if _, err := fmt.Fprintf(w, "%7d  %s\n", counts[reason], reason); err != nil {
				return err
			}
		}
	}
	return nil
}

func sum(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}
