package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/ergasterion-dev/aegolith/bench/internal/records"
	"github.com/ergasterion-dev/aegolith/bench/internal/remote"
	runner "github.com/ergasterion-dev/aegolith/bench/internal/run"
)

// joinOptions are the checked flags of the join command.
type joinOptions struct {
	results, access, decisions, out string
	allowNoDecisions                bool
}

func parseJoin(args []string, stderr io.Writer) (o joinOptions, help bool, err error) {
	fs := flag.NewFlagSet("aegobench join", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.results, "results", "", "results file remote wrote")
	fs.StringVar(&o.access, "access", "", "the target's access log, one JSON record per line")
	fs.StringVar(&o.decisions, "decisions", "", "the target's decision log, one JSON record per line")
	fs.StringVar(&o.out, "out", "", "joined results file to write")
	fs.BoolVar(&o.allowNoDecisions, "allow-no-decisions", false,
		"accept a decision log with no record of this run: only if the firewall truly decided nothing about it")
	if help, err := parseFlags(fs, args); help || err != nil {
		return o, help, err
	}
	if o.results == "" || o.access == "" || o.decisions == "" || o.out == "" {
		return o, false, fmt.Errorf("%w: --results, --access, --decisions and --out are required", errUsage)
	}
	if slices.ContainsFunc([]string{o.results, o.access, o.decisions}, func(in string) bool { return samePath(in, o.out) }) {
		return o, false, fmt.Errorf("%w: --out must not be the results file or a log", errUsage)
	}
	return o, false, nil
}

// runJoin sets the outcome of every case remote sent from the target's logs,
// collected by the operator, and writes the joined results. A case missing
// from the access log is never passed. It refuses logs that are not the run's
// (see remote.CheckLogs) and says how many sent requests each log holds.
func runJoin(args []string, stdout, stderr io.Writer) error {
	o, help, err := parseJoin(args, stderr)
	if help || err != nil {
		return err
	}
	results, err := readResultsOnly(o.results)
	if err != nil {
		return fmt.Errorf("reading results %s: %w", o.results, err)
	}
	access, badAccess, err := readLog(o.access, records.ReadAccess)
	if err != nil {
		return err
	}
	decisions, badDecisions, err := readLog(o.decisions, records.ReadDecisions)
	if err != nil {
		return err
	}
	coverage, err := remote.CheckLogs(results, access, decisions, o.allowNoDecisions)
	if err != nil {
		return fmt.Errorf("not joined: %w", err)
	}
	joined := runner.Join(results, access, decisions)
	if err := writeResults(o.out, joined); err != nil {
		return fmt.Errorf("writing %s: %w", o.out, err)
	}
	count := map[runner.Outcome]int{}
	for _, r := range joined {
		count[r.Outcome]++
	}
	var outcomes []string
	for _, oc := range []runner.Outcome{runner.Blocked, runner.Flagged, runner.RouteOnly, runner.Passed,
		runner.Rejected, runner.Unknown, runner.NotSent} {
		outcomes = append(outcomes, fmt.Sprintf("%d %s", count[oc], oc))
	}
	_, err = fmt.Fprintf(stdout, "wrote %d cases to %s: %s\n"+
		"%d sent requests: %d with an access record, %d with a decision record\n"+
		"skipped unreadable log lines: %d access, %d decision\n",
		len(joined), o.out, strings.Join(outcomes, ", "),
		coverage.Sent, coverage.WithAccess, coverage.WithDecision, badAccess, badDecisions)
	return err
}

// readResultsOnly reads a results file that must hold at least one result.
func readResultsOnly(path string) (out []runner.Result, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	out, err = runner.ReadResults(f)
	if err == nil && len(out) == 0 {
		err = errors.New("the file holds no results")
	}
	return out, err
}
