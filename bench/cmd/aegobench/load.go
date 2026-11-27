package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	runner "github.com/ergasterion-dev/aegolith/bench/internal/run"
)

// loadOptions are the checked flags of the load command.
type loadOptions struct {
	caseFiles      []string
	base, admin    *url.URL
	rps, workers   int
	duration       time.Duration
	attackShare    float64
	seed           int64
	decisions, out string
}

// parseLoad parses and checks the flags of load; help reports that the user
// asked for the flag list.
func parseLoad(args []string, stderr io.Writer) (o loadOptions, help bool, err error) {
	fs := flag.NewFlagSet("aegobench load", flag.ContinueOnError)
	fs.SetOutput(stderr)
	caseFiles := fs.String("cases", "", "case files to draw requests from, separated by commas")
	base := fs.String("base", "", "URL of a target on this machine, such as http://127.0.0.1:8088")
	admin := fs.String("admin", "", "URL of the target's admin endpoints, such as http://127.0.0.1:8089, to read its memory (optional)")
	fs.IntVar(&o.rps, "rps", 0, "requests to send per second")
	fs.DurationVar(&o.duration, "duration", 0, "how long to send, such as 60s")
	fs.IntVar(&o.workers, "workers", 64, "requests that may be in flight at once; a request due when all are is dropped")
	fs.Float64Var(&o.attackShare, "attack-share", 0.1, "share of the requests drawn from attack cases, 0 to 1")
	fs.Int64Var(&o.seed, "seed", 1, "seed of the choice of cases")
	fs.StringVar(&o.decisions, "decisions", "", "decision log the target writes, to read the firewall's own latency from (optional)")
	fs.StringVar(&o.out, "out", "", "load result to write")
	if help, err := parseFlags(fs, args); help || err != nil {
		return o, help, err
	}
	if *caseFiles == "" || *base == "" || o.out == "" {
		return o, false, fmt.Errorf("%w: --cases, --base, --rps, --duration and --out are required", errUsage)
	}
	o.caseFiles = strings.Split(*caseFiles, ",")
	if slices.Contains(o.caseFiles, "") {
		return o, false, fmt.Errorf("%w: --cases holds an empty file name", errUsage)
	}
	if o.base, err = parseBase("--base", *base); err != nil {
		return o, false, err
	}
	targets := map[string]*url.URL{"--base": o.base}
	if *admin != "" {
		if o.admin, err = parseBase("--admin", *admin); err != nil {
			return o, false, err
		}
		targets["--admin"] = o.admin
	}
	// As for detect: other hosts are for remote mode. The value is not
	// repeated.
	for name, u := range targets {
		if !isLoopback(u.Hostname()) {
			return o, false, fmt.Errorf("%w: %s must name a loopback host: localhost, 127.0.0.0/8 or ::1", errUsage, name)
		}
	}
	switch {
	case o.rps < 1 || o.rps > runner.MaxLoadRPS:
		return o, false, fmt.Errorf("%w: --rps is required and must be 1 to %d", errUsage, runner.MaxLoadRPS)
	case o.duration <= 0:
		return o, false, fmt.Errorf("%w: --duration is required and must be above zero", errUsage)
	case o.workers < 1:
		return o, false, fmt.Errorf("%w: --workers must be at least 1", errUsage)
	case !(o.attackShare >= 0 && o.attackShare <= 1): // also refuses NaN
		return o, false, fmt.Errorf("%w: --attack-share must be from 0 to 1", errUsage)
	}
	inputs := slices.Clone(o.caseFiles)
	if o.decisions != "" {
		inputs = append(inputs, o.decisions)
	}
	if slices.ContainsFunc(inputs, func(in string) bool { return sameFile(in, o.out) }) {
		return o, false, fmt.Errorf("%w: --out must not be a case file or the decision log", errUsage)
	}
	return o, false, nil
}

// runLoad sends a mix of the cases to the target at a fixed rate and writes
// what it measured. It writes no detection results. A run that ctx interrupts
// still writes its result, marked as interrupted, and is then an error.
func runLoad(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	o, help, err := parseLoad(args, stderr)
	if help || err != nil {
		return err
	}
	cs, conflicting, err := readCases(o.caseFiles)
	if err != nil {
		return err
	}
	// A wrong path should not cost a whole run.
	if o.decisions != "" {
		if _, err := os.Stat(o.decisions); err != nil {
			return fmt.Errorf("checking the target's log: %w", err)
		}
	}

	client := runner.NewLoadClient(sendTimeout, o.workers)
	defer client.CloseIdleConnections()
	res, err := runner.Load(ctx, client, runner.LoadOptions{
		Base: o.base, AdminURL: o.admin, Cases: cs, RPS: o.rps, Workers: o.workers,
		Duration: o.duration, AttackShare: o.attackShare, Seed: o.seed,
	})
	if err != nil {
		return err
	}
	// The target writes a decision before it answers, so the log is complete.
	var logErr error
	if o.decisions != "" {
		if res.Decisions, logErr = readDecisionLatency(o.decisions, res.IDPrefix); logErr != nil {
			logErr = fmt.Errorf("the result has no decision latency: %w", logErr)
		}
	}

	encoded, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding the load result: %w", err)
	}
	err = writeFile(o.out, func(w io.Writer) error {
		_, err := w.Write(append(encoded, '\n'))
		return err
	})
	if err != nil {
		return fmt.Errorf("writing %s: %w", o.out, err)
	}
	if err := summarizeLoad(stdout, o.out, res, conflicting); err != nil {
		return err
	}
	if res.Interrupted {
		return errors.Join(fmt.Errorf("load interrupted, the partial result was written: %w", context.Cause(ctx)), logErr)
	}
	return logErr
}

// readDecisionLatency reads the firewall's latency for one load run from the
// target's decision log.
func readDecisionLatency(path, idPrefix string) (out *runner.DecisionLatency, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening the target's log: %w", err)
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	latency, err := runner.ReadDecisionLatency(f, idPrefix)
	if err != nil {
		return nil, err
	}
	return &latency, nil
}

// summarizeLoad prints the main figures of a load run.
func summarizeLoad(w io.Writer, out string, res runner.LoadResult, conflicting int) error {
	interrupted := ""
	if res.Interrupted {
		interrupted = fmt.Sprintf("the run was interrupted with %d requests in flight\n", res.Cancelled)
	}
	_, err := fmt.Fprintf(w, "%ssent %d requests in %s (asked %d per second, achieved %.1f): "+
		"%d transport errors, %d dropped because every worker was busy\n"+
		"client round trip in microseconds: p50 %d, p90 %d, p99 %d, max %d\n"+
		"left out %d conflicting cases and %d that cannot be sent\n"+
		"wrote %s\n",
		interrupted, res.Sent, res.Duration.Round(time.Millisecond), res.RPS, res.AchievedRPS,
		res.TransportErrors, res.Dropped, res.P50US, res.P90US, res.P99US, res.MaxUS,
		conflicting, res.Excluded, out)
	return err
}
