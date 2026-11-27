// Command aegobench measures Aegolith against request sets: it imports each
// source into case lines, serves the target they are replayed against, sends
// them to it, judges the outcome of each and reports the results.
package main

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/ergasterion-dev/aegolith"
	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/records"
	runner "github.com/ergasterion-dev/aegolith/bench/internal/run"
	"github.com/ergasterion-dev/aegolith/bench/internal/sources/baseline"
	"github.com/ergasterion-dev/aegolith/bench/internal/sources/crs"
	"github.com/ergasterion-dev/aegolith/bench/internal/target"
)

const usage = `usage: aegobench <command> [flags]

commands:
  import    convert a source into case lines
  target    serve the firewall-wrapped server that cases are sent to
  detect    send every case to the target once and record each outcome
  report    count the outcomes and compare them with an earlier report
  help      show this text

Run "aegobench <command> -h" for a command's flags.
`

// errUsage marks a command line the user has to correct.
var errUsage = errors.New("usage error")

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "aegobench:", err)
		if errors.Is(err, errUsage) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

// run dispatches args to a subcommand.
func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return fmt.Errorf("%w: no command given", errUsage)
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		_, err := fmt.Fprint(stdout, usage)
		return err
	case "import":
		return runImport(args[1:], stdout, stderr)
	case "target":
		ctx, stop := signalContext()
		defer stop()
		return runTarget(ctx, args[1:], stdout, stderr)
	case "detect":
		ctx, stop := signalContext()
		defer stop()
		return runDetect(ctx, args[1:], stdout, stderr)
	case "report":
		return runReport(args[1:], stdout, stderr)
	default:
		fmt.Fprint(stderr, usage)
		return fmt.Errorf("%w: unknown command %q", errUsage, args[0])
	}
}

// signalContext returns a context that SIGINT or SIGTERM cancels. A second
// signal, during the shutdown that follows, ends the process at once.
func signalContext() (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	context.AfterFunc(ctx, stop)
	return ctx, stop
}

// parseFlags parses a subcommand's flags; no subcommand takes positional
// arguments. help reports that the user asked for the flag list, which has
// then been printed.
func parseFlags(fs *flag.FlagSet, args []string) (help bool, err error) {
	switch err := fs.Parse(args); {
	case errors.Is(err, flag.ErrHelp):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("%w: %w", errUsage, err)
	case fs.NArg() > 0:
		return false, fmt.Errorf("%w: unexpected argument %q", errUsage, fs.Arg(0))
	}
	return false, nil
}

func runImport(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("aegobench import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("source", "", `source to import: "baseline" or "crs"`)
	corpus := fs.String("corpus", "", "corpus directory (source baseline)")
	root := fs.String("root", "", "fetched source tree (source crs)")
	out := fs.String("out", "", "case file to write")
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("%w: --out is required", errUsage)
	}

	var lines []cases.Line
	var skipped []cases.Skip
	var err error
	switch *source {
	case cases.SourceBaseline:
		if *corpus == "" {
			return fmt.Errorf("%w: --corpus is required for source %s", errUsage, *source)
		}
		lines, err = baseline.Import(*corpus)
	case crs.Source:
		if *root == "" {
			return fmt.Errorf("%w: --root is required for source %s", errUsage, *source)
		}
		lines, skipped, err = crs.Import(*root)
	default:
		return fmt.Errorf("%w: unknown source %q", errUsage, *source)
	}
	if err != nil {
		return err
	}
	if err := writeCaseFile(*out, lines); err != nil {
		return fmt.Errorf("writing %s: %w", *out, err)
	}

	count := map[cases.Expected]int{}
	for _, l := range lines {
		count[l.Expected]++
	}
	_, err = fmt.Fprintf(stdout, "wrote %d cases from %s (%d attack, %d legit, %d near-miss) to %s\n",
		len(lines), *source, count[cases.Attack], count[cases.Legit], count[cases.NearMiss], *out)
	if err != nil || len(skipped) == 0 {
		return err
	}
	return printSkips(stdout, skipped)
}

// printSkips prints how many source cases were left out for each reason, the
// most frequent reason first.
func printSkips(w io.Writer, skipped []cases.Skip) error {
	count := map[string]int{}
	for _, s := range skipped {
		count[s.Reason]++
	}
	reasons := slices.SortedFunc(maps.Keys(count), func(a, b string) int {
		return cmp.Or(cmp.Compare(count[b], count[a]), cmp.Compare(a, b))
	})
	if _, err := fmt.Fprintf(w, "skipped %d:\n", len(skipped)); err != nil {
		return err
	}
	for _, reason := range reasons {
		if _, err := fmt.Fprintf(w, "%7d  %s\n", count[reason], reason); err != nil {
			return err
		}
	}
	return nil
}

// writeCaseFile replaces path with lines, see writeFile.
func writeCaseFile(path string, lines []cases.Line) error {
	return writeFile(path, func(w io.Writer) error { return cases.WriteLines(w, lines) })
}

// writeFile writes to a temporary file beside path and renames it into place,
// so path never holds a partial file.
func writeFile(path string, write func(io.Writer) error) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.Remove(tmp.Name()))
		}
	}()
	writeErr := write(tmp)
	if writeErr == nil {
		writeErr = tmp.Chmod(0o644) // CreateTemp makes the file private
	}
	if err := errors.Join(writeErr, tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// shutdownTimeout bounds how long a stopping target waits for open requests.
const shutdownTimeout = 10 * time.Second

// runTarget serves the target and its admin endpoints until ctx is cancelled
// or a server fails. The two log files are replaced, and only once the target
// is known to start: both ports are bound and the policy is loaded.
func runTarget(ctx context.Context, args []string, stdout, stderr io.Writer) (err error) {
	fs := flag.NewFlagSet("aegobench target", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:8088", "address of the target")
	adminAddr := fs.String("admin-addr", "127.0.0.1:8089", "address of /health and /memstats")
	modeName := fs.String("mode", "", `firewall mode: "enforce" or "monitor" (overrides the policy)`)
	policy := fs.String("policy", "", "Aegolith configuration file (default: no routes)")
	accessPath := fs.String("access", "", "access log to write (replaced)")
	decisionsPath := fs.String("decisions", "", "decision log to write (replaced)")
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}
	var mode aegolith.Mode
	if err := mode.UnmarshalText([]byte(*modeName)); err != nil {
		return fmt.Errorf(`%w: --mode must be "enforce" or "monitor"`, errUsage)
	}
	if *accessPath == "" || *decisionsPath == "" {
		return fmt.Errorf("%w: --access and --decisions are required", errUsage)
	}

	var listen net.ListenConfig
	listener, err := listen.Listen(ctx, "tcp", *addr)
	if err != nil {
		return fmt.Errorf("listening for the target: %w", err)
	}
	// Serve closes the listeners; this covers the returns before it.
	defer listener.Close()
	adminListener, err := listen.Listen(ctx, "tcp", *adminAddr)
	if err != nil {
		return fmt.Errorf("listening for the admin endpoints: %w", err)
	}
	defer adminListener.Close()

	logs, err := openLogs(*policy, *accessPath, *decisionsPath)
	if err != nil {
		return err
	}
	defer func() {
		for _, f := range logs {
			if closeErr := f.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("closing log: %w", closeErr))
			}
		}
	}()
	handler, err := target.Handler(target.Config{
		Mode:       mode,
		PolicyPath: *policy,
		Access:     records.NewWriter(logs[0]),
		Decisions:  records.NewWriter(logs[1]),
	})
	if err != nil {
		return err
	}
	for _, f := range logs {
		if err := emptyFile(f); err != nil {
			return fmt.Errorf("emptying log: %w", err)
		}
	}

	if _, err := fmt.Fprintf(stdout, "target listening on http://%s (mode %s), admin on http://%s\n",
		listener.Addr(), mode, adminListener.Addr()); err != nil {
		return err
	}
	errorLog := log.New(stderr, "aegobench target: ", log.LstdFlags)
	return serve(ctx,
		endpoint{newServer(handler, errorLog), listener},
		endpoint{newServer(target.AdminHandler(), errorLog), adminListener})
}

// openLogs opens the access and decision logs for writing without changing
// them. It refuses a log that is the other log or the policy file, because
// emptying it would destroy that file's content.
func openLogs(policy, accessPath, decisionsPath string) (logs []*os.File, err error) {
	defer func() {
		if err != nil {
			for _, f := range logs {
				err = errors.Join(err, f.Close())
			}
			logs = nil
		}
	}()
	var seen []os.FileInfo
	if policy != "" {
		info, err := os.Stat(policy)
		if err != nil {
			return nil, fmt.Errorf("reading policy: %w", err)
		}
		seen = append(seen, info)
	}
	for _, path := range []string{accessPath, decisionsPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return logs, fmt.Errorf("creating log directory: %w", err)
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return logs, fmt.Errorf("opening log: %w", err)
		}
		logs = append(logs, f)
		info, err := f.Stat()
		if err != nil {
			return logs, fmt.Errorf("opening log: %w", err)
		}
		for _, other := range seen {
			if os.SameFile(info, other) {
				return logs, fmt.Errorf("%w: --access, --decisions and --policy must be different files", errUsage)
			}
		}
		seen = append(seen, info)
	}
	return logs, nil
}

// emptyFile truncates f if it is a regular file; a pipe or a device has
// nothing to remove.
func emptyFile(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	return f.Truncate(0)
}

func newServer(h http.Handler, errorLog *log.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          errorLog,
	}
}

type endpoint struct {
	server   *http.Server
	listener net.Listener
}

// serve runs the endpoints until ctx is cancelled or one of them fails, then
// shuts all of them down and waits for them.
func serve(ctx context.Context, endpoints ...endpoint) error {
	stopped := make(chan error, len(endpoints))
	for _, e := range endpoints {
		go func() { stopped <- e.server.Serve(e.listener) }()
	}
	var errs []error
	running := len(endpoints)
	select {
	case <-ctx.Done():
	case err := <-stopped:
		running--
		errs = append(errs, fmt.Errorf("serving: %w", err))
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	for _, e := range endpoints {
		if err := e.server.Shutdown(shutdownCtx); err != nil {
			errs = append(errs, fmt.Errorf("shutting down: %w", errors.Join(err, e.server.Close())))
		}
	}
	for range running {
		if err := <-stopped; !errors.Is(err, http.ErrServerClosed) {
			errs = append(errs, fmt.Errorf("serving: %w", err))
		}
	}
	return errors.Join(errs...)
}

// sendTimeout is how long detect waits for one answer.
const sendTimeout = 10 * time.Second

// detectOptions are the checked flags of the detect command.
type detectOptions struct {
	caseFiles              []string
	base                   *url.URL
	access, decisions, out string
	idPrefix               string
	rps                    int
}

// parseDetect parses and checks the flags of detect; help reports that the
// user asked for the flag list.
func parseDetect(args []string, stderr io.Writer) (o detectOptions, help bool, err error) {
	fs := flag.NewFlagSet("aegobench detect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	caseFiles := fs.String("cases", "", "case files to send, separated by commas")
	base := fs.String("base", "", "URL of a target on this machine, such as http://127.0.0.1:8088")
	fs.StringVar(&o.access, "access", "", "access log the target writes")
	fs.StringVar(&o.decisions, "decisions", "", "decision log the target writes")
	fs.StringVar(&o.out, "out", "", "results file to write")
	fs.IntVar(&o.rps, "rps", 500, "ceiling on requests per second")
	fs.StringVar(&o.idPrefix, "id-prefix", "b0000000-", "start of every request ID")
	if help, err := parseFlags(fs, args); help || err != nil {
		return o, help, err
	}
	if *caseFiles == "" || *base == "" || o.access == "" || o.decisions == "" || o.out == "" {
		return o, false, fmt.Errorf("%w: --cases, --base, --access, --decisions and --out are required", errUsage)
	}
	o.caseFiles = strings.Split(*caseFiles, ",")
	if slices.Contains(o.caseFiles, "") {
		return o, false, fmt.Errorf("%w: --cases holds an empty file name", errUsage)
	}
	if o.base, err = parseBase(*base); err != nil {
		return o, false, err
	}
	// Other hosts are for remote mode, which has the limits that sending to
	// them needs. The value is not repeated.
	if !isLoopback(o.base.Hostname()) {
		return o, false, fmt.Errorf("%w: --base must name a loopback host: localhost, 127.0.0.0/8 or ::1", errUsage)
	}
	if o.rps < 1 {
		return o, false, fmt.Errorf("%w: --rps must be at least 1", errUsage)
	}
	// A case ID is 64 characters long.
	if !runner.ValidRequestID(o.idPrefix + strings.Repeat("0", 64)) {
		return o, false, fmt.Errorf("%w: --id-prefix must be at most 64 characters of A-Za-z0-9._-", errUsage)
	}
	inputs := append([]string{o.access, o.decisions}, o.caseFiles...)
	if slices.ContainsFunc(inputs, func(in string) bool { return sameFile(in, o.out) }) {
		return o, false, fmt.Errorf("%w: --out must not be a case file or a log", errUsage)
	}
	return o, false, nil
}

// parseBase accepts only a scheme and a host: anything else in the URL would
// be left out of the requests. Its errors do not repeat the value, which may
// hold a password.
func parseBase(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("%w: --base must be http://host[:port] or https://host[:port]", errUsage)
	}
	return u, nil
}

// isLoopback reports whether host is "localhost" or a loopback address. No
// name is looked up.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// sameFile reports whether the two paths name one existing file.
func sameFile(a, b string) bool {
	ai, errA := os.Stat(a)
	bi, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(ai, bi)
}

// runDetect sends every case to the target once, joins the answers with the
// target's logs and writes the results. The logs should hold this run only:
// records of an earlier run with the same ID prefix would be joined too. An
// interrupted run writes nothing.
func runDetect(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	o, help, err := parseDetect(args, stderr)
	if help || err != nil {
		return err
	}
	cs, conflicting, err := readCases(o.caseFiles)
	if err != nil {
		return err
	}
	// The target creates its logs when it starts; a wrong path should not
	// cost a whole run.
	for _, path := range []string{o.access, o.decisions} {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("checking the target's log: %w", err)
		}
	}

	sent := runner.Detect(ctx, runner.NewClient(sendTimeout), o.base, cs, o.idPrefix, o.rps)
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("detection interrupted, no results written: %w", err)
	}

	access, badAccess, err := readLog(o.access, records.ReadAccess)
	if err != nil {
		return err
	}
	decisions, badDecisions, err := readLog(o.decisions, records.ReadDecisions)
	if err != nil {
		return err
	}
	results := runner.Join(sent, access, decisions)
	err = writeFile(o.out, func(w io.Writer) error {
		buffered := bufio.NewWriter(w)
		lines := json.NewEncoder(buffered)
		for _, r := range results {
			if err := lines.Encode(r); err != nil {
				return err
			}
		}
		return buffered.Flush()
	})
	if err != nil {
		return fmt.Errorf("writing %s: %w", o.out, err)
	}
	return summarize(stdout, o.out, results, conflicting, badAccess, badDecisions)
}

// readCases reads the case files and merges identical requests. conflicting
// counts the cases left out because the sources disagree on what to expect.
func readCases(paths []string) (merged []cases.Case, conflicting int, err error) {
	var all []cases.Case
	for _, path := range paths {
		cs, err := readCaseFile(path)
		if err != nil {
			return nil, 0, fmt.Errorf("reading %s: %w", path, err)
		}
		all = append(all, cs...)
	}
	merged, conflicts := cases.Merge(all)
	if len(merged) == 0 {
		return nil, 0, errors.New("the case files hold no cases to use")
	}
	return merged, len(conflicts), nil
}

func readCaseFile(path string) (out []cases.Case, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	lines, err := cases.ReadLines(f)
	if err != nil {
		return nil, err
	}
	for i, l := range lines {
		c, err := cases.FromLine(l)
		if err != nil {
			// Without the source and case ID that FromLine adds: the case may
			// be held out.
			return nil, fmt.Errorf("line %d: %w", i+1, errors.Unwrap(err))
		}
		out = append(out, c)
	}
	return out, nil
}

// readLog reads one of the target's logs with read.
func readLog[T any](path string, read func(io.Reader) (T, int, error)) (out T, bad int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return out, 0, fmt.Errorf("opening the target's log: %w", err)
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return read(f)
}

// summarize prints how many cases had each outcome.
func summarize(w io.Writer, out string, results []runner.Result, conflicting, badAccess, badDecisions int) error {
	count := map[runner.Outcome]int{}
	for _, r := range results {
		count[r.Outcome]++
	}
	var outcomes []string
	for _, o := range []runner.Outcome{runner.Blocked, runner.Flagged, runner.RouteOnly, runner.Passed,
		runner.Rejected, runner.Unknown, runner.NotSent} {
		outcomes = append(outcomes, fmt.Sprintf("%d %s", count[o], o))
	}
	_, err := fmt.Fprintf(w, "wrote %d cases to %s: %s\n"+
		"left out %d conflicting cases; skipped unreadable log lines: %d access, %d decision\n",
		len(results), out, strings.Join(outcomes, ", "), conflicting, badAccess, badDecisions)
	return err
}
