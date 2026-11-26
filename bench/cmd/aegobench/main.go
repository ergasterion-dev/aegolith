// Command aegobench measures Aegolith against request sets: it imports each
// source into case lines that later steps replay over HTTP, and serves the
// target they are replayed against.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ergasterion-dev/aegolith"
	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/records"
	"github.com/ergasterion-dev/aegolith/bench/internal/sources/baseline"
	"github.com/ergasterion-dev/aegolith/bench/internal/target"
)

const usage = `usage: aegobench <command> [flags]

commands:
  import    convert a source into case lines
  target    serve the firewall-wrapped server that cases are sent to
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
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		// A second signal during shutdown ends the process at once.
		context.AfterFunc(ctx, stop)
		return runTarget(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprint(stderr, usage)
		return fmt.Errorf("%w: unknown command %q", errUsage, args[0])
	}
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
	source := fs.String("source", "", `source to import: "baseline"`)
	corpus := fs.String("corpus", "", "corpus directory (source baseline)")
	out := fs.String("out", "", "case file to write")
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("%w: --out is required", errUsage)
	}

	var lines []cases.Line
	var err error
	switch *source {
	case cases.SourceBaseline:
		if *corpus == "" {
			return fmt.Errorf("%w: --corpus is required for source %s", errUsage, *source)
		}
		lines, err = baseline.Import(*corpus)
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
	return err
}

// writeCaseFile writes lines to a temporary file beside path and renames it
// into place, so path never holds a partial case set.
func writeCaseFile(path string, lines []cases.Line) (err error) {
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
	writeErr := cases.WriteLines(tmp, lines)
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
