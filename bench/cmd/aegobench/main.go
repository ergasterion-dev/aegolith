// Command aegobench measures Aegolith against request sets: it imports each
// source into case lines that later steps replay over HTTP.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/sources/baseline"
)

const usage = `usage: aegobench <command> [flags]

commands:
  import    convert a source into case lines
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
