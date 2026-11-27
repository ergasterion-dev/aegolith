package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/report"
	runner "github.com/ergasterion-dev/aegolith/bench/internal/run"
)

// The files report writes into its output directory.
const (
	markdownName = "report.md"
	jsonName     = "report.json"
)

// resultsFile is one entry of --results: a configuration of the target and the
// results detect wrote for it.
type resultsFile struct{ name, path string }

// reportOptions are the checked flags of the report command.
type reportOptions struct {
	caseFiles     []string
	results       []resultsFile
	out, previous string
	load          string
}

// parseReport parses and checks the flags of report; help reports that the
// user asked for the flag list.
func parseReport(args []string, stderr io.Writer) (o reportOptions, help bool, err error) {
	fs := flag.NewFlagSet("aegobench report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	caseFiles := fs.String("cases", "", "case files that were sent, separated by commas")
	results := fs.String("results", "", "name=file pairs, separated by commas: a configuration and its results")
	fs.StringVar(&o.out, "out", "", "directory to write "+markdownName+" and "+jsonName+" into")
	fs.StringVar(&o.previous, "previous", "", "earlier "+jsonName+" to compare with")
	fs.StringVar(&o.load, "load", "", "result of a load run to include (optional)")
	if help, err := parseFlags(fs, args); help || err != nil {
		return o, help, err
	}
	if *caseFiles == "" || *results == "" || o.out == "" {
		return o, false, fmt.Errorf("%w: --cases, --results and --out are required", errUsage)
	}
	o.caseFiles = strings.Split(*caseFiles, ",")
	if slices.Contains(o.caseFiles, "") {
		return o, false, fmt.Errorf("%w: --cases holds an empty file name", errUsage)
	}
	if o.results, err = parseResultsFlag(*results); err != nil {
		return o, false, err
	}
	// --previous may name the report that is about to be replaced; it is read
	// first.
	inputs := slices.Clone(o.caseFiles)
	for _, r := range o.results {
		inputs = append(inputs, r.path)
	}
	if o.load != "" {
		inputs = append(inputs, o.load)
	}
	for _, name := range []string{markdownName, jsonName} {
		out := filepath.Join(o.out, name)
		if slices.ContainsFunc(inputs, func(in string) bool { return sameFile(in, out) }) {
			return o, false, fmt.Errorf("%w: --out would replace a case file, a results file or the load result", errUsage)
		}
	}
	return o, false, nil
}

func parseResultsFlag(value string) ([]resultsFile, error) {
	var out []resultsFile
	for _, entry := range strings.Split(value, ",") {
		name, path, ok := strings.Cut(entry, "=")
		if !ok || name == "" || path == "" {
			return nil, fmt.Errorf("%w: --results must be name=file pairs separated by commas", errUsage)
		}
		if slices.ContainsFunc(out, func(r resultsFile) bool { return r.name == name }) {
			return nil, fmt.Errorf("%w: --results uses the name %q twice", errUsage, name)
		}
		out = append(out, resultsFile{name, path})
	}
	return out, nil
}

// runReport counts the results of each configuration and writes the report.
// Nothing is written unless every input is usable. Its output and errors give
// numbers of cases and never name one, which may be held out.
func runReport(args []string, stdout, stderr io.Writer) error {
	o, help, err := parseReport(args, stderr)
	if help || err != nil {
		return err
	}
	cs, conflicting, err := readCases(o.caseFiles)
	if err != nil {
		return err
	}
	var previous *report.Report
	if o.previous != "" {
		if previous, err = readReport(o.previous); err != nil {
			return fmt.Errorf("reading the previous report %s: %w", o.previous, err)
		}
	}

	current := report.Report{Meta: report.Meta{
		Commit:  buildCommit(),
		Created: time.Now().UTC().Truncate(time.Second),
		Sources: sourcesOf(cs),
	}}
	if o.load != "" {
		if current.Load, err = readLoadResult(o.load); err != nil {
			return fmt.Errorf("reading the load result %s: %w", o.load, err)
		}
	}
	var missing []string
	for _, file := range o.results {
		results, err := readResultsFile(file.path, cs)
		if err != nil {
			return fmt.Errorf("reading results %s: %w", file.path, err)
		}
		if n := len(cs) - len(results); n > 0 {
			missing = append(missing, fmt.Sprintf("%s: %d cases have no result and count as not sent\n", file.name, n))
		}
		current.Configs = append(current.Configs, report.BuildConfig(file.name, cs, results))
	}

	encoded, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding the report: %w", err)
	}
	markdown := current.Markdown()
	if previous != nil {
		markdown += "\n" + report.Diff(*previous, current)
	}
	for _, f := range []struct {
		name    string
		content []byte
	}{{jsonName, append(encoded, '\n')}, {markdownName, []byte(markdown)}} {
		path := filepath.Join(o.out, f.name)
		err := writeFile(path, func(w io.Writer) error {
			_, err := w.Write(f.content)
			return err
		})
		if err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
	}
	_, err = fmt.Fprintf(stdout, "wrote %s and %s to %s: %d cases, %d configurations\n"+
		"left out %d conflicting cases\n%s",
		markdownName, jsonName, o.out, len(cs), len(current.Configs), conflicting, strings.Join(missing, ""))
	return err
}

// readResultsFile reads the results of one detection run over cs. A file with a
// repeated result, or one of a case that is not in cs, belongs to other case
// files and is refused.
func readResultsFile(path string, cs []cases.Case) (out []runner.Result, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	results, err := runner.ReadResults(f)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, errors.New("the file holds no results")
	}
	known := make(map[string]bool, len(cs))
	for _, c := range cs {
		known[c.ID] = true
	}
	seen := make(map[string]bool, len(results))
	var repeated, foreign int
	for _, r := range results {
		switch {
		case !known[r.CaseID]:
			foreign++
		case seen[r.CaseID]:
			repeated++
		}
		seen[r.CaseID] = true
	}
	if repeated > 0 || foreign > 0 {
		return nil, fmt.Errorf("%d results are of no case in the case files and %d repeat a case", foreign, repeated)
	}
	return results, nil
}

// readLoadResult reads the file the load command wrote. Its errors do not
// repeat the file.
func readLoadResult(path string) (*runner.LoadResult, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// The decoder would accept "null" as an empty object.
	if !bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) {
		return nil, errors.New("not a JSON object")
	}
	var res runner.LoadResult
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&res); err != nil {
		return nil, errors.New("not a load result: broken JSON, an unknown key or a value of the wrong type")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the JSON object")
	}
	// A file of another version has other fields: read as this one, those it
	// lacks would be reported as zero.
	if res.Format != runner.LoadResultFormat {
		return nil, fmt.Errorf("the load result has format version %d and this program reads version %d: run load again",
			res.Format, runner.LoadResultFormat)
	}
	counts := []int{res.Sent, res.TransportErrors, res.Attacks, res.Dropped, res.NotSent, res.Cancelled,
		res.AttackCases, res.LegitCases, res.Excluded, res.Conflicting, res.MemPolls, res.MemPollFailures}
	if res.RPS < 1 || res.Workers < 1 || res.Duration <= 0 || slices.ContainsFunc(counts, func(n int) bool { return n < 0 }) {
		return nil, errors.New("not a load result: it has no rate, workers or duration, or a negative count")
	}
	return &res, nil
}

// readReport reads a report.json.
func readReport(path string) (*report.Report, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r report.Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}
	if len(r.Configs) == 0 {
		return nil, errors.New("it holds no configuration, so it is not a report")
	}
	return &r, nil
}

// sourcesOf lists the sources the cases come from. The case files record no
// versions or licences.
func sourcesOf(cs []cases.Case) []report.SourceInfo {
	var names []string
	for _, c := range cs {
		for _, ref := range c.Sources {
			names = append(names, ref.Source)
		}
	}
	slices.Sort(names)
	var out []report.SourceInfo
	for _, name := range slices.Compact(names) {
		out = append(out, report.SourceInfo{Name: name, Included: true})
	}
	return out
}

// buildCommit is the commit this program was built from, which holds the
// Aegolith it tests.
func buildCommit() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return commitFrom(nil)
	}
	return commitFrom(info.Settings)
}

// commitFrom reads the commit the Go tool stamps into a binary; "go run" and
// "go test" stamp none.
func commitFrom(settings []debug.BuildSetting) string {
	value := map[string]string{}
	for _, s := range settings {
		value[s.Key] = s.Value
	}
	switch {
	case value["vcs.revision"] == "":
		return "unknown"
	case value["vcs.modified"] == "true":
		return value["vcs.revision"] + " (with uncommitted changes)"
	}
	return value["vcs.revision"]
}
