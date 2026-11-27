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
	"github.com/ergasterion-dev/aegolith/bench/internal/sources/legit"
)

// The files report writes into its output directory.
const (
	markdownName = "report.md"
	jsonName     = "report.json"
)

// namedFile is one name=file entry of a flag: a configuration of the target and
// the results detect wrote for it, or a source and the cases its importer
// skipped.
type namedFile struct{ name, path string }

// reportOptions are the checked flags of the report command.
type reportOptions struct {
	caseFiles     []string
	results       []namedFile
	out, previous string
	load          string
	// What the report records beside the counts; each is optional.
	sources, environment string
	skipped              []namedFile
	legitSeed            int64
	legitN               int
}

// parseReport parses and checks the flags of report; help reports that the
// user asked for the flag list.
func parseReport(args []string, stderr io.Writer) (o reportOptions, help bool, err error) {
	fs := flag.NewFlagSet("aegobench report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	caseFiles := fs.String("cases", "", "case files that were sent, separated by commas")
	results := fs.String("results", "", "name=file pairs, separated by commas: a configuration and its results "+
		"(optional with --load)")
	fs.StringVar(&o.out, "out", "", "directory to write "+markdownName+" and "+jsonName+" into")
	fs.StringVar(&o.previous, "previous", "", "earlier "+jsonName+" to compare with")
	fs.StringVar(&o.load, "load", "", "result of a load run to include (optional)")
	fs.StringVar(&o.sources, "sources", "", "source manifest (bench/sources.json) to take commits and licences from (optional)")
	skipped := fs.String("skipped", "", "source=file pairs, separated by commas: the files import wrote with --skipped (optional)")
	fs.StringVar(&o.environment, "environment", "", "file of name=value lines that describe the machine and the run (optional)")
	fs.Int64Var(&o.legitSeed, "legit-seed", 1, "seed the generated-legit cases were made with")
	fs.IntVar(&o.legitN, "legit-n", 0, "number of generated-legit cases that were made, to describe their material (optional)")
	if help, err := parseFlags(fs, args); help || err != nil {
		return o, help, err
	}
	if *caseFiles == "" || *results == "" && o.load == "" || o.out == "" {
		return o, false, fmt.Errorf("%w: --cases, --out and --results or --load are required", errUsage)
	}
	if o.legitN < 0 {
		return o, false, fmt.Errorf("%w: --legit-n must not be negative", errUsage)
	}
	o.caseFiles = strings.Split(*caseFiles, ",")
	if slices.Contains(o.caseFiles, "") {
		return o, false, fmt.Errorf("%w: --cases holds an empty file name", errUsage)
	}
	if o.results, err = parseNamedFiles("--results", *results); err != nil {
		return o, false, err
	}
	if o.skipped, err = parseNamedFiles("--skipped", *skipped); err != nil {
		return o, false, err
	}
	// --previous may name the report that is about to be replaced; it is read
	// first.
	inputs := slices.Clone(o.caseFiles)
	for _, r := range slices.Concat(o.results, o.skipped) {
		inputs = append(inputs, r.path)
	}
	for _, path := range []string{o.load, o.sources, o.environment} {
		if path != "" {
			inputs = append(inputs, path)
		}
	}
	for _, name := range []string{markdownName, jsonName} {
		out := filepath.Join(o.out, name)
		if slices.ContainsFunc(inputs, func(in string) bool { return sameFile(in, out) }) {
			return o, false, fmt.Errorf("%w: --out would replace one of the input files", errUsage)
		}
	}
	return o, false, nil
}

// parseNamedFiles reads the name=file pairs of a flag; an empty value has
// none.
func parseNamedFiles(flagName, value string) ([]namedFile, error) {
	if value == "" {
		return nil, nil
	}
	var out []namedFile
	for _, entry := range strings.Split(value, ",") {
		name, path, ok := strings.Cut(entry, "=")
		if !ok || name == "" || path == "" {
			return nil, fmt.Errorf("%w: %s must be name=file pairs separated by commas", errUsage, flagName)
		}
		if slices.ContainsFunc(out, func(f namedFile) bool { return f.name == name }) {
			return nil, fmt.Errorf("%w: %s uses the name %q twice", errUsage, flagName, name)
		}
		out = append(out, namedFile{name, path})
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
	all, err := readCaseFiles(o.caseFiles)
	if err != nil {
		return err
	}
	cs, conflicting, err := mergeCases(all)
	if err != nil {
		return err
	}
	var previous *report.Report
	if o.previous != "" {
		if previous, err = readReport(o.previous); err != nil {
			return fmt.Errorf("reading the previous report %s: %w", o.previous, err)
		}
	}

	meta, err := metaOf(o, all)
	if err != nil {
		return err
	}
	current := report.Report{Meta: meta}
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

// metaOf says what the report is made from: the build, the case lines all and
// what the optional flags add about them.
func metaOf(o reportOptions, all []cases.Case) (report.Meta, error) {
	input := report.CountInput(all)
	meta := report.Meta{
		Commit:  buildCommit(),
		Created: time.Now().UTC().Truncate(time.Second),
		Sources: sourcesOf(all),
		Input:   &input,
	}
	present := func(source string) bool {
		return slices.ContainsFunc(meta.Sources, func(s report.SourceInfo) bool { return s.Name == source })
	}
	if o.sources != "" {
		manifest, err := readManifest(o.sources)
		if err != nil {
			return meta, fmt.Errorf("reading the source manifest %s: %w", o.sources, err)
		}
		meta.Sources = describeSources(meta.Sources, manifest)
	}
	generatedNote := ""
	for _, f := range o.skipped {
		// A misspelt source would otherwise appear beside the one it means.
		if !slices.ContainsFunc(input.Sources, func(s report.SourceInput) bool { return s.Source == f.name }) {
			return meta, fmt.Errorf("--skipped names %q, which no case file holds", f.name)
		}
		reasons, err := readSkips(f.path)
		if err != nil {
			return meta, fmt.Errorf("reading the skipped cases %s: %w", f.path, err)
		}
		input.AddSkips(f.name, reasons)
	}
	if o.legitN > 0 {
		generated, err := describeGenerated(all, o.legitSeed, o.legitN)
		if err != nil {
			return meta, fmt.Errorf("describing the generated cases: %w", err)
		}
		meta.Generated = generated
		// The generator gives every line asked for or none.
		input.AddSkips(legit.Source, nil)
		generatedNote = fmt.Sprintf("Generated with seed %d, %d lines.", o.legitSeed, o.legitN)
	} else if present(legit.Source) {
		generatedNote = "Its material is not described: report was not given --legit-seed and --legit-n."
	}
	for i, s := range meta.Sources {
		if s.Name == legit.Source && generatedNote != "" {
			meta.Sources[i].Note = strings.TrimSpace(s.Note + " " + generatedNote)
		}
	}
	if o.environment != "" {
		var err error
		if meta.Environment, err = readEnvironment(o.environment); err != nil {
			return meta, fmt.Errorf("reading the environment %s: %w", o.environment, err)
		}
	}
	return meta, nil
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
// versions or licences; see describeSources.
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
