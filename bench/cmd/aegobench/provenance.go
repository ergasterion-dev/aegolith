package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/report"
	"github.com/ergasterion-dev/aegolith/bench/internal/sources/legit"
)

// thisRepository is the repository and the licence of the sources that are
// part of the project.
const (
	thisRepository = "this repository"
	projectLicense = "Apache-2.0"
)

// manifestSource is one entry of the source manifest, bench/sources.json,
// which pins the third-party sources.
type manifestSource struct {
	Name     string `json:"name"`
	Repo     string `json:"repo"`
	Commit   string `json:"commit"`
	License  string `json:"license"`
	Included bool   `json:"included"`
	Note     string `json:"note"`
}

// readManifest reads a source manifest. Its errors do not repeat the file.
func readManifest(path string) ([]manifestSource, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// The decoder would accept "null" as an empty list.
	if !bytes.HasPrefix(bytes.TrimSpace(b), []byte("[")) {
		return nil, errors.New("not a JSON list")
	}
	var out []manifestSource
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, errors.New("not a source manifest: broken JSON, an unknown key or a value of the wrong type")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the list")
	}
	seen := map[string]bool{}
	for i, s := range out {
		if s.Name == "" || seen[s.Name] {
			return nil, fmt.Errorf("entry %d has no name or the name of an earlier one", i+1)
		}
		seen[s.Name] = true
	}
	return out, nil
}

// describeSources fills in what is known of the sources of the cases, which
// sources holds by name only, and adds the manifest's other sources as not
// included. A source of the cases that is neither the project's own nor in the
// manifest stays as it is.
func describeSources(sources []report.SourceInfo, manifest []manifestSource) []report.SourceInfo {
	listed := map[string]manifestSource{}
	for _, m := range manifest {
		listed[m.Name] = m
	}
	present := map[string]bool{}
	for i, s := range sources {
		present[s.Name] = true
		switch m, ok := listed[s.Name]; {
		case s.Name == cases.SourceBaseline || s.Name == legit.Source:
			sources[i].Repo, sources[i].License = thisRepository, projectLicense
			sources[i].Note = "Part of the project; its case lines record no version."
		case ok:
			sources[i].Repo, sources[i].Commit, sources[i].License = m.Repo, m.Commit, m.License
			sources[i].Note = m.Note
		}
	}
	for _, m := range manifest {
		if present[m.Name] {
			continue
		}
		note := m.Note
		if m.Included {
			note = "Not among the case files of this report. " + note
		}
		sources = append(sources, report.SourceInfo{
			Name: m.Name, Repo: m.Repo, Commit: m.Commit, License: m.License, Note: note,
		})
	}
	slices.SortFunc(sources, func(a, b report.SourceInfo) int { return strings.Compare(a.Name, b.Name) })
	return sources
}

// describeGenerated describes the generated cases among cs, which must be the
// requests the generator gives for seed and n, with the same expectations: a
// description of another set would be false.
func describeGenerated(cs []cases.Case, seed int64, n int) (*report.Generated, error) {
	d, err := legit.Describe(seed, n)
	if err != nil {
		return nil, err
	}
	// How many lines there are of each request and expectation.
	type key struct {
		id       string
		expected cases.Expected
	}
	count := map[key]int{}
	for _, l := range d.Lines {
		c, err := cases.FromLine(l)
		if err != nil {
			return nil, err
		}
		count[key{c.ID, c.Expected}]++
	}
	for _, c := range cs {
		if slices.ContainsFunc(c.Sources, func(r cases.SourceRef) bool { return r.Source == legit.Source }) {
			count[key{c.ID, c.Expected}]--
		}
	}
	for _, left := range count {
		if left != 0 {
			return nil, fmt.Errorf("the %s case lines are not those of seed %d and %d lines", legit.Source, seed, n)
		}
	}
	out := &report.Generated{
		Seed: seed, N: n,
		Templates: d.Templates, Lists: d.Lists, Entries: d.Entries,
		TemplatesUsed: d.TemplatesUsed, EntriesUsed: d.EntriesUsed,
	}
	for _, c := range d.Categories {
		out.Categories = append(out.Categories, report.GeneratedCategory{
			Name: c.Category, Lines: c.Lines, NearMiss: c.NearMiss, Templates: c.Templates, Entries: c.Entries,
		})
	}
	for _, c := range d.Cores {
		out.Cores = append(out.Cores, report.GeneratedList{Name: c.List, Entries: c.Entries, Used: c.Used, Lines: c.Lines})
	}
	return out, nil
}

// readSkips returns the reason of every source case in a file that import
// wrote with --skipped. Its errors do not repeat the file.
func readSkips(path string) (reasons []string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		var record struct {
			CaseID string `json:"case_id"`
			Reason string `json:"reason"`
		}
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		if dec.Decode(&record) != nil || record.Reason == "" {
			return nil, fmt.Errorf("line %d is not a skipped case with a reason", line)
		}
		reasons = append(reasons, record.Reason)
	}
	return reasons, sc.Err()
}

// readEnvironment reads lines of the form name=value; blank lines are left
// out. Its errors do not repeat the file.
func readEnvironment(path string) ([]report.Field, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []report.Field
	for i, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("line %d is not name=value", i+1)
		}
		out = append(out, report.Field{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)})
	}
	return out, nil
}
