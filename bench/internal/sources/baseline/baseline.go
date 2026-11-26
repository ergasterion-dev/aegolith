// Package baseline imports the project's own request corpus
// (testdata/corpus) as bench case lines.
package baseline

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

// files are the corpus files, with the kind every line in each must have.
var files = []struct {
	name     string
	kind     string
	expected cases.Expected
}{
	{name: "attacks.jsonl", kind: "attack", expected: cases.Attack},
	{name: "legit.jsonl", kind: "legit", expected: cases.Legit},
}

// Import reads the attack and legitimate files in corpusDir. Each line keeps
// its corpus fields and gains Source "baseline", a SourceCaseID of the form
// "kind/name" and the matching Expected. Every returned line is accepted by
// cases.FromLine.
func Import(corpusDir string) ([]cases.Line, error) {
	var out []cases.Line
	for _, f := range files {
		path := filepath.Join(corpusDir, f.name)
		lines, err := readFile(path)
		if err != nil {
			return nil, fmt.Errorf("importing %s: %w", path, err)
		}
		seen := make(map[string]bool, len(lines))
		for i, l := range lines {
			if err := tag(&l, f.kind, f.expected); err != nil {
				return nil, fmt.Errorf("importing %s: line %d: %w", path, i+1, err)
			}
			if seen[l.SourceCaseID] {
				return nil, fmt.Errorf("importing %s: line %d: name %q is used twice", path, i+1, l.Name)
			}
			seen[l.SourceCaseID] = true
			out = append(out, l)
		}
	}
	return out, nil
}

func readFile(path string) (lines []cases.Line, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	lines, err = cases.ReadLines(f)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, errors.New("the file holds no cases")
	}
	return lines, nil
}

// tag checks one corpus line and adds its source fields.
func tag(l *cases.Line, kind string, expected cases.Expected) error {
	if l.Kind != kind {
		return fmt.Errorf("kind is not %q", kind)
	}
	if l.Source != "" || l.SourceCaseID != "" || l.Expected != "" {
		return errors.New("a corpus line must not carry source fields")
	}
	l.Source = cases.SourceBaseline
	l.SourceCaseID = kind + "/" + l.Name
	l.Expected = expected
	if _, err := cases.FromLine(*l); err != nil {
		return err
	}
	return nil
}
