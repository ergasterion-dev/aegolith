package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

const corpusDir = "../../../../testdata/corpus"

func TestBaselineImportCounts(t *testing.T) {
	t.Parallel()
	lines, err := Import(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[cases.Expected]int{}
	ids := map[string]bool{}
	var all []cases.Case
	for i, l := range lines {
		counts[l.Expected]++
		if l.Source != cases.SourceBaseline {
			t.Errorf("line %d: source %q", i, l.Source)
		}
		if l.SourceCaseID == "" || ids[l.SourceCaseID] {
			t.Errorf("line %d: source case ID %q is empty or repeated", i, l.SourceCaseID)
		}
		ids[l.SourceCaseID] = true
		c, err := cases.FromLine(l)
		if err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		all = append(all, c)
	}
	if counts[cases.Attack] != 230 || counts[cases.Legit] != 195 || len(lines) != 425 {
		t.Errorf("attack %d, legit %d, total %d; want 230, 195, 425", counts[cases.Attack], counts[cases.Legit], len(lines))
	}
	merged, conflicts := cases.Merge(all)
	if len(merged) != 425 || len(conflicts) != 0 {
		t.Errorf("merged %d, conflicts %d; want 425 distinct requests", len(merged), len(conflicts))
	}
}

const (
	attackLine = `{"name":"a","category":"sqli","kind":"attack","method":"GET","path":"/a","query":[["q","1 OR 1=1"]],"headers":{},"content_type":"","body":""}`
	legitLine  = `{"name":"a","category":"legit","kind":"legit","method":"GET","path":"/a","query":[["q","apples"]],"headers":{},"content_type":"","body":""}`
)

// writeCorpus writes a corpus directory; an empty content omits that file.
func writeCorpus(t *testing.T, attacks, legit string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{"attacks.jsonl": attacks, "legit.jsonl": legit} {
		if content == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestImportSetsSourceFields(t *testing.T) {
	t.Parallel()
	// The same name in both files must still give distinct case IDs.
	lines, err := Import(writeCorpus(t, attackLine+"\n", legitLine+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("%d lines, want 2", len(lines))
	}
	want := []struct {
		id       string
		expected cases.Expected
	}{{"attack/a", cases.Attack}, {"legit/a", cases.Legit}}
	for i, w := range want {
		l := lines[i]
		if l.Source != "baseline" || l.SourceCaseID != w.id || l.Expected != w.expected {
			t.Errorf("line %d: source %q, case %q, expected %q", i, l.Source, l.SourceCaseID, l.Expected)
		}
	}
}

func TestImportRejectsBadCorpus(t *testing.T) {
	t.Parallel()
	ok := attackLine + "\n"
	okLegit := legitLine + "\n"
	tests := []struct {
		name, attacks, legit, wantInError string
	}{
		{name: "no attacks file", legit: okLegit, wantInError: "attacks.jsonl"},
		{name: "no legit file", attacks: ok, wantInError: "legit.jsonl"},
		{name: "wrong kind", attacks: okLegit, legit: okLegit, wantInError: "attacks.jsonl"},
		{name: "unknown key", attacks: `{"extra":1}` + "\n", legit: okLegit, wantInError: "attacks.jsonl"},
		{name: "repeated name", attacks: ok + ok, legit: okLegit, wantInError: "attacks.jsonl"},
		{name: "not a request", attacks: strings.Replace(ok, `"/a"`, `"a"`, 1), legit: okLegit, wantInError: "attacks.jsonl"},
		{name: "source already set", attacks: strings.Replace(ok, `"name"`, `"source":"x","name"`, 1), legit: okLegit, wantInError: "attacks.jsonl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lines, err := Import(writeCorpus(t, tt.attacks, tt.legit))
			if err == nil {
				t.Fatalf("accepted %d lines, want an error", len(lines))
			}
			if !strings.Contains(err.Error(), tt.wantInError) {
				t.Errorf("error %v does not name %s", err, tt.wantInError)
			}
		})
	}
}

func TestImportRejectsEmptyFile(t *testing.T) {
	t.Parallel()
	dir := writeCorpus(t, attackLine+"\n", "")
	if err := os.WriteFile(filepath.Join(dir, "legit.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(dir); err == nil {
		t.Fatal("accepted an empty file")
	}
}
