package run

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestReadResultsRoundTrip(t *testing.T) {
	t.Parallel()
	want := []Result{
		{CaseID: "a", RequestID: "p-a", Status: 403, Outcome: Blocked, Rules: []string{"AEG-SQLI-001"}, LatencyUS: 12},
		{CaseID: "b", RequestID: "p-b", Outcome: NotSent, Reason: "the path does not start with /"},
	}
	for _, o := range []Outcome{Flagged, RouteOnly, Passed, Rejected, Unknown} {
		want = append(want, Result{CaseID: string(o), Outcome: o})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range want {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ReadResults(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("results = %+v, want %+v", got, want)
	}
}

func TestReadResultsRefusesBadLines(t *testing.T) {
	t.Parallel()
	const good = `{"case_id":"a","outcome":"passed"}` + "\n"
	tests := map[string]string{
		"empty line":     "\n",
		"half a line":    `{"case_id":"hidden-value`,
		"not an object":  `null`,
		"unknown key":    `{"case_id":"hidden-value","outcome":"passed","extra":1}`,
		"no case ID":     `{"outcome":"passed"}`,
		"no outcome":     `{"case_id":"hidden-value"}`,
		"other outcome":  `{"case_id":"a","outcome":"hidden-value"}`,
		"trailing data":  `{"case_id":"a","outcome":"passed"} {}`,
		"too long a one": `{"case_id":"` + strings.Repeat("a", 2<<20) + `","outcome":"passed"}`,
	}
	for name, line := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := ReadResults(strings.NewReader(good + line + "\n"))
			if err == nil || got != nil {
				t.Fatalf("results = %d, err = %v; want a failure", len(got), err)
			}
			// A line names a case, which may be held out.
			if msg := err.Error(); !strings.Contains(msg, "line 2") || strings.Contains(msg, "hidden-value") {
				t.Errorf("err = %q, want the line number and no value", msg)
			}
		})
	}
}
