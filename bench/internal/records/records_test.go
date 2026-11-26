package records

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

func TestReadSkipsTruncatedLine(t *testing.T) {
	t.Parallel()
	t.Run("access", func(t *testing.T) {
		t.Parallel()
		log := `{"id":"a","method":"GET","path":"/x","time":"2026-11-26T10:00:00Z"}
{"id":"b","method":"POST","path":"/y","time":"2026-11-26T10:00:01Z"}
{"id":"c","method":"GE`
		got, bad, err := ReadAccess(strings.NewReader(log))
		if err != nil {
			t.Fatal(err)
		}
		if bad != 1 {
			t.Errorf("bad = %d, want 1", bad)
		}
		want := Access{ID: "b", Method: "POST", Path: "/y", Time: time.Date(2026, 11, 26, 10, 0, 1, 0, time.UTC)}
		if len(got) != 2 || got["b"] != want {
			t.Errorf("records = %+v, want a and %+v", got, want)
		}
	})
	t.Run("decisions", func(t *testing.T) {
		t.Parallel()
		log := `{"id":"a","action":"block","monitored":false,"rules":["AEG-SQLI-001"],"route":"","latency_us":3}
{"id":"a","action":"allow","monitored":true,"rules":["AEG-ROUTE-001"],"route":"GET /x","latency_us":4,"error":"boom"}
{"id":"b","action":"blo`
		got, bad, err := ReadDecisions(strings.NewReader(log))
		if err != nil {
			t.Fatal(err)
		}
		if bad != 1 {
			t.Errorf("bad = %d, want 1", bad)
		}
		if len(got) != 1 || len(got["a"]) != 2 {
			t.Fatalf("records = %+v, want two for a", got)
		}
		second := got["a"][1]
		if second.Action != "allow" || !second.Monitored || !slices.Equal(second.Rules, []string{"AEG-ROUTE-001"}) ||
			second.Route != "GET /x" || second.LatencyUS != 4 || second.Error != "boom" {
			t.Errorf("second decision = %+v", second)
		}
	})
}

func TestReadSkipsUnusableLines(t *testing.T) {
	t.Parallel()
	const access = `{"id":"ok","method":"GET","path":"/","time":"2026-11-26T10:00:00Z"}`
	const decision = `{"id":"ok","action":"block","rules":["AEG-SQLI-001"]}`
	long := `{"id":"long","method":"GET","action":"block","path":"/` + strings.Repeat("a", maxLineBytes) + `"}`
	tests := []struct {
		name, line string
		wantBad    int
	}{
		{name: "blank line", line: "  ", wantBad: 0},
		{name: "not JSON", line: "starting up", wantBad: 1},
		{name: "null", line: "null", wantBad: 1},
		{name: "array", line: "[1]", wantBad: 1},
		{name: "no id", line: `{"method":"GET","action":"block"}`, wantBad: 1},
		{name: "two objects", line: access + decision, wantBad: 1},
		{name: "partial line run into the next", line: `{"id":"x","meth` + access, wantBad: 1},
		{name: "overlong", line: long, wantBad: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, bad, err := ReadAccess(strings.NewReader(tt.line + "\n" + access + "\n"))
			if err != nil || bad != tt.wantBad || len(a) != 1 || a["ok"].Method != "GET" {
				t.Errorf("access: %d records, bad %d, err %v; want the good record and bad %d", len(a), bad, err, tt.wantBad)
			}
			d, bad, err := ReadDecisions(strings.NewReader(tt.line + "\n" + decision + "\n"))
			if err != nil || bad != tt.wantBad || len(d) != 1 || len(d["ok"]) != 1 {
				t.Errorf("decisions: %d records, bad %d, err %v; want the good record and bad %d", len(d), bad, err, tt.wantBad)
			}
		})
	}
}

// Swapping the two log files must not produce records: an access record read
// as a decision would have no action, and the reverse no method.
func TestReadRejectsTheOtherLog(t *testing.T) {
	t.Parallel()
	d, bad, err := ReadDecisions(strings.NewReader(`{"id":"a","method":"GET","path":"/"}`))
	if err != nil || bad != 1 || len(d) != 0 {
		t.Errorf("decisions from an access line: %v, bad %d, err %v", d, bad, err)
	}
	a, bad, err := ReadAccess(strings.NewReader(`{"id":"a","action":"block"}`))
	if err != nil || bad != 1 || len(a) != 0 {
		t.Errorf("access from a decision line: %v, bad %d, err %v", a, bad, err)
	}
	d, bad, err = ReadDecisions(strings.NewReader(`{"id":"a","action":"deny"}`))
	if err != nil || bad != 1 || len(d) != 0 {
		t.Errorf("unknown action: %v, bad %d, err %v", d, bad, err)
	}
}

func TestReadReturnsReaderError(t *testing.T) {
	t.Parallel()
	broken := errors.New("disk gone")
	source := func() io.Reader {
		return io.MultiReader(strings.NewReader(`{"id":"a","method":"GET"}`+"\n"), iotest.ErrReader(broken))
	}
	if _, _, err := ReadAccess(source()); !errors.Is(err, broken) {
		t.Errorf("access: err = %v, want %v", err, broken)
	}
	if _, _, err := ReadDecisions(source()); !errors.Is(err, broken) {
		t.Errorf("decisions: err = %v, want %v", err, broken)
	}
}

func TestWriterUsesTheDocumentedKeys(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := NewWriter(&buf)
	at := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	if err := w.Write(Access{ID: "a", Method: "GET", Path: "/x", Time: at}); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(Decision{ID: "a", Action: "block", Rules: []string{"AEG-SQLI-001"}, Route: "GET /x", LatencyUS: 7, Error: "e"}); err != nil {
		t.Fatal(err)
	}
	want := `{"id":"a","method":"GET","path":"/x","time":"2026-11-26T10:00:00Z"}
{"id":"a","action":"block","monitored":false,"rules":["AEG-SQLI-001"],"route":"GET /x","latency_us":7,"error":"e"}
`
	if buf.String() != want {
		t.Errorf("log =\n%s\nwant\n%s", buf.String(), want)
	}
}

func TestWriterFlushesEachRecord(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := NewWriter(bufio.NewWriterSize(&buf, 1<<20))
	if err := w.Write(Access{ID: "a", Method: "GET"}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(buf.String(), "}\n") {
		t.Errorf("record not flushed: %q", buf.String())
	}
}

func TestWriterKeepsConcurrentRecordsWhole(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer // not safe for concurrent use: the Writer must serialize
	w := NewWriter(&buf)
	const n = 200
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.Write(Access{ID: fmt.Sprint(i), Method: "GET"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	got, bad, err := ReadAccess(&buf)
	if err != nil || bad != 0 || len(got) != n {
		t.Errorf("%d records, bad %d, err %v; want %d whole records", len(got), bad, err, n)
	}
}

// failOnce fails its first write after taking half of it, as a full disk can,
// and accepts every later one.
type failOnce struct {
	bytes.Buffer
	failed bool
}

var errFull = errors.New("disk full")

func (f *failOnce) Write(p []byte) (int, error) {
	if !f.failed {
		f.failed = true
		n, _ := f.Buffer.Write(p[:len(p)/2]) // a Buffer write cannot fail
		return n, errFull
	}
	return f.Buffer.Write(p)
}

// A record appended to a half-written line would be unreadable while its Write
// reported success, so the Writer stays failed.
func TestWriterStopsAfterFailedWrite(t *testing.T) {
	t.Parallel()
	out := &failOnce{}
	w := NewWriter(out)
	if err := w.Write(Access{ID: "a", Method: "GET"}); !errors.Is(err, errFull) {
		t.Fatalf("first write: err = %v, want %v", err, errFull)
	}
	size := out.Len()
	if err := w.Write(Access{ID: "b", Method: "GET"}); !errors.Is(err, errFull) {
		t.Errorf("second write: err = %v, want %v", err, errFull)
	}
	if out.Len() != size {
		t.Errorf("wrote %d more bytes after a failure", out.Len()-size)
	}
}

func TestWriterEncodingErrorWritesNothing(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.Write(func() {}); err == nil {
		t.Fatal("want an error for a value JSON cannot encode")
	}
	if err := w.Write(Access{ID: "a", Method: "GET"}); err != nil {
		t.Errorf("an encoding error must not fail later writes: %v", err)
	}
	if got := strings.Count(buf.String(), "\n"); got != 1 {
		t.Errorf("%d lines, want 1", got)
	}
}
