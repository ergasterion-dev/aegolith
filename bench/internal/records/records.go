// Package records holds the two logs the target server writes, an access log
// and a decision log, each one JSON object per line, joined by request ID.
// Neither holds a query string, a header other than the request ID, or a body.
//
// A request missing from the access log never reached the target, or its
// outcome was lost; a request in the access log with no decision was passed.
package records

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Access says that a request arrived and was answered.
type Access struct {
	ID     string    `json:"id"`
	Method string    `json:"method"`
	Path   string    `json:"path"` // escaped path, without the query
	Time   time.Time `json:"time"`
}

// Decision is what the firewall decided about a request it blocked, monitored
// or failed to inspect.
type Decision struct {
	ID        string   `json:"id"`
	Action    string   `json:"action"` // "block" or "allow"
	Monitored bool     `json:"monitored"`
	Rules     []string `json:"rules"` // rule IDs, never the matched values
	Route     string   `json:"route"` // matched route key, empty for none
	LatencyUS int64    `json:"latency_us"`
	Error     string   `json:"error,omitempty"` // internal error of the firewall
}

// Writer writes records as one JSON object per line, each line flushed before
// Write returns. It is safe for concurrent use.
//
// After a write fails, every later Write returns that error and writes
// nothing: the failure may have left half a line behind, and a record appended
// to it would be unreadable although its Write had succeeded.
type Writer struct {
	mu  sync.Mutex
	w   io.Writer
	err error
}

// NewWriter returns a Writer on w. If w buffers and has a Flush() error
// method, it is flushed after every record.
func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// Write appends v as one line.
func (w *Writer) Write(v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encoding record: %w", err)
	}
	line = append(line, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	if err := w.writeLine(line); err != nil {
		w.err = fmt.Errorf("writing record: %w", err)
	}
	return w.err
}

func (w *Writer) writeLine(line []byte) error {
	if _, err := w.w.Write(line); err != nil {
		return err
	}
	if f, ok := w.w.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}

// maxLineBytes bounds one line read back, newline included. The target's
// records are far smaller.
const maxLineBytes = 1 << 20

// ReadAccess reads an access log into a map by request ID; a later record
// replaces an earlier one with the same ID. The second value counts the lines
// skipped as unusable: not one JSON object (such as the half line a killed
// process leaves), too long, or without an ID or a method. Blank lines are
// ignored. The error is non-nil only if r fails.
func ReadAccess(r io.Reader) (map[string]Access, int, error) {
	out := map[string]Access{}
	bad, err := readLines(r, func(line []byte) bool {
		var a Access
		if json.Unmarshal(line, &a) != nil || a.ID == "" || a.Method == "" {
			return false
		}
		out[a.ID] = a
		return true
	})
	if err != nil {
		return nil, bad, fmt.Errorf("reading access log: %w", err)
	}
	return out, bad, nil
}

// ReadDecisions reads a decision log into a map by request ID, keeping the
// records of one ID in file order. It skips and counts lines as ReadAccess
// does; a usable record has an ID and the action "block" or "allow".
func ReadDecisions(r io.Reader) (map[string][]Decision, int, error) {
	out := map[string][]Decision{}
	bad, err := readLines(r, func(line []byte) bool {
		var d Decision
		if json.Unmarshal(line, &d) != nil || d.ID == "" || d.Action != "block" && d.Action != "allow" {
			return false
		}
		out[d.ID] = append(out[d.ID], d)
		return true
	})
	if err != nil {
		return nil, bad, fmt.Errorf("reading decision log: %w", err)
	}
	return out, bad, nil
}

// readLines passes each non-blank line of r to use and counts the lines use
// refuses or that are longer than maxLineBytes. A last line without a newline
// is a line like any other.
func readLines(r io.Reader, use func(line []byte) bool) (bad int, err error) {
	br := bufio.NewReader(r)
	var line []byte
	tooLong := false
	for {
		chunk, err := br.ReadSlice('\n')
		if tooLong || len(line)+len(chunk) > maxLineBytes {
			tooLong, line = true, line[:0]
		} else {
			line = append(line, chunk...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue // the line goes on
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return bad, err
		}
		trimmed := bytes.TrimSpace(line)
		if tooLong || len(trimmed) > 0 && !use(trimmed) {
			bad++
		}
		if err != nil {
			return bad, nil
		}
		line, tooLong = line[:0], false
	}
}
