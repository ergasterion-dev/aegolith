package run

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
)

// maxResultBytes bounds one line of a results file, newline included.
const maxResultBytes = 1 << 20

// outcomes are the values a results file may give.
var outcomes = []Outcome{Blocked, Flagged, RouteOnly, Passed, Rejected, Unknown, NotSent}

// ReadResults reads a results file: one Result as a JSON object per line, in
// file order. The file is written whole, so unlike a log it may hold no
// unusable line: every line must have a case ID, a known outcome, no unknown
// key and nothing after the object. Errors give the line number and never
// repeat a value of the line.
func ReadResults(r io.Reader) ([]Result, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxResultBytes)
	var out []Result
	for sc.Scan() {
		result, err := parseResult(sc.Bytes())
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", len(out)+1, err)
		}
		out = append(out, result)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("line %d: %w", len(out)+1, err)
	}
	return out, nil
}

func parseResult(line []byte) (Result, error) {
	var r Result
	// The decoder would accept "null" as an empty object.
	if !bytes.HasPrefix(bytes.TrimSpace(line), []byte("{")) {
		return r, errors.New("not a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	// The decoder's own error can quote the line.
	if err := dec.Decode(&r); err != nil {
		return r, errors.New("not a result: broken JSON, an unknown key or a value of the wrong type")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return r, errors.New("trailing data after the JSON object")
	}
	switch {
	case r.CaseID == "":
		return r, errors.New("case_id is empty")
	case !slices.Contains(outcomes, r.Outcome):
		return r, errors.New("outcome is missing or unknown")
	}
	return r, nil
}
