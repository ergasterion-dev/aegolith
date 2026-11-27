// Package remote sends cases to a deployment its operator owns, the only
// host other than loopback the bench sends to. Everything it sends is
// limited by a target file: an allow-list of method and path pairs whose
// query values, header values and JSON bodies the payloads are placed into,
// a rate ceiling, and statuses that stop the run. It proves each allowed
// route with a harmless control request before any case, checks the
// target's health, and stops at the first sign of trouble or when the
// operator's stop file appears.
package remote

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/ergasterion-dev/aegolith/bench/internal/run"
)

// MaxPrefixLen bounds RequestIDPrefix: with the run tag, a dash and a case ID
// a request ID stays within the 128 characters the target records.
const MaxPrefixLen = 54

// maxTargetBytes bounds the target file.
const maxTargetBytes = 1 << 20

// The values of Target.Mode.
const (
	ModeMonitor = "monitor"
	ModeEnforce = "enforce"
)

// The kinds of placement an entry may declare, as "kind:name".
const (
	PlaceQuery  = "query"
	PlaceHeader = "header"
	PlaceJSON   = "json"
)

// Entry is one allowed method and path, the placements its payloads may go
// into, and the statuses a benign control request may get.
type Entry struct {
	Method       string   `json:"method"`
	Path         string   `json:"path"`
	Placements   []string `json:"placements"` // "query:q", "header:X-Note", "json:note"
	BenignStatus []int    `json:"benign_status"`
}

// Target is the target file: the one deployment a remote run may send to and
// the limits it sends under.
type Target struct {
	BaseURL         string `json:"base_url"` // scheme and host[:port] only
	RequestIDPrefix string `json:"request_id_prefix"`
	Mode            string `json:"mode"`        // "monitor" or "enforce"
	HealthPath      string `json:"health_path"` // must answer 200 to GET
	MaxRPS          int    `json:"max_rps"`
	StopStatuses    []int  `json:"stop_statuses"`
	// Headers are sent with every request, such as credentials; nothing else
	// is.
	Headers map[string]string `json:"headers"`
	Allow   []Entry           `json:"allow"`
}

// forbiddenHeaders are header names neither the target file nor a placement
// may set: framing, routing and method overrides, and the request ID.
var forbiddenHeaders = []string{
	"Host", "Content-Length", "Transfer-Encoding", "Connection", "Upgrade", "Trailer", "TE", "Expect",
	"X-Request-Id", "X-Forwarded-Host", "Forwarded", "X-Original-URL", "X-Rewrite-URL",
	"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
	// A JSON placement sets it.
	"Content-Type",
}

// LoadTarget reads a target file: one JSON object with no unknown or repeated
// key and nothing after it. It does not validate the target; see Validate.
// Its errors never repeat a value of the file.
func LoadTarget(name string) (Target, error) {
	f, err := os.Open(name)
	if err != nil {
		return Target{}, fmt.Errorf("reading the target file: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxTargetBytes+1))
	if err != nil {
		return Target{}, fmt.Errorf("reading the target file: %w", err)
	}
	if len(b) > maxTargetBytes {
		return Target{}, errors.New("the target file is too large")
	}
	if !bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) {
		return Target{}, errors.New("the target file is not a JSON object")
	}
	if err := noRepeatedKeys(b); err != nil {
		return Target{}, err
	}
	var t Target
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	// The decoder's error can quote the file.
	if err := dec.Decode(&t); err != nil {
		return Target{}, errors.New("the target file is not a target: broken JSON, an unknown key or a value of the wrong type")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Target{}, errors.New("the target file has data after its JSON object")
	}
	return t, nil
}

// noRepeatedKeys refuses a JSON document in which an object repeats a key:
// the decoder would keep the last value without saying so.
func noRepeatedKeys(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	type frame struct {
		object bool
		keys   map[string]bool
		key    bool // the next token of an object is a key
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return errors.New("the target file is not valid JSON")
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.object && top.key {
			if s, ok := tok.(string); ok {
				if top.keys[s] {
					return errors.New("the target file repeats a key in one object")
				}
				top.keys[s] = true
				top.key = false
				continue
			}
		}
		switch tok {
		case json.Delim('{'):
			stack = append(stack, &frame{object: true, keys: map[string]bool{}, key: true})
			continue
		case json.Delim('['):
			stack = append(stack, &frame{})
			continue
		case json.Delim('}'), json.Delim(']'):
			stack = stack[:len(stack)-1]
		}
		// A value ends; an object's next token is a key.
		if len(stack) > 0 && stack[len(stack)-1].object {
			stack[len(stack)-1].key = true
		}
	}
}

// Validate checks t for a run at rps requests per second whose operator
// confirmed the host confirmHost, which must equal the host[:port] of BaseURL
// byte for byte. Its errors name fields and entries by position and never
// repeat a header value or user info.
func (t Target) Validate(confirmHost string, rps int) error {
	base, err := t.parseBase()
	if err != nil {
		return err
	}
	if confirmHost != base.Host {
		return errors.New("--confirm-host does not equal the host[:port] of base_url exactly")
	}
	switch {
	case t.MaxRPS < 1:
		return errors.New("max_rps must be at least 1")
	case rps < 1 || rps > t.MaxRPS:
		return fmt.Errorf("--rps must be from 1 to max_rps (%d)", t.MaxRPS)
	case t.RequestIDPrefix == "" || len(t.RequestIDPrefix) > MaxPrefixLen || !run.ValidRequestID(t.RequestIDPrefix):
		return fmt.Errorf("request_id_prefix must be 1 to %d characters of A-Za-z0-9._-", MaxPrefixLen)
	case t.Mode != ModeMonitor && t.Mode != ModeEnforce:
		return errors.New(`mode must be "monitor" or "enforce"`)
	}
	if err := normalPath(t.HealthPath); err != nil {
		return fmt.Errorf("health_path: %w", err)
	}
	for _, s := range t.StopStatuses {
		if !isStatus(s) {
			return errors.New("stop_statuses holds a number that is not an HTTP status")
		}
	}
	if t.Mode == ModeEnforce && slices.Contains(t.StopStatuses, 403) {
		return errors.New("stop_statuses must not hold 403 in enforce mode, where 403 is the expected block")
	}
	targetHeaders := map[string]bool{}
	for name, value := range t.Headers {
		if err := checkHeaderName(name); err != nil {
			return fmt.Errorf("headers: %w", err)
		}
		if !validHeaderValue(value) {
			return errors.New("headers: a header value holds a control character or blanks around it")
		}
		lower := strings.ToLower(name)
		if targetHeaders[lower] {
			return errors.New("headers: two header names differ only by case")
		}
		targetHeaders[lower] = true
	}
	if len(t.Allow) == 0 {
		return errors.New("allow is empty")
	}
	routes := map[string]bool{}
	for i, e := range t.Allow {
		if err := e.validate(targetHeaders); err != nil {
			return fmt.Errorf("allow entry %d: %w", i+1, err)
		}
		route := e.Method + " " + e.Path
		if routes[route] {
			return fmt.Errorf("allow entry %d: the method and path are listed twice", i+1)
		}
		routes[route] = true
	}
	return nil
}

// parseBase reads BaseURL: https, or http to a loopback host, with a host and
// nothing else.
func (t Target) parseBase() (*url.URL, error) {
	u, err := url.Parse(t.BaseURL)
	if err != nil {
		return nil, errors.New("base_url is not a URL")
	}
	switch {
	case u.User != nil:
		return nil, errors.New("base_url must not hold user info")
	case u.Scheme != "https" && !(u.Scheme == "http" && run.IsLoopback(u.Hostname())):
		return nil, errors.New("base_url must be https, or http to a loopback host")
	case u.Host == "" || u.Hostname() == "" || u.Opaque != "" || u.Path != "" || u.RawPath != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(t.BaseURL, "?#"):
		return nil, errors.New("base_url must hold only a scheme and host[:port]")
	}
	return u, nil
}

// Base returns the parsed base URL of a validated target.
func (t Target) Base() (*url.URL, error) { return t.parseBase() }

// placement is one parsed placement of an entry.
type placement struct{ kind, name string }

func parsePlacement(s string) (placement, error) {
	kind, name, ok := strings.Cut(s, ":")
	switch {
	case !ok || name == "":
		return placement{}, errors.New(`a placement is not "kind:name"`)
	case kind != PlaceQuery && kind != PlaceHeader && kind != PlaceJSON:
		return placement{}, errors.New("a placement kind is not query, header or json")
	case kind == PlaceHeader:
		if err := checkHeaderName(name); err != nil {
			return placement{}, fmt.Errorf("a header placement: %w", err)
		}
	case !utf8.ValidString(name) || hasControl(name):
		return placement{}, errors.New("a placement name is not valid UTF-8 or holds a control character")
	}
	return placement{kind, name}, nil
}

// placements returns the parsed placements of a validated entry.
func (e Entry) placements() []placement {
	out := make([]placement, 0, len(e.Placements))
	for _, s := range e.Placements {
		p, err := parsePlacement(s)
		if err == nil {
			out = append(out, p)
		}
	}
	return out
}

func (e Entry) validate(targetHeaders map[string]bool) error {
	switch {
	case !isToken(e.Method):
		return errors.New("method is not a valid token")
	case strings.EqualFold(e.Method, "CONNECT"):
		return errors.New("method CONNECT has no path")
	}
	if err := normalPath(e.Path); err != nil {
		return fmt.Errorf("path: %w", err)
	}
	if len(e.BenignStatus) == 0 {
		return errors.New("benign_status is empty")
	}
	for _, s := range e.BenignStatus {
		if !isStatus(s) || s == 403 || s >= 500 {
			return errors.New("benign_status must hold HTTP statuses below 500 other than 403")
		}
	}
	if len(e.Placements) == 0 {
		return errors.New("it has no placement")
	}
	seen := map[placement]bool{}
	for _, s := range e.Placements {
		p, err := parsePlacement(s)
		if err != nil {
			return err
		}
		key := p
		if p.kind == PlaceHeader {
			key.name = strings.ToLower(p.name)
			if targetHeaders[key.name] {
				return errors.New("a header placement would collide with a header of the target file")
			}
		}
		if seen[key] {
			return errors.New("two placements would collide")
		}
		seen[key] = true
	}
	return nil
}

// normalPath refuses a path that is not already in the normal form a server
// compares routes in, so that the path sent is the path allowed.
func normalPath(p string) error {
	switch {
	case !strings.HasPrefix(p, "/"):
		return errors.New("it does not start with /")
	case path.Clean(p) != p, strings.Contains(p, "//"), strings.Contains(p, ".."):
		return errors.New("it is not in normal form")
	case strings.ContainsAny(p, "%?;\\# "):
		return errors.New("it holds %, ?, ;, \\, # or a space")
	}
	for i := range len(p) {
		if p[i] < 0x20 || p[i] >= 0x7f {
			return errors.New("it holds a control character or a byte outside ASCII")
		}
	}
	return nil
}

// checkHeaderName refuses a name that is not a token or that framing,
// routing or the request ID depend on.
func checkHeaderName(name string) error {
	if !isToken(name) {
		return errors.New("a header name is not a valid token")
	}
	for _, f := range forbiddenHeaders {
		if strings.EqualFold(name, f) {
			return fmt.Errorf("header %s must not be set", f)
		}
	}
	return nil
}

func isStatus(s int) bool { return s >= 100 && s <= 599 }

// isToken reports whether s is an RFC 9110 token: a method or a header name.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

// validHeaderValue reports whether net/http sends v as given and the server
// reads it back unchanged: no control character but an inner tab, and no
// blank at either end.
func validHeaderValue(v string) bool {
	if v == "" || strings.Trim(v, " \t") != v {
		return false
	}
	return !hasControl(strings.ReplaceAll(v, "\t", " "))
}

func hasControl(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
