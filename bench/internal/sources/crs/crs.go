// Package crs imports the regression tests of the OWASP Core Rule Set as
// bench case lines. The test files are untrusted data: they are parsed as
// YAML and nothing in them is run.
//
// A test file belongs to one rule and holds tests; a test holds stages; a
// stage is one request (input) and what the rule set must log for it
// (output). A stage becomes a line only if the line makes the bench send the
// request that the upstream test runner sends; any other stage is reported
// as a cases.Skip.
//
// What the runner sends was read from the source of go-ftw v2.3.0, the
// version the pinned tree runs its tests with (ftwhttp.BuildRequest,
// ftwhttp.encodeDataParameters, (*ftwhttp.Request).AddStandardHeaders, the
// defaults in package test). For a stage that is not a raw request:
//
//   - the request line is the method (default GET), the target (default /)
//     and the version (default HTTP/1.1), as written;
//   - the headers are sent as written; none is replaced. With header
//     completion (the default) the runner adds "Connection: close" if there
//     is no Connection header, a form Content-Type if there is a body and no
//     Content-Type, and a Content-Length if there is none and the request
//     has a body or a method that matches ^POST|PUT|PATCH|DELETE$;
//   - with header completion, a body whose Content-Type is exactly the form
//     type and that holds no "%" escape and no "+" has the names and values
//     of its parameters query-escaped. Any other body is sent as written;
//   - a body whose Content-Type holds "multipart/form-data;" gets a carriage
//     return before every line feed.
//
// The lines reproduce all of this. The Connection header is in the line; the
// bench's sender writes the same Content-Length as the runner for a body and
// for POST, PUT and PATCH, and stages for which the two would differ are
// skipped. The sender names the headers in canonical case and in its own
// order, and adds X-Request-Id.
package crs

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

// Source is the source name of the lines this package writes.
const Source = "crs"

const (
	// testsDir is where the tree keeps its test files, one directory per rule
	// file group.
	testsDir = "tests/regression/tests"
	// maxFileBytes bounds one test file.
	maxFileBytes = 8 << 20
	// formContentType is what the upstream runner adds to a request that has
	// a body and no Content-Type.
	formContentType = "application/x-www-form-urlencoded"
	// multipartMark is what the upstream runner looks for in a Content-Type
	// to send the body with CRLF line ends.
	multipartMark = "multipart/form-data;"
	// testAgent is the User-Agent the upstream tests send when the agent is
	// not what they test.
	testAgent = "OWASP CRS test agent"
)

// categories maps the number of a rule file group to a category. Group 934
// mixes several attack classes and stays "other".
var categories = map[string]string{
	"911": "protocol",
	"913": "scanner",
	"920": "protocol",
	"921": "protocol",
	"922": "protocol",
	"930": "lfi",
	"931": "rfi",
	"932": "cmdi",
	"933": "codei",
	"941": "xss",
	"942": "sqli",
	"943": "session",
	"944": "java",
}

// mechanics are the groups that test how the rule set works (set-up,
// exclusions, anomaly scoring), not what it detects. Another firewall has no
// reason to flag their requests.
var mechanics = map[string]bool{"901": true, "905": true, "949": true, "980": true, "999": true}

// framing are the groups that test how a request is framed. The one value in
// such a request that looks like a payload is incidental, so none is named.
var framing = map[string]bool{"911": true, "920": true, "921": true, "922": true}

var groupPattern = regexp.MustCompile(`^(REQUEST|RESPONSE)-([0-9]{3})(-|$)`)

// groupNumber returns the phase and number of a rule file group such as
// "REQUEST-942-APPLICATION-ATTACK-SQLI", or two empty strings.
func groupNumber(group string) (phase, number string) {
	if m := groupPattern.FindStringSubmatch(group); m != nil {
		return m[1], m[2]
	}
	return "", ""
}

// category returns the category of a rule file group, or "other".
func category(group string) string {
	if phase, number := groupNumber(group); phase == "REQUEST" {
		if c, ok := categories[number]; ok {
			return c
		}
	}
	return "other"
}

// Import reads the regression tests of the Core Rule Set tree at root. A
// stage that must make the rule set log rule IDs becomes an attack line; one
// that must not make it log some IDs becomes a near-miss line, never a
// legitimate one: another rule may still match it. The case ID is
// "ruleid-testid", as upstream writes it.
//
// Every returned line is accepted by cases.FromLine. A file, test or stage
// that is not imported is returned in skipped, identified by its case ID or,
// without one, by its file (and the test's position in it). The error is for
// a tree that cannot be read or holds no test files.
func Import(root string) (lines []cases.Line, skipped []cases.Skip, err error) {
	tree, err := os.OpenRoot(root)
	if err != nil {
		return nil, nil, fmt.Errorf("opening the CRS tree: %w", err)
	}
	defer func() {
		if closeErr := tree.Close(); closeErr != nil && err == nil {
			lines, skipped, err = nil, nil, fmt.Errorf("closing the CRS tree: %w", closeErr)
		}
	}()
	// The tree cannot name a file outside itself: links are not followed.
	fsys := tree.FS()
	type entry struct {
		name string
		link bool
	}
	var entries []entry
	files := 0
	err = fs.WalkDir(fsys, testsDir, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		ext := path.Ext(name)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			entries = append(entries, entry{name, true})
		case d.Type().IsRegular() && (ext == ".yaml" || ext == ".yml"):
			entries = append(entries, entry{name, false})
			files++
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("listing the CRS tests: %w", err)
	}
	if files == 0 {
		return nil, nil, fmt.Errorf("no test files under %s", testsDir)
	}

	im := importer{seen: map[string]bool{}}
	for _, e := range entries {
		rel := strings.TrimPrefix(e.name, testsDir+"/")
		if e.link {
			im.skip(rel, "link is not followed")
			continue
		}
		content, err := readFile(fsys, e.name)
		if err != nil {
			return nil, nil, fmt.Errorf("reading a CRS test file: %w", err)
		}
		im.file(rel, content)
	}
	return im.lines, im.skipped, nil
}

// readFile reads at most maxFileBytes+1 bytes of the named file.
func readFile(fsys fs.FS, name string) (content []byte, err error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return io.ReadAll(io.LimitReader(f, maxFileBytes+1))
}

type importer struct {
	lines   []cases.Line
	skipped []cases.Skip
	// seen holds the case IDs given out, to lines and to skips.
	seen map[string]bool
}

func (im *importer) skip(id, reason string) {
	im.skipped = append(im.skipped, cases.Skip{CaseID: id, Reason: reason})
}

// file imports the tests of one file. rel is its path below testsDir and
// starts with the rule file group.
func (im *importer) file(rel string, content []byte) {
	if len(content) > maxFileBytes {
		im.skip(rel, fmt.Sprintf("file is larger than %d bytes", maxFileBytes))
		return
	}
	doc, more, err := documents(content)
	if err != nil {
		im.skip(rel, "file is not valid YAML")
		return
	}
	if doc.Kind == 0 {
		im.skip(rel, "file holds no tests")
		return
	}
	top, problem := mapping(doc.Content[0])
	if problem != "" {
		im.skip(rel, "file "+problem)
		return
	}
	ruleID, ok := number(top.get("rule_id"))
	if !ok {
		im.skip(rel, "rule_id is not a number")
		return
	}
	tests := top.get("tests")
	switch {
	case tests == nil:
		im.skip(rel, "file holds no tests")
		return
	case tests.Kind != yaml.SequenceNode:
		im.skip(rel, "tests is not a list")
		return
	case len(tests.Content) == 0:
		im.skip(rel, "file holds no tests")
		return
	}
	if more {
		// What is skipped is the later documents; the first is imported.
		im.skip(rel+" (documents after the first)", "YAML documents after the first of a file: they are not read")
	}

	group, _, inGroup := strings.Cut(rel, "/")
	if !inGroup {
		group = ""
	}
	for i, node := range tests.Content {
		position := rel + "#" + strconv.Itoa(i+1)
		test, problem := mapping(node)
		if problem != "" {
			im.skip(position, "test "+problem)
			continue
		}
		testID, ok := number(test.get("test_id"))
		if !ok {
			im.skip(position, "test_id is not a number")
			continue
		}
		id := ruleID + "-" + testID
		if im.seen[id] {
			im.skip(position, "case ID is used twice")
			continue
		}
		im.seen[id] = true
		line, reason := convert(group, id, test.get("stages"))
		if reason != "" {
			im.skip(id, reason)
			continue
		}
		im.lines = append(im.lines, line)
	}
}

// convert builds the line of the test with the given stages, or says why
// there is none.
func convert(group, id string, stages *yaml.Node) (line cases.Line, reason string) {
	phase, number := groupNumber(group)
	switch {
	case mechanics[number]:
		return line, "rule-set mechanics, not an attack"
	case phase == "RESPONSE":
		return line, "response-phase rule: the attack is not in the request"
	case stages == nil || stages.Kind != yaml.SequenceNode:
		return line, "stages is not a list"
	case len(stages.Content) == 0:
		return line, "test has no stages"
	case len(stages.Content) > 1:
		return line, "test has several stages"
	}
	stage, problem := mapping(stages.Content[0])
	if problem != "" {
		return line, "stage " + problem
	}
	req, reason := readInput(stage.get("input"))
	if reason != "" {
		return line, reason
	}
	expected, reason := readOutput(stage.get("output"))
	if reason != "" {
		return line, reason
	}
	line, reason = req.line(!framing[number])
	if reason != "" {
		return line, reason
	}
	line.Name = Source + "-" + id
	line.Category = category(group)
	line.Kind = string(expected)
	line.Source = Source
	line.SourceCaseID = id
	line.Expected = expected
	if _, err := cases.FromLine(line); err != nil {
		// Without the source and case ID that FromLine adds.
		if cause := errors.Unwrap(err); cause != nil {
			return cases.Line{}, cause.Error()
		}
		return cases.Line{}, "the line is not a valid case"
	}
	return line, ""
}

// readOutput says what a stage's output expects of the request.
func readOutput(node *yaml.Node) (expected cases.Expected, reason string) {
	output, problem := mapping(node)
	if problem != "" {
		return "", "output " + problem
	}
	if n := output.get("expect_error"); n != nil {
		var fails bool
		if n.Kind != yaml.ScalarNode || n.Decode(&fails) != nil {
			return "", "output expect_error is not a boolean"
		}
		if fails {
			return "", "the request is expected to fail"
		}
	}
	var required, excluded int
	if n := output.get("log"); n != nil && !isNull(n) {
		log, problem := mapping(n)
		if problem != "" {
			return "", "output log " + problem
		}
		var okRequired, okExcluded bool
		required, okRequired = listLength(log.get("expect_ids"))
		excluded, okExcluded = listLength(log.get("no_expect_ids"))
		if !okRequired || !okExcluded {
			return "", "output log IDs are not a list"
		}
	}
	switch {
	case required > 0:
		// Also when other IDs are excluded: the rule set must still flag the
		// request, the test only says which of its rules do.
		return cases.Attack, ""
	case excluded > 0:
		return cases.NearMiss, ""
	}
	return "", "output requires no rule IDs and excludes none"
}

// request is the input of one stage, as the test file gives it.
type request struct {
	method, uri string
	headers     []pair
	data        string
	// complete says that the upstream runner completes the headers.
	complete bool
}

// pair is one header.
type pair struct{ name, value string }

// readInput reads a stage's input, or says why the stage cannot be imported.
func readInput(node *yaml.Node) (req request, reason string) {
	input, problem := mapping(node)
	if problem != "" {
		return req, "input " + problem
	}
	req = request{method: "GET", uri: "/", complete: true}
	version := "HTTP/1.1"
	var headers *yaml.Node
	for _, f := range input {
		// An empty field is a field left out.
		if isNull(f.value) {
			continue
		}
		var ok bool
		switch f.key {
		case "dest_addr", "port", "protocol":
			// Where the upstream runner sends the request.
			ok = true
		case "method":
			req.method, ok = scalar(f.value)
		case "uri":
			req.uri, ok = scalar(f.value)
		case "version":
			version, ok = scalar(f.value)
		case "data":
			req.data, ok = scalar(f.value)
		case "headers":
			headers, ok = f.value, true
		case "autocomplete_headers":
			ok = f.value.Kind == yaml.ScalarNode && f.value.Decode(&req.complete) == nil
		case "encoded_request", "raw_request":
			// The runner writes these bytes to the connection as they are.
			return req, "request is given as raw or encoded bytes"
		default:
			return req, "input field is not supported" + fieldName(f.key)
		}
		if !ok {
			return req, "input field " + f.key + " has the wrong type"
		}
	}
	if version != "HTTP/1.1" {
		return req, "HTTP version is not HTTP/1.1"
	}
	// The upstream runner expands data as a template; nothing here does.
	if strings.Contains(req.data, "{{") {
		return req, "data is a template"
	}
	if headers != nil {
		fields, problem := mapping(headers)
		if problem != "" {
			return req, "headers " + problem
		}
		for _, f := range fields {
			value, ok := scalar(f.value)
			if !ok && !isNull(f.value) {
				return req, "a header value is not a scalar"
			}
			req.headers = append(req.headers, pair{f.key, value})
		}
	}
	return req, ""
}

var fieldPattern = regexp.MustCompile(`^[a-z_]{1,40}$`)

// fieldName returns ": name" for a name that reads like a field of the test
// format, and nothing for any other text: reasons do not repeat values.
func fieldName(key string) string {
	if fieldPattern.MatchString(key) {
		return ": " + key
	}
	return ""
}

// line builds the request part of the case line, with its payload if
// namePayload is set, or says why the bench cannot send the request the
// upstream runner sends.
func (r request) line(namePayload bool) (line cases.Line, reason string) {
	if !utf8.ValidString(r.method) {
		return line, "method is not valid UTF-8"
	}
	headers := make(map[string]string, len(r.headers)+1)
	lower := make(map[string]string, len(r.headers))
	sent := make([]pair, 0, len(r.headers))
	for _, h := range r.headers {
		// A case line has no other form for these bytes.
		if !utf8.ValidString(h.name) || !utf8.ValidString(h.value) {
			return line, "a header is not valid UTF-8"
		}
		name := lowerASCII(h.name)
		if _, ok := lower[name]; ok {
			return line, "a header name is used twice"
		}
		if h.value != strings.Trim(h.value, " \t") {
			return line, "a header value starts or ends with a blank, which the sender removes"
		}
		value := cases.RewriteCallbacks(h.value)
		headers[h.name], lower[name] = value, value
		sent = append(sent, pair{h.name, value})
	}
	// The sender always writes a Host header, and frames a body itself.
	if _, ok := lower["host"]; !ok {
		return line, "no Host header: the sender always sends one"
	}
	if _, ok := lower["transfer-encoding"]; ok {
		return line, "Transfer-Encoding header: the sender would frame the body differently"
	}
	if _, ok := lower["connection"]; r.complete && !ok {
		headers["Connection"] = "close"
	}

	uri := cases.RewriteCallbacks(r.uri)
	if !strings.HasPrefix(uri, "/") {
		return line, "request target is not a path"
	}
	rawPath, rawQuery, hasQuery := strings.Cut(uri, "?")
	if hasQuery && rawQuery == "" {
		return line, "request target ends in an empty query, which a case line cannot say"
	}

	contentType, hasContentType := lower["content-type"]
	if r.complete && r.data != "" && !hasContentType {
		line.ContentType = formContentType
		contentType = formContentType
	}
	// What the runner does to a body is decided by the test's own data, so
	// that rewriting a callback host cannot change it.
	escape := r.complete && strings.EqualFold(contentType, formContentType) && unescaped(r.data)
	crlf := strings.Contains(strings.ToLower(contentType), multipartMark)
	asSent := func(data string) string {
		if escape {
			data = escapeForm(data)
		}
		if crlf {
			data = strings.ReplaceAll(data, "\n", "\r\n")
		}
		return data
	}
	upstream, body := asSent(r.data), asSent(cases.RewriteCallbacks(r.data))

	stated, hasLength := lower["content-length"]
	runnerAdds := r.complete && !hasLength && (upstream != "" || runnerMethodHasBody(r.method))
	senderAdds := !hasLength && (body != "" || r.method == "POST" || r.method == "PUT" || r.method == "PATCH")
	switch {
	case hasLength && stated == strconv.Itoa(len(upstream)) && len(body) != len(upstream):
		return line, "rewriting a callback host changes the body length that a Content-Length header states"
	case senderAdds && !runnerAdds:
		return line, "no header completion and no Content-Length header: the sender would add one"
	case runnerAdds && !senderAdds:
		return line, "the upstream runner adds a Content-Length header for this method, the sender does not"
	}

	line.Method = r.method
	line.Path = escapeInvalid(rawPath)
	line.RawQuery = escapeInvalid(rawQuery)
	line.Headers = headers
	if utf8.ValidString(body) {
		line.Body = body
	} else {
		line.BodyBase64 = encodeBase64(body)
	}
	if !namePayload {
		return line, ""
	}
	payload, placement := findPayload(rawPath, rawQuery, sent, contentType, body)
	line.Placement = placement
	if utf8.ValidString(payload) {
		line.Payload = payload
	} else {
		line.PayloadBase64 = encodeBase64(payload)
	}
	return line, ""
}

// runnerMethodHasBody reports whether the upstream runner adds a
// Content-Length to a request with this method and no body: its pattern is
// ^POST|PUT|PATCH|DELETE$, which also matches POSTS and INPUT.
func runnerMethodHasBody(method string) bool {
	return strings.HasPrefix(method, "POST") || strings.Contains(method, "PUT") ||
		strings.Contains(method, "PATCH") || strings.HasSuffix(method, "DELETE")
}

// unescaped reports whether the upstream runner takes data for a form body
// that still has to be escaped: one that query-unescaping leaves unchanged,
// which is one without "+" and without a valid or invalid "%" escape.
func unescaped(data string) bool {
	decoded, err := url.QueryUnescape(data)
	return err == nil && decoded == data && data != ""
}

// escapeForm escapes a form body as the upstream runner does: the text
// around every "&" and on both sides of the first "=" in it is query-escaped.
// The runner does not write the empty part after a final "&".
func escapeForm(data string) string {
	parts := strings.Split(strings.TrimSuffix(data, "&"), "&")
	for i, part := range parts {
		name, value, hasValue := strings.Cut(part, "=")
		parts[i] = url.QueryEscape(name)
		if hasValue {
			parts[i] += "=" + url.QueryEscape(value)
		}
	}
	return strings.Join(parts, "&")
}

// escapeInvalid percent-encodes the bytes of s that are not valid UTF-8,
// which a case line cannot carry in a path or a query.
func escapeInvalid(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n == 1 {
			fmt.Fprintf(&b, "%%%02X", s[i])
		} else {
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

func encodeBase64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// lowerASCII lower-cases the ASCII letters of s, as cases compares header
// names.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
