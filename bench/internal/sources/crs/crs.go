// Package crs imports the regression tests of the OWASP Core Rule Set as
// bench case lines. The test files are untrusted data: they are parsed as
// YAML and nothing in them is run.
//
// A test file belongs to one rule and holds tests; a test holds stages; a
// stage is one request (input) and what the rule set must log for it
// (output). A stage becomes a line only if the line sends the request the
// upstream test runner would send. Three differences are accepted and are not
// reasons to skip:
//
//   - the runner adds "Connection: close" to a request that names no
//     Connection header; the line does not, so connections are reused;
//   - a body written with unescaped characters for a form content type is
//     sent as written, whether or not the runner would escape it;
//   - the bench's sender adds "Content-Length: 0" to a POST, PUT or PATCH
//     without a body.
//
// Everything else that cannot be reproduced is reported as a cases.Skip.
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
	// multipartPrefix is the start of the content types whose body the
	// upstream runner sends with CRLF line ends.
	multipartPrefix = "multipart/form-data;"
	// testAgent is the User-Agent the upstream tests send when the agent is
	// not what they test.
	testAgent = "OWASP CRS test agent"
)

// categories maps the number of a request rule file group to a category.
// Group 934 mixes several attack classes and stays "other".
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

var groupPattern = regexp.MustCompile(`^REQUEST-([0-9]{3})(-|$)`)

// category returns the category of a rule file group such as
// "REQUEST-942-APPLICATION-ATTACK-SQLI", or "other".
func category(group string) string {
	if m := groupPattern.FindStringSubmatch(group); m != nil {
		if c, ok := categories[m[1]]; ok {
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
	var files []string
	err = fs.WalkDir(fsys, testsDir, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ext := path.Ext(name); d.Type().IsRegular() && (ext == ".yaml" || ext == ".yml") {
			files = append(files, name)
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("listing the CRS tests: %w", err)
	}
	if len(files) == 0 {
		return nil, nil, fmt.Errorf("no test files under %s", testsDir)
	}

	im := importer{seen: map[string]bool{}}
	for _, name := range files {
		content, err := readFile(fsys, name)
		if err != nil {
			return nil, nil, fmt.Errorf("reading a CRS test file: %w", err)
		}
		im.file(strings.TrimPrefix(name, testsDir+"/"), content)
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
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		im.skip(rel, "file is not valid YAML")
		return
	}
	if doc.Kind == 0 {
		im.skip(rel, "file holds no tests")
		return
	}
	top, ok := mapping(doc.Content[0])
	if !ok {
		im.skip(rel, "file is not a YAML mapping")
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

	group, _, inGroup := strings.Cut(rel, "/")
	if !inGroup {
		group = ""
	}
	for i, node := range tests.Content {
		position := rel + "#" + strconv.Itoa(i+1)
		test, ok := mapping(node)
		if !ok {
			im.skip(position, "test is not a mapping")
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
	switch {
	case strings.HasPrefix(group, "RESPONSE-"):
		return line, "response-phase rule: the attack is not in the request"
	case stages == nil || stages.Kind != yaml.SequenceNode:
		return line, "stages is not a list"
	case len(stages.Content) == 0:
		return line, "test has no stages"
	case len(stages.Content) > 1:
		return line, "test has several stages"
	}
	stage, ok := mapping(stages.Content[0])
	if !ok {
		return line, "stage is not a mapping"
	}
	req, reason := readInput(stage.get("input"))
	if reason != "" {
		return line, reason
	}
	expected, reason := readOutput(stage.get("output"))
	if reason != "" {
		return line, reason
	}
	line, reason = req.line()
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
		return cases.Line{}, errors.Unwrap(err).Error()
	}
	return line, ""
}

// readOutput says what a stage's output expects of the request.
func readOutput(node *yaml.Node) (expected cases.Expected, reason string) {
	output, ok := mapping(node)
	if !ok {
		return "", "output is not a mapping"
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
		log, ok := mapping(n)
		if !ok {
			return "", "output log is not a mapping"
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
	// complete says that the upstream runner completes the headers: a
	// Content-Type and a Content-Length for a body.
	complete bool
}

// pair is one header.
type pair struct{ name, value string }

// readInput reads a stage's input, or says why the stage cannot be imported.
func readInput(node *yaml.Node) (req request, reason string) {
	input, ok := mapping(node)
	if !ok {
		return req, "input is not a mapping"
	}
	req = request{method: "GET", uri: "/", complete: true}
	version := "HTTP/1.1"
	var headers *yaml.Node
	seen := map[string]bool{}
	for _, f := range input {
		if seen[f.key] {
			return req, "input names a field twice"
		}
		seen[f.key] = true
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
		fields, ok := mapping(headers)
		if !ok {
			return req, "headers is not a mapping"
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

// line builds the request part of the case line, or says why the request
// cannot be sent as upstream means it.
func (r request) line() (line cases.Line, reason string) {
	if !utf8.ValidString(r.method) {
		return line, "method is not valid UTF-8"
	}
	headers := make(map[string]string, len(r.headers))
	lower := make(map[string]string, len(r.headers))
	for _, h := range r.headers {
		// A case line has no other form for these bytes.
		if !utf8.ValidString(h.name) || !utf8.ValidString(h.value) {
			return line, "a header is not valid UTF-8"
		}
		name := lowerASCII(h.name)
		if _, ok := lower[name]; ok {
			return line, "a header name is used twice"
		}
		value := cases.RewriteCallbacks(h.value)
		headers[h.name], lower[name] = value, value
	}
	// The sender always writes a Host header, and frames a body itself.
	if _, ok := lower["host"]; !ok {
		return line, "no Host header: the sender always sends one"
	}
	if _, ok := lower["transfer-encoding"]; ok {
		return line, "Transfer-Encoding header: the sender would frame the body differently"
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
	multipart := strings.HasPrefix(lowerASCII(contentType), strings.TrimSuffix(multipartPrefix, ";"))
	body, upstreamLength := cases.RewriteCallbacks(r.data), len(r.data)
	if multipart && strings.Contains(r.data, "\n") {
		// The upstream runner sends these bodies with CRLF line ends. Cases
		// in which it is not certain what it sends are left out.
		switch {
		case !r.complete:
			return line, "multipart body without header completion"
		case !strings.HasPrefix(contentType, multipartPrefix):
			return line, "multipart content type is spelled unusually"
		case strings.Contains(r.data, "\r"):
			return line, "multipart body already holds carriage returns"
		}
		body = strings.ReplaceAll(body, "\n", "\r\n")
		upstreamLength += strings.Count(r.data, "\n")
	}
	_, hasLength := lower["content-length"]
	switch {
	case hasLength && lower["content-length"] == strconv.Itoa(upstreamLength) && len(body) != upstreamLength:
		return line, "rewriting a callback host changes the body length that a Content-Length header states"
	case !r.complete && !hasLength && (body != "" || r.method == "POST" || r.method == "PUT" || r.method == "PATCH"):
		return line, "no header completion and no Content-Length header: the sender would add one"
	}
	if r.complete && body != "" && !hasContentType {
		line.ContentType = formContentType
		contentType = formContentType
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
	payload, placement := findPayload(rawPath, rawQuery, r.headers, lower, contentType, body)
	line.Placement = placement
	if utf8.ValidString(payload) {
		line.Payload = payload
	} else {
		line.PayloadBase64 = encodeBase64(payload)
	}
	return line, ""
}

// boilerplate are the headers that describe the client or the body and are
// not looked at for a payload.
var boilerplate = map[string]bool{
	"host": true, "accept": true, "accept-encoding": true, "accept-language": true, "accept-charset": true,
	"connection": true, "proxy-connection": true, "keep-alive": true, "cache-control": true,
	"content-type": true, "content-length": true,
}

var plainPath = regexp.MustCompile(`^(/[A-Za-z0-9_-]+(\.[A-Za-z0-9]+)?)*/?$`)

// findPayload returns the decoded part of the request that carries the
// attack, and where it is. Candidates are the query parameters, the
// parameters of a form body, the headers that are not boilerplate, and a
// path that is more than plain segments. With several candidates, or a body
// that is not a form, no part can be named and both results are empty.
func findPayload(rawPath, rawQuery string, headers []pair, lower map[string]string, contentType, body string) (payload, placement string) {
	type candidate struct{ value, placement string }
	var found []candidate
	parameters := func(encoded, placement string) {
		for _, parameter := range strings.Split(encoded, "&") {
			key, value, _ := strings.Cut(parameter, "=")
			if value == "" {
				value = key
			}
			if value != "" {
				found = append(found, candidate{decodeOr(url.QueryUnescape, value), placement})
			}
		}
	}
	parameters(rawQuery, "query")
	if body != "" {
		mediaType, _, _ := strings.Cut(contentType, ";")
		if lowerASCII(strings.TrimSpace(mediaType)) != formContentType {
			return "", ""
		}
		parameters(body, "body")
	}
	for _, h := range headers {
		name := lowerASCII(h.name)
		if value := lower[name]; !boilerplate[name] && value != "" && (name != "user-agent" || value != testAgent) {
			found = append(found, candidate{value, "header"})
		}
	}
	if !plainPath.MatchString(rawPath) {
		found = append(found, candidate{decodeOr(url.PathUnescape, rawPath), "path"})
	}
	if len(found) != 1 {
		return "", ""
	}
	return found[0].value, found[0].placement
}

// decodeOr returns s decoded, or s itself if it is not validly encoded.
func decodeOr(decode func(string) (string, error), s string) string {
	if decoded, err := decode(s); err == nil {
		return decoded
	}
	return s
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

// field is one entry of a YAML mapping.
type field struct {
	key   string
	value *yaml.Node
}

// fields are the entries of a YAML mapping, in file order.
type fields []field

// get returns the first value with the given key, or nil.
func (fs fields) get(key string) *yaml.Node {
	for _, f := range fs {
		if f.key == key {
			return f.value
		}
	}
	return nil
}

// mapping reads n as a mapping with scalar keys. Aliases are not followed
// here or below: the test format does not need them.
func mapping(n *yaml.Node) (fields, bool) {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, false
	}
	out := make(fields, 0, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, ok := scalar(n.Content[i])
		if !ok {
			return nil, false
		}
		out = append(out, field{key, n.Content[i+1]})
	}
	return out, true
}

// scalar returns the text of a scalar: as written for a number or a boolean,
// decoded for a !!binary value.
func scalar(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", false
	}
	var s string
	if err := n.Decode(&s); err != nil {
		return "", false
	}
	return s, true
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null"
}

var numberPattern = regexp.MustCompile(`^[0-9]{1,12}$`)

// number returns the digits of a rule or test ID.
func number(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode || !numberPattern.MatchString(n.Value) {
		return "", false
	}
	return n.Value, true
}

// listLength returns the length of a list; a list left out is empty.
func listLength(n *yaml.Node) (int, bool) {
	switch {
	case n == nil || isNull(n):
		return 0, true
	case n.Kind == yaml.SequenceNode:
		return len(n.Content), true
	}
	return 0, false
}
