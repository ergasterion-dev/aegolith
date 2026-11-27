// Package gotestwaf imports the test cases of GoTestWAF as bench case lines.
// The tree is untrusted data: its test cases and its configuration are parsed
// as YAML, and nothing in it is built or run.
//
// A test case file holds payloads, encoders and placeholders. The tool sends
// one request for every combination of the three: the payload goes through
// the encoder, and the placeholder puts the result somewhere in a request. A
// combination becomes a line only if the line makes the bench send the
// request that the tool sends; any other is reported as a cases.Skip. The
// files of a test set whose name holds "false" are the tool's false-positive
// checks and become legitimate lines; all others become attack lines.
//
// What the tool sends was read from the source of v0.5.11, with its defaults:
// the Go HTTP client, no debug header, no cookies, and the headers of the
// config.yaml at the root of the tree (package db for the files, package
// encoder, package placeholder, and the clients in scanner/clients/gohttp
// and scanner/clients/graphql). For every request:
//
//   - the encoders are Plain, Base64, Base64Flat (no padding), URL (escaped
//     as one path segment), JSUnicode (\uXXXX for every UTF-16 code unit) and
//     XMLEntity (an XML element named "string" around the escaped text);
//   - the placeholders build the request as the functions in placeholders.go
//     say. JSONRequest and SOAPBody encode the encoded payload once more;
//   - every header of the configuration that the request does not set itself
//     is added, except the User-Agent when the payload is the User-Agent;
//   - the client parses the URL and writes it again. So a fragment is not
//     sent, a path is escaped unless it is validly escaped already, and a
//     query is sent as written, blanks included. It sends no blanks around a
//     header value and no empty User-Agent.
//
// The lines differ from the tool in these ways:
//
//   - Callback hosts are replaced, in a payload before it is encoded and in
//     the templates of a RawRequest. The payload a line records is the
//     payload after that and before the encoder, so every encoder and
//     placeholder of one payload records the same payload.
//   - Where the tool draws random bytes (the name of a parameter, a header,
//     a form field or an XML element, and a multipart boundary), a line has
//     the same number of bytes from a hash of the test set, the test case,
//     the encoder, the placeholder and the payload. They are the same on
//     every import.
//   - The tool sends a GraphQL case to the endpoint its availability check
//     finds on the target, and none if it finds no endpoint. The lines use
//     /graphql, the first endpoint that check tries.
//   - The gRPC placeholder is a gRPC call and is skipped.
//   - A request that the tool's HTTP client refuses to send (a control
//     character in the URL or in a header, a "%" in the path that starts no
//     escape) is skipped. The tool counts such a case as failed.
//   - The bench's sender names the headers in canonical case and in its own
//     order, and adds X-Request-Id. It frames the body as the tool's client
//     does: both are Go's net/http.
//
// The envelope of a SOAPBody request and its SOAPAction header are the
// tool's and name public hosts as XML namespaces. They are sent as they are:
// they are identifiers, not addresses that a request makes a server contact.
package gotestwaf

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/textproto"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

// Source is the source name of the lines this package writes.
const Source = "gotestwaf"

const (
	// casesDir is where the tree keeps its test sets, one directory each.
	casesDir = "testcases"
	// configFile holds the headers the tool adds to every request.
	configFile = "config.yaml"
	// maxFileBytes bounds one file of the tree.
	maxFileBytes = 8 << 20
	// maxCombinations bounds the combinations of one test case file.
	maxCombinations = 10000
	// lineCheckBytes is the size from which a line is checked against the
	// longest line a case file may hold.
	lineCheckBytes = 1 << 20
)

// Reasons for which a file or a combination is skipped, besides those of the
// placeholders.
const (
	reasonLink     = "link is not followed"
	reasonTooLarge = "file is larger than 8 MiB"
	reasonFileName = "file name is not valid UTF-8"
	reasonSameName = "another file has the same name with another extension"
	reasonShape    = "file is not YAML in the shape of a test case"
	reasonMerge    = "file uses a YAML merge key"
	reasonNothing  = "file holds no payload, no encoder or no placeholder"
	reasonTooMany  = "file holds more than 10000 combinations of payload, encoder and placeholder"
	reasonEncoder  = "encoder is not one of the tool's"
	reasonTooLong  = "the case is too long for a line of a case file"
)

// categories maps a test case (the name of its file) to the bench's category
// for it, where the two clearly mean the same.
var categories = map[string]string{
	"sql-injection":           "sqli",
	"community-sqli":          "sqli",
	"xss-scripting":           "xss",
	"community-xss":           "xss",
	"path-traversal":          "lfi",
	"community-lfi":           "lfi",
	"community-lfi-multipart": "lfi",
	"shell-injection":         "cmdi",
	"nosql-injection":         "nosqli",
	"sst-injection":           "ssti",
	"xml-injection":           "xxe",
	"community-xxe":           "xxe",
	// The tool's RCE cases mix command and code injection, which the bench
	// keeps apart; they keep the tool's name for them.
	"rce":                       "rce",
	"rce-urlparam":              "rce",
	"rce-urlpath":               "rce",
	"community-rce":             "rce",
	"community-rce-rawrequests": "rce",
	"graphql":                   "graphql",
	"graphql-post":              "graphql",
}

var (
	// sizedCase is a community test case that pads a payload to a size.
	sizedCase = regexp.MustCompile(`^community-[0-9]+kb-(rce|sqli|xss)$`)
	// plainName is a test case name that can serve as a category.
	plainName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	// plainLabel is an encoder or placeholder name that can be part of a
	// case ID.
	plainLabel = regexp.MustCompile(`^[A-Za-z0-9]{1,40}$`)
)

// category returns the category of a test case: "fp" for a legitimate one,
// the bench's category where the name clearly matches one, and otherwise the
// name itself in lower case ("other" if it does not read like a name).
func category(name string, expected cases.Expected) string {
	if expected == cases.Legit {
		return "fp"
	}
	name = strings.ToLower(name)
	if m := sizedCase.FindStringSubmatch(name); m != nil {
		name = m[1]
	}
	if c, ok := categories[name]; ok {
		return c
	}
	if plainName.MatchString(name) {
		return name
	}
	return "other"
}

// Import reads the test cases of the GoTestWAF tree at root. Every
// combination of a payload, an encoder and a placeholder becomes one line.
// Its case ID is the path of its file below the test case directory without
// the extension, the position of the payload in the file, the encoder and
// the placeholder, such as "owasp/sql-injection/3/URL/URLParam". An encoder
// or placeholder that a file lists more than once, or whose name is not
// letters and digits, is followed or replaced by its position in the list.
//
// Every returned line is accepted by cases.FromLine. A file or a combination
// that is not imported is returned in skipped, identified by the path of the
// file or by the case ID. The error is for a tree that cannot be read, whose
// configuration cannot be read or that holds no test case files.
func Import(root string) (lines []cases.Line, skipped []cases.Skip, err error) {
	tree, err := os.OpenRoot(root)
	if err != nil {
		return nil, nil, fmt.Errorf("opening the GoTestWAF tree: %w", err)
	}
	defer func() {
		if closeErr := tree.Close(); closeErr != nil && err == nil {
			lines, skipped, err = nil, nil, fmt.Errorf("closing the GoTestWAF tree: %w", closeErr)
		}
	}()
	// The tree cannot name a file outside itself: links are not followed.
	fsys := tree.FS()
	defaults, err := readDefaults(fsys)
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s of the GoTestWAF tree: %w", configFile, err)
	}

	type entry struct {
		name string
		link bool
	}
	var entries []entry
	files := 0
	err = fs.WalkDir(fsys, casesDir, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		ext := path.Ext(name)
		switch {
		case ext != ".yaml" && ext != ".yml":
		case d.Type()&fs.ModeSymlink != 0:
			entries = append(entries, entry{name, true})
		case d.Type().IsRegular():
			entries = append(entries, entry{name, false})
			files++
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("listing the GoTestWAF test cases: %w", err)
	}
	if files == 0 {
		return nil, nil, fmt.Errorf("no test case files under %s", casesDir)
	}

	im := importer{defaults: defaults, seen: map[string]bool{}}
	for _, e := range entries {
		rel := strings.TrimPrefix(e.name, casesDir+"/")
		switch {
		case !utf8.ValidString(rel):
			im.skip(strings.ToValidUTF8(rel, "?"), reasonFileName)
			continue
		case e.link:
			im.skip(rel, reasonLink)
			continue
		}
		content, err := readFile(fsys, e.name)
		if err != nil {
			return nil, nil, fmt.Errorf("reading a GoTestWAF test case file: %w", err)
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

// readDefaults reads the headers of the tool's configuration file, which the
// tool adds to every request that does not set them. The tool cannot run
// without the file. It reads keys without regard to their case and sets the
// headers under their canonical names; the result is sorted by name.
func readDefaults(fsys fs.FS) ([]header, error) {
	content, err := readFile(fsys, configFile)
	if err != nil {
		return nil, err
	}
	if len(content) > maxFileBytes {
		return nil, errors.New("the file is too large")
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, errors.New("the file is not valid YAML")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || resolve(doc.Content[0]).Kind != yaml.MappingNode {
		return nil, errors.New("the file is not a mapping")
	}
	top := resolve(doc.Content[0])
	var defaults []header
	sections := 0
	for i := 0; i+1 < len(top.Content); i += 2 {
		if key := resolve(top.Content[i]); key.Kind != yaml.ScalarNode || !strings.EqualFold(key.Value, "headers") {
			continue
		}
		if sections++; sections > 1 {
			return nil, errors.New("the file has two headers sections")
		}
		section := resolve(top.Content[i+1])
		if section.Kind != yaml.MappingNode {
			return nil, errors.New("the headers are not a mapping")
		}
		for j := 0; j+1 < len(section.Content); j += 2 {
			name, value := resolve(section.Content[j]), resolve(section.Content[j+1])
			// The tool also turns other values into text; which text is not
			// read from its source here, so they are refused.
			if name.Kind != yaml.ScalarNode || name.Value == "" || value.Kind != yaml.ScalarNode ||
				value.ShortTag() != "!!str" && !decimal.MatchString(value.Value) {
				return nil, errors.New("a header is not a name with a string or a decimal number")
			}
			defaults = append(defaults, header{textproto.CanonicalMIMEHeaderKey(strings.ToLower(name.Value)), value.Value})
		}
	}
	slices.SortFunc(defaults, func(a, b header) int { return strings.Compare(a.name, b.name) })
	for i := 1; i < len(defaults); i++ {
		if defaults[i].name == defaults[i-1].name {
			return nil, errors.New("two headers have the same name")
		}
	}
	return defaults, nil
}

// decimal is an integer that YAML and the tool's configuration reader both
// write back as it is.
var decimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})$`)

type importer struct {
	defaults []header
	lines    []cases.Line
	skipped  []cases.Skip
	// seen holds the file paths, without extension, that case IDs start with.
	seen map[string]bool
}

func (im *importer) skip(id, reason string) {
	im.skipped = append(im.skipped, cases.Skip{CaseID: id, Reason: reason})
}

// testCase is the content of one test case file.
type testCase struct {
	payloads, encoders []string
	placeholders       []placeholder
}

// readTestCase reads a test case file as the tool reads it: the lists under
// the keys payload, encoder and placeholder of the first document, and
// nothing else. A payload or an encoder is any scalar, taken as text; a null
// is the empty string.
func readTestCase(content []byte) (tc testCase, reason string) {
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return tc, reasonShape
	}
	if doc.Kind == 0 {
		return tc, ""
	}
	top := resolve(doc.Content[0])
	if isNull(top) {
		return tc, ""
	}
	if top.Kind != yaml.MappingNode {
		return tc, reasonShape
	}
	seen := map[string]bool{}
	for i := 0; i+1 < len(top.Content); i += 2 {
		key, value := resolve(top.Content[i]), resolve(top.Content[i+1])
		if key.Kind != yaml.ScalarNode {
			return tc, reasonShape
		}
		ok := true
		switch key.Value {
		case "<<":
			// The tool's reader would merge the mapping it names.
			return tc, reasonMerge
		case "payload":
			tc.payloads, ok = stringList(value)
		case "encoder":
			tc.encoders, ok = stringList(value)
		case "placeholder":
			switch {
			case isNull(value):
			case value.Kind != yaml.SequenceNode:
				ok = false
			default:
				for _, item := range value.Content {
					p, reason := readPlaceholder(item)
					if reason != "" {
						return tc, reason
					}
					tc.placeholders = append(tc.placeholders, p)
				}
			}
		default:
			continue
		}
		// The tool would use the last of two equal keys; such a file is left
		// out instead.
		if !ok || seen[key.Value] {
			return testCase{}, reasonShape
		}
		seen[key.Value] = true
	}
	return tc, ""
}

// stringList reads a list of scalars as text.
func stringList(n *yaml.Node) (out []string, ok bool) {
	if isNull(n) {
		return nil, true
	}
	if n.Kind != yaml.SequenceNode {
		return nil, false
	}
	for _, item := range n.Content {
		item = resolve(item)
		if item.Kind != yaml.ScalarNode {
			return nil, false
		}
		var s string
		// A null decodes to nothing, a binary value to its bytes and any
		// other scalar to its text.
		if err := item.Decode(&s); err != nil {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null"
}

// file imports the combinations of one test case file. rel is its path
// below casesDir.
func (im *importer) file(rel string, content []byte) {
	if len(content) > maxFileBytes {
		im.skip(rel, reasonTooLarge)
		return
	}
	stem := strings.TrimSuffix(rel, path.Ext(rel))
	if im.seen[stem] {
		im.skip(rel, reasonSameName)
		return
	}
	im.seen[stem] = true

	tc, reason := readTestCase(content)
	if reason != "" {
		im.skip(rel, reason)
		return
	}
	placeholders := tc.placeholders
	names := make([]string, len(placeholders))
	for i, p := range placeholders {
		names[i] = p.name
	}
	switch {
	case len(tc.payloads) == 0 || len(tc.encoders) == 0 || len(placeholders) == 0:
		im.skip(rel, reasonNothing)
		return
	case len(tc.payloads) > maxCombinations, len(tc.encoders) > maxCombinations, len(placeholders) > maxCombinations,
		len(tc.payloads)*len(tc.encoders)*len(placeholders) > maxCombinations:
		im.skip(rel, reasonTooMany)
		return
	}

	// As the tool names them: the set is the directory the file is in, the
	// case is the file. A set is a false-positive set if its name holds
	// "false".
	c := combination{set: path.Base(path.Dir(casesDir + "/" + rel)), name: path.Base(stem)}
	expected := cases.Attack
	if strings.Contains(c.set, "false") {
		expected = cases.Legit
	}
	encoderLabels, placeholderLabels := labels(tc.encoders, "encoder"), labels(names, "placeholder")
	for i, payload := range tc.payloads {
		c.payload = cases.RewriteCallbacks(payload)
		for j, encoder := range tc.encoders {
			for k, p := range placeholders {
				c.encoder, c.placeholder = encoder, p
				id := stem + "/" + strconv.Itoa(i+1) + "/" + encoderLabels[j] + "/" + placeholderLabels[k]
				line, reason := c.line(im.defaults)
				if reason != "" {
					im.skip(id, reason)
					continue
				}
				line.Name = Source + "-" + id
				line.Category = category(c.name, expected)
				line.Kind = string(expected)
				line.Source = Source
				line.SourceCaseID = id
				line.Expected = expected
				if reason := check(line); reason != "" {
					im.skip(id, reason)
					continue
				}
				im.lines = append(im.lines, line)
			}
		}
	}
}

// labels returns what stands for each name in a case ID: the name, with its
// position in the list if the list holds it more than once, or kind and
// position for a name that is not letters and digits.
func labels(names []string, kind string) []string {
	count := make(map[string]int, len(names))
	for _, name := range names {
		count[name]++
	}
	out := make([]string, len(names))
	for i, name := range names {
		switch position := "#" + strconv.Itoa(i+1); {
		case !plainLabel.MatchString(name):
			out[i] = kind + position
		case count[name] > 1:
			out[i] = name + position
		default:
			out[i] = name
		}
	}
	return out
}

// combination is one payload with one encoder and one placeholder.
type combination struct {
	set, name string
	// payload is the payload after its callback hosts were replaced.
	payload     string
	encoder     string
	placeholder placeholder
}

// line builds the request of the combination and the payload it carries, or
// says why there is no line for it.
func (c combination) line(defaults []header) (line cases.Line, reason string) {
	encoded, ok := encode(c.encoder, c.payload)
	if !ok {
		return line, reasonEncoder
	}
	req, reason := c.placeholder.request(c.payload, encoded, c.token)
	if reason != "" {
		return line, reason
	}
	line, reason = req.line(defaults, c.placeholder.name == "UserAgent")
	if reason != "" {
		return line, reason
	}
	line.Encoder = c.encoder
	if utf8.ValidString(c.payload) {
		line.Payload = c.payload
	} else {
		line.PayloadBase64 = base64.StdEncoding.EncodeToString([]byte(c.payload))
	}
	return line, ""
}

// token returns the hex of n bytes (at most 32) that stand for random bytes
// of the tool. They depend on the combination and on label, which tells the
// uses within one request apart, and on nothing else.
func (c combination) token(label string, n int) string {
	h := sha256.New()
	for _, part := range []string{c.set, c.name, c.encoder, c.placeholder.name, c.payload, label} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		h.Write(length[:]) // a hash never returns a write error
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil)[:n])
}

// check says why a line cannot be part of a case file, if it cannot.
func check(line cases.Line) (reason string) {
	if _, err := cases.FromLine(line); err != nil {
		// Without the source and case ID that FromLine adds.
		if cause := errors.Unwrap(err); cause != nil {
			return cause.Error()
		}
		return "the line is not a valid case"
	}
	size := len(line.Path) + len(line.RawQuery) + len(line.Body) + len(line.BodyBase64) + len(line.Payload) + len(line.PayloadBase64)
	for _, value := range line.Headers {
		size += len(value)
	}
	if size < lineCheckBytes {
		return ""
	}
	// Writing fails for a line that is too long, and for nothing else here:
	// every string of the line is valid UTF-8.
	if err := cases.WriteLines(io.Discard, []cases.Line{line}); err != nil {
		return reasonTooLong
	}
	return ""
}
