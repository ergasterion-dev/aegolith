package report

// These tests hold what the report says about the firewall against the library
// itself, so that a change there cannot leave a sentence behind.

import (
	"encoding/base64"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith"
)

const injection = "1' OR '1'='1"

func inspect(t *testing.T, cfg aegolith.Config, r aegolith.Request) []string {
	t.Helper()
	fw, err := aegolith.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Method == "" {
		r.Method, r.RawPath = http.MethodPost, "/x"
	}
	var ids []string
	for _, m := range fw.Inspect(&r).Matches {
		ids = append(ids, m.RuleID)
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// Every rule the library names belongs to a family the report knows, so that
// "a content rule" cannot silently miss or take in a new kind of rule.
func TestEveryRuleOfTheLibraryHasAFamily(t *testing.T) {
	t.Parallel()
	id := regexp.MustCompile(`"AEG-([A-Z]+)-[0-9]+"`)
	found := map[string]bool{}
	root := filepath.Join("..", "..", "..")
	for _, dir := range []string{filepath.Join(root, "internal")} {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			source, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range id.FindAllStringSubmatch(string(source), -1) {
				found[m[1]] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	known := append(slices.Clone(contentFamilies), familyProtocol, familyRoute, familySchema, familyScanner)
	for family := range found {
		if !slices.Contains(known, family) {
			t.Errorf("the library has rules of family %q, which the report does not know", family)
		}
	}
	for _, family := range known {
		if !found[family] {
			t.Errorf("the report knows family %q, of which the library names no rule", family)
		}
	}
}

func TestClaimsAboutContentTypes(t *testing.T) {
	t.Parallel()
	body := []byte("<a>" + injection + "</a>")
	request := func(contentType string) aegolith.Request {
		return aegolith.Request{Method: http.MethodPost, RawPath: "/x",
			Header: http.Header{"Content-Type": {contentType}}, Body: body}
	}
	// The first blocking match ends the inspection: a refused body is not read.
	for _, contentType := range []string{"application/xml", "text/plain", "application/soap+xml"} {
		if got := inspect(t, aegolith.Config{}, request(contentType)); !slices.Equal(got, []string{"AEG-PROTO-002"}) {
			t.Errorf("%s by default: rules %v, want the refusal alone", contentType, got)
		}
	}
	// Allowed text and XML bodies are read; an allowed binary type is not.
	allowed := aegolith.Config{AllowXML: true,
		AllowedContentTypes: []string{"text/plain", "application/soap+xml", "application/octet-stream"}}
	for _, contentType := range []string{"application/xml", "text/plain", "application/soap+xml"} {
		if got := inspect(t, allowed, request(contentType)); !slices.Contains(got, "AEG-SQLI-001") ||
			slices.Contains(got, "AEG-PROTO-002") {
			t.Errorf("%s when allowed: rules %v, want the injection", contentType, got)
		}
	}
	if got := inspect(t, allowed, request("application/octet-stream")); len(got) != 0 {
		t.Errorf("an allowed binary type: rules %v, want none", got)
	}
}

func TestClaimsAboutHeaders(t *testing.T) {
	t.Parallel()
	request := func(name, value string) aegolith.Request {
		return aegolith.Request{Method: http.MethodGet, RawPath: "/x", Header: http.Header{name: {value}}}
	}
	for _, tt := range []struct{ name, value string }{
		{"User-Agent", injection}, {"Referer", injection}, {"Cookie", "c=" + injection},
	} {
		if got := inspect(t, aegolith.Config{}, request(tt.name, tt.value)); !slices.Contains(got, "AEG-SQLI-001") {
			t.Errorf("%s by default: rules %v, want the injection", tt.name, got)
		}
	}
	if got := inspect(t, aegolith.Config{}, request("User-Agent", "sqlmap/1.0")); !slices.Equal(got,
		[]string{"AEG-SCANNER-001"}) {
		t.Errorf("a scanner's name: rules %v", got)
	}
	metadata := "http://169.254.169.254/latest/meta-data/"
	if got := inspect(t, aegolith.Config{}, request("Referer", metadata)); slices.ContainsFunc(got,
		func(id string) bool { return strings.HasPrefix(id, "AEG-SSRF-") }) {
		t.Errorf("an internal URL in Referer: rules %v, want no SSRF", got)
	}
	// Any other header is read only when the configuration names it.
	other := request("X-Api-Version", injection)
	if got := inspect(t, aegolith.Config{}, other); len(got) != 0 {
		t.Errorf("another header by default: rules %v, want none", got)
	}
	named := aegolith.Config{InspectHeaders: []string{"X-Api-Version"}}
	if got := inspect(t, named, other); !slices.Contains(got, "AEG-SQLI-001") {
		t.Errorf("a named header: rules %v, want the injection", got)
	}
	if got := inspect(t, aegolith.Config{}, request("X-Other", "a\r\nb")); !slices.Equal(got,
		[]string{"AEG-PROTO-004"}) {
		t.Errorf("a line break in another header: rules %v", got)
	}
	// The example policy of the repository names the header the report names.
	policy, err := aegolith.LoadConfig(filepath.Join("..", "..", "..", "testdata", "corpus", "example-api-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(policy.InspectHeaders, []string{"X-Api-Version"}) {
		t.Errorf("the example policy inspects %v", policy.InspectHeaders)
	}
}

func TestClaimsAboutBase64(t *testing.T) {
	t.Parallel()
	query := func(value string) aegolith.Request {
		return aegolith.Request{Method: http.MethodGet, RawPath: "/x", RawQuery: "q=" + value}
	}
	if got := inspect(t, aegolith.Config{}, query("1%27%20OR%20%271%27%3D%271")); !slices.Contains(got, "AEG-SQLI-001") {
		t.Errorf("the plain injection: rules %v", got)
	}
	encoded := base64.RawURLEncoding.EncodeToString([]byte(injection))
	if got := inspect(t, aegolith.Config{}, query(encoded)); len(got) != 0 {
		t.Errorf("the injection in base64: rules %v, want none", got)
	}
	declared := func(typ string) aegolith.Config {
		return aegolith.Config{Routes: []aegolith.Route{{Method: http.MethodGet, Path: "/x",
			Query: map[string]aegolith.Field{"q": {Type: typ}}}}}
	}
	std := url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(injection)))
	for typ, value := range map[string]string{aegolith.TypeBase64: std, aegolith.TypeBase64URL: encoded} {
		if got := inspect(t, declared(typ), query(value)); !slices.Contains(got, "AEG-SQLI-001") {
			t.Errorf("the injection in a declared %s field: rules %v", typ, got)
		}
	}
}
