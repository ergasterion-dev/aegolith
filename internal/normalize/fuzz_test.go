package normalize

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

// FuzzWalkJSON: WalkJSON never panics, returns only nil, ErrLimit or
// ErrMalformed, agrees with json.Valid on syntax, respects MaxFields and
// keeps every Path within maxPath bytes.
func FuzzWalkJSON(f *testing.F) {
	for _, s := range []string{
		``, ` `, `{}`, `[]`, `null`, `1`, `"x"`, `true`,
		`{"a":1,"b":"x","c":[1,2,{"d":null}],"e":{"f":true}}`,
		`{"items":[{"sku":"A-1","qty":2},{"sku":"B-2","qty":1}]}`,
		`[[[[[[[[[[1]]]]]]]]]]`,
		`{"a":"\ud800","b":"\u0000","c":"\xff\xfe"}`,
		`{"a":1}{"b":2}`, `{"a" 1}`, `{"a":1,}`, `[1,]`, `{`, `"`,
		`{"` + strings.Repeat("k", 300) + `":{"` + strings.Repeat("k", 300) + `":1}}`,
		`{"$where":"1","__proto__":{"x":1}}`,
	} {
		f.Add([]byte(s), 8, 50)
	}
	f.Fuzz(func(t *testing.T, body []byte, depth, fields int) {
		lim := model.Limits{
			MaxBodyBytes: 1 << 20,
			MaxDepth:     1 + abs(depth)%64,
			MaxFields:    1 + abs(fields)%2000,
			MaxValueLen:  8 << 10,
		}
		scalars := 0
		err := WalkJSON(body, lim, func(v JSONValue) {
			if len(v.Path) > maxPath {
				t.Fatalf("path of %d bytes, max %d", len(v.Path), maxPath)
			}
			if !v.IsContainer {
				scalars++
			}
			if v.IsContainer && v.Value != "" {
				t.Fatalf("container with value %q", v.Value)
			}
		})
		if scalars > lim.MaxFields {
			t.Fatalf("%d fields emitted, MaxFields %d", scalars, lim.MaxFields)
		}
		blank := len(bytes.TrimSpace(body)) == 0
		switch {
		case err == nil:
			if !blank && !json.Valid(body) {
				t.Fatalf("walk accepted invalid JSON %q", body)
			}
		case errors.Is(err, ErrMalformed):
			if json.Valid(body) {
				t.Fatalf("walk rejected valid JSON %q as malformed", body)
			}
		case errors.Is(err, ErrLimit):
		default:
			t.Fatalf("unexpected error %v", err)
		}
	})
}

// FuzzDecodeValue: DecodeValue never panics, never grows its input, leaves
// strings without '%' alone, agrees with url.PathUnescape when every escape
// is valid, and flags double encoding only when an escape survives.
func FuzzDecodeValue(f *testing.F) {
	for _, s := range []string{
		``, `plain`, `a+b`, `%`, `%2`, `%zz`, `%41`, `%2541`, `%252e%252e%252f`,
		`%2e%2e%2fetc%2fpasswd`, `%3Cscript%3E`, `%00`, `%0d%0a`, `100%`, `%%41`,
		`%e2%80%ae`, `%ff%fe`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		dec, double := DecodeValue(s)
		if len(dec) > len(s) {
			t.Fatalf("decoded %q is longer than input %q", dec, s)
		}
		if !strings.Contains(s, "%") && (dec != s || double) {
			t.Fatalf("input without %% changed: %q -> %q (double %v)", s, dec, double)
		}
		if double && !strings.Contains(dec, "%") {
			t.Fatalf("double-encoded without a %% left in %q", dec)
		}
		if double != hasSuspiciousEscape(dec) {
			t.Fatalf("double %v disagrees with hasSuspiciousEscape(%q)", double, dec)
		}
		if ref, err := url.PathUnescape(s); err == nil && ref != dec {
			t.Fatalf("DecodeValue(%q) = %q, url.PathUnescape = %q", s, dec, ref)
		}
	})
}

func abs(n int) int {
	if n < 0 {
		if n == -n { // math.MinInt
			return 0
		}
		return -n
	}
	return n
}
