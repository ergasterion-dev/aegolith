package policy

import (
	"regexp"
	"strings"
	"testing"
)

const (
	canon      = "4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b"
	canonUpper = "4B8E2F1A-9C3D-4E5F-8A7B-1C2D3E4F5A6B"
	hex32      = "4b8e2f1a9c3d4e5f8a7b1c2d3e4f5a6b"
)

// uuidLenientAccept lists every form uuid_lenient accepts: the four
// encodings github.com/google/uuid's Parse (v1.6.0) takes, hex in any case.
var uuidLenientAccept = []string{
	canon,
	canonUpper,
	"4b8E2f1A-9c3D-4e5F-8a7B-1c2D3e4F5a6B",
	"00000000-0000-0000-0000-000000000000",
	"ffffffff-ffff-ffff-ffff-ffffffffffff",
	hex32,
	strings.ToUpper(hex32),
	"{" + canon + "}",
	"{" + canonUpper + "}",
	"urn:uuid:" + canon,
	"URN:UUID:" + canon,
	"Urn:Uuid:" + canonUpper,
}

// uuidLenientReject lists near misses and payloads uuid_lenient must refuse.
var uuidLenientReject = []string{
	"",
	"x",
	// Canonical form, broken.
	canon[:35],
	canon + "0",
	"4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6g",
	"4b8e2f1a_9c3d_4e5f_8a7b_1c2d3e4f5a6b",
	"4b8e2f1a-9c3d4-e5f-8a7b-1c2d3e4f5a6b",
	"4b8e2f1a--9c3d-4e5f-8a7b-1c2d3e4f5a6",
	"-4b8e2f1a9c3d-4e5f-8a7b-1c2d3e4f5a6b",
	"4b8e2f1a-9c3d-4e5f-8a7b1c2d3e4f5a6b-",
	"+4b8e2f1-9c3d-4e5f-8a7b-1c2d3e4f5a6b",
	"0x8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b",
	// 32 hex, broken.
	hex32[:31],
	hex32 + "0",
	hex32[:31] + "g",
	hex32[:31] + "-",
	"0x" + hex32[:30],
	// Whitespace, NUL and control bytes anywhere.
	" " + canon,
	canon + " ",
	canon + "\n",
	"\t" + hex32[1:],
	hex32[:31] + "\x00",
	"\x00" + canon[1:],
	canon[:35] + "\x00",
	"{" + canon + "}\x00",
	"{" + canon + "} ",
	" {" + canon + "}",
	"{ " + canon[1:] + "}",
	"urn:uuid: " + canon,
	"urn:uuid:" + canon + "\x00",
	"urn:uuid:" + canon[:35] + "\x00",
	" " + canon,
	// Braces: missing, mismatched, nested, other bracket pairs. Parse in
	// google/uuid v1.6.0 skips the two outer bytes of a 38-byte value
	// without looking at them; uuid_lenient requires exactly '{' and '}'.
	"{" + canon,
	canon + "}",
	"{" + canon + "{",
	"}" + canon + "{",
	"}" + canon + "}",
	"(" + canon + ")",
	"[" + canon + "]",
	"<" + canon + ">",
	"'" + canon + "'",
	`"` + canon + `"`,
	"x" + canon + "x",
	"{{" + canon + "}}",
	"{{" + canon[1:] + "}",
	"{" + canon[:35] + "}}",
	"{" + hex32 + "}",
	"{urn:uuid:" + canon + "}",
	"{}",
	// urn:uuid: prefix, broken or combined.
	"urn:uuid:" + hex32,
	"urn:uuid:{" + canon + "}",
	"urn:uuid:" + canon[:35],
	"urn:uuid:" + canon + "0",
	"urn:uuid;" + canon,
	"urn-uuid:" + canon,
	"urn:uid::" + canon,
	"xrn:uuid:" + canon,
	"uuid:" + canon,
	"urn:" + canon,
	"urn:uuid:urn:uuid:" + canon,
	"urn:uuid:",
	"urn:ﬀid:" + canon[:35], // non-ASCII bytes where the prefix should be
	// Attack payloads, including ones sized to the accepted lengths.
	"1' OR '1'='1",
	"' OR 1=1 -- -----------------------",          // 36 bytes
	"{' OR 1=1 -- -----------------------}",        // 38 bytes
	"urn:uuid:' OR 1=1 -- -----------------------", // 45 bytes
	"<script>alert(1)</script>xxxxxxxxxxx",         // 36 bytes
	"../../../../../../../etc/passwd/xxxx",         // 36 bytes
	"$(id)xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",         // 36 bytes
	"{\"$ne\":null}xxxxxxxxxxxxxxxxxxxxxxxxx",
	"4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b' OR '1'='1",
	"4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b;DROP",
	"4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b%00",
	"4b8e2f1a%2D9c3d-4e5f-8a7b-1c2d3e4f5a6b",
	strings.Repeat("a", 1<<20),
	strings.Repeat("{", 19) + strings.Repeat("}", 19),
}

func TestUUIDLenientAccepts(t *testing.T) {
	spec := FieldSpec{Type: TypeUUIDLenient}
	for _, v := range uuidLenientAccept {
		if !Validate(spec, v, true) {
			t.Errorf("uuid_lenient rejected %q", v)
		}
	}
}

func TestUUIDLenientRejects(t *testing.T) {
	spec := FieldSpec{Type: TypeUUIDLenient}
	for _, v := range uuidLenientReject {
		if Validate(spec, v, true) {
			t.Errorf("uuid_lenient accepted %q", trunc(v))
		}
	}
}

// TestUUIDStrictUnchanged pins the strict type: it accepts only the
// canonical 36-byte form, so every non-canonical form uuid_lenient adds is
// still a mismatch for "uuid".
func TestUUIDStrictUnchanged(t *testing.T) {
	strict := FieldSpec{Type: TypeUUID}
	for _, v := range uuidLenientAccept {
		want := len(v) == 36
		if got := Validate(strict, v, true); got != want {
			t.Errorf("uuid on %q = %v, want %v", v, got, want)
		}
	}
	for _, v := range uuidLenientReject {
		if Validate(strict, v, true) {
			t.Errorf("uuid accepted %q", trunc(v))
		}
	}
}

// uuidLenientOracle is an independent statement of the grammar, used as
// the reference in the fuzz test. Letters are spelled out rather than
// matched with (?i), whose Unicode folding could add non-ASCII matches.
var uuidLenientOracle = func() *regexp.Regexp {
	const h = `[0-9a-fA-F]`
	c := h + `{8}-` + h + `{4}-` + h + `{4}-` + h + `{4}-` + h + `{12}`
	return regexp.MustCompile(`^(?:` + c + `|` + h + `{32}|\{` + c + `\}|[uU][rR][nN]:[uU][uU][iI][dD]:` + c + `)$`)
}()

func TestUUIDLenientMatchesOracle(t *testing.T) {
	for _, v := range append(append([]string(nil), uuidLenientAccept...), uuidLenientReject...) {
		if got, want := isUUIDLenient(v), uuidLenientOracle.MatchString(v); got != want {
			t.Errorf("isUUIDLenient(%q) = %v, oracle %v", trunc(v), got, want)
		}
	}
}

// FuzzUUIDLenient: isUUIDLenient agrees with the regexp oracle, accepts
// every value the strict type accepts, and never accepts a value with a
// byte outside hex digits, '-', '{', '}' and the letters of "urn:uuid:".
func FuzzUUIDLenient(f *testing.F) {
	for _, v := range uuidLenientAccept {
		f.Add(v)
	}
	for _, v := range uuidLenientReject {
		if len(v) < 128 {
			f.Add(v)
		}
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := isUUIDLenient(s)
		if want := uuidLenientOracle.MatchString(s); got != want {
			t.Fatalf("isUUIDLenient(%q) = %v, oracle %v", s, got, want)
		}
		if isUUID(s) && !got {
			t.Fatalf("strict accepted %q but lenient did not", s)
		}
		if got {
			for i := range len(s) {
				if c := s[i]; !isHex(c) && !strings.ContainsRune("-{}:uUrRnNiIdD", rune(c)) {
					t.Fatalf("accepted %q with byte %q", s, c)
				}
			}
		}
	})
}

func trunc(v string) string {
	if len(v) > 60 {
		return v[:60] + "..."
	}
	return v
}
