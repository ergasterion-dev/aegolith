package policy

import "testing"

// base64Decoders pairs each base64 field type with its decoder.
var base64Decoders = map[string]func(string) (string, bool){
	TypeBase64:    DecodeBase64,
	TypeBase64URL: DecodeBase64URL,
}

func TestDecodeBase64(t *testing.T) {
	// std and url say whether base64 and base64url accept the input; an
	// accepting type returns want, a refusing one "".
	for _, tc := range []struct {
		name, in, want string
		std, url       bool
	}{
		{"empty", "", "", true, true},
		{"line breaks only", "\r\n", "", true, true},
		{"padded", "aGVsbG8=", "hello", true, true},
		{"two padding bytes", "aGVsbA==", "hell", true, true},
		{"unpadded", "aGVsbG8", "hello", true, true},
		{"no padding needed", "aGVs", "hel", true, true},
		{"CR and LF inside", "aGVs\r\nbG8=", "hello", true, true},
		{"CR and LF around padding", "aGVsbA\r\n=\n=\r\n", "hell", true, true},
		{"bare CR", "aGVs\rbG8", "hello", true, true},
		{"unused trailing bits", "aGVsbG9=", "hello", true, true},
		{"standard", "+/8=", "\xfb\xff", true, false},
		{"standard unpadded", "+/8", "\xfb\xff", true, false},
		{"plus", "aGVs+A", "hel\xf8", true, false},
		{"slash", "aGVs/A", "hel\xfc", true, false},
		{"URL-safe", "-_8", "\xfb\xff", false, true},
		{"URL-safe padded", "-_8=", "\xfb\xff", false, true},
		{"minus", "aGVs-A", "hel\xf8", false, true},
		{"underscore", "aGVs_A", "hel\xfc", false, true},
		{"underscores among letters", "M_ScgVU5___", "3\xf4\x9c\x81U9\xff\xff", false, true},
		{"mixed alphabets", "+_8", "", false, false},
		{"mixed alphabets apart", "-AAA/AAA", "", false, false},
		{"too much padding", "aGVsbG8==", "", false, false},
		{"data after padding", "aGVsbG8=x", "", false, false},
		{"too little padding", "aGVsbA=", "", false, false},
		{"padding on a whole group", "aGVs=", "", false, false},
		{"padding on one byte over", "a===", "", false, false},
		{"padding alone", "=", "", false, false},
		{"four padding bytes", "aGVs====", "", false, false},
		{"padding inside", "aG=sbG8", "", false, false},
		{"space", "aGVs bG8=", "", false, false},
		{"tab", "aGVs\tbG8=", "", false, false},
		{"asterisk", "aGVsbG8*", "", false, false},
		{"percent", "aGVsbG8%3D", "", false, false},
		{"NUL", "aGVs\x00bG8", "", false, false},
		{"non-ASCII", "aGVsbG8é", "", false, false},
		{"one byte over", "a", "", false, false},
		{"five bytes", "aGVsb", "", false, false},
	} {
		for typ, ok := range map[string]bool{TypeBase64: tc.std, TypeBase64URL: tc.url} {
			t.Run(typ+"/"+tc.name, func(t *testing.T) {
				want := ""
				if ok {
					want = tc.want
				}
				got, gotOK := base64Decoders[typ](tc.in)
				if gotOK != ok || got != want {
					t.Errorf("decode(%q) = %q, %v; want %q, %v", tc.in, got, gotOK, want, ok)
				}
				// The validator and the decoder share one grammar.
				if v := Validate(FieldSpec{Type: typ}, tc.in, true); v != ok {
					t.Errorf("Validate(%q) = %v, want %v", tc.in, v, ok)
				}
			})
		}
	}
}

func TestValidateBase64(t *testing.T) {
	for typ := range base64Decoders {
		t.Run(typ, func(t *testing.T) {
			spec := FieldSpec{Type: typ, MaxLen: 8}
			if _, err := spec.compile(); err != nil {
				t.Fatalf("compile: %v", err)
			}
			// max_len bounds the encoded value: 8 characters hold 5
			// decoded bytes.
			if !Validate(spec, "aGVsbG8=", true) {
				t.Error("rejected a value of max_len characters")
			}
			if Validate(spec, "aGVsbG8gd29ybGQ=", true) {
				t.Error("accepted a value over max_len")
			}
			// A JSON number or null is not a base64 value, even when its
			// text is.
			for _, v := range []string{"1234", "true", "null"} {
				if Validate(spec, v, false) {
					t.Errorf("accepted the JSON non-string %q", v)
				}
			}
		})
	}
}
