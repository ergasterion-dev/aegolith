package policy

import "testing"

func TestDecodeBase64(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
		ok             bool
	}{
		{"empty", "", "", true},
		{"line breaks only", "\r\n", "", true},
		{"padded", "aGVsbG8=", "hello", true},
		{"two padding bytes", "aGVsbA==", "hell", true},
		{"unpadded", "aGVsbG8", "hello", true},
		{"no padding needed", "aGVs", "hel", true},
		{"CR and LF inside", "aGVs\r\nbG8=", "hello", true},
		{"CR and LF around padding", "aGVsbA\r\n=\n=\r\n", "hell", true},
		{"bare CR", "aGVs\rbG8", "hello", true},
		{"URL-safe", "-_8", "\xfb\xff", true},
		{"URL-safe padded", "-_8=", "\xfb\xff", true},
		{"standard", "+/8=", "\xfb\xff", true},
		{"unused trailing bits", "aGVsbG9=", "hello", true},
		{"mixed alphabets", "+_8", "", false},
		{"mixed alphabets apart", "-AAA/AAA", "", false},
		{"too much padding", "aGVsbG8==", "", false},
		{"data after padding", "aGVsbG8=x", "", false},
		{"too little padding", "aGVsbA=", "", false},
		{"padding on a whole group", "aGVs=", "", false},
		{"padding on one byte over", "a===", "", false},
		{"padding alone", "=", "", false},
		{"four padding bytes", "aGVs====", "", false},
		{"padding inside", "aG=sbG8", "", false},
		{"space", "aGVs bG8=", "", false},
		{"tab", "aGVs\tbG8=", "", false},
		{"asterisk", "aGVsbG8*", "", false},
		{"percent", "aGVsbG8%3D", "", false},
		{"NUL", "aGVs\x00bG8", "", false},
		{"non-ASCII", "aGVsbG8é", "", false},
		{"one byte over", "a", "", false},
		{"five bytes", "aGVsb", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := DecodeBase64(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Errorf("DecodeBase64(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
			}
			// The validator and the decoder share one grammar.
			if v := Validate(FieldSpec{Type: TypeBase64}, tc.in, true); v != tc.ok {
				t.Errorf("Validate(%q) = %v, want %v", tc.in, v, tc.ok)
			}
		})
	}
}

func TestValidateBase64(t *testing.T) {
	spec := FieldSpec{Type: TypeBase64, MaxLen: 8}
	if _, err := spec.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	// max_len bounds the encoded value: 8 characters hold 5 decoded bytes.
	if !Validate(spec, "aGVsbG8=", true) {
		t.Error("rejected a value of max_len characters")
	}
	if Validate(spec, "aGVsbG8gd29ybGQ=", true) {
		t.Error("accepted a value over max_len")
	}
	// A JSON number or null is not a base64 value, even when its text is.
	for _, v := range []string{"1234", "true", "null"} {
		if Validate(spec, v, false) {
			t.Errorf("accepted the JSON non-string %q", v)
		}
	}
}
