package model

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestActionJSONRoundTrip(t *testing.T) {
	b, err := json.Marshal(ActionMonitor)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"monitor"` {
		t.Fatalf("got %s", b)
	}
	var a Action
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	if a != ActionMonitor {
		t.Fatalf("got %v", a)
	}
}

func TestParseActionUnknown(t *testing.T) {
	if _, err := ParseAction("deny"); err == nil {
		t.Fatal("expected error")
	}
	for s, want := range map[string]Action{"allow": ActionAllow, "block": ActionBlock, "monitor": ActionMonitor} {
		got, err := ParseAction(s)
		if err != nil || got != want {
			t.Fatalf("%s: got %v, %v", s, got, err)
		}
	}
}

func TestModeJSONRoundTrip(t *testing.T) {
	for m, s := range map[Mode]string{ModeEnforce: `"enforce"`, ModeMonitor: `"monitor"`} {
		b, err := json.Marshal(m)
		if err != nil || string(b) != s {
			t.Fatalf("marshal %v: %s, %v", m, b, err)
		}
		var back Mode
		if err := json.Unmarshal(b, &back); err != nil || back != m {
			t.Fatalf("unmarshal %s: %v, %v", b, back, err)
		}
	}
	var m Mode
	if err := json.Unmarshal([]byte(`"off"`), &m); err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestDefaultLimits(t *testing.T) {
	l := DefaultLimits()
	if l.MaxBodyBytes != 1<<20 || l.MaxDepth != 32 || l.MaxFields != 1000 || l.MaxValueLen != 8192 {
		t.Fatalf("unexpected defaults: %+v", l)
	}
}

func TestRedact(t *testing.T) {
	if got := Redact(strings.Repeat("a", 100)); len(got) != 64 {
		t.Fatalf("len = %d", len(got))
	}
	if got := Redact("a\nb"); got != "a?b" {
		t.Fatalf("got %q", got)
	}
	// 63 ASCII bytes then a 3-byte rune straddling the 64-byte cut.
	got := Redact(strings.Repeat("a", 63) + "€€")
	if !utf8.ValidString(got) || len(got) > 64 || got != strings.Repeat("a", 63) {
		t.Fatalf("rune split or overlong: %q (%d)", got, len(got))
	}
	if got := Redact("x\u0085y\x00z"); got != "x?y?z" {
		t.Fatalf("got %q", got)
	}
	if got := Redact("a\xffb"); !utf8.ValidString(got) || len(got) > 64 {
		t.Fatalf("invalid utf-8 leaked: %q", got)
	}
	if Redact("") != "" {
		t.Fatal("empty")
	}
	// Line/paragraph separators and format (Cf) characters such as bidi
	// overrides can forge or reorder log lines.
	for in, want := range map[string]string{
		"a\u2028b":        "a?b",
		"a\u2029b":        "a?b",
		"x\u202eevil":     "x?evil",
		"\u2066a\u2069":   "?a?",
		"zero\u200bwidth": "zero?width",
		"bom\ufeff":       "bom?",
		"café اردو":       "café اردو",
	} {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q want %q", in, got, want)
		}
	}
}

func TestSafeName(t *testing.T) {
	long := strings.Repeat("k", 300)
	if got := SafeName(long); len(got) != 256 {
		t.Fatalf("len = %d", len(got))
	}
	if got := SafeName("a\nb\u202ec"); got != "a?b?c" {
		t.Fatalf("got %q", got)
	}
	if got := SafeName("items[].sku"); got != "items[].sku" {
		t.Fatalf("got %q", got)
	}
}

func TestMarshalInvalid(t *testing.T) {
	for _, v := range []any{Action(-1), Action(3), Mode(-1), Mode(2)} {
		if _, err := json.Marshal(v); err == nil {
			t.Errorf("marshal %v: expected error", v)
		}
	}
	if Action(7).String() != "unknown" || Mode(7).String() != "unknown" {
		t.Fatal("String of invalid value")
	}
}

func TestLimitsJSONTags(t *testing.T) {
	b, err := json.Marshal(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"max_body_bytes":1048576,"max_depth":32,"max_fields":1000,"max_value_len":8192}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
}
