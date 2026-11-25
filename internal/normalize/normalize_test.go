package normalize

import (
	"bytes"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

func TestDecodeValue(t *testing.T) {
	tests := []struct {
		in     string
		want   string
		double bool
	}{
		{"1%27%20OR", "1' OR", false},
		{"%252e%252e%252f", "%2e%2e%2f", true},
		{"50% off", "50% off", false},
		{"a+b", "a+b", false},
		{"%zz%4", "%zz%4", false},
		{"%2527", "%27", true},
		{"%2541", "%41", false},
		{"", "", false},
	}
	for _, tc := range tests {
		got, dbl := DecodeValue(tc.in)
		if got != tc.want || dbl != tc.double {
			t.Errorf("DecodeValue(%q) = %q,%v want %q,%v", tc.in, got, dbl, tc.want, tc.double)
		}
	}
}

func TestParseQueryOrderAndPlus(t *testing.T) {
	got := ParseQuery("q=milk+%26+bread&q=x")
	want := []KV{{"q", "milk & bread"}, {"q", "x"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseQueryTolerant(t *testing.T) {
	got := ParseQuery("a&b=&=c&&d=50%&e=%zz")
	want := []KV{{"a", ""}, {"b", ""}, {"", "c"}, {"d", "50%"}, {"e", "%zz"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if ParseQuery("") != nil {
		t.Fatal("empty query should yield nil")
	}
}

func TestParseForm(t *testing.T) {
	got := ParseForm([]byte("user=a%40b.c&note=hi+there"))
	want := []KV{{"user", "a@b.c"}, {"note", "hi there"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseCookies(t *testing.T) {
	h := http.Header{}
	h.Add("Cookie", "sid=abc123; theme=dark")
	h.Add("Cookie", "x=1")
	got := ParseCookies(h)
	want := []KV{{"sid", "abc123"}, {"theme", "dark"}, {"x", "1"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if len(ParseCookies(http.Header{})) != 0 {
		t.Fatal("no cookies expected")
	}
}

func TestParseCookiesNoEvasion(t *testing.T) {
	h := http.Header{}
	h.Add("Cookie", `a=x\y; b=ok; c=café`)
	h.Add("Cookie", `bad name=1; q="quoted"; flag; =v; ;e=1=2`)
	got := ParseCookies(h)
	want := []KV{{"a", `x\y`}, {"b", "ok"}, {"c", "café"}, {"bad name", "1"}, {"q", "quoted"}, {"flag", ""}, {"", "v"}, {"e", "1=2"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	h = http.Header{"Cookie": {`a=1' OR 1=1--\`}}
	if got := ParseCookies(h); len(got) != 1 || got[0].Value != `1' OR 1=1--\` {
		t.Fatalf("payload dropped: %q", got)
	}
}

func collect(body string, lim model.Limits) ([]JSONValue, error) {
	var out []JSONValue
	err := WalkJSON([]byte(body), lim, func(v JSONValue) { out = append(out, v) })
	return out, err
}

func TestWalkJSONPaths(t *testing.T) {
	got, err := collect(`{"a":{"b":["x",1,true]},"c":"y"}`, model.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	want := []JSONValue{
		{IsContainer: true},
		{Path: "a", Key: "a", Value: "a", IsString: true, IsKey: true},
		{Path: "a", Key: "a", IsContainer: true},
		{Path: "a.b", Key: "b", Value: "b", IsString: true, IsKey: true},
		{Path: "a.b", Key: "b", IsContainer: true},
		{Path: "a.b[]", Key: "", Value: "x", IsString: true},
		{Path: "a.b[]", Key: "", Value: "1"},
		{Path: "a.b[]", Key: "", Value: "true"},
		{Path: "c", Key: "c", Value: "c", IsString: true, IsKey: true},
		{Path: "c", Key: "c", Value: "y", IsString: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestWalkJSONNestedArrayOfObjects(t *testing.T) {
	got, err := collect(`{"items":[{"sku":"A"},{"sku":"B"}],"n":null}`, model.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, v := range got {
		if !v.IsKey && !v.IsContainer {
			paths = append(paths, v.Path+"="+v.Value)
		}
	}
	want := []string{"items[].sku=A", "items[].sku=B"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("got %v want %v", paths, want)
	}
}

func TestWalkJSONKeyEqualsValue(t *testing.T) {
	got, err := collect(`{"a":"a"}`, model.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	want := []JSONValue{
		{IsContainer: true},
		{Path: "a", Key: "a", Value: "a", IsString: true, IsKey: true},
		{Path: "a", Key: "a", Value: "a", IsString: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

func TestWalkJSONContainers(t *testing.T) {
	got, err := collect(`{"q":[],"o":{},"n":null,"l":[[1]]}`, model.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var containers []string
	for _, v := range got {
		if v.IsContainer {
			containers = append(containers, v.Path)
		}
	}
	want := []string{"", "q", "o", "l", "l[]"}
	if !reflect.DeepEqual(containers, want) {
		t.Fatalf("containers at %q want %q", containers, want)
	}
}

func TestWalkJSONPathBounds(t *testing.T) {
	lim := model.DefaultLimits()
	long := strings.Repeat("k", 300)
	got, err := collect(`{"`+long+`":{"b":1}}`, lim)
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if want := strings.Repeat("k", 256) + ".b"; last.Path != want {
		t.Fatalf("path %q... (%d bytes), want 256-byte segment + .b", last.Path[:10], len(last.Path))
	}
	if got[1].Key != long || got[1].Value != long || !got[1].IsKey {
		t.Fatalf("full key not reported: %+v", got[1])
	}
	// 30 levels of 300-byte keys: the path stops growing at 1 KiB.
	var b strings.Builder
	for range 30 {
		b.WriteString(`{"` + long + `":`)
	}
	b.WriteString("1" + strings.Repeat("}", 30))
	got, err = collect(b.String(), lim)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range got {
		if len(v.Path) > 1024 {
			t.Fatalf("path %d bytes", len(v.Path))
		}
	}
	// Once the path is full, containers, closes and keys that leave its
	// bytes unchanged reuse the same string instead of copying it; so do
	// siblings that rebuild an identical path.
	prefix := strings.Repeat(`{"`+long+`":`, 5)
	for name, inner := range map[string]string{
		"arrays":  `[[],[],[[]],[]]`,
		"objects": `[{"a":1},{"a":2},{"a":3}]`,
		"keys":    `{"a":1,"a":2,"a":3}`,
	} {
		var data []*byte
		err := WalkJSON([]byte(prefix+inner+strings.Repeat("}", 5)), lim, func(v JSONValue) {
			if len(v.Path) == 1024 {
				data = append(data, unsafe.StringData(v.Path))
			}
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(data) < 4 {
			t.Fatalf("%s: %d full-path emissions", name, len(data))
		}
		for _, p := range data[1:] {
			if p != data[0] {
				t.Fatalf("%s: full path copied again", name)
			}
		}
	}
	// Below the cap, a sibling with an identical path also reuses it.
	var data []*byte
	if err := WalkJSON([]byte(`{"x":[{"a":1},{"a":2},{"a":3}]}`), lim, func(v JSONValue) {
		if v.Path == "x[].a" {
			data = append(data, unsafe.StringData(v.Path))
		}
	}); err != nil {
		t.Fatal(err)
	}
	for _, p := range data[1:] {
		if p != data[0] {
			t.Fatal("identical sibling path copied again")
		}
	}
	// Leaving a capped level restores the parent path exactly.
	got, err = collect(`{"`+long+`":{"x":1},"c":2}`, lim)
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Path != "c" || last.Value != "2" {
		t.Fatalf("after capped key: %+v", last)
	}
}

func TestWalkJSONScalarAndEmpty(t *testing.T) {
	got, err := collect(`"abc"`, model.DefaultLimits())
	if err != nil || !reflect.DeepEqual(got, []JSONValue{{Value: "abc", IsString: true}}) {
		t.Fatalf("scalar: %+v %v", got, err)
	}
	for _, body := range []string{"", "  \n"} {
		got, err = collect(body, model.DefaultLimits())
		if err != nil || len(got) != 0 {
			t.Fatalf("empty %q: %+v %v", body, got, err)
		}
	}
}

func TestWalkJSONLimits(t *testing.T) {
	lim := model.DefaultLimits()

	deep := strings.Repeat("[", 10000)
	start := time.Now()
	_, err := collect(deep, lim)
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("depth: got %v want ErrLimit", err)
	}
	if d, lim := time.Since(start), wallLimit(50*time.Millisecond, 2*time.Second); !testing.Short() && d > lim {
		t.Fatalf("depth rejection took %v", d)
	}

	// Exactly MaxDepth levels is allowed; one more is not.
	ok := strings.Repeat("[", lim.MaxDepth) + strings.Repeat("]", lim.MaxDepth)
	if _, err := collect(ok, lim); err != nil {
		t.Fatalf("depth==max: %v", err)
	}
	over := strings.Repeat("[", lim.MaxDepth+1) + strings.Repeat("]", lim.MaxDepth+1)
	if _, err := collect(over, lim); !errors.Is(err, ErrLimit) {
		t.Fatalf("depth>max: %v", err)
	}

	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < 100000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"k%d":1`, i)
	}
	b.WriteString("}")
	got, err := collect(b.String(), lim)
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("fields: got %v want ErrLimit", err)
	}
	counted := 0
	for _, v := range got {
		if !v.IsContainer {
			counted++
		}
	}
	if counted != lim.MaxFields {
		t.Fatalf("emitted %d keys and values, want exactly %d", counted, lim.MaxFields)
	}
	// Containers do not count toward MaxFields.
	small := model.Limits{MaxDepth: 32, MaxFields: 2}
	if _, err := collect(`[[[[{"a":1}]]]]`, small); err != nil {
		t.Fatalf("containers counted: %v", err)
	}
}

func TestWalkJSONMalformed(t *testing.T) {
	got, err := collect(`{"a":"x",`, model.DefaultLimits())
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v want ErrMalformed", err)
	}
	found := false
	for _, v := range got {
		if v.Value == "x" {
			found = true
		}
	}
	if !found {
		t.Fatalf("x not emitted: %+v", got)
	}
	for _, body := range []string{`{"a":1} {"b":2}`, `[1,2`, `{"a" 1}`, `}`} {
		if _, err := collect(body, model.DefaultLimits()); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: got %v want ErrMalformed", body, err)
		}
	}
}

func buildMultipart(t *testing.T, fn func(w *multipart.Writer)) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fn(w)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), w.FormDataContentType()
}

func TestParseMultipartSkipsFiles(t *testing.T) {
	body, ct := buildMultipart(t, func(w *multipart.Writer) {
		_ = w.WriteField("title", "hello")
		fw, _ := w.CreateFormFile("upload", "a.txt")
		_, _ = fw.Write([]byte("file contents"))
	})
	got, err := ParseMultipart(body, ct, model.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	want := []Part{{Name: "title", Value: "hello"}, {Name: "upload", IsFile: true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

func TestParseMultipartQuotedPrintable(t *testing.T) {
	body, ct := buildMultipart(t, func(w *multipart.Writer) {
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", `form-data; name="title"`)
		h.Set("Content-Transfer-Encoding", "quoted-printable")
		pw, _ := w.CreatePart(h)
		_, _ = pw.Write([]byte("=3Cscript=3Ealert(1)=3C/script=3E"))
		h = textproto.MIMEHeader{}
		h.Set("Content-Disposition", `form-data; name="up"; filename="a.html"`)
		h.Set("Content-Transfer-Encoding", "quoted-printable")
		pw, _ = w.CreatePart(h)
		_, _ = pw.Write([]byte("=3Cscript=3E"))
	})
	got, err := ParseMultipart(body, ct, model.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	want := []Part{{Name: "title", Value: "<script>alert(1)</script>"}, {Name: "up", IsFile: true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

func TestParseMultipartBounds(t *testing.T) {
	lim := model.DefaultLimits()
	lim.MaxValueLen = 5
	body, ct := buildMultipart(t, func(w *multipart.Writer) { _ = w.WriteField("f", "0123456789") })
	got, err := ParseMultipart(body, ct, lim)
	if err != nil || len(got) != 1 || got[0].Value != "01234" || !got[0].Truncated {
		t.Fatalf("value cap: %+v %v", got, err)
	}

	body, ct = buildMultipart(t, func(w *multipart.Writer) { _ = w.WriteField("f", "01234") })
	got, err = ParseMultipart(body, ct, lim)
	if err != nil || len(got) != 1 || got[0].Value != "01234" || got[0].Truncated {
		t.Fatalf("exact-length value must not be truncated: %+v %v", got, err)
	}

	lim = model.DefaultLimits()
	lim.MaxFields = 3
	body, ct = buildMultipart(t, func(w *multipart.Writer) {
		for i := 0; i < 10; i++ {
			_ = w.WriteField(fmt.Sprintf("f%d", i), "v")
		}
	})
	if _, err := ParseMultipart(body, ct, lim); !errors.Is(err, ErrLimit) {
		t.Fatalf("parts: got %v want ErrLimit", err)
	}
}

func TestParseMultipartErrors(t *testing.T) {
	lim := model.DefaultLimits()
	if _, err := ParseMultipart([]byte("x"), "text/plain", lim); err == nil {
		t.Fatal("non-multipart content type should error")
	}
	if _, err := ParseMultipart([]byte("x"), "multipart/form-data", lim); err == nil {
		t.Fatal("missing boundary should error")
	}
}

// An input that just ends early is ErrTruncated (which is also
// ErrMalformed); a syntax error is ErrMalformed only.
func TestWalkJSONTruncated(t *testing.T) {
	lim := model.DefaultLimits()
	for _, in := range []string{`{"a":"x`, `{"a":1,`, `[1,2`, `{"a":tr`, `{"a"`, `{`} {
		err := WalkJSON([]byte(in), lim, func(JSONValue) {})
		if !errors.Is(err, ErrTruncated) || !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v, want ErrTruncated", in, err)
		}
	}
	for _, in := range []string{`{"a":1,,"b":2}`, `{"a":1}x`, `{"a":1]`, `{"a":tx}`} {
		err := WalkJSON([]byte(in), lim, func(JSONValue) {})
		if !errors.Is(err, ErrMalformed) || errors.Is(err, ErrTruncated) {
			t.Errorf("%q: %v, want ErrMalformed only", in, err)
		}
	}
}

// Every prefix of a valid multipart body either parses or fails with
// ErrIncomplete (the input ended inside the last part, content or header
// block); real errors do not wrap ErrIncomplete.
func TestParseMultipartIncomplete(t *testing.T) {
	const ct = "multipart/form-data; boundary=XB"
	lim := model.Limits{MaxFields: 100, MaxValueLen: 1 << 20}
	for _, full := range []string{
		"--XB\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhello\r\n--XB\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x\"\r\n\r\n" +
			strings.Repeat("z", 64) + "\r\n--XB\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nvalue\r\n--XB--\r\n",
		"preamble\r\n--XB\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--XB--\r\n",
	} {
		for i := 1; i <= len(full); i++ {
			_, err := ParseMultipart([]byte(full[:i]), ct, lim)
			if err != nil && !errors.Is(err, ErrIncomplete) {
				t.Errorf("prefix %d %q: %v, want nil or ErrIncomplete", i, full[:i], err)
			}
		}
	}
	for name, body := range map[string]string{
		"bad header first part":            "--XB\r\nno colon\r\n\r\nx\r\n--XB\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--XB--\r\n",
		"bad header, then incomplete last": "--XB\r\nno colon\r\n\r\nx\r\n--XB\r\nContent-Disp",
		"bad header in complete last":      "--XB\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--XB\r\nno colon\r\n\r\ny",
	} {
		_, err := ParseMultipart([]byte(body), ct, lim)
		if err == nil || errors.Is(err, ErrIncomplete) {
			t.Errorf("%s: %v, want a malformed error without ErrIncomplete", name, err)
		}
	}
}
