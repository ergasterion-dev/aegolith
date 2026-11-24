package normalize

import (
	"bytes"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/pylolith/internal/model"
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
		{Path: "a", Key: "a", Value: "a", IsString: true},
		{Path: "a.b", Key: "b", Value: "b", IsString: true},
		{Path: "a.b[]", Key: "", Value: "x", IsString: true},
		{Path: "a.b[]", Key: "", Value: "1"},
		{Path: "a.b[]", Key: "", Value: "true"},
		{Path: "c", Key: "c", Value: "c", IsString: true},
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
		if !v.IsString || v.Value != v.Key {
			paths = append(paths, v.Path+"="+v.Value)
		}
	}
	want := []string{"items[].sku=A", "items[].sku=B"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("got %v want %v", paths, want)
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
	if d := time.Since(start); d > 50*time.Millisecond {
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
	if len(got) != lim.MaxFields {
		t.Fatalf("emitted %d values, want exactly %d", len(got), lim.MaxFields)
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

func TestParseMultipartBounds(t *testing.T) {
	lim := model.DefaultLimits()
	lim.MaxValueLen = 5
	body, ct := buildMultipart(t, func(w *multipart.Writer) { _ = w.WriteField("f", "0123456789") })
	got, err := ParseMultipart(body, ct, lim)
	if err != nil || len(got) != 1 || got[0].Value != "01234" {
		t.Fatalf("value cap: %+v %v", got, err)
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
