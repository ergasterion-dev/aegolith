package detect

import (
	"testing"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

func TestJSONKey(t *testing.T) {
	nosql := Hit{RuleID: "AEG-NOSQL-001", Category: model.CatNoSQLi, Severity: model.SeverityHigh}
	assertHits(t, "JSONKey", JSONKey, nosql, []string{"$gt", "$where", "$ne", "$regex", "$"})
	ppoll := Hit{RuleID: "AEG-PPOLL-001", Category: model.CatProtoPollute, Severity: model.SeverityHigh}
	assertHits(t, "JSONKey", JSONKey, ppoll, []string{"__proto__", "constructor", "prototype"})
	assertNoKeyHits(t, "JSONKey", JSONKey, []string{
		"price", "email", "product_id", "qty", "line1", "note", "image_url",
		"cost$", "a$b", "Constructor", "proto", "__proto", "prototypes", "constructor_name", "",
	})
}

func TestQueryKey(t *testing.T) {
	want := Hit{RuleID: "AEG-NOSQL-002", Category: model.CatNoSQLi, Severity: model.SeverityHigh}
	assertHits(t, "QueryKey", QueryKey, want, []string{
		"[$ne]",
		"email[$ne]",
		"password[$gt]",
		"age[$gte]",
		"age[$lt]",
		"age[$lte]",
		"name[$regex]",
		"x[$where]",
		"id[$in][]",
		"id[$nin]",
		"f[$exists]",
		"[$anything]",
		"$where",
		"email%5B%24ne%5D",
		// any operator shape, not only a fixed list
		"a[$or][0][b]",
		"filter[$and]",
		"a[$size]",
		"a[$elemMatch][b]",
		"a[$eq]",
		"a[$expr]",
		"tags[$all][]",
	})
	assertNoKeyHits(t, "QueryKey", QueryKey, []string{
		"price", "page", "limit", "sort", "q", "items[]", "filter[name]", "a[0][b]", "cost$", "price[$5]x",
		"a[$]", "a[$ne", "tag[$100]", "note[$ 5]", "price[usd$]",
	})
}

func TestSession(t *testing.T) {
	want := Hit{RuleID: "AEG-SESSION-001", Category: model.CatSession, Severity: model.SeverityMedium}
	for _, kv := range [][2]string{
		{"q", "PHPSESSID=attacker-fixed-id"},
		{"redirect", "/home;jsessionid=ABC123"},
		{"x", "ASPSESSIONIDQASDBRCT=KJHGF"},
		{"PHPSESSID", "attacker-fixed-id"},
		{"jsessionid", "abc"},
		{"next", "/a?JSESSIONID=1"},
		{"ASPSESSIONIDQQ", "x"},
	} {
		hit, ok := Session(kv[0], kv[1])
		if !ok || hit != want {
			t.Errorf("Session(%q, %q) = %+v, %v; want %+v", kv[0], kv[1], hit, ok, want)
		}
	}
	for _, kv := range [][2]string{
		{"q", "milk"},
		{"session", "abc"},
		{"note", "My session id is lost"},
		{"phpsessid_hint", "x"},
		{"q", "PHPSESSID"},
		{"sid", "4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b"},
	} {
		if hit, ok := Session(kv[0], kv[1]); ok {
			t.Errorf("Session(%q, %q) = %+v, want no hit", kv[0], kv[1], hit)
		}
	}
}

// assertNoKeyHits is assertNoHits without the prose table: keys are names,
// and prose such as "$5 off" is not a realistic key.
func assertNoKeyHits(t *testing.T, name string, fn func(string) (Hit, bool), keys []string) {
	t.Helper()
	for _, k := range keys {
		if hit, ok := fn(k); ok {
			t.Errorf("%s(%q) = %+v, want no hit", name, k, hit)
		}
	}
}
