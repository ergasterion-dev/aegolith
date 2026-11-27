package remote

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/report"
	"github.com/ergasterion-dev/aegolith/bench/internal/run"
)

// origin returns an original case as an importer gives it, with a path, a
// query, headers and a body of its own that are never sent.
func origin(t *testing.T, id, placement string, expected cases.Expected, payloads ...string) cases.Case {
	t.Helper()
	var all []cases.Case
	for _, p := range payloads {
		all = append(all, originLine(t, id, placement, expected, p))
	}
	if len(payloads) == 0 {
		all = append(all, originLine(t, id, placement, expected, ""))
	}
	merged, conflicts := cases.Merge(all)
	if len(merged) != 1 || len(conflicts) != 0 {
		t.Fatalf("fixture %s: %d merged", id, len(merged))
	}
	return merged[0]
}

func originLine(t *testing.T, id, placement string, expected cases.Expected, payload string) cases.Case {
	t.Helper()
	c, err := cases.FromLine(cases.Line{
		Name: id, Category: "cat-" + placement, Method: "PUT", Path: "/orig/" + id,
		Query:   [][]string{{"orig", "x"}},
		Headers: map[string]string{"Cookie": "session=orig", "X-Orig": "1"}, Body: "orig body",
		Source: "src", SourceCaseID: id, Expected: expected, Payload: payload,
		Placement: placement, Encoder: "URL",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func placeTarget() Target {
	t := validTarget()
	t.Allow = []Entry{
		{Method: "GET", Path: "/search", Placements: []string{"query:q", "query:term"}, BenignStatus: []int{200}},
		{Method: "GET", Path: "/list", Placements: []string{"query:s", "header:X-Note"}, BenignStatus: []int{200}},
		{Method: "POST", Path: "/api/notes", Placements: []string{"json:note", "header:X-Other"}, BenignStatus: []int{200},
			MayWriteData: true},
	}
	return t
}

func TestPlaceEachPayloadEachSlot(t *testing.T) {
	t.Parallel()
	c := origin(t, "a-1", "query", cases.Attack, "1' OR '1'='1", "<b>x</b>")
	placed, refused := Place(c, placeTarget())
	if len(refused) != 0 {
		t.Fatalf("refused %v", refused)
	}
	if len(placed) != 6 { // 2 payloads x (2 + 1) query slots
		t.Fatalf("placed %d requests, want 6", len(placed))
	}
	ids := map[string]bool{}
	for _, p := range placed {
		ids[p.ID] = true
		if len(p.Payloads) != 1 {
			t.Fatalf("placed case has %d payloads", len(p.Payloads))
		}
		if !slices.ContainsFunc(placeTarget().Allow, func(e Entry) bool { return e.Method == p.Method && e.Path == p.Path }) {
			t.Errorf("placed %s %s is not an allow entry", p.Method, p.Path)
		}
		if len(p.Headers) != 0 || len(p.Body) != 0 {
			t.Errorf("a query placement has headers %v or a body", p.Headers)
		}
		name, value, _ := strings.Cut(p.RawQuery, "=")
		decoded, err := url.QueryUnescape(value)
		if err != nil || decoded != string(p.Payloads[0]) || !slices.Contains([]string{"q", "term", "s"}, name) {
			t.Errorf("query %q does not carry the payload", p.RawQuery)
		}
		if strings.ContainsAny(value, "'<> ") {
			t.Errorf("query %q is not percent-encoded", p.RawQuery)
		}
		if p.Category != c.Category || p.Expected != c.Expected || p.Placement != "query" ||
			!slices.Equal(p.Sources, c.Sources) {
			t.Errorf("placed case lost a field of the original: %+v", p)
		}
		// The decoded payload is sent, not the original's encoding of it.
		if p.Encoder != PlacedEncoder {
			t.Errorf("placed case has encoder %q, want %q", p.Encoder, PlacedEncoder)
		}
		again, err := cases.FromLine(cases.Lines(p)[0])
		if err != nil || again.ID != p.ID {
			t.Errorf("placed ID %s is not the usual ID (%v)", p.ID[:8], err)
		}
	}
	if len(ids) != 6 {
		t.Errorf("%d distinct IDs, want 6", len(ids))
	}
}

func TestPlaceHeaderAndJSON(t *testing.T) {
	t.Parallel()
	payload := `<script>alert("x")</script>`
	headerCase := origin(t, "h-1", "header", cases.Attack, payload)
	placed, refused := Place(headerCase, placeTarget())
	if len(refused) != 0 || len(placed) != 2 {
		t.Fatalf("header: %d placed, refused %v", len(placed), refused)
	}
	for _, p := range placed {
		if len(p.Headers) != 1 || p.RawQuery != "" || len(p.Body) != 0 {
			t.Errorf("header placement sends %v, query %q, body %q", p.Headers, p.RawQuery, p.Body)
		}
		for name, value := range p.Headers {
			if value != payload || name != "X-Note" && name != "X-Other" {
				t.Errorf("header %s: %q", name, value)
			}
		}
	}

	jsonCase := origin(t, "j-1", "json", cases.Legit, payload)
	placed, refused = Place(jsonCase, placeTarget())
	if len(refused) != 0 || len(placed) != 1 {
		t.Fatalf("json: %d placed, refused %v", len(placed), refused)
	}
	p := placed[0]
	if p.Method != "POST" || p.Path != "/api/notes" || p.RawQuery != "" {
		t.Errorf("json placed at %s %s?%s", p.Method, p.Path, p.RawQuery)
	}
	if len(p.Headers) != 1 || p.Headers["Content-Type"] != "application/json" {
		t.Errorf("json headers %v", p.Headers)
	}
	var body map[string]string
	if err := json.Unmarshal(p.Body, &body); err != nil || len(body) != 1 || body["note"] != payload {
		t.Errorf("json body %q", p.Body)
	}
	if !bytes.Contains(p.Body, []byte("<script>")) {
		t.Errorf("json body %q escapes markup", p.Body)
	}
}

func TestNoPayloadInPath(t *testing.T) {
	t.Parallel()
	target := placeTarget()
	for _, c := range []cases.Case{
		origin(t, "p-1", "path", cases.Attack, "../../etc/passwd"),
		origin(t, "p-2", "query", cases.Attack, "/../admin"),
		origin(t, "p-3", "header", cases.Attack, "/..;/admin"),
		origin(t, "p-4", "json", cases.Attack, "%2e%2e/admin"),
	} {
		placed, _ := Place(c, target)
		for _, p := range placed {
			if !slices.ContainsFunc(target.Allow, func(e Entry) bool { return e.Path == p.Path && e.Method == p.Method }) {
				t.Errorf("%s: placed at %s %s", c.Sources[0].CaseID, p.Method, p.Path)
			}
		}
		if c.Placement == "path" && len(placed) != 0 {
			t.Errorf("a path payload was placed")
		}
	}
}

func TestPlaceRefuses(t *testing.T) {
	t.Parallel()
	target := placeTarget()
	queryOnly := placeTarget()
	queryOnly.Allow = queryOnly.Allow[:1]
	tests := []struct {
		name   string
		c      cases.Case
		target Target
		want   string
	}{
		{"no payload", origin(t, "r-1", "query", cases.Attack), target, ReasonNoPayload},
		{"path placement", origin(t, "r-2", "path", cases.Attack, "x"), target, ReasonPlacement},
		{"body placement", origin(t, "r-3", "body", cases.Attack, "x"), target, ReasonPlacement},
		{"raw placement", origin(t, "r-4", "raw", cases.Attack, "x"), target, ReasonPlacement},
		{"no placement", origin(t, "r-5", "", cases.Attack, "x"), target, ReasonPlacement},
		{"no entry of the kind", origin(t, "r-6", "json", cases.Attack, "x"), queryOnly, ReasonNoEntry},
		{"callback", origin(t, "r-7", "query", cases.Attack, "curl abc.oastify.com"), target, ReasonPublicHost},
		{"dev tcp", origin(t, "r-8", "query", cases.Attack, "/dev/tcp/198.51.100.7/80"), target, ReasonPublicHost},
		{"ping", origin(t, "r-9", "header", cases.Attack, "ping 8.8.8.8"), target, ReasonPublicHost},
		{"bare name", origin(t, "r-10", "json", cases.Legit, "see www.google.com"), target, ReasonPublicHost},
		{"mail", origin(t, "r-11", "json", cases.Legit, "write to a@mail.example.org"), target, ReasonPublicHost},
		{"ipv6", origin(t, "r-12", "query", cases.Attack, "http://[2001:db8::1]/"), target, ReasonPublicHost},
		{"line break in a header", origin(t, "r-13", "header", cases.Attack, "a\r\nX-Injected: 1"), target, ReasonHeaderValue},
		{"blank around a header", origin(t, "r-14", "header", cases.Attack, " a"), target, ReasonHeaderValue},
		{"nul in a header", origin(t, "r-15", "header", cases.Attack, "a\x00b"), target, ReasonHeaderValue},
		{"metadata address", origin(t, "r-20", "query", cases.Attack, "http://169.254.169.254/latest/meta-data/"), target, ReasonInternalHost},
		{"short link-local", origin(t, "r-21", "query", cases.Attack, "curl http://169.16689662/"), target, ReasonInternalHost},
		{"numeric link-local", origin(t, "r-22", "header", cases.Attack, "http://2852039166/"), target, ReasonInternalHost},
		{"quote-split link-local", origin(t, "r-23", "json", cases.Attack, "curl 169.254.'169'.254"), target, ReasonInternalHost},
		{"link-local ipv6", origin(t, "r-24", "query", cases.Attack, "http://[fe80::1]/"), target, ReasonInternalHost},
		{"aws ipv6 metadata", origin(t, "r-25", "query", cases.Attack, "http://[fd00:ec2::254]/"), target, ReasonInternalHost},
		{"gcp metadata name", origin(t, "r-26", "query", cases.Attack, "http://metadata.google.internal/computeMetadata/v1/"), target, ReasonInternalHost},
		{"azure wireserver", origin(t, "r-27", "json", cases.Attack, "ping 168.63.129.16"), target, ReasonInternalHost},
		{"alibaba metadata", origin(t, "r-28", "query", cases.Attack, "http://100.100.100.200/latest/meta-data/"), target, ReasonInternalHost},
	}
	for _, tc := range tests {
		placed, refused := Place(tc.c, tc.target)
		if len(placed) != 0 {
			t.Errorf("%s: placed %d", tc.name, len(placed))
		}
		if len(refused) != max(1, len(tc.c.Payloads)) || refused[0].Reason != tc.want {
			t.Errorf("%s: refused %+v, want reason %q", tc.name, refused, tc.want)
		}
	}

	binary := origin(t, "r-16", "json", cases.Attack)
	binary.Payloads = [][]byte{{0xff, 'a'}}
	placed, refused := Place(binary, target)
	if len(placed) != 0 || len(refused) != 1 || refused[0].Reason != ReasonNotUTF8 {
		t.Errorf("invalid UTF-8 in JSON: %d placed, refused %+v", len(placed), refused)
	}
	// Loopback and private addresses are sent: a route with a request
	// forgery bug would fetch them, which the README states.
	for i, payload := range []string{"http://127.0.0.1/admin", "http://10.0.0.5:8080/", "ping 192.168.1.1", "http://[::1]/"} {
		placed, refused := Place(origin(t, fmt.Sprintf("r-3%d", i), "query", cases.Attack, payload), target)
		if len(placed) == 0 || len(refused) != 0 {
			t.Errorf("%q: %d placed, refused %+v, want it placed", payload, len(placed), refused)
		}
	}
	// One payload refused, the other placed.
	mixed := origin(t, "r-17", "query", cases.Attack, "ok payload", "ping 8.8.8.8")
	placed, refused = Place(mixed, target)
	if len(placed) != 3 || len(refused) != 1 || string(refused[0].Payload) != "ping 8.8.8.8" {
		t.Errorf("mixed: %d placed, refused %+v", len(placed), refused)
	}
}

// payloadIn returns a payload made from format and a number that
// cases.Split puts in the wanted set.
func payloadIn(t *testing.T, split, format string) string {
	t.Helper()
	for i := 0; ; i++ {
		p := fmt.Sprintf(format, i)
		c := cases.Case{Sources: []cases.SourceRef{{Source: "src", CaseID: "x"}}, Payloads: [][]byte{[]byte(p)}}
		if cases.Split(c) == split {
			return p
		}
	}
}

func TestPrepare(t *testing.T) {
	t.Parallel()
	target := placeTarget()
	sendable := origin(t, "s-1", "json", cases.Attack, "plain payload")
	refusedOne := origin(t, "s-2", "query", cases.Attack, "good one", "ping 8.8.8.8")
	none := origin(t, "s-3", "query", cases.Attack)
	path := origin(t, "s-4", "path", cases.Attack, "../x")
	// The same placed request from two sources that disagree.
	conflictA := origin(t, "s-5", "json", cases.Attack, "same text")
	conflictB := origin(t, "s-6", "json", cases.Legit, "same text")
	// The same placed request from two sources that agree: sent once.
	twinA := origin(t, "s-7", "header", cases.Attack, "twin")
	twinB := origin(t, "s-8", "header", cases.Attack, "twin")
	originals := []cases.Case{sendable, refusedOne, none, path, conflictA, conflictB, twinA, twinB}

	plan, err := Prepare(originals, nil, target)
	if err != nil {
		t.Fatal(err)
	}
	// sendable 1, refusedOne 3 for "good one", twins 2 header slots.
	if len(plan.Send) != 6 {
		t.Errorf("%d cases to send, want 6", len(plan.Send))
	}
	if !slices.IsSortedFunc(plan.Send, func(a, b cases.Case) int { return strings.Compare(a.ID, b.ID) }) {
		t.Error("cases to send are not ordered by ID")
	}
	for _, c := range plan.Send {
		if c.Payloads[0][0] == 't' && len(c.Sources) != 2 {
			t.Errorf("twin request credits %d sources", len(c.Sources))
		}
	}
	if len(plan.Conflicts) != 2 {
		t.Errorf("%d conflicting cases, want 2", len(plan.Conflicts))
	}
	// Not sent: the refused payload of s-2, s-3, s-4, and s-5 and s-6, whose
	// only placement conflicts.
	results := plan.NotSentResults()
	if len(results) != len(plan.NotSent) || len(results) != 5 {
		t.Fatalf("%d not-sent results for %d cases, want 5", len(results), len(plan.NotSent))
	}
	reasons := map[string]bool{}
	for _, r := range results {
		if r.Outcome != run.NotSent || r.Reason == "" {
			t.Errorf("result %+v", r)
		}
		reasons[r.Reason] = true
	}
	for _, want := range []string{ReasonPublicHost, ReasonNoPayload, ReasonPlacement, ReasonConflict} {
		if !reasons[want] {
			t.Errorf("no case is not sent because %q", want)
		}
	}

	// The lines hold every source reference and every payload, and read back
	// as the same cases.
	lines := plan.Lines()
	var buf bytes.Buffer
	if err := cases.WriteLines(&buf, lines); err != nil {
		t.Fatal(err)
	}
	read, err := cases.ReadLines(&buf)
	if err != nil {
		t.Fatal(err)
	}
	var back []cases.Case
	for _, l := range read {
		c, err := cases.FromLine(l)
		if err != nil {
			t.Fatal(err)
		}
		back = append(back, c)
	}
	// The case file says how each line was sent: placed requests (the
	// conflicting ones included) decoded, cases not placed as the source
	// wrote them.
	sendIDs := map[string]bool{}
	for _, c := range slices.Concat(plan.Send, plan.Conflicts) {
		sendIDs[c.ID] = true
	}
	for i, c := range back {
		want := "URL"
		if sendIDs[c.ID] {
			want = PlacedEncoder
		}
		if read[i].Encoder != want {
			t.Errorf("line %d (placed %t) has encoder %q, want %q", i+1, sendIDs[c.ID], read[i].Encoder, want)
		}
	}
	merged, conflicts := cases.Merge(back)
	if len(merged) != len(plan.Send)+len(plan.NotSent) || len(conflicts) != len(plan.Conflicts) {
		t.Errorf("lines re-merge to %d cases and %d conflicts", len(merged), len(conflicts))
	}
	for _, o := range originals {
		for _, p := range o.Payloads {
			if !slices.ContainsFunc(back, func(c cases.Case) bool {
				return slices.Equal(c.Sources, o.Sources) && slices.ContainsFunc(c.Payloads, func(q []byte) bool { return bytes.Equal(p, q) })
			}) {
				t.Errorf("payload %q of %s is in no line", p, o.Sources[0].CaseID)
			}
		}
	}
}

// TestHeldOutOriginalNeverListed builds a report from what a run writes and
// checks that the name of a held-out case never appears, although one of its
// payloads is placed as a development case and missed.
func TestHeldOutOriginalNeverListed(t *testing.T) {
	t.Parallel()
	target := placeTarget()
	dev, held := payloadIn(t, cases.SplitDev, "dev payload %d"), payloadIn(t, cases.SplitHeldOut, "held payload %d")
	heldPublic := payloadIn(t, cases.SplitHeldOut, "held www.google.com %d")
	const secretName = "held-out-original-17"
	tests := map[string]cases.Case{
		// The held-out payload is placed too.
		"placed": origin(t, secretName, "json", cases.Attack, dev, held),
		// The held-out payload is refused.
		"refused": origin(t, secretName, "json", cases.Attack, dev, heldPublic),
	}
	conflictA := origin(t, secretName, "json", cases.Attack, dev, held)
	conflictB := origin(t, "other", "json", cases.Legit, held)
	for name, original := range tests {
		if cases.Split(original) != cases.SplitHeldOut {
			t.Fatalf("fixture: the original is %s", cases.Split(original))
		}
		check(t, name, target, []cases.Case{original}, secretName)
	}
	// The held-out payload's only placement conflicts with another source.
	conflictB.Sources[0].Source = "other-src"
	check(t, "conflict", target, []cases.Case{conflictA, conflictB}, secretName)
}

func check(t *testing.T, name string, target Target, originals []cases.Case, secretName string) {
	t.Helper()
	plan, err := Prepare(originals, nil, target)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var buf bytes.Buffer
	if err := cases.WriteLines(&buf, plan.Lines()); err != nil {
		t.Fatal(err)
	}
	read, err := cases.ReadLines(&buf)
	if err != nil {
		t.Fatal(err)
	}
	var cs []cases.Case
	for _, l := range read {
		c, err := cases.FromLine(l)
		if err != nil {
			t.Fatal(err)
		}
		cs = append(cs, c)
	}
	// Every sent case passed: each development attack is listed as missed.
	results := plan.NotSentResults()
	for _, c := range plan.Send {
		results = append(results, run.Result{CaseID: c.ID, Status: 200, Outcome: run.Passed})
	}
	config := report.BuildConfig("remote", cs, results)
	if len(config.Missed) == 0 {
		t.Fatalf("%s: fixture lists no missed case", name)
	}
	rendered := report.Report{Configs: []report.Config{config}}
	encoded, err := json.Marshal(rendered)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered.Markdown(), secretName) || strings.Contains(string(encoded), secretName) {
		t.Errorf("%s: the report names the held-out case", name)
	}
}

// TestPrepareRefusesToExposeHeldOut checks the last line of defence: when the
// only case that would hide a held-out name is left out as a conflict,
// Prepare fails instead.
func TestPrepareRefusesToExposeHeldOut(t *testing.T) {
	t.Parallel()
	dev := payloadIn(t, cases.SplitDev, "dev payload %d")
	heldPublic := payloadIn(t, cases.SplitHeldOut, "held www.google.com %d")
	original := origin(t, "x-1", "query", cases.Attack, dev, heldPublic)
	// An input conflict that sends the original's own request.
	other := originLine(t, "x-1", "query", cases.Legit, "")
	_, err := Prepare([]cases.Case{original}, []cases.Case{other}, placeTarget())
	if err == nil || !strings.Contains(err.Error(), "held-out") {
		t.Errorf("a plan that would name a held-out case was made (%v)", err)
	}
}
