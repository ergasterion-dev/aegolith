package run

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/bench/internal/records"
)

func TestClassifyTable(t *testing.T) {
	t.Parallel()
	arrived := &records.Access{ID: "r1", Method: "GET", Path: "/"}
	block := records.Decision{ID: "r1", Action: "block", Rules: []string{"AEG-SQLI-001"}}
	failClosed := records.Decision{ID: "r1", Action: "block", Rules: []string{}, Error: "inspection failed"}
	monitored := records.Decision{ID: "r1", Action: "allow", Monitored: true, Rules: []string{"AEG-ROUTE-001", "AEG-SQLI-001"}}
	routeOnly := records.Decision{ID: "r1", Action: "allow", Monitored: true, Rules: []string{"AEG-ROUTE-001", "AEG-ROUTE-002"}}
	faulted := records.Decision{ID: "r1", Action: "allow", Rules: []string{}, Error: "aegolith: internal error"}
	faultedMonitored := records.Decision{ID: "r1", Action: "allow", Monitored: true, Error: "aegolith: internal error"}
	faultedWithRules := records.Decision{ID: "r1", Action: "allow", Monitored: true, Rules: []string{"AEG-XSS-001"}, Error: "aegolith: internal error"}
	transport := errors.New("broken")

	tests := []struct {
		name    string
		status  int
		sendErr error
		access  *records.Access
		ds      []records.Decision
		want    Outcome
		reason  string // a part the reason must hold; empty means no reason
	}{
		{name: "client refused to encode", sendErr: &NotSentError{Reason: "a header is bad"}, want: NotSent, reason: "a header is bad"},
		{name: "refusal wrapped", sendErr: fmt.Errorf("sending: %w", &NotSentError{Reason: "wrapped"}), want: NotSent, reason: "wrapped"},
		{name: "send error without a response", sendErr: transport, want: Unknown, reason: "no response"},
		{name: "send error beats a recorded block", sendErr: context.DeadlineExceeded, access: arrived, ds: []records.Decision{block}, want: Unknown, reason: "timed out"},
		{name: "send error with a response", status: 200, sendErr: transport, access: arrived, want: Passed},
		{name: "rejected 400", status: 400, want: Rejected, reason: "400"},
		{name: "rejected 414", status: 414, want: Rejected, reason: "414"},
		{name: "rejected 417", status: 417, want: Rejected, reason: "417"},
		{name: "rejected 431", status: 431, want: Rejected, reason: "431"},
		{name: "rejected 501", status: 501, want: Rejected, reason: "501"},
		{name: "rejected status with a decision but no access record", status: 400, ds: []records.Decision{block}, want: Rejected, reason: "400"},
		{name: "400 that arrived is not rejected", status: 400, access: arrived, want: Passed},
		{name: "no access record", status: 200, want: Unknown, reason: "access record"},
		{name: "no access record despite a block", status: 403, ds: []records.Decision{block}, want: Unknown, reason: "access record"},
		{name: "block", status: 403, access: arrived, ds: []records.Decision{block}, want: Blocked},
		{name: "fail-closed block", status: 403, access: arrived, ds: []records.Decision{failClosed}, want: Blocked, reason: "inspection error"},
		{name: "any block among several", status: 403, access: arrived, ds: []records.Decision{routeOnly, block}, want: Blocked},
		{name: "monitored with a content rule", status: 200, access: arrived, ds: []records.Decision{monitored}, want: Flagged},
		{name: "monitored with route rules only", status: 200, access: arrived, ds: []records.Decision{routeOnly}, want: RouteOnly},
		{name: "route-only and content records", status: 200, access: arrived, ds: []records.Decision{routeOnly, monitored}, want: Flagged},
		{name: "fault without rules", status: 200, access: arrived, ds: []records.Decision{faulted}, want: Unknown, reason: "inspection error"},
		{name: "monitored fault without rules", status: 200, access: arrived, ds: []records.Decision{faultedMonitored}, want: Unknown, reason: "inspection error"},
		{name: "fault with rules", status: 200, access: arrived, ds: []records.Decision{faultedWithRules}, want: Flagged},
		{name: "403 without a decision", status: 403, access: arrived, want: Unknown, reason: "403"},
		{name: "passed", status: 200, access: arrived, want: Passed},
		{name: "passed with another status", status: 404, access: arrived, want: Passed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, reason := Classify(tt.status, tt.sendErr, tt.access, tt.ds)
			if got != tt.want {
				t.Errorf("outcome = %q (%s), want %q", got, reason, tt.want)
			}
			if tt.reason == "" && reason != "" {
				t.Errorf("reason = %q, want none", reason)
			}
			if !strings.Contains(reason, tt.reason) {
				t.Errorf("reason = %q, want it to hold %q", reason, tt.reason)
			}
		})
	}
}

func TestJoin(t *testing.T) {
	t.Parallel()
	sent := []Result{
		{CaseID: "a", RequestID: "p-a", Status: 403, LatencyUS: 900},
		{CaseID: "b", RequestID: "p-b", Status: 200, LatencyUS: 800},
		{CaseID: "c", RequestID: "p-c", Outcome: NotSent, Reason: "refused"},
		{CaseID: "d", RequestID: "p-d", Reason: "no response: timed out"},
		{CaseID: "e", RequestID: "p-e", Status: 501},
		{CaseID: "f", RequestID: "p-f"},
	}
	before := append([]Result(nil), sent...)
	access := map[string]records.Access{}
	for _, id := range []string{"p-a", "p-b", "p-c", "p-d", "p-f"} {
		access[id] = records.Access{ID: id, Method: "GET"}
	}
	block := func(id string, rules ...string) []records.Decision {
		return []records.Decision{{ID: id, Action: "block", Rules: rules, LatencyUS: 7}}
	}
	ds := map[string][]records.Decision{
		"p-a": append(block("p-a", "AEG-XSS-001", "AEG-SQLI-001"), block("p-a", "AEG-SQLI-001")...),
		"p-c": block("p-c", "AEG-SQLI-001"),
		"p-d": block("p-d", "AEG-SQLI-001"),
		"p-f": block("p-f", "AEG-SQLI-001"),
	}

	got := Join(sent, access, ds)

	want := []Result{
		{CaseID: "a", RequestID: "p-a", Status: 403, Outcome: Blocked, Rules: []string{"AEG-SQLI-001", "AEG-XSS-001"}, LatencyUS: 900},
		{CaseID: "b", RequestID: "p-b", Status: 200, Outcome: Passed, LatencyUS: 800},
		{CaseID: "c", RequestID: "p-c", Outcome: NotSent, Reason: "refused"},
		{CaseID: "d", RequestID: "p-d", Outcome: Unknown, Reason: "no response: timed out", Rules: []string{"AEG-SQLI-001"}},
		{CaseID: "e", RequestID: "p-e", Status: 501, Outcome: Rejected},
		{CaseID: "f", RequestID: "p-f", Outcome: Unknown, Rules: []string{"AEG-SQLI-001"}},
	}
	if len(got) != len(want) {
		t.Fatalf("%d results, want %d", len(got), len(want))
	}
	for i := range want {
		g := got[i]
		// Reasons that Join makes itself are Classify's; only their presence
		// is checked here.
		if i == 4 || i == 5 {
			if g.Reason == "" {
				t.Errorf("result %s has no reason", g.CaseID)
			}
			g.Reason = ""
		}
		if !reflect.DeepEqual(g, want[i]) {
			t.Errorf("result %d = %+v, want %+v", i, g, want[i])
		}
	}
	if !reflect.DeepEqual(sent, before) {
		t.Error("Join changed its input")
	}
}
