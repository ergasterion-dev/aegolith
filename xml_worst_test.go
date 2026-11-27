package aegolith_test

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith"
)

// xmlWorstBodies are in-limit (at most 1 MiB) XML bodies that make the walk
// do the most work per byte, each with an attack at the end. The costliest
// shapes read every value and then fail late, so the raw body is rescanned
// as well ("then a mismatched end tag", "then an error").
func xmlWorstBodies() map[string]string {
	const sql = `<q>1' UNION SELECT password FROM users--</q>`
	room := 1<<20 - 300
	return map[string]string{
		"tiny elements":      `<r>` + strings.Repeat(`<i>v</i>`, room/8) + sql + `</r>`,
		"empty elements":     `<r>` + strings.Repeat(`<i/>`, room/4) + sql + `</r>`,
		"comment-split text": `<r>` + strings.Repeat(`x<!---->`, room/8) + `</r>` + sql,
		"script elements":    `<r>` + strings.Repeat(`<script/>`, room/9) + sql + `</r>`,
		"attributes":         `<r` + strings.Repeat(` a="&lt;a "`, room/12) + `/>` + sql,
		"instructions":       `<r>` + strings.Repeat(`<?a <a ?>`, room/9) + sql + `</r>`,
		"latin-1 SVG attribute": `<?xml version="1.0" encoding="ISO-8859-1"?><svg xmlns="http://www.w3.org/2000/svg" t="` +
			strings.Repeat("\xe9", room-100) + `"/>` + sql,
		"tag-dense text":                            `<r>` + strings.Repeat("&lt;a ", room/6) + `</r>` + sql,
		"tiny values then a mismatched end tag":     `<r>` + strings.Repeat(`x<a/>`, room/5) + sql + `</b>`,
		"instructions then an error":                `<r>` + strings.Repeat(`<?a <a ?>`, room/9) + sql + `</b>`,
		"script elements then a mismatched end tag": `<r>` + strings.Repeat(`<script/>`, room/9) + sql + `</b>`,
		"unclosed tiny elements then an error":      `<r>` + strings.Repeat(`x<a>`, room/4) + sql + `</b>`,
	}
}

// minInspect inspects r runs times and returns the fastest time, the
// allocation of that run and its decision.
func minInspect(fw *aegolith.Firewall, r *aegolith.Request, runs int) (time.Duration, uint64, aegolith.Decision) {
	var best time.Duration
	var bestAlloc uint64
	var d aegolith.Decision
	for i := range runs {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		d = fw.Inspect(r)
		el := time.Since(start)
		runtime.ReadMemStats(&after)
		if i == 0 || el < best {
			best, bestAlloc = el, after.TotalAlloc-before.TotalAlloc
		}
	}
	return best, bestAlloc, d
}

// TestInspectXMLWorstCaseBounded times each xmlWorstBodies body in monitor
// mode (nothing stops early), best of three runs, next to the JSON worst
// body (ff-lt-trailing-sqli) in the same process, and checks that the
// attack at the end is still seen, so the walk and the raw rescan stay
// within the scan budget. Measured on a loaded machine (load average about
// 60, Apple M4 Pro, no -race): see docs/threat-model.md; to be re-measured
// on a quiet machine before the tag.
func TestInspectXMLWorstCaseBounded(t *testing.T) {
	runs := 3
	if raceSlowdown != 1 || testing.Short() {
		runs = 1
	}
	fw := mustNew(t, aegolith.Config{Mode: aegolith.ModeMonitor, AllowXML: true})
	fw.Inspect(get("/warm"))
	ref, refAlloc, _ := minInspect(fw, withBody("POST", "/s", "application/json", worstCaseBodies()[0].body), runs)
	t.Logf("JSON worst body: %v, %d MiB allocated", ref, refAlloc>>20)
	for name, body := range xmlWorstBodies() {
		if len(body) > 1<<20 {
			t.Fatalf("%s: body %d bytes", name, len(body))
		}
		el, alloc, d := minInspect(fw, withBody("POST", "/s", "application/xml", body), runs)
		t.Logf("%s: %v (%.2fx the JSON worst body), %d MiB allocated", name, el, float64(el)/float64(ref), alloc>>20)
		if lim := wallLimit(2*time.Second, 20*time.Second); !testing.Short() && el > lim {
			t.Errorf("%s took %v, want under %v", name, el, lim)
		}
		if alloc > 192<<20 {
			t.Errorf("%s allocated %d MiB, want under 192 MiB", name, alloc>>20)
		}
		mustHave(t, d, "AEG-SQLI-001", "body")
	}
}
