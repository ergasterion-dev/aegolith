package aegolith_test

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith"
)

// xmlWorstBodies are in-limit (at most 1 MiB) XML bodies that make the walk
// do the most work per byte, each with an attack at the end.
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
		"tag-dense text": `<r>` + strings.Repeat("&lt;a ", room/6) + `</r>` + sql,
	}
}

// TestInspectXMLWorstCaseBounded times each xmlWorstBodies body in monitor
// mode (nothing stops early) and checks that the attack at its end is
// still seen, so the walk and the raw rescan stay within the scan budget.
// Measured at load average 54: 21-340 ms and up to 49 MiB each (Apple M4 Pro, no
// -race), below the documented 1 MiB worst case.
func TestInspectXMLWorstCaseBounded(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Mode: aegolith.ModeMonitor, AllowXML: true})
	fw.Inspect(get("/warm"))
	for name, body := range xmlWorstBodies() {
		if len(body) > 1<<20 {
			t.Fatalf("%s: body %d bytes", name, len(body))
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		d := fw.Inspect(withBody("POST", "/s", "application/xml", body))
		el := time.Since(start)
		runtime.ReadMemStats(&after)
		alloc := after.TotalAlloc - before.TotalAlloc
		t.Logf("%s: %v, %d MiB allocated", name, el, alloc>>20)
		if lim := wallLimit(time.Second, 10*time.Second); !testing.Short() && el > lim {
			t.Errorf("%s took %v, want under %v", name, el, lim)
		}
		if alloc > 128<<20 {
			t.Errorf("%s allocated %d MiB, want under 128 MiB", name, alloc>>20)
		}
		mustHave(t, d, "AEG-SQLI-001", "body")
	}
}
