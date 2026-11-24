package detect

import (
	"strings"
	"testing"
)

// scanBenchInputs are ScanText inputs from typical customer text to 8 KiB
// (MaxValueLen) adversarial windows.
var scanBenchInputs = []struct{ name, v string }{
	{"word", "milk"},
	{"prose", "Please ring the bell, don't knock. Gate code 1234 & leave at door"},
	{"urdu", "دودھ اور روٹی"},
	{"sqli", "1' OR '1'='1"},
	{"xss", "<script>alert(1)</script>"},
	{"8KiB-letters", strings.Repeat("a", 8<<10)},
	{"8KiB-quotes", strings.Repeat("a'", 4<<10)},
	{"8KiB-prose", strings.Repeat("We'll deliver between 9 & 5; ring twice. ", 8<<10/42)},
	{"8KiB-tags", strings.Repeat("<a ", 8<<10/3)},
}

func BenchmarkScanText(b *testing.B) {
	for _, in := range scanBenchInputs {
		b.Run(in.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(in.v)))
			for b.Loop() {
				ScanText(in.v)
			}
		})
	}
}

// cmdMarkerWorst are 8 KiB inputs that make hasCmdMarker's searches do the
// most work without matching.
var cmdMarkerWorst = []struct{ name, v string }{
	{"powershell", strings.Repeat("powershell -x ", 8<<10/14)},
	{"powershell-e-upper", strings.Repeat("POWERSHELL -EX1 ", 8<<10/16)},
	{"powershell-nospace", strings.Repeat("powershel", 8<<10/9)},
	{"bash", strings.Repeat("xbash -i", 8<<10/8)},
	{"nc", strings.Repeat("xnc -e", 8<<10/6)},
	{"shellshock", strings.Repeat("() {"+strings.Repeat("a", 60), 8<<10/64)},
	{"parens", strings.Repeat("()", 4<<10)},
	{"parens-space", strings.Repeat("() x", 2<<10)},
	{"devtcp", strings.Repeat("/dev/tc", 8<<10/7)},
	{"letters", strings.Repeat("p", 8<<10)},
}

func BenchmarkHasCmdMarker(b *testing.B) {
	for _, in := range cmdMarkerWorst {
		b.Run(in.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(in.v)))
			for b.Loop() {
				hasCmdMarker(in.v)
			}
		})
	}
}
