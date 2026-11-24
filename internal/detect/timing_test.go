package detect

import (
	"os"
	"time"
)

// wallLimit returns the bound for a wall-clock assertion, scaled for
// -race. With AEGOLITH_PERF=1 (meant for a quiet machine) it is the strict
// bound. Otherwise it is the catastrophic bound: at least 20x the time the
// case takes on a quiet machine, so a heavily loaded machine (load average
// over 50) still passes, yet far below the super-linear blow-ups the tests
// guard against (seconds to minutes on these inputs). Tests skip wall-clock
// assertions entirely under -short. Deterministic checks (allocated bytes,
// decisions) are asserted in every mode.
func wallLimit(strict, catastrophic time.Duration) time.Duration {
	if os.Getenv("AEGOLITH_PERF") == "1" {
		return strict * raceSlowdown
	}
	return catastrophic * raceSlowdown
}
