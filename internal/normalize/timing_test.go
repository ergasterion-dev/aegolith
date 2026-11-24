package normalize

import (
	"os"
	"time"
)

// wallLimit returns the bound for a wall-clock assertion: strict with
// AEGOLITH_PERF=1 (meant for a quiet machine), otherwise a catastrophic
// bound that a heavily loaded machine (load average over 50) still meets
// but a super-linear regression does not. Tests skip wall-clock assertions
// under -short.
func wallLimit(strict, catastrophic time.Duration) time.Duration {
	if os.Getenv("AEGOLITH_PERF") == "1" {
		return strict
	}
	return catastrophic
}
