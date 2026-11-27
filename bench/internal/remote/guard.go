package remote

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"time"
)

const (
	// HeartbeatMaxAge is how old the operator's heartbeat file may be.
	HeartbeatMaxAge = 30 * time.Second
	// HealthInterval is how often the target's health is checked.
	HealthInterval = 5 * time.Second
	// ControlEvery is the number of case requests to an entry after which
	// its benign control is sent again.
	ControlEvery = 50
	// maxFailures is the number of requests in a row that may end in a
	// redirect or without an answer.
	maxFailures = 3
)

// Guard decides when a remote run stops: on answers that show trouble, on
// the operator's stop file or a stale heartbeat, and on a failed health
// check. Its reasons give statuses and never a request value.
type Guard struct {
	Target Target
	// StopFile, when set, stops the run once it exists. HeartbeatFile, when
	// set, must exist and be modified at most HeartbeatMaxAge ago.
	StopFile, HeartbeatFile string

	failures   int // requests in a row ending in a redirect or no answer
	lastHealth time.Time
	checked    bool
}

// Check judges the answer to one request to entry e: status 0 means none
// arrived, and benign marks a control request. It stops on any 5xx, on a
// stop status of the target, on a control answered with a status not in
// e.BenignStatus, and on the third request in a row that ends in a redirect
// or without an answer. In enforce mode a 403 to a case is the expected
// block and no reason to stop.
func (g *Guard) Check(status int, benign bool, e Entry) (stop bool, reason string) {
	if status == 0 || status >= 300 && status < 400 {
		g.failures++
	} else {
		g.failures = 0
	}
	switch {
	case status >= 500:
		return true, fmt.Sprintf("the target answered %d", status)
	case slices.Contains(g.Target.StopStatuses, status):
		return true, fmt.Sprintf("the target answered %d, a stop status of the target file", status)
	case benign && status == 0:
		return true, "a benign control got no answer"
	case benign && !slices.Contains(e.BenignStatus, status):
		return true, fmt.Sprintf("a benign control was answered %d, which is not in its benign_status", status)
	case g.failures >= maxFailures:
		return true, fmt.Sprintf("%d requests in a row ended in a redirect or without an answer", maxFailures)
	}
	return false, ""
}

// External checks what the operator controls: the stop file and the
// heartbeat file, against the time now.
func (g *Guard) External(now time.Time) (stop bool, reason string) {
	if g.StopFile != "" {
		_, err := os.Lstat(g.StopFile)
		switch {
		case err == nil:
			return true, "the stop file exists"
		case !errors.Is(err, fs.ErrNotExist):
			return true, "the stop file cannot be checked"
		}
	}
	if g.HeartbeatFile != "" {
		info, err := os.Stat(g.HeartbeatFile)
		switch {
		case err != nil:
			return true, "the heartbeat file is missing or cannot be read"
		case now.Sub(info.ModTime()) > HeartbeatMaxAge:
			return true, fmt.Sprintf("the heartbeat file is older than %s", HeartbeatMaxAge)
		}
	}
	return false, ""
}

// HealthDue reports whether the target's health must be checked before the
// next request: before the first, and once HealthInterval has passed since
// the last check.
func (g *Guard) HealthDue(now time.Time) bool {
	return !g.checked || now.Sub(g.lastHealth) >= HealthInterval
}

// Health judges the answer to a health check made at now; only 200 passes.
func (g *Guard) Health(now time.Time, status int) (stop bool, reason string) {
	g.checked, g.lastHealth = true, now
	switch status {
	case 200:
		return false, ""
	case 0:
		return true, "the health check got no answer"
	}
	return true, fmt.Sprintf("the health check was answered %d", status)
}
