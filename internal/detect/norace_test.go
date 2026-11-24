//go:build !race

package detect

// raceSlowdown scales wall-clock limits in timing tests (see race_test.go).
const raceSlowdown = 1
