//go:build !race

package aegolith_test

// raceSlowdown scales wall-clock limits in timing tests (see race_test.go).
const raceSlowdown = 1
