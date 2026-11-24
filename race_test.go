//go:build race

package aegolith_test

// raceSlowdown scales wall-clock limits in timing tests: the race detector
// makes byte loops five to ten times slower.
const raceSlowdown = 8
