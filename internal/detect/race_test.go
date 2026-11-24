//go:build race

package detect

// raceSlowdown scales wall-clock limits in timing tests: the race detector
// instruments every memory access and makes byte loops five to ten times slower.
const raceSlowdown = 8
