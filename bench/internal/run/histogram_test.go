package run

import (
	"math/rand/v2"
	"slices"
	"testing"
)

// exact is the nearest-rank percentile of the values themselves.
func exact(values []int64, p float64) int64 {
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	rank := int(p / 100 * float64(len(sorted)))
	if float64(rank) < p/100*float64(len(sorted)) {
		rank++
	}
	return sorted[max(rank, 1)-1]
}

func TestHistogramPercentiles(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		var h histogram
		if h.percentile(50) != 0 || h.percentile(99) != 0 || h.max != 0 {
			t.Errorf("an empty histogram reports %d, %d, max %d", h.percentile(50), h.percentile(99), h.max)
		}
	})
	t.Run("small values are exact", func(t *testing.T) {
		var h histogram
		for v := int64(1); v <= 100; v++ {
			h.add(v)
		}
		for p, want := range map[float64]int64{50: 50, 90: 90, 99: 99, 100: 100, 1: 1, 0: 1} {
			if got := h.percentile(p); got != want {
				t.Errorf("p%v = %d, want %d", p, got, want)
			}
		}
		if h.max != 100 {
			t.Errorf("max = %d, want 100", h.max)
		}
	})
	t.Run("one value", func(t *testing.T) {
		var h histogram
		h.add(123457)
		for _, p := range []float64{50, 90, 99} {
			if got := h.percentile(p); got != 123457 {
				t.Errorf("p%v = %d, want the only value: no percentile is above the maximum", p, got)
			}
		}
	})
	t.Run("a tail is not averaged away", func(t *testing.T) {
		var h histogram
		for range 98 {
			h.add(200)
		}
		h.add(50_000)
		h.add(900_000)
		if got := h.percentile(50); got != 200 {
			t.Errorf("p50 = %d, want 200", got)
		}
		if got := h.percentile(99); got < 50_000 || got > 50_000+50_000/128 {
			t.Errorf("p99 = %d, want 50000 or up to 1/128 more", got)
		}
		if h.max != 900_000 {
			t.Errorf("max = %d, want 900000", h.max)
		}
	})
	t.Run("within the stated error", func(t *testing.T) {
		rng := rand.New(rand.NewPCG(7, 7))
		var h histogram
		var values []int64
		for range 20_000 {
			// From microseconds to minutes.
			v := int64(1) << rng.IntN(27)
			v += rng.Int64N(v)
			values = append(values, v)
			h.add(v)
		}
		for _, p := range []float64{1, 25, 50, 90, 99, 99.9, 100} {
			got, want := h.percentile(p), exact(values, p)
			if got < want || (got-want)*128 > want {
				t.Errorf("p%v = %d, want %d or up to 1/128 more", p, got, want)
			}
		}
	})
	t.Run("out of range", func(t *testing.T) {
		var h histogram
		h.add(-5)
		if h.percentile(50) != 0 {
			t.Errorf("a negative value counts as %d, want 0", h.percentile(50))
		}
		huge := int64(1) << 50
		h.add(huge)
		h.add(huge)
		if got := h.percentile(99); got != huge {
			t.Errorf("p99 = %d, want the maximum for values past the last bucket", got)
		}
	})
}

// TestHistogramBuckets checks the resolution the comment on histogram states.
func TestHistogramBuckets(t *testing.T) {
	t.Parallel()
	last := -1
	check := func(v int64) {
		i := bucketOf(v)
		if i < last || i >= histBuckets {
			t.Fatalf("bucket of %d is %d after %d", v, i, last)
		}
		last = i
		top := bucketMax(i)
		if top < v || (top-v)*128 > v {
			t.Fatalf("bucket %d of %d ends at %d: more than 1/128 above", i, v, top)
		}
		if v < histExact && top != v {
			t.Fatalf("value %d below %d is not exact: %d", v, histExact, top)
		}
	}
	for v := int64(0); v < 1<<16; v++ {
		check(v)
	}
	for v := int64(1 << 16); v < 1<<histMaxBits; v += v / 300 {
		check(v)
	}
	check(1<<histMaxBits - 1)
	if got := bucketOf(1 << histMaxBits); got != histBuckets-1 {
		t.Errorf("a value past the range is in bucket %d, want the last", got)
	}
}
