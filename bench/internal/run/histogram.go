package run

import (
	"math"
	"math/bits"
)

// Bucket layout of histogram.
const (
	// histSubBits sets the resolution: every power of two is cut into
	// 1<<histSubBits buckets.
	histSubBits = 7
	// Values below histExact have a bucket each.
	histExact = 1 << (histSubBits + 1)
	// Values of 1<<histMaxBits and more share the last bucket. In
	// microseconds that is 19 hours.
	histMaxBits = 36
	histBuckets = histExact + (histMaxBits-histSubBits-1)<<histSubBits
)

// PercentileError is the most a percentile of a load run can be above the true
// one, as a share of it. See histogram.
const PercentileError = 1.0 / (1 << histSubBits)

// histogram counts non-negative values, microseconds here, in a fixed number
// of buckets (3840, about 30 KiB), so that its size does not depend on how
// many values it has seen.
//
// A value below 256 has a bucket of its own. Above that, each range from a
// power of two to the next is cut into 128 buckets of equal width, and a
// percentile is the highest value its bucket can hold, capped at the largest
// value seen. A percentile is therefore never below the true one and at most
// 1/128 (under 0.8%) above it; below 256 it is exact. max is exact.
//
// It is not safe for concurrent use.
type histogram struct {
	counts [histBuckets]uint64
	n      uint64
	max    int64
}

// add counts v; a negative value counts as 0.
func (h *histogram) add(v int64) {
	v = max(v, 0)
	h.counts[bucketOf(v)]++
	h.n++
	h.max = max(h.max, v)
}

// percentile returns the smallest bucket bound that at least p percent of the
// values do not exceed (the nearest-rank percentile), or 0 without values.
func (h *histogram) percentile(p float64) int64 {
	if h.n == 0 {
		return 0
	}
	rank := uint64(math.Ceil(p / 100 * float64(h.n)))
	rank = min(max(rank, 1), h.n)
	var seen uint64
	for i, c := range h.counts {
		seen += c
		if seen < rank {
			continue
		}
		if i == histBuckets-1 {
			// The last bucket has no upper bound.
			return h.max
		}
		return min(bucketMax(i), h.max)
	}
	return h.max
}

// bucketOf returns the bucket of v, which is not negative.
func bucketOf(v int64) int {
	if v < histExact {
		return int(v)
	}
	exp := bits.Len64(uint64(v)) - 1
	if exp >= histMaxBits {
		return histBuckets - 1
	}
	sub := int(v>>(exp-histSubBits)) & (1<<histSubBits - 1)
	return histExact + (exp-histSubBits-1)<<histSubBits + sub
}

// bucketMax returns the highest value of bucket i.
func bucketMax(i int) int64 {
	if i < histExact {
		return int64(i)
	}
	i -= histExact
	exp := i>>histSubBits + histSubBits + 1
	sub := int64(i & (1<<histSubBits - 1))
	return (1<<histSubBits+sub+1)<<(exp-histSubBits) - 1
}
