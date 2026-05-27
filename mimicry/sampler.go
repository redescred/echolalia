package mimicry

import (
	"math"
	"math/rand"
	"sort"

	"github.com/Emul4nt/echolalia/profiler"
)

// EmpiricalSample draws a packet size from the profile's empirical histogram using
// inverse transform sampling. Falls back to boxMullerSample if hist is nil (ETW profile).
func EmpiricalSample(p *profiler.TrafficProfile) float64 {
	if len(p.PktSizeHist) == 0 {
		return boxMullerSample(p)
	}

	cdf := make([]float64, len(p.PktSizeHist))
	cdf[0] = p.PktSizeHist[0]
	for i := 1; i < len(p.PktSizeHist); i++ {
		cdf[i] = cdf[i-1] + p.PktSizeHist[i]
	}

	u := rand.Float64()
	idx := sort.SearchFloat64s(cdf, u)
	if idx >= len(cdf) {
		idx = len(cdf) - 1
	}

	// Reconstruct the histogram's domain: the profiler used [min, max] of observed
	// packet sizes. We approximate with mean ± 3σ, clamped to [0, ∞).
	minVal := p.AvgPktSize - 3*p.PktSizeStddev
	if minVal < 0 {
		minVal = 0
	}
	maxVal := p.AvgPktSize + 3*p.PktSizeStddev
	binWidth := (maxVal - minVal) / float64(len(p.PktSizeHist))
	if binWidth < 1 {
		binWidth = 1
	}
	low := minVal + float64(idx)*binWidth
	sample := low + rand.Float64()*binWidth
	if sample < 1 {
		sample = 1
	}
	return sample
}

// boxMullerSample draws a packet size from a normal distribution using Box-Muller transform.
// Used for ETW-captured profiles where PktSizeHist is nil.
func boxMullerSample(p *profiler.TrafficProfile) float64 {
	u1, u2 := rand.Float64(), rand.Float64()
	if u1 == 0 {
		u1 = 1e-10
	}
	z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
	sample := p.AvgPktSize + p.PktSizeStddev*z
	if sample < 1 {
		sample = 1
	}
	return sample
}

// iatSamples generates n inter-arrival time samples matching the profile's IAT distribution.
func iatSamples(p *profiler.TrafficProfile, n int) []float64 {
	samples := make([]float64, n)
	for i := range samples {
		if p.IATDistShape == "exponential" {
			u := rand.Float64()
			if u == 0 {
				u = 1e-10
			}
			samples[i] = -p.AvgIAT * math.Log(u)
		} else {
			u1, u2 := rand.Float64(), rand.Float64()
			if u1 == 0 {
				u1 = 1e-10
			}
			z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
			s := p.AvgIAT + p.IATStddev*z
			if s < 0 {
				s = 0
			}
			samples[i] = s
		}
	}
	return samples
}
