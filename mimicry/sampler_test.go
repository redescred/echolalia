package mimicry

import (
	"math"
	"testing"

	"github.com/Emul4nt/echolalia/profiler"
)

func TestEmpiricalSample_MatchesInputDistribution(t *testing.T) {
	hist := make([]float64, 20)
	hist[5] = 0.5  // peak at 500-600 bytes
	hist[13] = 0.5 // peak at 1300-1400 bytes

	profile := &profiler.TrafficProfile{
		CaptureMethod: "pcap",
		AvgPktSize:    950,
		PktSizeStddev: 400,
		PktSizeHist:   hist,
	}

	const n = 1000
	samples := make([]float64, n)
	for i := range samples {
		samples[i] = EmpiricalSample(profile)
	}

	var low, high int
	for _, s := range samples {
		switch {
		case s >= 400 && s < 800:
			low++
		case s >= 1200 && s < 1600:
			high++
		}
	}
	if low < 400 || high < 400 {
		t.Errorf("bimodal distribution not reproduced: low=%d high=%d (want ~500 each)", low, high)
	}
}

func TestBoxMullerSample_MeanAndStddev(t *testing.T) {
	profile := &profiler.TrafficProfile{
		CaptureMethod: "etw",
		AvgPktSize:    1400,
		PktSizeStddev: 100,
	}
	const n = 10000
	samples := make([]float64, n)
	for i := range samples {
		samples[i] = boxMullerSample(profile)
	}
	m := sampleMean(samples)
	s := sampleStddev(samples)
	if math.Abs(m-1400) > 50 {
		t.Errorf("mean off: got %.1f, want ~1400", m)
	}
	if math.Abs(s-100) > 30 {
		t.Errorf("stddev off: got %.1f, want ~100", s)
	}
}

func TestIATSamples_ExponentialShape(t *testing.T) {
	profile := &profiler.TrafficProfile{
		AvgIAT:       0.1,
		IATStddev:    0.09,
		IATDistShape: "exponential",
	}
	const n = 1000
	samples := iatSamples(profile, n)
	if len(samples) != n {
		t.Fatalf("expected %d samples, got %d", n, len(samples))
	}
	for _, s := range samples {
		if s < 0 {
			t.Errorf("negative IAT: %f", s)
		}
	}
	m := sampleMean(samples)
	if math.Abs(m-0.1) > 0.05 {
		t.Errorf("exponential mean off: got %.4f, want ~0.1", m)
	}
}

func sampleMean(xs []float64) float64 {
	var sum float64
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}

func sampleStddev(xs []float64) float64 {
	m := sampleMean(xs)
	var v float64
	for _, x := range xs {
		d := x - m
		v += d * d
	}
	return math.Sqrt(v / float64(len(xs)))
}
