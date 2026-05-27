package mimicry

import (
	"math"
	"sort"
	"testing"

	"github.com/Emul4nt/echolalia/profiler"
)

func TestShape_PacketCountAndOrdering(t *testing.T) {
	profile := &profiler.TrafficProfile{
		CaptureMethod: "pcap",
		AvgPktSize:    1400,
		PktSizeStddev: 50,
		PktSizeHist:   uniformHist(20),
		AvgIAT:        0.05,
		IATStddev:     0.01,
		IATDistShape:  "normal",
		JA4:           "t13d1516h2_8daaf6152771_e5627efa2ab1",
		Protocol:      "http2",
	}
	payload := make([]byte, 3000)

	seq, err := Shape(profile, payload)
	if err != nil {
		t.Fatalf("Shape: %v", err)
	}
	if len(seq.Packets) == 0 {
		t.Fatal("expected at least one packet")
	}

	for i := 1; i < len(seq.Packets); i++ {
		if !seq.Packets[i].SendAt.After(seq.Packets[i-1].SendAt) {
			t.Errorf("packet %d SendAt not after packet %d: %v vs %v",
				i, i-1, seq.Packets[i].SendAt, seq.Packets[i-1].SendAt)
		}
	}
}

func TestShape_PacketSizesPassKS(t *testing.T) {
	hist := uniformHist(20)
	profile := &profiler.TrafficProfile{
		CaptureMethod: "pcap",
		AvgPktSize:    1400,
		PktSizeStddev: 200,
		PktSizeHist:   hist,
		AvgIAT:        0.1,
		IATStddev:     0.02,
		IATDistShape:  "normal",
		JA4:           "t13d1516h2_8daaf6152771_e5627efa2ab1",
	}

	payload := make([]byte, 500000)
	seq, err := Shape(profile, payload)
	if err != nil {
		t.Fatalf("Shape: %v", err)
	}

	got := make([]float64, len(seq.Packets))
	for i, pkt := range seq.Packets {
		got[i] = float64(len(pkt.Data))
	}

	ref := make([]float64, len(got))
	for i := range ref {
		ref[i] = EmpiricalSample(profile)
	}

	d := ksStatistic(got, ref)
	if d > 0.15 {
		t.Errorf("KS statistic too high: %.4f (want < 0.15)", d)
	}
}

func uniformHist(numBins int) []float64 {
	h := make([]float64, numBins)
	for i := range h {
		h[i] = 1.0 / float64(numBins)
	}
	return h
}

func ksStatistic(a, b []float64) float64 {
	ac := make([]float64, len(a))
	bc := make([]float64, len(b))
	copy(ac, a)
	copy(bc, b)
	sort.Float64s(ac)
	sort.Float64s(bc)

	n1, n2 := float64(len(ac)), float64(len(bc))
	var i, j int
	var d float64
	for i < len(ac) || j < len(bc) {
		switch {
		case i < len(ac) && (j >= len(bc) || ac[i] < bc[j]):
			i++
		case j < len(bc) && (i >= len(ac) || bc[j] < ac[i]):
			j++
		default:
			i++
			j++
		}
		cdf1 := float64(i) / n1
		cdf2 := float64(j) / n2
		if diff := math.Abs(cdf1 - cdf2); diff > d {
			d = diff
		}
	}
	return d
}
