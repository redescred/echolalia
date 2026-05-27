//go:build integration

package testharness

import (
	"context"
	"math"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/Emul4nt/echolalia/mimicry"
	"github.com/Emul4nt/echolalia/profiler"
)

func TestKS_MimickedTrafficMatchesProfile(t *testing.T) {
	if os.Getenv("ECHOLALIA_INTEGRATION") == "" {
		t.Skip("set ECHOLALIA_INTEGRATION=1 to run live capture tests")
	}

	t.Log("capturing real traffic for 60s...")
	ctx := context.Background()
	realProfile, err := profiler.Profile(ctx, 60*time.Second)
	if err != nil {
		t.Fatalf("profiling failed: %v", err)
	}
	t.Logf("profiled process: %s (pid %d), capture method: %s",
		realProfile.ProcessName, realProfile.PID, realProfile.CaptureMethod)

	payload := make([]byte, 100_000)
	seq, err := mimicry.Shape(realProfile, payload)
	if err != nil {
		t.Fatalf("Shape: %v", err)
	}

	mimickedSizes := make([]float64, len(seq.Packets))
	for i, pkt := range seq.Packets {
		mimickedSizes[i] = float64(len(pkt.Data))
	}

	ref := make([]float64, len(mimickedSizes))
	for i := range ref {
		ref[i] = mimicry.EmpiricalSample(realProfile)
	}

	d := ksStatistic(mimickedSizes, ref)

	if realProfile.CaptureMethod == "etw" {
		t.Logf("KS statistic (ETW profile, normal sampling): %.4f", d)
		if d > 0.20 {
			t.Errorf("KS statistic too high for ETW profile: %.4f (want < 0.20)", d)
		}
		return
	}

	p := ksPValue(d, len(mimickedSizes), len(ref))
	t.Logf("KS statistic: %.4f, p-value: %.4f", d, p)

	if d >= 0.05 {
		t.Errorf("KS test FAIL: D=%.4f p=%.4f (want D < 0.05)", d, p)
	} else {
		t.Logf("KS test PASS: D=%.4f p=%.4f", d, p)
	}
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
		default: // ac[i] == bc[j]: advance both to avoid artificial D=1 on ties
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

// ksPValue approximates the p-value for the two-sample KS test.
func ksPValue(d float64, n1, n2 int) float64 {
	lambda := d * math.Sqrt(float64(n1*n2)/float64(n1+n2))
	var p float64
	for k := 1; k <= 100; k++ {
		sign := math.Pow(-1, float64(k+1))
		p += sign * math.Exp(-2*float64(k*k)*lambda*lambda)
	}
	return 2 * p
}
