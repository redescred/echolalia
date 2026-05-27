package profiler

import (
	"context"
	"testing"
)

func TestScore_PrefersHighVolumeStableProcess(t *testing.T) {
	stable := FlowMetrics{
		ProcessName: "teams",
		PktSizes:    []float64{1200, 1180, 1210, 1190, 1200},
		IATs:        []float64{0.1, 0.11, 0.09, 0.10, 0.10},
		TotalBytes:  60000,
		Endpoints:   []string{"1.2.3.4:443", "1.2.3.5:443"},
	}
	noisy := FlowMetrics{
		ProcessName: "random_app",
		PktSizes:    []float64{100, 5000, 300, 4500, 50},
		IATs:        []float64{0.01, 2.0, 0.5, 0.001, 3.0},
		TotalBytes:  9950,
		Endpoints:   []string{"9.9.9.9:80"},
	}

	sScore := score(stable)
	nScore := score(noisy)

	if sScore <= nScore {
		t.Errorf("expected stable process to score higher: got stable=%.4f noisy=%.4f", sScore, nScore)
	}
}

func TestSelectBest_ReturnsHighestScorer(t *testing.T) {
	flows := []FlowMetrics{
		{ProcessName: "a", PktSizes: []float64{100, 5000}, IATs: []float64{0.01, 5.0}, TotalBytes: 100, Endpoints: []string{"1.1.1.1:80"}},
		{ProcessName: "b", PktSizes: []float64{1400, 1390, 1410}, IATs: []float64{0.1, 0.1, 0.1}, TotalBytes: 50000, Endpoints: []string{"2.2.2.2:443", "3.3.3.3:443"}},
	}
	best, err := selectBest(flows)
	if err != nil {
		t.Fatalf("selectBest: %v", err)
	}
	if best.ProcessName != "b" {
		t.Errorf("expected 'b' to win, got %q", best.ProcessName)
	}
}

func TestProfile_SelectsBestProcess(t *testing.T) {
	flows := []FlowMetrics{
		{
			ProcessName:   "slack",
			PID:           1001,
			PktSizes:      []float64{1400, 1380, 1420, 1390, 1400, 1410},
			IATs:          []float64{0.1, 0.09, 0.11, 0.10, 0.10, 0.09},
			TLSRecSizes:   []float64{1400, 1390, 1400},
			JA4:           "t13d1516h2_8daaf6152771_e5627efa2ab1",
			Endpoints:     []string{"52.1.2.3:443", "52.1.2.4:443", "52.1.2.5:443"},
			TotalBytes:    840000,
			Protocol:      "http2",
			CaptureMethod: "pcap",
		},
		{
			ProcessName:   "notepad",
			PID:           2002,
			PktSizes:      []float64{60, 200},
			IATs:          []float64{5.0, 10.0},
			Endpoints:     []string{"8.8.8.8:53"},
			TotalBytes:    260,
			Protocol:      "http1",
			CaptureMethod: "pcap",
		},
	}

	backend := newMockBackend(flows)
	profile, err := profileWithBackend(context.Background(), backend)
	if err != nil {
		t.Fatalf("profileWithBackend: %v", err)
	}

	if profile.ProcessName != "slack" {
		t.Errorf("expected slack, got %q", profile.ProcessName)
	}
	if profile.CaptureMethod != "pcap" {
		t.Errorf("expected pcap, got %q", profile.CaptureMethod)
	}
	if profile.JA4 != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Errorf("JA4 mismatch: %q", profile.JA4)
	}
	if len(profile.PktSizeHist) == 0 {
		t.Error("expected non-empty PktSizeHist for pcap capture")
	}
}
