package profiler

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// TrafficProfile is the statistical fingerprint of a process's outbound traffic.
// PktSizeHist is nil when CaptureMethod == "etw".
type TrafficProfile struct {
	ProcessName   string    `json:"process_name"`
	PID           int       `json:"pid"`
	Protocol      string    `json:"protocol"`       // "http1", "http2", "websocket"
	CaptureMethod string    `json:"capture_method"` // "pcap" or "etw"
	AvgPktSize    float64   `json:"avg_pkt_size"`
	PktSizeStddev float64   `json:"pkt_size_stddev"`
	PktSizeHist   []float64 `json:"pkt_size_hist,omitempty"` // nil when CaptureMethod == "etw"
	AvgIAT        float64   `json:"avg_iat"`
	IATStddev     float64   `json:"iat_stddev"`
	IATDistShape  string    `json:"iat_dist_shape"` // "exponential" or "normal"
	JA4           string    `json:"ja4"`
	Endpoints     []string  `json:"endpoints"`
}

// FlowMetrics holds raw per-process observations from the capture backend.
type FlowMetrics struct {
	ProcessName   string
	PID           int
	PktSizes      []float64 // nil for ETW captures (packet-level sizes not available)
	IATs          []float64
	TLSRecSizes   []float64
	JA4           string
	Endpoints     []string
	TotalBytes    int64
	Protocol      string
	CaptureMethod string // "pcap" or "etw" — set by the backend
}

// JSON returns the profile as indented JSON bytes.
func (p *TrafficProfile) JSON() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// Profile captures outbound traffic for duration, scores candidate processes,
// and returns the best-matching TrafficProfile.
func Profile(ctx context.Context, duration time.Duration) (*TrafficProfile, error) {
	backend := newBackend()
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	return profileWithBackend(ctx, backend)
}

// profileWithBackend is the testable core: accepts any CaptureBackend.
func profileWithBackend(ctx context.Context, backend CaptureBackend) (*TrafficProfile, error) {
	var collected []FlowMetrics

	var startErr error
	done := make(chan struct{})
	go func() {
		startErr = backend.Start(ctx)
		close(done)
	}()

loop:
	for {
		select {
		case f, ok := <-backend.Flows():
			if !ok {
				break loop
			}
			collected = append(collected, f)
		case <-ctx.Done():
			break loop
		}
	}
	<-done

	// Drain any flows flushed during backend shutdown (ETW flushAll writes to the
	// buffered channel after ctx cancels, by which point the read loop above has
	// already exited).
	for f := range backend.Flows() {
		collected = append(collected, f)
	}

	if startErr != nil && len(collected) == 0 {
		return nil, fmt.Errorf("profileWithBackend: capture backend failed: %w", startErr)
	}

	best, err := selectBest(collected)
	if err != nil {
		return nil, fmt.Errorf("profileWithBackend: %w", err)
	}

	captureMethod := best.CaptureMethod
	if captureMethod == "" {
		captureMethod = "pcap"
	}
	return buildProfile(best, captureMethod), nil
}

// buildProfile converts a FlowMetrics into a TrafficProfile.
func buildProfile(f FlowMetrics, captureMethod string) *TrafficProfile {
	p := &TrafficProfile{
		ProcessName:   f.ProcessName,
		PID:           f.PID,
		Protocol:      f.Protocol,
		CaptureMethod: captureMethod,
		AvgPktSize:    mean(f.PktSizes),
		PktSizeStddev: stddev(f.PktSizes),
		AvgIAT:        mean(f.IATs),
		IATStddev:     stddev(f.IATs),
		IATDistShape:  aicShape(f.IATs),
		JA4:           f.JA4,
		Endpoints:     f.Endpoints,
	}
	if captureMethod == "pcap" {
		p.PktSizeHist = buildHistogram(f.PktSizes, 20)
	}
	return p
}

// buildHistogram returns a normalised histogram of xs using numBins bins.
func buildHistogram(xs []float64, numBins int) []float64 {
	if len(xs) == 0 || numBins <= 0 {
		return nil
	}
	sorted := make([]float64, len(xs))
	copy(sorted, xs)
	sort.Float64s(sorted)

	min, max := sorted[0], sorted[len(sorted)-1]
	if min == max {
		hist := make([]float64, numBins)
		hist[0] = 1.0
		return hist
	}

	binWidth := (max - min) / float64(numBins)
	counts := make([]float64, numBins)
	for _, x := range xs {
		idx := int((x - min) / binWidth)
		if idx >= numBins {
			idx = numBins - 1
		}
		counts[idx]++
	}
	total := float64(len(xs))
	for i := range counts {
		counts[i] /= total
	}
	return counts
}
