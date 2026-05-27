package profiler

import (
	"context"
)

// mockBackend replays a fixed set of FlowMetrics then closes the channel.
type mockBackend struct {
	flows []FlowMetrics
	ch    chan FlowMetrics
}

func newMockBackend(flows []FlowMetrics) *mockBackend {
	return &mockBackend{flows: flows, ch: make(chan FlowMetrics, len(flows))}
}

func (m *mockBackend) Start(ctx context.Context) error {
	for _, f := range m.flows {
		m.ch <- f
	}
	close(m.ch)
	return nil
}

func (m *mockBackend) Flows() <-chan FlowMetrics {
	return m.ch
}
