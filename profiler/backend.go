package profiler

import "context"

// CaptureBackend is implemented by each platform-specific capture mechanism.
type CaptureBackend interface {
	// Start begins capturing. Blocks until ctx is cancelled or an error occurs.
	Start(ctx context.Context) error
	// Flows returns a channel of per-process flow observations.
	// May be called before or after Start. The channel is closed when Start returns.
	// Implementors: Start must not block on a channel send after its context is cancelled.
	Flows() <-chan FlowMetrics
}
