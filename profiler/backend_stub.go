//go:build !windows

package profiler

func newBackend() CaptureBackend {
	panic("unsupported platform")
}
