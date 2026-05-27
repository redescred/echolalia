//go:build windows && !npcap

package profiler

// newBackend always returns the ETW backend when the npcap build tag is absent.
// Build with -tags npcap to enable runtime pcap/ETW selection when npcap is installed.
func newBackend() CaptureBackend {
	return newETWBackend()
}

// npcapPresent stubs out to false without the npcap build tag.
func npcapPresent() bool { return false }
