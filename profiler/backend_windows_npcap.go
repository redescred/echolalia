//go:build windows && npcap

package profiler

import (
	"golang.org/x/sys/windows"
)

// newBackend returns a PCAPBackend if npcap is installed at runtime, else ETWBackend.
// Only compiled when the npcap build tag is present (requires CGO + npcap SDK).
func newBackend() CaptureBackend {
	if npcapPresent() {
		return newPCAPBackend()
	}
	return newETWBackend()
}

// npcapPresent checks for the npcap driver device without loading it.
func npcapPresent() bool {
	name, err := windows.UTF16PtrFromString(`\\.\NPCAP`)
	if err != nil {
		return false
	}
	h, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return false
	}
	windows.CloseHandle(h)
	return true
}
