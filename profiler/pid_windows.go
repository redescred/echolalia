//go:build windows

package profiler

import (
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
)

// resolvePID converts a Windows PID to the base executable name (e.g. "teams.exe").
// Uses PROCESS_QUERY_LIMITED_INFORMATION which works without admin for most user processes.
func resolvePID(pid uint32) string {
	if pid == 0 {
		return "system"
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "unknown"
	}
	defer windows.CloseHandle(h)

	var buf [260]uint16 // MAX_PATH
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "unknown"
	}
	return filepath.Base(windows.UTF16ToString(buf[:size]))
}

// portToPID finds the owning PID and process name for a local TCP port by
// scanning the current TCP connection table. Returns 0/"unknown" on miss.
func portToPID(localPort uint16) (uint32, string) {
	rows, err := getTCPTableRows()
	if err != nil {
		return 0, "unknown"
	}
	for _, row := range rows {
		if row.pid != 0 && rowLocalPort(row.local) == localPort {
			return row.pid, row.processName
		}
	}
	return 0, "unknown"
}

func rowLocalPort(addr string) uint16 {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		p, _ := strconv.ParseUint(addr[i+1:], 10, 16)
		return uint16(p)
	}
	return 0
}
