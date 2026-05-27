//go:build windows

package profiler

import "testing"

func TestDiag_BackendSelection(t *testing.T) {
	t.Logf("npcap present: %v", npcapPresent())
}

func TestDiag_TCPTable(t *testing.T) {
	rows, err := getTCPTableRows()
	if err != nil {
		t.Fatalf("getTCPTableRows error: %v", err)
	}
	t.Logf("TCP table rows (ESTABLISHED): %d", len(rows))
	for i, r := range rows {
		if i >= 10 {
			t.Logf("  ... (%d more)", len(rows)-10)
			break
		}
		t.Logf("  [%d] local=%s remote=%s pid=%d process=%s", i, r.local, r.remote, r.pid, r.processName)
	}
}

func TestDiag_PIDResolution(t *testing.T) {
	for _, p := range []uint32{0, 4, 8} {
		t.Logf("pid %d → %q", p, resolvePID(p))
	}
}
