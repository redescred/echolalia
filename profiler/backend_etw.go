//go:build windows

package profiler

import (
	"context"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

var (
	iphlpapi            = syscall.NewLazyDLL("iphlpapi.dll")
	getExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

type etwFlowState struct {
	processName string
	pid         uint32
	pktSizes    []float64
	iats        []float64
	lastSeen    time.Time
	totalBytes  int64
	endpoints   map[string]struct{}
}

type etwBackend struct {
	flows chan FlowMetrics
	state map[string]*etwFlowState
}

func newETWBackend() CaptureBackend {
	return &etwBackend{
		flows: make(chan FlowMetrics, 256),
		state: make(map[string]*etwFlowState),
	}
}

func (b *etwBackend) Flows() <-chan FlowMetrics {
	return b.flows
}

func (b *etwBackend) Start(ctx context.Context) error {
	defer close(b.flows)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.flushAll()
			return nil
		case <-ticker.C:
			b.pollTCPTable()
		}
	}
}

// pollTCPTable reads established TCP connections and synthesises flow observations.
// Packet sizes are estimated at 1400 bytes (typical MTU-sized segment) since ETW
// connection-table polling does not give per-packet byte sizes.
func (b *etwBackend) pollTCPTable() {
	rows, err := getTCPTableRows()
	if err != nil {
		return
	}
	now := time.Now()
	for _, row := range rows {
		key := fmt.Sprintf("%s-%s", row.local, row.remote)
		fs, ok := b.state[key]
		if !ok {
			fs = &etwFlowState{
				processName: row.processName,
				pid:         row.pid,
				endpoints:   make(map[string]struct{}),
			}
			b.state[key] = fs
		}
		const estimatedPktSize = 1400.0
		if !fs.lastSeen.IsZero() {
			iat := now.Sub(fs.lastSeen).Seconds()
			fs.iats = append(fs.iats, iat)
		}
		fs.lastSeen = now
		fs.pktSizes = append(fs.pktSizes, estimatedPktSize)
		fs.totalBytes += 1400
		fs.endpoints[row.remote] = struct{}{}
	}
}

func (b *etwBackend) flushAll() {
	for _, fs := range b.state {
		if len(fs.pktSizes) < 5 {
			continue
		}
		endpoints := make([]string, 0, len(fs.endpoints))
		for ep := range fs.endpoints {
			endpoints = append(endpoints, ep)
		}
		b.flows <- FlowMetrics{
			ProcessName:   fs.processName,
			PID:           int(fs.pid),
			PktSizes:      fs.pktSizes,
			IATs:          fs.iats,
			Endpoints:     endpoints,
			TotalBytes:    fs.totalBytes,
			Protocol:      "http1",
			CaptureMethod: "etw",
		}
	}
}

// tcpRow is a TCP connection table entry with owning process information.
type tcpRow struct {
	local       string
	remote      string
	pid         uint32
	processName string
}

// getTCPTableRows calls GetExtendedTcpTable via iphlpapi and returns
// established outbound TCP connections.
func getTCPTableRows() ([]tcpRow, error) {
	// MIB_TCPTABLE_OWNER_PID = 5, AF_INET = 2
	var size uint32 = 4096
	buf := make([]byte, size)
	r, _, _ := getExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, // sort
		2, // AF_INET
		5, // TCP_TABLE_OWNER_PID_ALL
		0,
	)
	if r == 0x7A { // ERROR_INSUFFICIENT_BUFFER
		buf = make([]byte, size)
		r, _, _ = getExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			1, 2, 5, 0,
		)
	}
	if r != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable: error %d", r)
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	// MIB_TCPROW_OWNER_PID layout: state(4) + localAddr(4) + localPort(4) + remoteAddr(4) + remotePort(4) + pid(4) = 24 bytes
	const rowSize = 24
	var rows []tcpRow
	for i := uint32(0); i < numEntries; i++ {
		base := 4 + i*rowSize
		if int(base)+rowSize > len(buf) {
			break
		}
		state := *(*uint32)(unsafe.Pointer(&buf[base]))
		if state != 5 { // MIB_TCP_STATE_ESTAB
			continue
		}
		la := buf[base+4 : base+8]
		lp := buf[base+8 : base+12]
		ra := buf[base+12 : base+16]
		rp := buf[base+16 : base+20]

		localIP := fmt.Sprintf("%d.%d.%d.%d", la[0], la[1], la[2], la[3])
		localPort := uint16(lp[0])<<8 | uint16(lp[1]) // network (big-endian) byte order per MSDN
		remoteIP := fmt.Sprintf("%d.%d.%d.%d", ra[0], ra[1], ra[2], ra[3])
		remotePort := uint16(rp[0])<<8 | uint16(rp[1])
		pid := *(*uint32)(unsafe.Pointer(&buf[base+20]))

		rows = append(rows, tcpRow{
			local:       fmt.Sprintf("%s:%d", localIP, localPort),
			remote:      fmt.Sprintf("%s:%d", remoteIP, remotePort),
			pid:         pid,
			processName: resolvePID(pid),
		})
	}
	return rows, nil
}
