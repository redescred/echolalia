//go:build windows && npcap

package profiler

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type flowState struct {
	processName string
	pid         int
	pktSizes    []float64
	iats        []float64
	lastSeen    time.Time
	totalBytes  int64
	endpoints   map[string]struct{}
	protocol    string
	ja4         string
}

type pcapBackend struct {
	flows chan FlowMetrics
	state map[string]*flowState
}

func newPCAPBackend() *pcapBackend {
	return &pcapBackend{
		flows: make(chan FlowMetrics, 256),
		state: make(map[string]*flowState),
	}
}

func (b *pcapBackend) Flows() <-chan FlowMetrics {
	return b.flows
}

// openBestHandle enumerates npcap interfaces and returns a handle on the first
// non-loopback adapter. npcap on Windows does not expose a generic "any" device.
func openBestHandle() (*pcap.Handle, error) {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("pcap.FindAllDevs: %w", err)
	}
	for _, iface := range ifaces {
		if strings.Contains(strings.ToLower(iface.Name), "loopback") ||
			strings.Contains(strings.ToLower(iface.Description), "loopback") {
			continue
		}
		if h, err := pcap.OpenLive(iface.Name, 65535, false, pcap.BlockForever); err == nil {
			return h, nil
		}
	}
	return nil, fmt.Errorf("pcap: no suitable interface found across %d enumerated interfaces", len(ifaces))
}

func (b *pcapBackend) Start(ctx context.Context) error {
	defer close(b.flows)

	handle, err := openBestHandle()
	if err != nil {
		return err
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("tcp and not dst net 127.0.0.0/8"); err != nil {
		return fmt.Errorf("SetBPFFilter: %w", err)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.flushAll()
			return nil
		case <-ticker.C:
			b.flushStale(30 * time.Second)
		case pkt, ok := <-src.Packets():
			if !ok {
				return nil
			}
			b.observe(pkt)
		}
	}
}

func (b *pcapBackend) observe(pkt gopacket.Packet) {
	netLayer := pkt.NetworkLayer()
	transLayer := pkt.TransportLayer()
	if netLayer == nil || transLayer == nil {
		return
	}

	srcIP := netLayer.NetworkFlow().Src().String()
	dstIP := netLayer.NetworkFlow().Dst().String()

	tcp, ok := transLayer.(*layers.TCP)
	if !ok {
		return
	}
	// Use numeric port values — TCPPort.String() returns "443(https)" not "443".
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	key := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	pktLen := float64(len(pkt.Data()))
	now := time.Now()

	fs, exists := b.state[key]
	if !exists {
		pid, procName := portToPID(srcPort)
		fs = &flowState{
			processName: procName,
			pid:         int(pid),
			endpoints:   make(map[string]struct{}),
			protocol:    detectProtocol(dstPort),
		}
		b.state[key] = fs
	}

	if !fs.lastSeen.IsZero() {
		iat := now.Sub(fs.lastSeen).Seconds()
		fs.iats = append(fs.iats, iat)
	}
	fs.lastSeen = now
	fs.pktSizes = append(fs.pktSizes, pktLen)
	fs.totalBytes += int64(pktLen)
	fs.endpoints[fmt.Sprintf("%s:%d", dstIP, dstPort)] = struct{}{}

	if appLayer := pkt.ApplicationLayer(); appLayer != nil && dstPort == 443 {
		if ja4 := extractJA4(appLayer.Payload()); ja4 != "" {
			fs.ja4 = ja4
		}
	}
}

func (b *pcapBackend) flushAll() {
	for key, fs := range b.state {
		b.emit(fs)
		delete(b.state, key)
	}
}

func (b *pcapBackend) flushStale(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	for key, fs := range b.state {
		if fs.lastSeen.Before(cutoff) {
			b.emit(fs)
			delete(b.state, key)
		}
	}
}

func (b *pcapBackend) emit(fs *flowState) {
	if len(fs.pktSizes) < 5 {
		return
	}
	endpoints := make([]string, 0, len(fs.endpoints))
	for ep := range fs.endpoints {
		endpoints = append(endpoints, ep)
	}
	metrics := FlowMetrics{
		ProcessName:   fs.processName,
		PID:           fs.pid,
		PktSizes:      fs.pktSizes,
		IATs:          fs.iats,
		Endpoints:     endpoints,
		TotalBytes:    fs.totalBytes,
		Protocol:      fs.protocol,
		JA4:           fs.ja4,
		CaptureMethod: "pcap",
	}
	select {
	case b.flows <- metrics:
	default:
		// consumer not keeping up; drop rather than blocking the capture loop
	}
}

func detectProtocol(dstPort uint16) string {
	switch dstPort {
	case 443:
		return "http2"
	case 80:
		return "http1"
	default:
		return "http1"
	}
}

// extractJA4 attempts to parse a JA4 fingerprint from a raw TLS ClientHello payload.
// Returns empty string if payload is not a valid ClientHello.
func extractJA4(payload []byte) string {
	// TLS record: type=0x16 (handshake), 2-byte version, 2-byte length, type=0x01 (ClientHello)
	if len(payload) < 9 || payload[0] != 0x16 || payload[5] != 0x01 {
		return ""
	}

	recordVersion := uint16(payload[1])<<8 | uint16(payload[2])
	body := payload[9:]
	if len(body) < 35 {
		return ""
	}

	clientVersion := uint16(body[0])<<8 | uint16(body[1])
	tlsVer := ja4TLSVersion(recordVersion, clientVersion)

	// Skip 2-byte client version + 32-byte random
	offset := 2 + 32
	if offset >= len(body) {
		return ""
	}
	sessionLen := int(body[offset])
	offset += 1 + sessionLen

	if offset+2 > len(body) {
		return ""
	}
	csLen := int(uint16(body[offset])<<8 | uint16(body[offset+1]))
	numCS := csLen / 2
	offset += 2 + csLen

	if offset >= len(body) {
		return fmt.Sprintf("t%sd%02d00_00_", tlsVer, numCS)
	}
	compLen := int(body[offset])
	offset += 1 + compLen

	if offset+2 > len(body) {
		return fmt.Sprintf("t%sd%02d00_00_", tlsVer, numCS)
	}
	extTotalLen := int(uint16(body[offset])<<8 | uint16(body[offset+1]))
	offset += 2
	if offset+extTotalLen > len(body) {
		// Truncated record — return empty rather than a partial fingerprint
		return ""
	}
	numExt, alpn := parseExtensions(body[offset : offset+extTotalLen])

	return fmt.Sprintf("t%sd%02d%02d%s_", tlsVer, numCS, numExt, alpnCode(alpn))
}

func ja4TLSVersion(record, client uint16) string {
	v := client
	if record > client {
		v = record
	}
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	default:
		return "00"
	}
}

func parseExtensions(data []byte) (count int, alpn string) {
	offset := 0
	for offset+4 <= len(data) {
		extType := uint16(data[offset])<<8 | uint16(data[offset+1])
		extLen := int(uint16(data[offset+2])<<8 | uint16(data[offset+3]))
		offset += 4
		if offset+extLen > len(data) {
			break
		}
		count++
		if extType == 0x0010 && extLen >= 4 { // ALPN extension
			alpnListLen := int(uint16(data[offset])<<8 | uint16(data[offset+1]))
			if alpnListLen >= 2 && offset+2+alpnListLen <= len(data) {
				protoLen := int(data[offset+2])
				if protoLen > 0 && offset+3+protoLen <= len(data) {
					alpn = string(data[offset+3 : offset+3+protoLen])
				}
			}
		}
		offset += extLen
	}
	return
}

func alpnCode(alpn string) string {
	switch alpn {
	case "h2":
		return "h2"
	case "http/1.1":
		return "h1"
	default:
		return "00"
	}
}
