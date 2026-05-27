package mimicry

import (
	"fmt"
	"time"

	"github.com/Emul4nt/echolalia/profiler"
)

// Packet is a single shaped unit of the beacon payload with a scheduled send time.
type Packet struct {
	Data   []byte
	SendAt time.Time
}

// PacketSequence is the output of Shape(): an ordered list of packets to send in sequence.
type PacketSequence struct {
	Packets []Packet
}

// Shape takes a traffic profile and a beacon payload and returns a PacketSequence
// whose packet sizes and inter-arrival times statistically match the profile.
func Shape(p *profiler.TrafficProfile, payload []byte) (*PacketSequence, error) {
	if p == nil {
		return nil, fmt.Errorf("nil profile")
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	avgSize := p.AvgPktSize
	if avgSize < 10 {
		avgSize = 1400
	}
	estimatedCount := int(float64(len(payload))/avgSize) + 1
	if estimatedCount < 4 {
		estimatedCount = 4
	}

	sizes := make([]float64, estimatedCount)
	for i := range sizes {
		sizes[i] = EmpiricalSample(p)
	}

	chunks := fragment(payload, sizes)
	iats := iatSamples(p, len(chunks))

	seq := &PacketSequence{Packets: make([]Packet, len(chunks))}
	cursor := time.Now()
	for i, chunk := range chunks {
		seq.Packets[i] = Packet{
			Data:   chunk,
			SendAt: cursor,
		}
		if i < len(iats) {
			cursor = cursor.Add(time.Duration(iats[i] * float64(time.Second)))
		}
	}
	return seq, nil
}
