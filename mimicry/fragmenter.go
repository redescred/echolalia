package mimicry

import (
	"crypto/rand"
	"math"
)

// fragment splits payload into chunks matching the given target sizes.
// Each chunk format: [2-byte data length][data bytes][random padding to fill chunk]
// Minimum chunk size is 3 bytes (2-byte prefix + at least 1 byte capacity).
// If payload is longer than total capacity across all sizes, extra chunks are appended.
func fragment(payload []byte, sizes []float64) [][]byte {
	var chunks [][]byte
	payloadOffset := 0

	for _, sz := range sizes {
		chunkSize := int(math.Round(sz))
		if chunkSize < 3 {
			chunkSize = 3
		}

		capacity := chunkSize - 2
		if capacity < 1 {
			capacity = 1
		}

		dataLen := len(payload) - payloadOffset
		if dataLen > capacity {
			dataLen = capacity
		}
		if dataLen < 0 {
			dataLen = 0
		}

		chunk := make([]byte, chunkSize)
		chunk[0] = byte(dataLen >> 8)
		chunk[1] = byte(dataLen)
		copy(chunk[2:], payload[payloadOffset:payloadOffset+dataLen])
		payloadOffset += dataLen

		if paddingStart := 2 + dataLen; paddingStart < chunkSize {
			rand.Read(chunk[paddingStart:]) //nolint:errcheck
		}

		chunks = append(chunks, chunk)

		if payloadOffset >= len(payload) {
			break
		}
	}

	for payloadOffset < len(payload) {
		const defaultChunk = 1400
		capacity := defaultChunk - 2
		dataLen := len(payload) - payloadOffset
		if dataLen > capacity {
			dataLen = capacity
		}
		chunk := make([]byte, defaultChunk)
		chunk[0] = byte(dataLen >> 8)
		chunk[1] = byte(dataLen)
		copy(chunk[2:], payload[payloadOffset:payloadOffset+dataLen])
		payloadOffset += dataLen
		rand.Read(chunk[2+dataLen:]) //nolint:errcheck
		chunks = append(chunks, chunk)
	}

	return chunks
}
