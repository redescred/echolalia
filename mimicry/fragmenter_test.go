package mimicry

import (
	"bytes"
	"testing"
)

func TestFragment_ReassemblesExactPayload(t *testing.T) {
	payload := []byte("hello world this is a test beacon payload that is longer than one chunk")
	sizes := []float64{20, 15, 30, 25, 10}

	chunks := fragment(payload, sizes)

	var reassembled []byte
	for _, c := range chunks {
		if len(c) < 2 {
			t.Fatalf("chunk too short: %d bytes", len(c))
		}
		dataLen := int(c[0])<<8 | int(c[1])
		if dataLen > len(c)-2 {
			t.Fatalf("corrupt length prefix: dataLen=%d chunkLen=%d", dataLen, len(c))
		}
		reassembled = append(reassembled, c[2:2+dataLen]...)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Errorf("reassembly mismatch:\n  got  %q\n  want %q", reassembled, payload)
	}
}

func TestFragment_PaddingIsRandom(t *testing.T) {
	payload := []byte("x")
	sizes := []float64{100}

	chunks1 := fragment(payload, sizes)
	chunks2 := fragment(payload, sizes)

	if len(chunks1) == 0 || len(chunks2) == 0 {
		t.Fatal("expected at least one chunk")
	}
	if bytes.Equal(chunks1[0][3:], chunks2[0][3:]) {
		t.Error("padding bytes are identical across two calls — not random")
	}
}

func TestFragment_ChunkSizesMatchTarget(t *testing.T) {
	payload := make([]byte, 200)
	sizes := []float64{50, 60, 70, 80}

	chunks := fragment(payload, sizes)
	for i, c := range chunks {
		if i >= len(sizes) {
			break
		}
		expected := int(sizes[i])
		if len(c) != expected {
			t.Errorf("chunk %d: got %d bytes, want %d", i, len(c), expected)
		}
	}
}
