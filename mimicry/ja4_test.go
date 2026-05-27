package mimicry

import (
	"crypto/tls"
	"testing"
)

func TestParseJA4_TLS13(t *testing.T) {
	ja4 := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	cfg, warnings, err := ParseJA4(ja4)
	if err != nil {
		t.Fatalf("ParseJA4: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion TLS1.2, got %x", cfg.MinVersion)
	}
	if len(cfg.NextProtos) == 0 || cfg.NextProtos[0] != "h2" {
		t.Errorf("expected h2 ALPN, got %v", cfg.NextProtos)
	}
	_ = warnings
}

func TestParseJA4_InvalidFormat(t *testing.T) {
	_, _, err := ParseJA4("notaja4string")
	if err == nil {
		t.Error("expected error for invalid JA4")
	}
}

func TestParseJA4_HTTP1ALPN(t *testing.T) {
	ja4 := "t12d1208h1_abc123def456_fedcba987654"
	cfg, _, err := ParseJA4(ja4)
	if err != nil {
		t.Fatalf("ParseJA4: %v", err)
	}
	if len(cfg.NextProtos) == 0 || cfg.NextProtos[0] != "http/1.1" {
		t.Errorf("expected http/1.1 ALPN, got %v", cfg.NextProtos)
	}
}
