package mimicry

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// ParseJA4 converts a JA4 fingerprint string into a crypto/tls.Config that approximates
// the fingerprint. Returns the config, a list of warnings for any fields that couldn't
// be replicated exactly, and an error if the JA4 string is malformed.
func ParseJA4(ja4 string) (*tls.Config, []string, error) {
	// JA4 format: t<ver><sni><numCS><numExt><alpn>_<cs_hash>_<ext_hash>
	// e.g.       t13d1516h2_8daaf6152771_e5627efa2ab1
	parts := strings.Split(ja4, "_")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid JA4: expected 3 underscore-separated parts, got %d", len(parts))
	}

	prefix := parts[0]
	// prefix must start with 't' (TCP) and have at least 9 chars:
	// t + 2(ver) + 1(sni) + 2(numCS) + 2(numExt) + 2(alpn) = 10
	if len(prefix) < 9 || prefix[0] != 't' {
		return nil, nil, fmt.Errorf("invalid JA4 prefix: %q", prefix)
	}

	tlsVerStr := prefix[1:3]
	alpnCode := prefix[8:]

	cfg := &tls.Config{}
	var warnings []string

	switch tlsVerStr {
	case "13":
		cfg.MinVersion = tls.VersionTLS12
		cfg.MaxVersion = tls.VersionTLS13
	case "12":
		cfg.MinVersion = tls.VersionTLS12
		cfg.MaxVersion = tls.VersionTLS12
	default:
		cfg.MinVersion = tls.VersionTLS12
		warnings = append(warnings, fmt.Sprintf("unknown TLS version %q in JA4; defaulting to TLS1.2+", tlsVerStr))
	}

	switch alpnCode {
	case "h2":
		cfg.NextProtos = []string{"h2", "http/1.1"}
	case "h1":
		cfg.NextProtos = []string{"http/1.1"}
	case "00":
		// no ALPN
	default:
		cfg.NextProtos = []string{"http/1.1"}
		warnings = append(warnings, fmt.Sprintf("unknown ALPN code %q in JA4; defaulting to http/1.1", alpnCode))
	}

	// Cipher suites cannot be reconstructed from the hash without a lookup table.
	warnings = append(warnings, "cipher suite list uses Go defaults (JA4 hash not reversible without lookup table)")

	return cfg, warnings, nil
}
