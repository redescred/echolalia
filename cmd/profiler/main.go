package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Emul4nt/echolalia/profiler"
)

func main() {
	duration := flag.Duration("duration", 60*time.Second, "capture duration")
	output := flag.String("output", "", "output file path (default: stdout)")
	flag.Parse()

	log.Printf("[echolalia-profiler] capturing for %s...", *duration)

	ctx := context.Background()
	profile, err := profiler.Profile(ctx, *duration)
	if err != nil {
		log.Fatalf("profile failed: %v", err)
	}

	data, err := profile.JSON()
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}

	if *output == "" {
		fmt.Println(string(data))
		return
	}

	f, err := os.Create(*output)
	if err != nil {
		log.Fatalf("create %s: %v", *output, err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		log.Fatalf("write: %v", err)
	}
	log.Printf("[echolalia-profiler] profile written to %s", *output)
}
