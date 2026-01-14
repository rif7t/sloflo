# AI Coding Guidelines for sloflo

## Project Overview
sloflo is an SLO-guided network rate limiter using eBPF. It dynamically adjusts TCP connection concurrency limits based on latency gradients to maintain service level objectives.

## Architecture
- **eBPF Kernel Components** (`ebpf/rlimit.c`): XDP program for packet dropping, kprobes for TCP event tracing
- **Go User Space** (`cmd/rlimit/main.go`): Control loop reading latency events, adjusting concurrency via gradient-based algorithm
- **Data Flow**: TCP RTT measurements → ringbuffer → Go analysis → eBPF map updates → XDP enforcement

## Build Process
```bash
cd cmd/rlimit
go generate  # Generates eBPF object files (rlimit_bpfeb.go, rlimit_bpfel.go)
go build     # Produces rlimit binary
```

## Key Patterns
- **Concurrency Control**: Gradient = minRTT/currentRTT; >0.9 increases limit, <0.75 decreases by 30%
- **eBPF Maps**: `control_map` (array[1]) for global state, `sock_to_cs` (hash) for per-socket control states
- **RTT Measurement**: From `tcp_sock.srtt_us` in `tcp_rcv_established` kprobe, converted to nanoseconds
- **State Management**: `mark_active()` increments inflight, `decay_if_stalled()` decrements after 5s inactivity

## Development Workflow
- Modify `ebpf/rlimit.c` for kernel logic, run `go generate` to regenerate Go bindings
- Test with `rlimit_results.csv` output and console logs showing RTT/gradient/concurrency changes
- Interface hardcoded as "wlp0s20f3" - update for different networks

## Dependencies
- `github.com/cilium/ebpf` for eBPF operations
- `bpf2go` tool for code generation from C to Go
- Requires kernel eBPF support and CAP_SYS_ADMIN

## Conventions
- Concurrency bounds: 5-40 (MinConcurrency/MaxConcurrency constants)
- Stall timeout: 5 seconds (STALL_NS)
- XDP mode: Generic (works on most NICs, less performant than native)</content>
<parameter name="filePath">/home/rif7t/ebpf-tools/sloflo/.github/copilot-instructions.md