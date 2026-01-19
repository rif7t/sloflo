package main

//go:generate go tool bpf2go -tags linux rlimit ../../ebpf/rlimit.c

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type ControlState struct {
	MinRTTNs         uint64
	ConcurrencyLimit uint32
	Inflight         uint32
	LatestRTTNs      uint64
	WindowMinRTTNs   uint64
	WindowStartNS    uint64
}

const (
	MinConcurrency     = 8
	MaxConcurrency     = 250
	InitialConcurrency = 20
	RTTWindowNs        = uint64(0.001 * 1e9)
)

func main() {
	var objs rlimitObjects
	err := loadRlimitObjects(&objs, nil)
	if err != nil {
		log.Fatalf("failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	var zero uint32 = 0
	var initial uint64 = 0

	if err := objs.InflightTotal.Update(&zero, &initial, 0); err != nil {
		log.Fatalf("init control_map failed: %v", err)
	}

	reader, err := ringbuf.NewReader(objs.LatencyEvents)
	if err != nil {
		log.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer reader.Close()

	recordCh := make(chan *ringbuf.Record)
	go func() {
		defer close(recordCh)
		for {
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}
			recordCh <- &record
		}
	}()

	ifsource, _ := os.Open("/proc/net/route")
	defer ifsource.Close()

	scanner := bufio.NewScanner(ifsource)
	scanner.Scan()
	var ifname string
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if fields[1] == "00000000" {
			ifname = fields[0]
		}
	}
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("interface not found: %v", err)
	}

	xdp_rate_limiter_link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpRateLimiter,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("failed to attach XDP program: %v", err)
	}
	defer xdp_rate_limiter_link.Close()

	tcp_rcv_established_link, err := link.AttachTracing(link.TracingOptions{
		Program: objs.FentryTcpRcvEstablished,
	})
	if err != nil {
		log.Fatalf("load tcp_rcv_established kprobe: %v", err)
	}
	defer tcp_rcv_established_link.Close()

	tcp_set_state_link, err := link.AttachTracing(link.TracingOptions{
		Program: objs.FentryTcpSetState,
	})
	if err != nil {
		log.Fatalf("load tcp set state kprobe: %v", err)
	}
	defer tcp_set_state_link.Close()

	fmt.Println("Listening for packet events...")

	f, err := os.Create("rlimit_results.csv")
	if err != nil {
		log.Fatalf("failed to create results file: %v", err)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	header := []string{"TimeStamp", "LatestRTTNs", "Gradient", "MinRTTNs", "Inflight", "ConcurrencyLimit"}
	if err := writer.Write(header); err != nil {
		log.Fatalf("failed to write CSV header: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})

	go func() {
		<-sigCh
		close(done)
	}()

	for {
		select {
		case <-done:
			reader.Close()
			fmt.Println("Exiting")
			return
		case record := <-recordCh:
			var rtt uint64
			if err := binary.Read(
				bytes.NewReader(record.RawSample),
				binary.LittleEndian,
				&rtt,
			); err != nil {
				continue
			}
			var (
				key   uint32 = 0
				state ControlState
			)

			err = objs.ControlMap.Lookup(&key, &state)
			if err != nil {
				log.Fatalf("lookup control_state failed: %v", err)
			}
			now := uint64(time.Now().UnixNano())

			if state.WindowStartNS == 0 {
				state.WindowStartNS = now
				state.WindowMinRTTNs = rtt
			}

			if now-state.WindowStartNS > RTTWindowNs {
				state.MinRTTNs = state.WindowMinRTTNs
				state.WindowStartNS = now
				state.WindowMinRTTNs = rtt
			} else {
				if state.WindowMinRTTNs == 0 || rtt < state.WindowMinRTTNs {
					state.WindowMinRTTNs = rtt
				}
			}
			state.MinRTTNs = state.WindowMinRTTNs
			state.LatestRTTNs = rtt

			if state.ConcurrencyLimit <= 0 {
				state.ConcurrencyLimit = InitialConcurrency
			}

			gradient := float64(state.MinRTTNs) / float64(rtt)

			var zero uint32
			var inflight_total uint64
			err = objs.InflightTotal.Lookup(&zero, &inflight_total)

			if err != nil {
				log.Fatalf("error reading total inflight: %v", err)
			}

			state.Inflight = uint32(inflight_total)
			state.ConcurrencyLimit = uint32(uint64(float64(state.ConcurrencyLimit)*gradient) + uint64(math.Sqrt(float64(state.ConcurrencyLimit))))
			err = objs.ControlMap.Update(&key, &state, ebpf.UpdateAny)
			if err != nil {
				log.Fatalf("update control_map failed: %v", err)
			}

			writer.Write([]string{
				fmt.Sprintf("%d", time.Now().UnixNano()),
				fmt.Sprintf("%d", rtt),
				fmt.Sprintf("%.5f", gradient),
				fmt.Sprintf("%d", state.MinRTTNs),
				fmt.Sprintf("%d", inflight_total),
				fmt.Sprintf("%d", state.ConcurrencyLimit),
			})
			writer.Flush()
			fmt.Printf("LatestRTT: %d ns, Gradient: %.5f, MinRTT: %d, Inflight: %d, New Concurrency Limit: %d\n", rtt, gradient, state.MinRTTNs, inflight_total, state.ConcurrencyLimit)
		}
	}

}
