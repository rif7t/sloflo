package main

//go:generate go tool bpf2go -tags linux rlimit ../../ebpf/rlimit.c

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type ControlState struct {
	MinRTTNs         uint64
	ConcurrencyLimit uint32
	Inflight         uint32
	LatestRTTNs      uint64
}

const (
	MinConcurrency     = 30
	MaxConcurrency     = 150
	InitialConcurrency = 50
)

func main() {
	var objs rlimitObjects
	err := loadRlimitObjects(&objs, nil)
	if err != nil {
		log.Fatalf("failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	var zero uint32 = 0
	initial := ControlState{
		ConcurrencyLimit: InitialConcurrency,
	}

	if err := objs.ControlMap.Update(&zero, &initial, 0); err != nil {
		log.Fatalf("init control_map failed: %v", err)
	}

	// Verify initialization
	var verifyState ControlState
	if err := objs.ControlMap.Lookup(&zero, &verifyState); err != nil {
		log.Fatalf("verify control_map failed: %v", err)
	}
	fmt.Printf("ControlMap initialized: inflight=%d, concurrency_limit=%d\n", verifyState.Inflight, verifyState.ConcurrencyLimit)

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

	iface, err := net.InterfaceByName("wlp0s20f3")
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

	inet_csk_accept_link, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TraceInetSockSetState, nil)
	if err != nil {
		log.Fatalf("load inet_sock_set_state tracepoint: %v", err)
	}
	defer inet_csk_accept_link.Close()

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
			if state.MinRTTNs == 0 || rtt < state.MinRTTNs {
				state.MinRTTNs = rtt
			}
			if state.ConcurrencyLimit <= 0 {
				state.ConcurrencyLimit = InitialConcurrency
			}

			gradient := float64(state.MinRTTNs) / float64(rtt)

			switch {
			case gradient > 0.95:
				state.ConcurrencyLimit++
			case gradient < 0.70:
				if state.ConcurrencyLimit > 1 {
					var limit = state.ConcurrencyLimit
					state.ConcurrencyLimit = limit * 6 / 10
				}
			}

			if state.ConcurrencyLimit < MinConcurrency {
				state.ConcurrencyLimit = MinConcurrency
			} else if state.ConcurrencyLimit > MaxConcurrency {
				state.ConcurrencyLimit = MaxConcurrency
			}

			writer.Write([]string{
				fmt.Sprintf("%d", time.Now().UnixNano()),
				fmt.Sprintf("%d", rtt),
				fmt.Sprintf("%.5f", gradient),
				fmt.Sprintf("%d", state.MinRTTNs),
				fmt.Sprintf("%d", state.Inflight),
				fmt.Sprintf("%d", state.ConcurrencyLimit),
			})
			writer.Flush()
			state.LatestRTTNs = rtt

			err = objs.ControlMap.Update(&key, &state, 0)
			if err != nil {
				log.Fatalf("update control_map failed: %v", err)
			}

			fmt.Printf("LatestRTT: %d ns, Gradient: %.5f, MinRTT: %d, Inflight: %d, New Concurrency Limit: %d\n", rtt, gradient, state.MinRTTNs, state.Inflight, state.ConcurrencyLimit)
		}
	}

}
