package main

//go:generate go tool bpf2go -tags linux rlimit ../../ebpf/rlimit.c

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/rif7t/slowflo/internal/control"
)

type ControlState struct {
	MinRTTNs         uint64
	ConcurrencyLimit uint32
	Inflight         uint32
	LatestRTTNs      uint64
	WindowMinRTTNs   uint64
	WindowStartNS    uint64
}

var observeOnly = flag.Bool("observe-only", false, "skip attaching the XDP packet dropper")
var ifaceName = flag.String("iface", "", "interface to attach XDP to (default: the default-route interface)")
var window = flag.Duration("window", 5*time.Second, "how long a minimum latency is trusted before it is forgotten")
var tick = flag.Duration("tick", 100*time.Millisecond, "control interval: latency samples are averaged and the limit updated once per tick")
var serverAddr = flag.String("server-addr", "", "only measure/police the server listening on this local IPv4 address (default: any address on the port)")
var csvPath = flag.String("csv", "rlimit_results.csv", "path for the control-loop CSV trace")

func main() {
	flag.Parse()

	spec, err := loadRlimit()
	if err != nil {
		log.Fatalf("failed to load eBPF spec: %v", err)
	}
	if *serverAddr != "" {
		ip := net.ParseIP(*serverAddr).To4()
		if ip == nil {
			log.Fatalf("-server-addr %q is not an IPv4 address", *serverAddr)
		}
		// skc_rcv_saddr is stored in network byte order
		if err := spec.Variables["target_addr"].Set(binary.NativeEndian.Uint32(ip)); err != nil {
			log.Fatalf("set target_addr: %v", err)
		}
	}
	var objs rlimitObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
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

	ifname := *ifaceName
	if ifname == "" {
		ifsource, _ := os.Open("/proc/net/route")
		defer ifsource.Close()

		scanner := bufio.NewScanner(ifsource)
		scanner.Scan()
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if fields[1] == "00000000" {
				ifname = fields[0]
			}
		}
	}
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("interface not found: %v", err)
	}

	if !*observeOnly {
		xdpRateLimiterLink, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpRateLimiter,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			log.Fatalf("failed to attach XDP program: %v", err)
		}
		defer xdpRateLimiterLink.Close()
	} else {
		fmt.Println("Observe-only mode: XDP packet dropping is disabled")
	}

	tcp_rcv_established_link, err := link.AttachTracing(link.TracingOptions{
		Program: objs.FentryTcpRcvEstablished,
	})
	if err != nil {
		log.Fatalf("load tcp_rcv_established kprobe: %v", err)
	}
	defer tcp_rcv_established_link.Close()

	tcp_sendmsg_link, err := link.AttachTracing(link.TracingOptions{
		Program: objs.FentryTcpSendmsg,
	})
	if err != nil {
		log.Fatalf("attach tcp_sendmsg fentry: %v", err)
	}
	defer tcp_sendmsg_link.Close()

	tcp_set_state_link, err := link.AttachTracing(link.TracingOptions{
		Program: objs.FentryTcpSetState,
	})
	if err != nil {
		log.Fatalf("load tcp set state kprobe: %v", err)
	}
	defer tcp_set_state_link.Close()

	fmt.Println("Listening for packet events...")

	f, err := os.Create(*csvPath)
	if err != nil {
		log.Fatalf("failed to create results file: %v", err)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	header := []string{
		"TimeStamp", "LatestRTTNs", "Gradient", "MinRTTNs", "Inflight", "ConcurrencyLimit",
		"WindowReset", "OldMinRTTNs", "NewMinRTTNs", "OldConcurrencyLimit", "NewConcurrencyLimit", "Samples",
	}
	if err := writer.Write(header); err != nil {
		log.Fatalf("failed to write CSV header: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})
	startTime := time.Now()

	go func() {
		<-sigCh
		close(done)
	}()

	ticker := time.NewTicker(*tick)
	defer ticker.Stop()
	var agg control.Aggregator

	for {
		select {
		case <-done:
			reader.Close()
			fmt.Println("Exiting")
			return
		case record, ok := <-recordCh:
			if !ok {
				return
			}
			var rtt uint64
			if err := binary.Read(
				bytes.NewReader(record.RawSample),
				binary.LittleEndian,
				&rtt,
			); err != nil {
				continue
			}
			agg.Add(rtt)
		case <-ticker.C:
			rtt, samples, ok := agg.Flush()
			if !ok {
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
			cs := control.State{
				WindowStartNS:    state.WindowStartNS,
				WindowMinRTTNs:   state.WindowMinRTTNs,
				MinRTTNs:         state.MinRTTNs,
				ConcurrencyLimit: state.ConcurrencyLimit,
			}
			res := control.Step(&cs, rtt, now, uint64(window.Nanoseconds()))
			state.WindowStartNS = cs.WindowStartNS
			state.WindowMinRTTNs = cs.WindowMinRTTNs
			state.MinRTTNs = cs.MinRTTNs
			state.LatestRTTNs = rtt
			windowReset, oldMinRTTNs := res.WindowReset, res.OldMinRTTNs
			oldConcurrencyLimit, gradient := res.OldConcurrencyLimit, res.Gradient

			var zero uint32
			var inflight_total uint64
			err = objs.InflightTotal.Lookup(&zero, &inflight_total)

			if err != nil {
				log.Fatalf("error reading total inflight: %v", err)
			}

			state.Inflight = uint32(inflight_total)
			state.ConcurrencyLimit = cs.ConcurrencyLimit
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
				fmt.Sprintf("%t", windowReset),
				fmt.Sprintf("%d", oldMinRTTNs),
				fmt.Sprintf("%d", state.MinRTTNs),
				fmt.Sprintf("%d", oldConcurrencyLimit),
				fmt.Sprintf("%d", state.ConcurrencyLimit),
				fmt.Sprintf("%d", samples),
			})
			writer.Flush()
			fmt.Printf("Elapsed: %s, WindowReset: %t, Latency: %d ns (%d samples), MinLatency: %d -> %d ns, Gradient: %.5f, Limit: %d -> %d, Inflight: %d\n",
				time.Since(startTime).Round(time.Millisecond), windowReset, rtt, samples, oldMinRTTNs,
				state.MinRTTNs, gradient, oldConcurrencyLimit, state.ConcurrencyLimit, inflight_total)
		}
	}

}
