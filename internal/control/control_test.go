package control

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"testing"
)

// the scripted trace below is laid out around a 1ms window
const window = uint64(1_000_000)

var traceCSV = flag.String("window-csv", "", "write the window-reset trace to this CSV path (for plotting)")

// sample is one scripted RTT observation on a fake clock.
type sample struct {
	atNs uint64
	rtt  uint64
}

// windowResetScript is deterministic: a 100us sampling cadence over ~3.5 windows
// (window = 1ms). RTT is stable at 200us, then queueing inflates it inside
// window 1, then the window rolls over while RTT is still elevated (minRTT is
// forgotten and rises), then RTT recovers.
func windowResetScript() []sample {
	const (
		step  = uint64(100_000) // 100us between samples
		start = uint64(1_000_000_000)
	)
	rtts := []uint64{
		// window 0: baseline, min settles at 180us
		200_000, 190_000, 180_000, 200_000, 195_000, 185_000, 200_000, 190_000, 200_000, 195_000,
		// window 1: congestion builds (RTT 3x baseline)
		210_000, 300_000, 400_000, 500_000, 600_000, 600_000, 550_000, 500_000, 450_000, 400_000,
		// window 2: still elevated at roll-over, then recovery
		420_000, 380_000, 300_000, 250_000, 220_000, 210_000, 200_000, 200_000, 205_000, 200_000,
		// window 3
		200_000, 195_000, 200_000, 190_000,
	}
	out := make([]sample, len(rtts))
	for i, r := range rtts {
		out[i] = sample{atNs: start + uint64(i)*step, rtt: r}
	}
	return out
}

func TestWindowResetTrace(t *testing.T) {
	var (
		s       State
		results []Result
		script  = windowResetScript()
	)
	for _, smp := range script {
		results = append(results, Step(&s, smp.rtt, smp.atNs, window))
	}

	if *traceCSV != "" {
		writeTrace(t, *traceCSV, script, results)
	}

	// First sample seeds the window: no reset, min == rtt, gradient == 1.
	r0 := results[0]
	if r0.WindowReset || r0.NewMinRTTNs != script[0].rtt || r0.Gradient != 1 {
		t.Fatalf("first sample should seed window, got %+v", r0)
	}
	if r0.OldConcurrencyLimit != InitialConcurrency {
		t.Fatalf("expected initial limit %d, got %d", InitialConcurrency, r0.OldConcurrencyLimit)
	}

	var resets []int
	for i, r := range results {
		// Invariants that hold at every step.
		if r.NewMinRTTNs > script[i].rtt {
			t.Errorf("sample %d: min %d exceeds rtt %d", i, r.NewMinRTTNs, script[i].rtt)
		}
		if r.NewConcurrencyLimit < MinConcurrency || r.NewConcurrencyLimit > MaxConcurrency {
			t.Errorf("sample %d: limit %d outside [%d,%d]", i, r.NewConcurrencyLimit, MinConcurrency, MaxConcurrency)
		}
		if r.Gradient <= 0 || r.Gradient > 1 {
			t.Errorf("sample %d: gradient %f outside (0,1]", i, r.Gradient)
		}
		if r.WindowReset {
			resets = append(resets, i)
			// A reset discards history: new min is exactly the triggering sample,
			// which makes gradient 1 regardless of how bad the RTT is.
			if r.NewMinRTTNs != script[i].rtt || r.Gradient != 1 {
				t.Errorf("sample %d: reset should set min=rtt and gradient=1, got %+v", i, r)
			}
		} else if i > 0 && r.NewMinRTTNs > r.OldMinRTTNs {
			t.Errorf("sample %d: min rose %d -> %d without a window reset", i, r.OldMinRTTNs, r.NewMinRTTNs)
		}
	}

	// 100us cadence, 1ms window, reset is strict ">" so it fires on the 12th
	// sample of each window (1.1ms after start): indices 11, 22, 33.
	want := []int{11, 22, 33}
	if fmt.Sprint(resets) != fmt.Sprint(want) {
		t.Fatalf("window resets at %v, want %v", resets, want)
	}

	// Before the first reset min is the true floor (180us); at the reset it
	// jumps to the inflated RTT of the triggering sample.
	if got := results[11].OldMinRTTNs; got != 180_000 {
		t.Errorf("old min at first reset = %d, want 180000", got)
	}
	if got := results[11].NewMinRTTNs; got != script[11].rtt {
		t.Errorf("new min at first reset = %d, want %d", got, script[11].rtt)
	}

	// Inside a window, rising RTT against a fixed min drives gradient < 1.
	if results[14].Gradient >= results[11].Gradient {
		t.Errorf("gradient should fall as RTT rises within a window")
	}
}

func writeTrace(t *testing.T, path string, script []sample, results []Result) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"Index", "ElapsedNs", "RTTNs", "WindowReset", "OldMinRTTNs", "NewMinRTTNs", "Gradient", "OldConcurrencyLimit", "NewConcurrencyLimit"})
	for i, r := range results {
		w.Write([]string{
			fmt.Sprint(i),
			fmt.Sprint(script[i].atNs - script[0].atNs),
			fmt.Sprint(script[i].rtt),
			fmt.Sprint(r.WindowReset),
			fmt.Sprint(r.OldMinRTTNs),
			fmt.Sprint(r.NewMinRTTNs),
			fmt.Sprintf("%.5f", r.Gradient),
			fmt.Sprint(r.OldConcurrencyLimit),
			fmt.Sprint(r.NewConcurrencyLimit),
		})
	}
}

func TestLimitClamped(t *testing.T) {
	var s State
	// healthy: gradient 1 grows the limit until it saturates at the cap
	for i := 0; i < 1000; i++ {
		Step(&s, 1_000_000, uint64(i+1)*100, window)
	}
	if s.ConcurrencyLimit != MaxConcurrency {
		t.Fatalf("limit %d, want cap %d", s.ConcurrencyLimit, MaxConcurrency)
	}
	// congested: latency far above the window minimum drives it to the floor
	for i := 0; i < 50; i++ {
		Step(&s, 100_000_000, uint64(1000+i)*100, window)
	}
	if s.ConcurrencyLimit != MinConcurrency {
		t.Fatalf("limit %d, want floor %d", s.ConcurrencyLimit, MinConcurrency)
	}
}

func TestAggregator(t *testing.T) {
	var a Aggregator
	if _, _, ok := a.Flush(); ok {
		t.Fatal("empty aggregator should report no samples")
	}
	for _, v := range []uint64{100, 200, 600} {
		a.Add(v)
	}
	if mean, n, ok := a.Flush(); !ok || mean != 300 || n != 3 {
		t.Fatalf("got mean=%d n=%d ok=%v, want 300 3 true", mean, n, ok)
	}
	if _, _, ok := a.Flush(); ok {
		t.Fatal("flush should reset the aggregator")
	}
}

// A burst of stale slow samples shrinks the limit once per tick, not once per
// sample: 100 samples at 2x the minimum move the limit by one gradient step.
func TestTickAggregationDampsBursts(t *testing.T) {
	seed := func() State {
		var s State
		for i := 0; i < 200; i++ {
			Step(&s, 1_000_000, uint64(i+1)*100, window)
		}
		return s
	}
	perEvent, perTick := seed(), seed()
	var agg Aggregator
	for i := 0; i < 100; i++ {
		now := uint64(1000+i) * 100
		Step(&perEvent, 2_000_000, now, window)
		agg.Add(2_000_000)
	}
	mean, _, _ := agg.Flush()
	Step(&perTick, mean, 1100*100, window)

	if perEvent.ConcurrencyLimit != MinConcurrency {
		t.Errorf("per-event limit %d, want it driven to floor %d", perEvent.ConcurrencyLimit, MinConcurrency)
	}
	if perTick.ConcurrencyLimit <= perEvent.ConcurrencyLimit {
		t.Errorf("per-tick limit %d should stay above per-event %d", perTick.ConcurrencyLimit, perEvent.ConcurrencyLimit)
	}
}
