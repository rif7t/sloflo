// Package control holds the pure windowed-minRTT / gradient logic so it can be
// exercised without eBPF or root.
package control

import "math"

const (
	MinConcurrency     = 8
	MaxConcurrency     = 250
	InitialConcurrency = 20
)

// State is the subset of the kernel control state that Step reads and writes.
type State struct {
	WindowStartNS    uint64
	WindowMinRTTNs   uint64
	MinRTTNs         uint64
	ConcurrencyLimit uint32
}

// Result describes what a single Step did.
type Result struct {
	WindowReset         bool
	OldMinRTTNs         uint64
	NewMinRTTNs         uint64
	Gradient            float64
	OldConcurrencyLimit uint32
	NewConcurrencyLimit uint32
}

// Step applies one latency sample observed at time now (ns) to the state.
// window (ns) is how long a minimum is trusted before it is forgotten.
func Step(s *State, rtt, now, window uint64) Result {
	windowReset := s.WindowStartNS != 0 && now-s.WindowStartNS > window
	oldMinRTTNs := s.WindowMinRTTNs

	if s.WindowStartNS == 0 {
		s.WindowStartNS = now
		s.WindowMinRTTNs = rtt
	}

	if windowReset {
		s.WindowStartNS = now
		s.WindowMinRTTNs = rtt
	} else {
		if s.WindowMinRTTNs == 0 || rtt < s.WindowMinRTTNs {
			s.WindowMinRTTNs = rtt
		}
	}
	s.MinRTTNs = s.WindowMinRTTNs

	if s.ConcurrencyLimit <= 0 {
		s.ConcurrencyLimit = InitialConcurrency
	}
	oldLimit := s.ConcurrencyLimit

	gradient := float64(s.MinRTTNs) / float64(rtt)
	limit := uint64(float64(s.ConcurrencyLimit)*gradient) + uint64(math.Sqrt(float64(s.ConcurrencyLimit)))
	s.ConcurrencyLimit = uint32(min(max(limit, MinConcurrency), MaxConcurrency))

	return Result{
		WindowReset:         windowReset,
		OldMinRTTNs:         oldMinRTTNs,
		NewMinRTTNs:         s.MinRTTNs,
		Gradient:            gradient,
		OldConcurrencyLimit: oldLimit,
		NewConcurrencyLimit: s.ConcurrencyLimit,
	}
}

// Aggregator collects the latency samples seen during one control tick so Step
// runs once per tick on their mean, rather than once per sample. Per-sample
// updates react to feedback that is a full service time stale and swing the
// limit between its bounds.
type Aggregator struct {
	sum uint64
	n   uint64
}

func (a *Aggregator) Add(rtt uint64) {
	a.sum += rtt
	a.n++
}

// Flush returns the mean and count of the samples added since the last Flush;
// ok is false when there were none.
func (a *Aggregator) Flush() (mean, n uint64, ok bool) {
	if a.n == 0 {
		return 0, 0, false
	}
	mean, n = a.sum/a.n, a.n
	*a = Aggregator{}
	return mean, n, true
}
