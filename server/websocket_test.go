package server

import (
	"math/rand"
	"sort"
	"testing"
	"time"

	"etherchimp/graph"
)

// topKFlows must return the same flows as the first k of a full stable
// descending sort by Packets (the old hub behavior), including under ties.
func TestTopKFlowsMatchesFullSort(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	const k = 60

	makeFlows := func(n int, maxPackets int) []graph.TrafficFlow {
		flows := make([]graph.TrafficFlow, n)
		for i := range flows {
			flows[i] = graph.TrafficFlow{
				EdgeID:  string(rune('a'+i%26)) + string(rune('A'+i/26)),
				Packets: rng.Intn(maxPackets) + 1,
				Bytes:   int64(rng.Intn(1 << 20)),
			}
		}
		return flows
	}

	stableTopK := func(flows []graph.TrafficFlow) []graph.TrafficFlow {
		cp := make([]graph.TrafficFlow, len(flows))
		copy(cp, flows)
		sort.SliceStable(cp, func(a, b int) bool { return cp[a].Packets > cp[b].Packets })
		if len(cp) > k {
			cp = cp[:k]
		}
		return cp
	}

	cases := []struct {
		name       string
		n          int
		maxPackets int
	}{
		{"fewer than k", k - 10, 1000},
		{"exactly k", k, 1000},
		{"many more than k", 5000, 10000},
		{"heavy ties", 3000, 5}, // only 5 distinct packet counts
		{"all equal", 2000, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := makeFlows(tc.n, tc.maxPackets)
			got := topKFlows(flows, k)
			if tc.n <= k {
				// Within the cap the slice passes through untouched
				// (the old code never sorted in this case).
				if len(got) != len(flows) {
					t.Fatalf("got %d flows, want %d (passthrough)", len(got), len(flows))
				}
				for i := range got {
					if got[i] != flows[i] {
						t.Fatalf("passthrough reordered at %d: %+v vs %+v", i, got[i], flows[i])
					}
				}
				return
			}
			want := stableTopK(flows)
			if len(got) != k {
				t.Fatalf("got %d flows, want %d", len(got), k)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("mismatch at %d: got %+v, want %+v", i, got[i], want[i])
				}
			}
		})
	}
}

// Nothing kept may have fewer packets than anything dropped.
func TestTopKFlowsKeepsBusiest(t *testing.T) {
	const k = 60
	flows := make([]graph.TrafficFlow, 0, 1000)
	for i := 0; i < 1000; i++ {
		flows = append(flows, graph.TrafficFlow{EdgeID: string(rune(i)), Packets: i})
	}
	got := topKFlows(flows, k)
	if len(got) != k {
		t.Fatalf("got %d flows, want %d", len(got), k)
	}
	kept := make(map[int]bool, k)
	for _, f := range got {
		kept[f.Packets] = true
	}
	for _, f := range flows {
		if f.Packets >= 1000-k && !kept[f.Packets] {
			t.Fatalf("busiest flow (packets=%d) dropped", f.Packets)
		}
	}
	// Descending order.
	for i := 1; i < len(got); i++ {
		if got[i-1].Packets < got[i].Packets {
			t.Fatalf("not descending at %d: %d < %d", i, got[i-1].Packets, got[i].Packets)
		}
	}
}

// pacingBand maps the tick-cost EMA onto cadence bands at the documented
// boundaries: <50ms → fast, 50–80ms → busy, >80ms → max.
func TestPacingBand(t *testing.T) {
	cases := []struct {
		ema  time.Duration
		want time.Duration
	}{
		{0, tickIntervalFast},
		{tickEMAMedium - time.Millisecond, tickIntervalFast},
		{tickEMAMedium, tickIntervalBusy}, // 50ms is in the busy band
		{tickEMAHigh, tickIntervalBusy},   // 80ms is still busy (>80 → max)
		{tickEMAHigh + time.Millisecond, tickIntervalMax},
		{500 * time.Millisecond, tickIntervalMax},
	}
	for _, tc := range cases {
		if got := pacingBand(tc.ema); got != tc.want {
			t.Errorf("pacingBand(%v) = %v, want %v", tc.ema, got, tc.want)
		}
	}
}

// tickPacer steps up immediately when the EMA crosses into a higher band, but
// steps down only after the EMA has held in the lower band for
// pacingHysteresis — and a relapse resets that hold timer. Driven with a fake
// clock, so it's deterministic.
func TestTickPacer(t *testing.T) {
	now := time.Now()
	p := tickPacer{interval: tickIntervalFast}
	next := func(ema time.Duration) time.Duration {
		now = now.Add(100 * time.Millisecond)
		return p.next(ema, now)
	}

	// Cheap ticks stay at the fast cadence.
	if got := next(10 * time.Millisecond); got != tickIntervalFast {
		t.Fatalf("cheap EMA: got %v, want %v", got, tickIntervalFast)
	}
	// Crossing the medium threshold steps up immediately.
	if got := next(67 * time.Millisecond); got != tickIntervalBusy {
		t.Fatalf("medium EMA: got %v, want %v", got, tickIntervalBusy)
	}
	// Crossing the high threshold steps up immediately too.
	if got := next(90 * time.Millisecond); got != tickIntervalMax {
		t.Fatalf("high EMA: got %v, want %v", got, tickIntervalMax)
	}
	// EMA back in the fast band: NO immediate step-down (hysteresis).
	if got := next(10 * time.Millisecond); got != tickIntervalMax {
		t.Fatalf("step-down must wait: got %v, want %v", got, tickIntervalMax)
	}
	// Held below the threshold for just under pacingHysteresis: still max.
	for i := 0; i < int(pacingHysteresis/(100*time.Millisecond))-2; i++ {
		next(10 * time.Millisecond)
	}
	if got := next(10 * time.Millisecond); got != tickIntervalMax {
		t.Fatalf("step-down before hysteresis elapsed: got %v, want %v", got, tickIntervalMax)
	}
	// A relapse into the current band resets the hold timer...
	if got := next(90 * time.Millisecond); got != tickIntervalMax {
		t.Fatalf("relapse: got %v, want %v", got, tickIntervalMax)
	}
	// ...so another ~2s of low EMA is required before stepping down.
	for i := 0; i < int(pacingHysteresis/(100*time.Millisecond))-1; i++ {
		next(10 * time.Millisecond)
	}
	if got := next(10 * time.Millisecond); got != tickIntervalMax {
		t.Fatalf("step-down before renewed hysteresis elapsed: got %v, want %v", got, tickIntervalMax)
	}
	// Hysteresis elapsed: step straight down to the EMA's band.
	if got := next(10 * time.Millisecond); got != tickIntervalFast {
		t.Fatalf("step-down after hysteresis: got %v, want %v", got, tickIntervalFast)
	}
	// And from busy, a medium-band EMA held long enough steps down one band.
	if got := next(67 * time.Millisecond); got != tickIntervalBusy {
		t.Fatalf("medium EMA: got %v, want %v", got, tickIntervalBusy)
	}
	for i := 0; i < int(pacingHysteresis/(100*time.Millisecond)); i++ {
		next(10 * time.Millisecond)
	}
	if got := next(10 * time.Millisecond); got != tickIntervalFast {
		t.Fatalf("busy→fast after hysteresis: got %v, want %v", got, tickIntervalFast)
	}
}
