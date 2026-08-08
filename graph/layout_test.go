package graph

import (
	"fmt"
	"testing"
)

// settleLayout steps the given mode over raw until the engine reports it
// settled (or the step cap is hit, which fails the test).
func settleLayout(t *testing.T, le *LayoutEngine, raw RawSnapshot, mode string, pins map[string]Vec) {
	t.Helper()
	modes := map[string]bool{mode: true}
	for i := 0; i < 2000; i++ {
		le.Step(raw, modes, pins, nil, nil)
		if !le.Unsettled(modes) {
			return
		}
	}
	t.Fatalf("layout mode %q did not settle within the step cap", mode)
}

func snapshotPositions(le *LayoutEngine, mode string, raw RawSnapshot) map[string]Vec {
	out := make(map[string]Vec, len(raw.Nodes))
	for _, n := range raw.Nodes {
		out[n.ID()] = le.Position(mode, n.ID())
	}
	return out
}

func smallRawSnapshot() RawSnapshot {
	nodes := make([]Node, 0, 12)
	edges := make([]Edge, 0, 11)
	for i := 0; i < 12; i++ {
		id := "10.0.0." + layoutTestItoa(i+1)
		nodes = append(nodes, Node{IP: id, PacketCount: i + 1})
		if i > 0 {
			edges = append(edges, Edge{From: "10.0.0.1", To: id, PacketCount: i})
		}
	}
	return RawSnapshot{Nodes: nodes, Edges: edges}
}

func layoutTestItoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

// A settled force layout with unchanged inputs must skip relaxation entirely:
// positions come back byte-for-byte identical (no residual jitter drift).
func TestForceSettledSkipsRelaxation(t *testing.T) {
	raw := smallRawSnapshot()
	le := NewLayoutEngine()
	settleLayout(t, le, raw, "force", nil)

	before := snapshotPositions(le, "force", raw)
	modes := map[string]bool{"force": true}
	for i := 0; i < 5; i++ {
		le.Step(raw, modes, nil, nil, nil)
	}
	for id, p := range before {
		if got := le.Position("force", id); got != p {
			t.Fatalf("settled step moved node %s: %v -> %v", id, p, got)
		}
	}
}

// Any change to the inputs must un-settle: a new node reheats the layout, and a
// changed pin must be applied even while settled.
func TestForceSettleGateUnsettles(t *testing.T) {
	raw := smallRawSnapshot()
	le := NewLayoutEngine()
	modes := map[string]bool{"force": true}
	settleLayout(t, le, raw, "force", nil)

	// Adding a node marks the layout unsettled and lays the new node out.
	raw2 := RawSnapshot{Nodes: append(append([]Node{}, raw.Nodes...), Node{IP: "10.0.0.99", PacketCount: 1}), Edges: raw.Edges}
	le.Step(raw2, modes, nil, nil, nil)
	if !le.Unsettled(modes) {
		t.Fatal("adding a node should un-settle the force layout")
	}
	if _, ok := le.positions["force"]["10.0.0.99"]; !ok {
		t.Fatal("new node should have been seeded with a position")
	}

	// Once re-settled, a changed pin position must still be honoured (the skip
	// gate compares pins, so a pin drag forces a real step).
	settleLayout(t, le, raw2, "force", nil)
	pin := Vec{X: 1234, Y: -567}
	le.Step(raw2, modes, map[string]Vec{"10.0.0.5": pin}, nil, nil)
	if got := le.Position("force", "10.0.0.5"); got != pin {
		t.Fatalf("pin change on settled layout was not applied: got %v, want %v", got, pin)
	}
}

// The gravity (clustered-host) mode wraps stepForce, so the same settle gate
// applies: unchanged inputs skip the relaxation pass.
func TestGravitySettledSkipsRelaxation(t *testing.T) {
	raw := smallRawSnapshot()
	le := NewLayoutEngine()
	modes := map[string]bool{"gravity": true}
	settleLayout(t, le, raw, "gravity", nil)

	before := snapshotPositions(le, "gravity", raw)
	for i := 0; i < 5; i++ {
		le.Step(raw, modes, nil, nil, nil)
	}
	for id, p := range before {
		if got := le.Position("gravity", id); got != p {
			t.Fatalf("settled gravity step moved node %s: %v -> %v", id, p, got)
		}
	}
}

// addScanHosts returns a copy of raw with count extra hosts (10.0.1.<start>+)
// hung off the 10.0.0.1 hub, simulating scan-class node arrivals, plus the new
// node IDs.
func addScanHosts(raw RawSnapshot, start, count int) (RawSnapshot, []string) {
	nodes := append([]Node{}, raw.Nodes...)
	edges := append([]Edge{}, raw.Edges...)
	ids := make([]string, 0, count)
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("10.0.1.%d", start+i)
		nodes = append(nodes, Node{IP: id, PacketCount: 1})
		edges = append(edges, Edge{From: "10.0.0.1", To: id, PacketCount: 1})
		ids = append(ids, id)
	}
	return RawSnapshot{Nodes: nodes, Edges: edges}, ids
}

// cooledTemp applies the per-step temperature decay (0.9 per iteration over
// forceIterationsPerStep iterations) to t, in the same order stepForce does.
func cooledTemp(t float64) float64 {
	for i := 0; i < forceIterationsPerStep; i++ {
		t *= 0.9
	}
	return t
}

// During a scan-class burst the already-placed (elder) nodes must stay frozen
// byte-exact while only the newcomers relax, under a capped temperature.
func TestForceBurstFreezesElders(t *testing.T) {
	raw := smallRawSnapshot()
	le := NewLayoutEngine()
	modes := map[string]bool{"force": true}
	settleLayout(t, le, raw, "force", nil)
	elders := snapshotPositions(le, "force", raw)

	assertEldersFrozen := func(where string) {
		t.Helper()
		for id, p := range elders {
			if got := le.Position("force", id); got != p {
				t.Fatalf("%s: elder %s moved during burst: %v -> %v", where, id, p, got)
			}
		}
	}

	// First wave: 30 new nodes in one step (> burstGrowthAbs), so burst mode
	// must engage on this very step and the elders never reheat at all.
	cur, newcomers := addScanHosts(raw, 1, 30)
	le.Step(cur, modes, nil, nil, nil)
	if !le.burst["force"] {
		t.Fatal("expected burst mode after a >threshold node-set jump")
	}
	assertEldersFrozen("first burst wave")
	// The step's temperature was capped at forceReheatTemp*burstTempFactor,
	// not reheated to forceReheatTemp.
	if got, want := le.temp["force"], cooledTemp(forceReheatTemp*burstTempFactor); got != want {
		t.Fatalf("burst step temperature = %v, want capped %v", got, want)
	}

	// Successive waves keep the node set changing: burst persists, elders stay
	// byte-exact frozen.
	for w := 0; w < 4; w++ {
		var ids []string
		cur, ids = addScanHosts(cur, 31+w*3, 3)
		newcomers = append(newcomers, ids...)
		le.Step(cur, modes, nil, nil, nil)
		if !le.burst["force"] {
			t.Fatalf("wave %d: burst mode exited while nodes kept arriving", w)
		}
		assertEldersFrozen(fmt.Sprintf("burst wave %d", w))
	}

	// The newcomers keep relaxing among themselves: at least one must still be
	// moving right after a wave (they were seeded in a tight clump at the hub).
	prev := snapshotPositions(le, "force", cur)
	le.Step(cur, modes, nil, nil, nil)
	moved := false
	for _, id := range newcomers {
		if le.Position("force", id) != prev[id] {
			moved = true
			break
		}
	}
	if !moved {
		t.Fatal("newcomers did not move at all during burst")
	}
	assertEldersFrozen("newcomer relaxation")
}

// Once the node set stays unchanged for burstStableSteps consecutive steps,
// burst mode must exit with exactly ONE gentle reheat: the elders move again,
// the graph re-settles, and then the settle gate resumes (no further drift).
func TestForceBurstExitReheatsOnce(t *testing.T) {
	raw := smallRawSnapshot()
	le := NewLayoutEngine()
	modes := map[string]bool{"force": true}
	settleLayout(t, le, raw, "force", nil)

	cur, _ := addScanHosts(raw, 1, 30)
	le.Step(cur, modes, nil, nil, nil)
	if !le.burst["force"] {
		t.Fatal("expected burst mode after a >threshold node-set jump")
	}

	// Steps 1..burstStableSteps-1 with an unchanged node set: still in burst.
	for i := 1; i < burstStableSteps; i++ {
		le.Step(cur, modes, nil, nil, nil)
		if !le.burst["force"] {
			t.Fatalf("burst exited after only %d stable steps, want %d", i, burstStableSteps)
		}
	}
	frozen := snapshotPositions(le, "force", cur)

	// The burstStableSteps-th stable step exits burst mode and reheats once.
	le.Step(cur, modes, nil, nil, nil)
	if le.burst["force"] {
		t.Fatalf("burst should have exited after %d stable steps", burstStableSteps)
	}
	moved := false
	for id, p := range frozen {
		if got := le.Position("force", id); got != p {
			moved = true
			break
		}
	}
	if !moved {
		t.Fatal("burst exit should reheat the graph once (elders move again)")
	}

	// After re-settling, further steps must be byte-exact no-ops: exactly one
	// reheat happened, and the settle gate resumed.
	settleLayout(t, le, cur, "force", nil)
	settled := snapshotPositions(le, "force", cur)
	for i := 0; i < 20; i++ {
		le.Step(cur, modes, nil, nil, nil)
	}
	for id, p := range settled {
		if got := le.Position("force", id); got != p {
			t.Fatalf("unexpected second reheat after burst exit moved node %s: %v -> %v", id, p, got)
		}
	}
	if le.burst["force"] {
		t.Fatal("burst mode re-entered with a stable node set")
	}
}

// Trickling in a couple of nodes at a time (below both burst triggers, thanks
// to the absolute floor on the percentage trigger) must behave exactly as
// before: no burst mode, and the normal reheat to forceReheatTemp still fires.
func TestForceSmallAddDoesNotBurst(t *testing.T) {
	raw := smallRawSnapshot()
	le := NewLayoutEngine()
	modes := map[string]bool{"force": true}
	settleLayout(t, le, raw, "force", nil)

	cur := raw
	for w := 0; w < 4; w++ {
		cur, _ = addScanHosts(cur, 1+w*2, 2)
		le.Step(cur, modes, nil, nil, nil)
		if le.burst["force"] {
			t.Fatalf("wave %d: adding 2 nodes triggered burst mode", w)
		}
		if le.settled["force"] {
			t.Fatalf("wave %d: adding nodes should un-settle the layout", w)
		}
		// The pre-burst reheat path sets temp to forceReheatTemp, which then
		// decays over the step's iterations.
		if got, want := le.temp["force"], cooledTemp(forceReheatTemp); got != want {
			t.Fatalf("wave %d: temperature after small add = %v, want reheated %v", w, got, want)
		}
	}
}
