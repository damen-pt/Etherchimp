package graph

import (
	"testing"
	"time"
)

func TestClassifyNode(t *testing.T) {
	peers := func(n int) map[string]struct{} {
		m := make(map[string]struct{}, n)
		for i := 0; i < n; i++ {
			m[string(rune('a'+i))] = struct{}{}
		}
		return m
	}

	cases := []struct {
		name string
		n    Node
		want string
	}{
		{"group", Node{IsGroup: true, InPackets: 5}, "multicast"},
		{"gateway by fanout", Node{Peers: peers(20), InPackets: 100, OutPackets: 100}, "gateway"},
		{"server on low port", Node{ListenPorts: map[uint16]int{443: 50}, InPackets: 80, OutPackets: 40, Peers: peers(3)}, "server"},
		{"iot single peer", Node{Peers: peers(1), InPackets: 2, OutPackets: 3}, "iot"},
		{"client default", Node{Peers: peers(4), OutPackets: 50, InPackets: 10}, "client"},
		{"unknown no traffic", Node{}, "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			role, icon := classifyNode(&c.n)
			if role != c.want {
				t.Errorf("role = %q, want %q", role, c.want)
			}
			if icon != roleIcons[c.want] {
				t.Errorf("icon = %q, want %q", icon, roleIcons[c.want])
			}
		})
	}
}

// clientNode returns a node whose stats classify it as a plain "client".
func clientNode() *Node {
	return &Node{
		IP:         "10.0.0.1",
		InPackets:  10,
		OutPackets: 50,
		Peers:      map[string]struct{}{"a": {}, "b": {}},
	}
}

// makeScanner adds gatewayFanout peers so the node classifies as "gateway".
func makeScanner(n *Node) {
	for i := 0; i < gatewayFanout+4; i++ {
		n.Peers[string(rune('A'+i))] = struct{}{}
	}
}

func TestCommitRoleFirstClassificationImmediate(t *testing.T) {
	n := clientNode()
	commitRole(n, time.Now())
	if n.Role != "client" {
		t.Errorf("first classification: role = %q, want %q (no damping on birth)", n.Role, "client")
	}
	if n.Icon != roleIcons["client"] {
		t.Errorf("first classification: icon = %q, want %q", n.Icon, roleIcons["client"])
	}
}

func TestCommitRoleFlipDamped(t *testing.T) {
	t0 := time.Now()
	n := clientNode()
	commitRole(n, t0) // birth: commits "client" immediately

	makeScanner(n) // now classifies as "gateway"

	// Within the damping window the committed role must not change.
	for _, dt := range []time.Duration{0, time.Second, roleFlipDamping - time.Millisecond} {
		commitRole(n, t0.Add(dt))
		if n.Role != "client" {
			t.Fatalf("at +%v: role = %q, want %q (flip still damped)", dt, n.Role, "client")
		}
		if n.pendingRole != "gateway" {
			t.Fatalf("at +%v: pendingRole = %q, want %q", dt, n.pendingRole, "gateway")
		}
	}

	// Once the candidate has persisted for the full window it commits, once.
	commitRole(n, t0.Add(roleFlipDamping))
	if n.Role != "gateway" {
		t.Errorf("after damping window: role = %q, want %q", n.Role, "gateway")
	}
	if n.Icon != roleIcons["gateway"] {
		t.Errorf("after damping window: icon = %q, want %q", n.Icon, roleIcons["gateway"])
	}
	if n.pendingRole != "" {
		t.Errorf("after commit: pendingRole = %q, want cleared", n.pendingRole)
	}
}

func TestCommitRoleFlickerNeverCommits(t *testing.T) {
	t0 := time.Now()
	n := clientNode()
	commitRole(n, t0) // birth: "client"

	makeScanner(n)
	commitRole(n, t0) // candidate "gateway" starts its window

	// Flicker back to "client" within the window: the pending flip is dropped.
	n.Peers = map[string]struct{}{"a": {}, "b": {}} // back under gatewayFanout
	commitRole(n, t0.Add(time.Second))
	if n.Role != "client" {
		t.Fatalf("after flicker back: role = %q, want %q", n.Role, "client")
	}
	if n.pendingRole != "" {
		t.Fatalf("after flicker back: pendingRole = %q, want cleared", n.pendingRole)
	}

	// The flip reappears later: the window restarts from scratch, so well past
	// the original deadline the role is still not flipped.
	makeScanner(n)
	commitRole(n, t0.Add(2*time.Second))
	commitRole(n, t0.Add(3*time.Second)) // >roleFlipDamping after t0, but only 1s into the new window
	if n.Role != "client" {
		t.Errorf("restarted window: role = %q, want %q (window must restart)", n.Role, "client")
	}
	commitRole(n, t0.Add(2*time.Second+roleFlipDamping))
	if n.Role != "gateway" {
		t.Errorf("after restarted window: role = %q, want %q", n.Role, "gateway")
	}
}

func TestSnapshotRawDampsRoleFlip(t *testing.T) {
	m := NewManager()
	m.AddOrUpdateNode("10.0.0.1", "", 100)

	// Seed client-like stats, then snapshot: birth classification is immediate.
	m.mu.Lock()
	n := m.nodes["10.0.0.1"]
	n.InPackets, n.OutPackets = 10, 50
	n.Peers = map[string]struct{}{"a": {}, "b": {}}
	m.mu.Unlock()

	snap := m.SnapshotRaw()
	if got := snap.Nodes[0].Role; got != "client" {
		t.Fatalf("birth snapshot: role = %q, want %q", got, "client")
	}

	// Turn it into a scanner; the very next snapshot must still show the old
	// role (flip damped), with the candidate tracked on the live node.
	m.mu.Lock()
	makeScanner(m.nodes["10.0.0.1"])
	m.mu.Unlock()

	snap = m.SnapshotRaw()
	if got := snap.Nodes[0].Role; got != "client" {
		t.Errorf("immediately after flip: snapshot role = %q, want %q (damped)", got, "client")
	}
	m.mu.RLock()
	pending := m.nodes["10.0.0.1"].pendingRole
	m.mu.RUnlock()
	if pending != "gateway" {
		t.Errorf("after flip: pendingRole = %q, want %q", pending, "gateway")
	}
}
