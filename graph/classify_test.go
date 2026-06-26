package graph

import "testing"

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
