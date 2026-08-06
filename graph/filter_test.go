package graph

import "testing"

// evalFilter parses q and evaluates it against ctx, returning (matched,
// isStructured). A non-structured query (bare substring) reports structured=false.
func evalFilter(q string, ctx *nodeCtx) (matched, structured bool) {
	toks, err := tokenizeFilter(q)
	if err != nil {
		return false, false
	}
	p := &filterParser{toks: toks}
	pred, err := p.parse()
	if err != nil || !p.atEnd() {
		return false, false
	}
	if !p.sawStructured {
		return false, false
	}
	return pred(ctx), true
}

func TestSearchFilterGrammar(t *testing.T) {
	ctx := &nodeCtx{
		id: "10.0.1.5",
		node: &Node{
			IP:          "10.0.1.5",
			Hostname:    "web-01.corp",
			IPs:         []string{"10.0.1.5"},
			MACs:        []string{"aa:bb:cc:dd:ee:ff"},
			ListenPorts: map[uint16]int{443: 3},
		},
		protos: map[string]bool{"tcp": true, "https": true},
	}

	cases := []struct {
		q          string
		structured bool
		match      bool
	}{
		{"192", false, false},                         // bare substring -> fallback
		{"web", false, false},                         // bare word, unknown proto -> fallback
		{"ip.addr == 10.0.1.5", true, true},           // exact ip
		{"ip.addr == 10.0.1.6", true, false},          // wrong ip
		{"ip.src == 10.0.0.0/16", true, true},         // cidr contains
		{"ip.dst == 10.1.0.0/16", true, false},        // cidr excludes
		{"ip.addr contains 0.1.", true, true},         // substring
		{"eth.addr == aa:bb:cc:dd:ee:ff", true, true}, // mac exact
		{"eth.addr contains bb:cc", true, true},       // mac substring
		{"mac == 00:00:00:00:00:00", true, false},     // mac miss
		{"host == web-01.corp", true, true},           // hostname exact
		{"host contains corp", true, true},            // hostname substring
		{"hostname != nope", true, true},              // negation true
		{"tcp.port == 443", true, true},               // listen port
		{"tcp.port == 80", true, false},               // wrong port
		{"tcp", true, true},                           // proto keyword
		{"udp", true, false},                          // proto absent
		{"tcp and https", true, true},                 // and
		{"tcp and udp", true, false},                  // and miss
		{"udp or https", true, true},                  // or
		{"not udp", true, true},                       // not
		{"(udp or tcp) and not udp", true, true},      // precedence + parens
		{"frame contains MUNGE", true, false},         // payload term never matches a node
		{`ip.addr == 10.0.1.5 and host contains corp`, true, true},
	}
	for _, tc := range cases {
		match, structured := evalFilter(tc.q, ctx)
		if structured != tc.structured {
			t.Errorf("%q: structured=%v want %v", tc.q, structured, tc.structured)
		}
		if structured && match != tc.match {
			t.Errorf("%q: match=%v want %v", tc.q, match, tc.match)
		}
	}
}
