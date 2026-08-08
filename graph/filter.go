package graph

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

// filter.go implements a small, Wireshark-flavored display-filter subset for the
// search box, evaluated over the node graph. It is intentionally bounded to the
// fields etherchimp actually indexes:
//
//	ip.addr / ip.src / ip.dst / ip   == | != | contains  <ip | cidr | text>
//	eth.addr / eth.src / eth.dst / mac == | != | contains <mac | text>
//	host / hostname / dns / dns.qry.name == | != | contains <text>
//	port / tcp.port / udp.port        == | != <number>
//	tcp | udp | dns | http | tls | icmp | arp | ...   (bare protocol keyword)
//	and / && , or / || , not / ! , parentheses
//
// A payload term (`frame contains "X"` / `contains "X"`) parses but never
// matches a node — payload lives in packets, not the graph — so it is handled
// by the client's payload search and the /api/packet/recent endpoint instead.
//
// Anything that isn't recognizable as a structured filter (e.g. a bare "192")
// is reported as not-a-filter so the caller falls back to substring SearchNodes.

// SearchFilter evaluates a structured display-filter query against the graph and
// returns matching nodes busiest-first. The second return is false when the
// query is not a structured filter (no field/op/keyword/boolean), signalling the
// caller to fall back to substring search — this preserves bare-text behavior
// like "192" matching all 192.x.x.x nodes.
func (m *Manager) SearchFilter(query string, limit int) ([]SearchResult, bool) {
	toks, err := tokenizeFilter(query)
	if err != nil || len(toks) == 0 {
		return nil, false
	}
	p := &filterParser{toks: toks}
	pred, err := p.parse()
	if err != nil || !p.atEnd() {
		return nil, false
	}
	if !p.sawStructured {
		// Only bare words/strings — not a real filter. Let substring search run.
		return nil, false
	}
	if limit <= 0 {
		limit = 20
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Precompute, once per query, the set of protocol names each node
	// participates in (protocol keywords are edge-level).
	nodeProtos := make(map[string]map[string]bool)
	for i := range m.edges {
		e := m.edges[i]
		p := strings.ToLower(e.Protocol.Name)
		if p == "" {
			continue
		}
		for _, end := range [2]string{e.From, e.To} {
			set := nodeProtos[end]
			if set == nil {
				set = make(map[string]bool)
				nodeProtos[end] = set
			}
			set[p] = true
		}
	}

	var out []SearchResult
	for id, n := range m.nodes {
		ctx := &nodeCtx{id: id, node: n, protos: nodeProtos[id]}
		if !pred(ctx) {
			continue
		}
		r := SearchResult{
			ID:          id,
			Label:       n.Hostname,
			IPs:         append([]string(nil), n.IPs...),
			PacketCount: n.PacketCount,
			ByteCount:   n.ByteCount,
		}
		if s := primarySubnet24(*n); s != "" {
			r.Subnet24 = s + ".0/24"
			if dot := strings.LastIndexByte(s, '.'); dot > 0 {
				r.Subnet16 = s[:dot] + ".0.0/16"
			}
		}
		out = append(out, r)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].PacketCount != out[b].PacketCount {
			return out[a].PacketCount > out[b].PacketCount
		}
		return out[a].ID < out[b].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, true
}

// nodeCtx is the per-node evaluation context handed to a predicate.
type nodeCtx struct {
	id     string
	node   *Node
	protos map[string]bool // lowercased protocol names on this node's edges
}

// ipStrings returns the node's id plus every associated IP.
func (c *nodeCtx) ipStrings() []string {
	out := make([]string, 0, len(c.node.IPs)+1)
	out = append(out, c.id)
	out = append(out, c.node.IPs...)
	return out
}

// ----- predicate type ------------------------------------------------------

type predicate func(*nodeCtx) bool

// ----- tokenizer -----------------------------------------------------------

type tokKind int

const (
	tokWord   tokKind = iota // identifier, field name, ip, cidr, mac, number
	tokString                // quoted string
	tokOp                    // == != contains
	tokAnd
	tokOr
	tokNot
	tokLParen
	tokRParen
)

type token struct {
	kind tokKind
	val  string
}

func tokenizeFilter(s string) ([]token, error) {
	var toks []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			toks = append(toks, token{tokLParen, "("})
			i++
		case c == ')':
			toks = append(toks, token{tokRParen, ")"})
			i++
		case c == '"' || c == '\'':
			quote := c
			i++
			start := i
			for i < len(s) && s[i] != quote {
				i++
			}
			toks = append(toks, token{tokString, s[start:i]})
			if i < len(s) {
				i++ // closing quote
			}
		case c == '=' && i+1 < len(s) && s[i+1] == '=':
			toks = append(toks, token{tokOp, "=="})
			i += 2
		case c == '!' && i+1 < len(s) && s[i+1] == '=':
			toks = append(toks, token{tokOp, "!="})
			i += 2
		case c == '!':
			toks = append(toks, token{tokNot, "!"})
			i++
		case c == '&' && i+1 < len(s) && s[i+1] == '&':
			toks = append(toks, token{tokAnd, "&&"})
			i += 2
		case c == '|' && i+1 < len(s) && s[i+1] == '|':
			toks = append(toks, token{tokOr, "||"})
			i += 2
		default:
			// A bareword: letters, digits, and the punctuation that appears in
			// ip/cidr/mac/field tokens.
			start := i
			for i < len(s) {
				ch := s[i]
				if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' ||
					ch == '(' || ch == ')' || ch == '"' || ch == '\'' ||
					ch == '=' || ch == '!' || ch == '&' || ch == '|' {
					break
				}
				i++
			}
			w := s[start:i]
			switch strings.ToLower(w) {
			case "and":
				toks = append(toks, token{tokAnd, "and"})
			case "or":
				toks = append(toks, token{tokOr, "or"})
			case "not":
				toks = append(toks, token{tokNot, "not"})
			case "contains", "eq", "ne":
				toks = append(toks, token{tokOp, strings.ToLower(w)})
			default:
				toks = append(toks, token{tokWord, w})
			}
		}
	}
	return toks, nil
}

// ----- parser --------------------------------------------------------------

type filterParser struct {
	toks []token
	pos  int
	// sawStructured is set once the parser consumes anything that makes this a
	// real filter (a field comparison, protocol keyword, or boolean operator),
	// as opposed to a lone bareword we should treat as substring search.
	sawStructured bool
}

func (p *filterParser) atEnd() bool { return p.pos >= len(p.toks) }

func (p *filterParser) peek() (token, bool) {
	if p.atEnd() {
		return token{}, false
	}
	return p.toks[p.pos], true
}

func (p *filterParser) next() token {
	t := p.toks[p.pos]
	p.pos++
	return t
}

func (p *filterParser) parse() (predicate, error) {
	return p.parseOr()
}

func (p *filterParser) parseOr() (predicate, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tokOr {
			return left, nil
		}
		p.next()
		p.sawStructured = true
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l, r := left, right
		left = func(c *nodeCtx) bool { return l(c) || r(c) }
	}
}

func (p *filterParser) parseAnd() (predicate, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tokAnd {
			return left, nil
		}
		p.next()
		p.sawStructured = true
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		l, r := left, right
		left = func(c *nodeCtx) bool { return l(c) && r(c) }
	}
}

func (p *filterParser) parseNot() (predicate, error) {
	t, ok := p.peek()
	if ok && t.kind == tokNot {
		p.next()
		p.sawStructured = true
		inner, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return func(c *nodeCtx) bool { return !inner(c) }, nil
	}
	return p.parsePrimary()
}

func (p *filterParser) parsePrimary() (predicate, error) {
	t, ok := p.peek()
	if !ok {
		return nil, errParse
	}
	if t.kind == tokLParen {
		p.next()
		p.sawStructured = true
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if nt, ok := p.peek(); !ok || nt.kind != tokRParen {
			return nil, errParse
		}
		p.next()
		return inner, nil
	}
	if t.kind != tokWord {
		return nil, errParse
	}
	// A word is either "field op value" or a bare protocol keyword.
	field := p.next().val
	if nt, ok := p.peek(); ok && nt.kind == tokOp {
		op := p.next().val
		vt, ok := p.peek()
		if !ok || (vt.kind != tokWord && vt.kind != tokString) {
			return nil, errParse
		}
		value := p.next().val
		p.sawStructured = true
		return buildComparison(field, op, value)
	}
	// Bare word: only meaningful as a known protocol keyword. Unknown bare
	// words leave sawStructured unset so the caller uses substring search.
	lf := strings.ToLower(field)
	if knownProtocols[lf] {
		p.sawStructured = true
		want := lf
		return func(c *nodeCtx) bool { return c.protos[want] }, nil
	}
	// Not a filter construct — accept it as an always-false leaf but do NOT mark
	// structured, so a lone bareword falls back to substring search upstream.
	return func(*nodeCtx) bool { return false }, nil
}

var errParse = errParseError("bad filter")

type errParseError string

func (e errParseError) Error() string { return string(e) }

// knownProtocols is the set of bare keywords treated as protocol filters.
var knownProtocols = map[string]bool{
	"tcp": true, "udp": true, "icmp": true, "icmpv6": true, "arp": true,
	"dns": true, "mdns": true, "http": true, "https": true, "tls": true,
	"ssl": true, "quic": true, "dhcp": true, "ntp": true, "snmp": true,
	"ssh": true, "ftp": true, "smtp": true, "ntlm": true, "smb": true,
	"lldp": true, "cdp": true, "stp": true, "ospf": true, "bgp": true,
}

// buildComparison turns "field op value" into a predicate.
func buildComparison(field, op, value string) (predicate, error) {
	f := strings.ToLower(field)
	switch f {
	case "ip.addr", "ip.src", "ip.dst", "ip", "ip.host":
		return ipComparison(op, value), nil
	case "eth.addr", "eth.src", "eth.dst", "eth", "mac":
		return macComparison(op, value), nil
	case "host", "hostname", "dns", "dns.qry.name", "http.host":
		return hostComparison(op, value), nil
	case "port", "tcp.port", "udp.port", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport":
		return portComparison(op, value), nil
	case "frame", "data", "payload":
		// Payload term: never matches a node (payload isn't graph data). Return
		// an always-false predicate; the client/endpoint handles payload text.
		return func(*nodeCtx) bool { return false }, nil
	default:
		return nil, errParse
	}
}

// negatable wraps eq-style matching so == and !=/ne/contains share one path.
func negatable(op string, match func() bool) bool {
	switch op {
	case "!=", "ne":
		return !match()
	default: // ==, eq, contains
		return match()
	}
}

func ipComparison(op, value string) predicate {
	// CIDR value: containment test over all node IPs.
	if _, cidr, err := net.ParseCIDR(value); err == nil {
		return func(c *nodeCtx) bool {
			hit := false
			for _, s := range c.ipStrings() {
				if ip := net.ParseIP(s); ip != nil && cidr.Contains(ip) {
					hit = true
					break
				}
			}
			return negatable(op, func() bool { return hit })
		}
	}
	valLower := strings.ToLower(value)
	return func(c *nodeCtx) bool {
		hit := false
		for _, s := range c.ipStrings() {
			sl := strings.ToLower(s)
			if op == "contains" {
				if strings.Contains(sl, valLower) {
					hit = true
					break
				}
			} else if sl == valLower {
				hit = true
				break
			}
		}
		return negatable(op, func() bool { return hit })
	}
}

func macComparison(op, value string) predicate {
	valLower := strings.ToLower(value)
	return func(c *nodeCtx) bool {
		hit := false
		for _, mac := range c.node.MACs {
			ml := strings.ToLower(mac)
			if op == "contains" {
				if strings.Contains(ml, valLower) {
					hit = true
					break
				}
			} else if ml == valLower {
				hit = true
				break
			}
		}
		return negatable(op, func() bool { return hit })
	}
}

func hostComparison(op, value string) predicate {
	valLower := strings.ToLower(value)
	return func(c *nodeCtx) bool {
		h := strings.ToLower(c.node.Hostname)
		var hit bool
		if op == "contains" {
			hit = strings.Contains(h, valLower)
		} else {
			hit = h == valLower
		}
		return negatable(op, func() bool { return hit })
	}
}

func portComparison(op, value string) predicate {
	port, err := strconv.Atoi(value)
	if err != nil || port < 0 || port > 65535 {
		return func(*nodeCtx) bool { return false }
	}
	pu := uint16(port)
	return func(c *nodeCtx) bool {
		_, hit := c.node.ListenPorts[pu]
		return negatable(op, func() bool { return hit })
	}
}
