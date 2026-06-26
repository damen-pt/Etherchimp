package graph

import (
	"fmt"
	"math"
	"math/rand"
	"net"
	"sort"
	"sync"
)

// layout.go computes node positions on the server so the browser can render with
// physics OFF. A LayoutEngine is PER CLIENT and is stepped over only that client's
// filtered/displayed nodes, so hidden nodes never spread the visible ones apart.
// Deterministic layouts (circular/gravity/hierarchical/subnet) recompute only when
// the node set changes; the force layout relaxes incrementally with central
// gravity (to stay compact) and freezes once it converges.

// Vec is a 2D position in graph coordinates.
type Vec struct{ X, Y float64 }

// SubnetIsland describes the dotted ring drawn around a /24 in subnet mode.
type SubnetIsland struct {
	CIDR   string  `json:"cidr"`
	VLANID uint16  `json:"vlanId,omitempty"`
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Radius float64 `json:"radius"`
}

const (
	forceIterationsPerStep = 6   // relaxation iterations per hub tick
	forceEpsilon           = 0.5 // px; max node move below which a step is "settled"

	// Ideal edge length, held CONSTANT (independent of node count). Deriving it
	// from sqrt(area/n) makes k explode for small graphs (e.g. ~850px at 8 nodes),
	// which — combined with reheating on every node-set change — flings the whole
	// graph on each new node during a live capture. A fixed k keeps spacing and
	// motion bounded as the graph churns.
	forceIdealLen = 140.0

	// Temperature (max per-iteration node move) for the very first layout of a
	// graph: hot, so randomly-seeded nodes find a good global arrangement.
	forceInitialTemp = 300.0

	// Temperature applied when the node set changes on an already-laid-out graph:
	// a gentle nudge so new nodes settle without throwing existing ones around.
	forceReheatTemp = 70.0

	// Central gravity strength (per iteration). Pulls nodes toward the origin so
	// the graph stays compact instead of spreading without bound. Tuned so a
	// typical graph settles to a sensible, fits-on-screen size.
	forceGravity = 5.0

	// Node render-radius range (px), mirroring the client's node scaling (20..30,
	// i.e. high-traffic nodes are only 1.5x the base). Big nodes get a slightly
	// larger collision radius so they don't crowd their neighbours' labels.
	layoutNodeRadiusMin = 20.0
	layoutNodeRadiusMax = 30.0

	// Collision: keep at least (r_i + r_j + collisionPad) between node centers,
	// with this separation strength. The pad leaves room for labels under nodes.
	collisionPad      = 34.0
	collisionStrength = 1.2
)

// LayoutEngine holds positions for every active layout mode.
type LayoutEngine struct {
	mu        sync.Mutex
	positions map[string]map[string]Vec // mode -> nodeID -> position
	settled   map[string]bool           // mode -> converged (force) / computed (deterministic)
	temp      map[string]float64        // force temperature per mode
	sig       map[string]uint64         // node-set signature per mode
	islands   map[string][]SubnetIsland // subnet mode islands
	rng       *rand.Rand

	// Clustered-host (gravity) island assignment, recomputed when the node set
	// changes: each node's gravity target is its island centre, and hub nodes are
	// pinned to those centres so their neighbours orbit them.
	gravitySig     uint64
	gravityAnchors map[string]Vec
	gravityHubPins map[string]Vec
}

// NewLayoutEngine creates an empty engine with a deterministic RNG (so seeding
// is reproducible across runs).
func NewLayoutEngine() *LayoutEngine {
	return &LayoutEngine{
		positions: map[string]map[string]Vec{},
		settled:   map[string]bool{},
		temp:      map[string]float64{},
		sig:       map[string]uint64{},
		islands:   map[string][]SubnetIsland{},
		rng:       rand.New(rand.NewSource(1)),
	}
}

// Position returns the stored position for a node in a mode (zero if unknown).
func (le *LayoutEngine) Position(mode, id string) Vec {
	le.mu.Lock()
	defer le.mu.Unlock()
	if m, ok := le.positions[mode]; ok {
		return m[id]
	}
	return Vec{}
}

// Islands returns the subnet islands for a mode (nil for non-subnet modes).
func (le *LayoutEngine) Islands(mode string) []SubnetIsland {
	le.mu.Lock()
	defer le.mu.Unlock()
	return le.islands[mode]
}

// Unsettled reports whether any of the given active modes still needs ticking
// (force layout converging, or a mode never computed). The hub uses this to keep
// stepping a live force layout even when the graph itself is idle.
func (le *LayoutEngine) Unsettled(modes map[string]bool) bool {
	le.mu.Lock()
	defer le.mu.Unlock()
	for mode := range modes {
		if !le.settled[mode] {
			return true
		}
	}
	return false
}

// Step advances every active layout mode over the current snapshot. radii holds
// each node's render radius (for size-aware collision in the force layout); it
// may be nil.
func (le *LayoutEngine) Step(raw RawSnapshot, modes map[string]bool, pins map[string]Vec, vlanByIP map[string]uint16, radii map[string]float64) {
	le.mu.Lock()
	defer le.mu.Unlock()
	for mode := range modes {
		switch mode {
		case "circular":
			le.layoutCircular(raw)
		case "gravity":
			le.stepGravityIslands(raw, pins, radii)
		case "hierarchical":
			le.layoutHierarchical(raw)
		case "subnet":
			le.layoutSubnet(raw, vlanByIP)
		default: // "force" and anything unknown
			le.stepForce(raw, pins, radii, nil, "force")
		}
	}
}

// --- helpers ---

func sortedIDs(nodes []Node) []string {
	ids := make([]string, len(nodes))
	for i := range nodes {
		ids[i] = nodes[i].ID()
	}
	sort.Strings(ids)
	return ids
}

// nodeSetSig is an order-independent FNV-1a hash of the node ID set, used to skip
// recomputing deterministic layouts when membership is unchanged.
func nodeSetSig(nodes []Node) uint64 {
	ids := sortedIDs(nodes)
	var h uint64 = 14695981039346656037
	for _, id := range ids {
		for j := 0; j < len(id); j++ {
			h ^= uint64(id[j])
			h *= 1099511628211
		}
		h ^= '|'
		h *= 1099511628211
	}
	return h
}

// subnet24 returns the "a.b.c" /24 prefix of an IPv4 address, or "" if not IPv4.
func subnet24(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", v4[0], v4[1], v4[2])
}

// primarySubnet24 finds a node's /24 from its real IPs (falling back to its ID).
func primarySubnet24(n Node) string {
	for _, ip := range n.IPs {
		if s := subnet24(ip); s != "" {
			return s
		}
	}
	return subnet24(n.IP)
}

// --- deterministic layouts (ported from static/app.js applyClusterLayout) ---

func (le *LayoutEngine) layoutCircular(raw RawSnapshot) {
	const mode = "circular"
	if sig := nodeSetSig(raw.Nodes); le.sig[mode] == sig && le.positions[mode] != nil {
		le.settled[mode] = true
		return
	} else {
		le.sig[mode] = sig
	}
	ids := sortedIDs(raw.Nodes)
	n := len(ids)
	radius := math.Max(300, float64(n)*8)
	pos := make(map[string]Vec, n)
	for i, id := range ids {
		a := 2 * math.Pi * float64(i) / math.Max(1, float64(n))
		pos[id] = Vec{radius * math.Cos(a), radius * math.Sin(a)}
	}
	le.positions[mode] = pos
	le.settled[mode] = true
}

// stepGravityIslands is the "Clustered Host" layout: the highest-traffic nodes
// become island hubs (pinned to spread-out centres), and every other node is
// pulled toward the hub it talks to most, so its neighbours orbit it. It reuses
// the force engine, so each island self-arranges with its own clustering force.
func (le *LayoutEngine) stepGravityIslands(raw RawSnapshot, pins map[string]Vec, radii map[string]float64) {
	const mode = "gravity"
	// Recompute the island assignment when the node set changes (before stepForce
	// updates its own per-mode signature).
	if sig := nodeSetSig(raw.Nodes); le.gravitySig != sig {
		le.gravitySig = sig
		le.gravityAnchors, le.gravityHubPins = computeIslands(raw)
	}
	// Pin hubs to their island centres, merged with any user pins (which win).
	merged := pins
	if len(le.gravityHubPins) > 0 {
		merged = make(map[string]Vec, len(pins)+len(le.gravityHubPins))
		for id, v := range le.gravityHubPins {
			merged[id] = v
		}
		for id, v := range pins {
			merged[id] = v
		}
	}
	le.stepForce(raw, merged, radii, le.gravityAnchors, mode)
}

// computeIslands picks the top-traffic nodes as island hubs, lays their centres
// out on a ring, and assigns every other node to the hub it exchanges the most
// traffic with. Returns each node's anchor (its island centre) and the hub pins.
func computeIslands(raw RawSnapshot) (anchors, hubPins map[string]Vec) {
	anchors = make(map[string]Vec, len(raw.Nodes))
	hubPins = make(map[string]Vec)
	n := len(raw.Nodes)
	if n == 0 {
		return anchors, hubPins
	}

	// Rank nodes by total traffic.
	type nodeTraffic struct {
		id string
		c  int
	}
	arr := make([]nodeTraffic, n)
	for i := range raw.Nodes {
		arr[i] = nodeTraffic{raw.Nodes[i].ID(), raw.Nodes[i].PacketCount}
	}
	sort.Slice(arr, func(a, b int) bool {
		if arr[a].c != arr[b].c {
			return arr[a].c > arr[b].c
		}
		return arr[a].id < arr[b].id
	})

	// Number of islands: ~sqrt(n)/2, clamped to [1, 8].
	k := int(math.Round(math.Sqrt(float64(n)) / 2))
	if k < 1 {
		k = 1
	}
	if k > 8 {
		k = 8
	}
	if k > n {
		k = n
	}

	// Place hub centres on a ring (bigger graphs spread further); pin hubs there.
	hubCenter := make(map[string]Vec, k)
	clusterRadius := math.Max(450, float64(k)*340)
	for i := 0; i < k; i++ {
		c := Vec{}
		if k > 1 {
			ang := 2 * math.Pi * float64(i) / float64(k)
			c = Vec{clusterRadius * math.Cos(ang), clusterRadius * math.Sin(ang)}
		}
		hub := arr[i].id
		hubCenter[hub] = c
		hubPins[hub] = c
		anchors[hub] = c
	}

	// Sum per (node, hub) traffic so each non-hub node can join its strongest hub.
	isHub := func(id string) bool { _, ok := hubCenter[id]; return ok }
	weight := make(map[string]map[string]int)
	addW := func(node, hub string, p int) {
		if weight[node] == nil {
			weight[node] = make(map[string]int)
		}
		weight[node][hub] += p
	}
	for i := range raw.Edges {
		e := &raw.Edges[i]
		if isHub(e.From) && !isHub(e.To) {
			addW(e.To, e.From, e.PacketCount)
		} else if isHub(e.To) && !isHub(e.From) {
			addW(e.From, e.To, e.PacketCount)
		}
	}

	// Assign non-hub nodes to their strongest hub; nodes connected to no hub are
	// spread round-robin so the islands stay balanced.
	rr := 0
	for _, it := range arr {
		if isHub(it.id) {
			continue
		}
		bestHub, best := "", -1
		for hub, w := range weight[it.id] {
			if w > best {
				best, bestHub = w, hub
			}
		}
		if bestHub == "" {
			bestHub = arr[rr%k].id
			rr++
		}
		anchors[it.id] = hubCenter[bestHub]
	}
	return anchors, hubPins
}

func (le *LayoutEngine) layoutHierarchical(raw RawSnapshot) {
	const mode = "hierarchical"
	if sig := nodeSetSig(raw.Nodes); le.sig[mode] == sig && le.positions[mode] != nil {
		le.settled[mode] = true
		return
	} else {
		le.sig[mode] = sig
	}
	inc := make(map[string]int)
	out := make(map[string]int)
	conn := make(map[string]map[string]bool)
	addConn := func(a, b string) {
		if conn[a] == nil {
			conn[a] = make(map[string]bool)
		}
		conn[a][b] = true
	}
	for i := range raw.Edges {
		e := &raw.Edges[i]
		out[e.From] += e.PacketCount
		inc[e.To] += e.PacketCount
		addConn(e.From, e.To)
		addConn(e.To, e.From)
	}
	type ns struct {
		id    string
		score float64
	}
	arr := make([]ns, len(raw.Nodes))
	for i := range raw.Nodes {
		id := raw.Nodes[i].ID()
		in := inc[id]
		ou := out[id]
		total := in + ou
		score := 0.0
		if total > 0 {
			ratio := float64(in) / float64(total)
			vol := math.Log(float64(total) + 1)
			cy := math.Log(float64(len(conn[id])) + 1)
			score = ratio*50 + vol*30 + cy*20
		}
		arr[i] = ns{id, score}
	}
	sort.Slice(arr, func(a, b int) bool {
		if arr[a].score != arr[b].score {
			return arr[a].score > arr[b].score
		}
		return arr[a].id < arr[b].id
	})
	n := len(arr)
	numLevels := int(math.Min(math.Ceil(float64(n)/5), 10))
	if numLevels < 1 {
		numLevels = 1
	}
	perLevel := int(math.Ceil(float64(n) / float64(numLevels)))
	if perLevel < 1 {
		perLevel = 1
	}
	const levelSep, nodeSpacing = 150.0, 120.0
	pos := make(map[string]Vec, n)
	for i, e := range arr {
		level := i / perLevel
		inLevel := i % perLevel
		nodesThis := perLevel
		if (level+1)*perLevel > n {
			nodesThis = n - level*perLevel
		}
		y := float64(level) * levelSep
		x := (float64(inLevel) - float64(nodesThis-1)/2) * nodeSpacing
		pos[e.id] = Vec{x, y}
	}
	le.positions[mode] = pos
	le.settled[mode] = true
}

func (le *LayoutEngine) layoutSubnet(raw RawSnapshot, vlanByIP map[string]uint16) {
	const mode = "subnet"
	if sig := nodeSetSig(raw.Nodes); le.sig[mode] == sig && le.positions[mode] != nil {
		le.settled[mode] = true
		return
	} else {
		le.sig[mode] = sig
	}
	groups := make(map[string][]string) // subnet key -> node IDs
	idIPs := make(map[string][]string)  // node ID -> real IPs (for VLAN lookup)
	for i := range raw.Nodes {
		n := raw.Nodes[i]
		id := n.ID()
		idIPs[id] = n.IPs
		key := primarySubnet24(n)
		if key == "" {
			key = "unknown"
		}
		groups[key] = append(groups[key], id)
	}
	order := make([]string, 0, len(groups))
	for k := range groups {
		order = append(order, k)
	}
	sort.Strings(order)

	count := len(order)
	clusterRadius := math.Max(300, float64(count)*120)
	pos := make(map[string]Vec)
	islands := make([]SubnetIsland, 0, count)
	for i, key := range order {
		ids := groups[key]
		sort.Strings(ids)
		ang := 2 * math.Pi * float64(i) / math.Max(1, float64(count))
		cx := clusterRadius * math.Cos(ang)
		cy := clusterRadius * math.Sin(ang)
		subRadius := math.Max(60, math.Min(180, float64(len(ids))*18))
		for j, id := range ids {
			r := subRadius
			if len(ids) == 1 {
				r = 0
			}
			na := 2 * math.Pi * float64(j) / math.Max(1, float64(len(ids)))
			pos[id] = Vec{cx + r*math.Cos(na), cy + r*math.Sin(na)}
		}

		var vlan uint16
		if len(vlanByIP) > 0 {
			counts := make(map[uint16]int)
			for _, id := range ids {
				for _, ip := range idIPs[id] {
					if v := vlanByIP[ip]; v != 0 {
						counts[v]++
					}
				}
			}
			best := 0
			for v, c := range counts {
				if c > best {
					best = c
					vlan = v
				}
			}
		}
		cidr := "unknown"
		if key != "unknown" {
			cidr = key + ".0/24"
		}
		baseR := subRadius
		if len(ids) == 1 {
			baseR = 60
		}
		islands = append(islands, SubnetIsland{CIDR: cidr, VLANID: vlan, X: cx, Y: cy, Radius: baseR + 70})
	}
	le.positions[mode] = pos
	le.islands[mode] = islands
	le.settled[mode] = true
}

// --- force-directed (Fruchterman-Reingold, incremental with freezing) ---

// stepForce runs one incremental force-relaxation step for the given mode.
// anchors gives each node a gravity target (its island centre in "gravity" mode);
// when nil, gravity pulls every node toward the origin (plain "force" mode).
func (le *LayoutEngine) stepForce(raw RawSnapshot, pins map[string]Vec, radii map[string]float64, anchors map[string]Vec, mode string) {
	pos := le.positions[mode]
	if pos == nil {
		pos = make(map[string]Vec)
		le.positions[mode] = pos
	}
	ids := make([]string, len(raw.Nodes))
	idset := make(map[string]bool, len(raw.Nodes))
	for i := range raw.Nodes {
		ids[i] = raw.Nodes[i].ID()
		idset[ids[i]] = true
	}
	n := len(ids)
	if n == 0 {
		le.settled[mode] = true
		return
	}

	k := forceIdealLen
	// A graph with no stored positions is being laid out for the first time.
	wasEmpty := len(pos) == 0

	// Note a node-set change so we can add just enough mobility for the new nodes
	// to settle, without zeroing the temperature (which used to fling everything).
	changed := false
	if sig := nodeSetSig(raw.Nodes); le.sig[mode] != sig {
		le.sig[mode] = sig
		le.settled[mode] = false
		changed = true
	}

	// Seed new nodes near a connected neighbour (or on a ring if none).
	neighbors := make(map[string][]string)
	for i := range raw.Edges {
		e := &raw.Edges[i]
		neighbors[e.From] = append(neighbors[e.From], e.To)
		neighbors[e.To] = append(neighbors[e.To], e.From)
	}
	for _, id := range ids {
		if _, ok := pos[id]; ok {
			continue
		}
		placed := false
		for _, nb := range neighbors[id] {
			if p, ok := pos[nb]; ok {
				a := le.rng.Float64() * 2 * math.Pi
				pos[id] = Vec{p.X + math.Cos(a)*k*0.5, p.Y + math.Sin(a)*k*0.5}
				placed = true
				break
			}
		}
		if !placed {
			a := le.rng.Float64() * 2 * math.Pi
			r := le.rng.Float64() * k * math.Sqrt(float64(n))
			pos[id] = Vec{math.Cos(a) * r, math.Sin(a) * r}
		}
		le.settled[mode] = false
	}
	// Drop positions for nodes that no longer exist.
	for id := range pos {
		if !idset[id] {
			delete(pos, id)
		}
	}
	// Honor pinned nodes (Phase D); they exert forces but never move.
	for id, p := range pins {
		if idset[id] {
			pos[id] = p
		}
	}

	temp := le.temp[mode]
	switch {
	case wasEmpty:
		temp = forceInitialTemp // first layout: hot for a good global arrangement
	case changed && temp < forceReheatTemp:
		temp = forceReheatTemp // new nodes arrived: gentle, bounded re-settle
	case temp <= 0:
		temp = forceReheatTemp
	}

	// Precompute slice-indexed views of the per-node state so the O(n^2) repulsion
	// loop below operates on plain slices instead of hashing string keys on every
	// pair (the dominant cost at high node counts, run per client per tick).
	idx := make(map[string]int, n)
	for i, id := range ids {
		idx[id] = i
	}
	posArr := make([]Vec, n)
	radArr := make([]float64, n)
	anchorArr := make([]Vec, n)
	pinnedArr := make([]bool, n)
	hasRadii := radii != nil
	for i, id := range ids {
		posArr[i] = pos[id]
		if hasRadii {
			radArr[i] = radii[id]
		}
		if anchors != nil {
			anchorArr[i] = anchors[id] // zero Vec when absent — matches map lookup default
		}
		if _, pinned := pins[id]; pinned {
			pinnedArr[i] = true
		}
	}
	// Resolve edge endpoints to indices once; skip edges with an unplaced endpoint.
	type edgeIdx struct{ from, to int }
	edgeIdxs := make([]edgeIdx, 0, len(raw.Edges))
	for i := range raw.Edges {
		e := &raw.Edges[i]
		fi, ok1 := idx[e.From]
		ti, ok2 := idx[e.To]
		if !ok1 || !ok2 {
			continue
		}
		edgeIdxs = append(edgeIdxs, edgeIdx{fi, ti})
	}

	dispArr := make([]Vec, n)
	maxDisp := 0.0
	for iter := 0; iter < forceIterationsPerStep; iter++ {
		for i := range dispArr {
			dispArr[i] = Vec{}
		}
		// Repulsion between all pairs.
		for i := 0; i < n; i++ {
			pi := posArr[i]
			for j := i + 1; j < n; j++ {
				pj := posArr[j]
				dx, dy := pi.X-pj.X, pi.Y-pj.Y
				dist := math.Hypot(dx, dy)
				if dist < 0.01 {
					dx, dy = le.rng.Float64()-0.5, le.rng.Float64()-0.5
					dist = math.Hypot(dx, dy) + 0.01
				}
				f := k * k / dist
				ux, uy := dx/dist, dy/dist
				// Size-aware collision: if the circles (plus label padding) would
				// overlap, add a strong separation so big nodes don't cover the
				// labels of their neighbours.
				if hasRadii {
					minSep := radArr[i] + radArr[j] + collisionPad
					if dist < minSep {
						f += (minSep - dist) * collisionStrength
					}
				}
				dispArr[i].X += ux * f
				dispArr[i].Y += uy * f
				dispArr[j].X -= ux * f
				dispArr[j].Y -= uy * f
			}
		}
		// Attraction along edges.
		for _, e := range edgeIdxs {
			pu := posArr[e.from]
			pv := posArr[e.to]
			dx, dy := pu.X-pv.X, pu.Y-pv.Y
			dist := math.Hypot(dx, dy)
			if dist < 0.01 {
				dist = 0.01
			}
			f := dist * dist / k
			ux, uy := dx/dist, dy/dist
			dispArr[e.from].X -= ux * f
			dispArr[e.from].Y -= uy * f
			dispArr[e.to].X += ux * f
			dispArr[e.to].Y += uy * f
		}
		// Gravity: pull every node toward its anchor (the origin in plain force
		// mode, or its island centre in gravity/clustered-host mode), proportional
		// to distance. Bounds the spread, keeps clusters compact, and in island
		// mode is what makes nodes orbit their hub.
		for i := 0; i < n; i++ {
			dispArr[i].X -= forceGravity * (posArr[i].X - anchorArr[i].X)
			dispArr[i].Y -= forceGravity * (posArr[i].Y - anchorArr[i].Y)
		}
		// Integrate, capped by temperature.
		for i := 0; i < n; i++ {
			if pinnedArr[i] {
				continue
			}
			d := dispArr[i]
			dl := math.Hypot(d.X, d.Y)
			if dl < 1e-9 {
				continue
			}
			step := math.Min(dl, temp)
			posArr[i].X += d.X / dl * step
			posArr[i].Y += d.Y / dl * step
			if step > maxDisp {
				maxDisp = step
			}
		}
		temp *= 0.9
	}
	// Write the converged positions back into the live map.
	for i, id := range ids {
		pos[id] = posArr[i]
	}
	// Let the temperature cool toward zero so the layout actually freezes once it
	// converges (no per-tick jitter). A node-set change reheats temp to k above,
	// so the layout still re-converges when the graph changes.
	le.temp[mode] = temp
	le.settled[mode] = maxDisp < forceEpsilon
}
