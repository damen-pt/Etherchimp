package graph

import (
	"math"
	"sort"
	"strings"
)

// solar.go — deterministic "solar system" layout for the cosmos explorer.
//
// Metaphor (forensic / ops map, not physics sim):
//   • Galaxy centre  — multicast/broadcast group nodes (protocol rendezvous)
//   • Star systems   — /24 subnets (or role islands when non-IP)
//   • System centre  — geometric barycenter of the system (not a traffic-ranked host)
//   • Planets        — hosts on fixed orbits from id hash only
//   • Links          — rendered separately; no spring forces
//
// CRITICAL: positions depend ONLY on the node-id set (and pins). Traffic must
// never reshuffle orbits — that was the "nodes hop around with packets" bug.
// Size/color still update from traffic on the client; coordinates stay put.

const (
	solarSystemBaseR    = 320.0 // first star-system distance from origin
	solarSystemStepR    = 260.0 // spacing between system galactic rings
	solarPlanetBaseR    = 55.0  // innermost planet orbit around system centre
	solarPlanetStepR    = 42.0  // spacing between orbital shells
	solarGroupBeltR     = 100.0 // group nodes sit on a tight inner belt
	solarMaxSystemsRing = 10    // systems per galactic ring before next ring
	solarOrbitShells    = 8     // discrete orbital shells (hash picks shell)
)

// layoutSolar places nodes in a hierarchical solar-system arrangement.
// pins override final positions (user-dragged / override store).
func (le *LayoutEngine) layoutSolar(raw RawSnapshot, pins map[string]Vec) {
	const mode = "solar"
	// Membership only — intentionally ignore packet counts.
	sig := nodeSetSig(raw.Nodes)
	if le.sig[mode] == sig && le.positions[mode] != nil {
		if pins != nil {
			pos := le.positions[mode]
			for id, p := range pins {
				if _, ok := pos[id]; ok {
					pos[id] = p
				}
			}
		}
		le.settled[mode] = true
		return
	}
	le.sig[mode] = sig

	type member struct {
		n     Node
		angle float64
	}
	type system struct {
		key     string
		members []member
		angle   float64
	}

	systems := map[string]*system{}
	var groups []member

	for i := range raw.Nodes {
		n := raw.Nodes[i]
		id := n.ID()
		ang := solarAngle(id)
		if n.IsGroup || strings.Contains(strings.ToLower(n.Hostname), "(group)") {
			groups = append(groups, member{n: n, angle: ang})
			continue
		}
		key := solarSystemKey(n)
		s := systems[key]
		if s == nil {
			s = &system{key: key, angle: solarAngle(key)}
			systems[key] = s
		}
		s.members = append(s.members, member{n: n, angle: ang})
	}

	// Stable system order: alphabetical by key (never traffic).
	sysList := make([]*system, 0, len(systems))
	for _, s := range systems {
		sort.Slice(s.members, func(a, b int) bool {
			return s.members[a].n.ID() < s.members[b].n.ID()
		})
		sysList = append(sysList, s)
	}
	sort.Slice(sysList, func(a, b int) bool {
		return sysList[a].key < sysList[b].key
	})

	pos := make(map[string]Vec, len(raw.Nodes))

	// Inner belt: protocol group nodes around the galactic centre.
	for i, g := range groups {
		a := g.angle + float64(i)*0.17
		r := solarGroupBeltR * (0.7 + 0.3*frac(g.angle))
		pos[g.n.ID()] = Vec{math.Cos(a) * r, math.Sin(a) * r}
	}

	// Place each star system on a galactic ring; planets on fixed local orbits.
	for i, s := range sysList {
		ring := i / solarMaxSystemsRing
		slot := i % solarMaxSystemsRing
		nOnRing := minInt(solarMaxSystemsRing, len(sysList)-ring*solarMaxSystemsRing)
		step := (2 * math.Pi) / float64(nOnRing)
		// Mix stable key angle with even slot spacing so systems don't pile up.
		sysAngle := s.angle*0.12 + float64(slot)*step + float64(ring)*0.35
		sysR := solarSystemBaseR + float64(ring)*solarSystemStepR +
			float64(slot%3)*22

		star := Vec{math.Cos(sysAngle) * sysR, math.Sin(sysAngle) * sysR}

		if len(s.members) == 1 {
			// Lone host sits at the system centre (its own star).
			pos[s.members[0].n.ID()] = star
			continue
		}

		// All members orbit the system centre. Angle + shell from id hash only
		// so a host never jumps rings when traffic ranks change.
		for _, m := range s.members {
			id := m.n.ID()
			shell := solarShell(id)
			orbit := solarPlanetBaseR + float64(shell)*solarPlanetStepR
			// Slight eccentricity from hash keeps systems from looking rigid.
			orbit *= 0.94 + 0.12*frac(m.angle)
			a := m.angle
			pos[id] = Vec{
				star.X + math.Cos(a)*orbit,
				star.Y + math.Sin(a)*orbit,
			}
		}
	}

	// Honour pins last.
	for id, p := range pins {
		if _, ok := pos[id]; ok {
			pos[id] = p
		}
	}

	// Incremental: keep prior coordinates for ids that still exist when the set
	// only grew — new nodes get placed above; existing don't teleport if we
	// already had them (membership sig change already implies recompute, but
	// when a single host is added we recompute fully; prior positions for
	// unchanged ids would still be re-derived identically from hashes).
	_ = le.positions[mode]

	le.positions[mode] = pos
	le.settled[mode] = true
	le.temp[mode] = 0
}

// solarSystemKey groups a host into a star system: /24 when IPv4, else a
// coarse role/name bucket so non-IP nodes still form islands.
func solarSystemKey(n Node) string {
	if s := primarySubnet24(n); s != "" {
		return s + ".0/24"
	}
	id := n.ID()
	if strings.Contains(id, "/") {
		return baseCIDR(id)
	}
	if n.Role != "" && n.Role != "unknown" {
		return "role:" + n.Role
	}
	return "other"
}

func solarAngle(id string) float64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(id); i++ {
		h ^= uint64(id[i])
		h *= 1099511628211
	}
	return float64(h%1000000) / 1000000.0 * 2 * math.Pi
}

// solarShell picks a stable orbital shell 0..solarOrbitShells-1 from the id.
func solarShell(id string) int {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(id); i++ {
		h ^= uint64(id[i])
		h *= 1099511628211
	}
	return int(h % uint64(solarOrbitShells))
}

func frac(a float64) float64 {
	x := a / math.Pi
	return x - math.Floor(x)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	if b < 1 {
		return 1
	}
	return b
}
