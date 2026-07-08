// Protocol color mapping (must match server-side capture/protocols.go)
const PROTOCOL_COLORS = {
    'TCP': '#3498db',
    'UDP': '#2ecc71',
    'ICMP': '#f39c12',
    'HTTP': '#e67e22',
    'HTTPS': '#9b59b6',
    'DNS': '#1abc9c',
    'SSH': '#e74c3c',
    'FTP': '#ff6b9d',
    'SMTP': '#8b4513',
    'MySQL': '#34495e',
    'PostgreSQL': '#16a085',
    'InfluxDB': '#22ADF6',
    'Slurm': '#ff7f50',
    'ARP': '#95a5a6',
    'IPv6': '#7f8c8d',
    // L2 topology / mapping
    'VLAN': '#d35400',
    'LLDP': '#27ae60',
    'CDP': '#2980b9',
    'STP': '#8e44ad',
    // L3 routing / discovery
    'NDP': '#1f8a70',
    'IGMP': '#c0392b',
    'OSPF': '#f1c40f',
    // L7 broadcast / service discovery
    'mDNS': '#e84393',
    'SSDP': '#00cec9',
    'LLMNR': '#6c5ce7',
    'NetBIOS': '#fdcb6e',
    'DHCP': '#0984e3',
    'WS-Discovery': '#a29bfe',
    // VPN / tunnel
    'WireGuard': '#b5179e',
    'OpenVPN': '#f48c06',
    // Kubernetes cluster
    'VXLAN': '#326ce5',
    'Geneve': '#5b8def',
    'K8s-API': '#1f6feb',
    'etcd': '#419eda',
    'Kubelet': '#6cb6ff',
    'Other': '#ecf0f1'
};

// OSI layer grouping for the legend/filters (must match server-side LayerNum).
// Order here controls display order: top (L2) to bottom (L7).
const PROTOCOL_LAYERS = [
    { label: 'L2 · Data Link', protocols: ['ARP', 'VLAN', 'LLDP', 'CDP', 'STP'] },
    { label: 'L3 · Network', protocols: ['ICMP', 'NDP', 'IGMP', 'OSPF', 'IPv6'] },
    { label: 'L4 · Transport', protocols: ['TCP', 'UDP'] },
    { label: 'L7 · Application', protocols: ['HTTP', 'HTTPS', 'DNS', 'mDNS', 'SSDP', 'LLMNR', 'NetBIOS', 'DHCP', 'WS-Discovery', 'SSH', 'FTP', 'SMTP', 'MySQL', 'PostgreSQL', 'InfluxDB', 'Slurm'] },
    { label: 'VPN · Tunnel', protocols: ['WireGuard', 'OpenVPN'] },
    { label: 'K8s · Cluster', protocols: ['VXLAN', 'Geneve', 'K8s-API', 'etcd', 'Kubelet'] },
    { label: '— · Other', protocols: ['Other'] }
];

// Protocols shown by default. Everything else starts filtered out (checkbox
// unchecked) so the initial graph shows only general host-to-host traffic;
// topology, routing, and zero-config discovery noise (mDNS, SSDP, LLMNR, …)
// stay hidden until the user checks them to include that traffic.
const DEFAULT_VISIBLE_PROTOCOLS = new Set([
    'ICMP', 'TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS'
    // K8s · Cluster (VXLAN/Geneve/K8s-API/etcd/Kubelet) stays off by default.
]);

// Global state
let network = null;
let nodes = new vis.DataSet();
let edges = new vis.DataSet();
let ws = null;
let protocolFilters = new Set();
let protocolStats = {}; // latest per-protocol packet totals from the server (all protocols)
let packets = []; // Store captured packets
let packetCache = new Map(); // Persistent packet cache by ID
let packetCursor = 0; // Highest packet ID fetched (for incremental /api/packets polling)
let selectedPacketId = null;
let selectedPacketIndex = -1; // Track selected packet index for keyboard navigation
let currentClusterLayout = 'force'; // Track current cluster layout
// Subnet "islands" computed by the Clustered Subnet layout. Each entry holds the
// bounding circle + label so the network's afterDrawing hook can render a dotted
// blue ring around every subnet. Empty for every other layout.
let subnetIslands = [];

// Smooth layout animation. The server computes node positions (its own physics),
// but only sends them ~10x/second; snapping nodes to each update looks jittery.
// We instead store the server position as a per-node target and a separate
// rendered position, then ease rendered -> target every animation frame so the
// graph glides smoothly at the display's refresh rate. Physics stays on the
// server; this is pure presentation interpolation.
let nodeTargetPos = new Map(); // id -> {x, y} latest server position
let nodeRenderPos = new Map(); // id -> {x, y} currently displayed position
let positionAnimationActive = false;
const POSITION_EASE = 0.28; // fraction of remaining distance moved per frame
// When the user changes a filter, re-fit the camera to just the displayed nodes
// on the resulting full snapshot (so the view isn't centered on now-empty space).
let fitOnNextFull = false;
// While a CHUNKED full snapshot streams in (first message isFull+partial, then
// partial chunks, ending with fullDone), the ids applied so far accumulate here
// so stale reconciliation and the camera fit run over the complete view.
let fullSyncIds = null; // { nodes: Set, edges: Set } or null

// Focus mode: hovering/clicking a node highlights it + neighbours, dims the rest.
let focusActive = false;
let focusPinned = false; // true when a click locked focus (hover won't change it)
let focusKeepNodes = null; // Set of node ids kept bright while focus is active
let focusKeepEdges = null; // Set of edge ids kept bright while focus is active

// Latest server data per node/edge id. Tooltips, details panels, and search read
// live counts from here, so count-only changes never need to touch the vis
// DataSet (whose update path deep-merges, re-parses and redraws per item).
let nodeMeta = new Map(); // id -> latest server ViewNode
let edgeMeta = new Map(); // id -> latest server ViewEdge

// Render signature per id: a string of everything that affects how the item is
// drawn. A delta whose signature matches the last applied one is data-only
// (counters ticking up) and skips the DataSet entirely.
let lastNodeSig = new Map(); // id -> render signature string
let lastEdgeSig = new Map(); // id -> render signature string

// Node currently under the pointer (for async tooltip enrichment) and the node
// the details panel is showing (for async detail re-render).
let lastHoverNodeId = null;
let detailsNodeId = null;

// Phase 4 subnet aggregation: /24 CIDRs the user expanded back into hosts.
// Mirrors the server's per-client ExpandedSubnets (we initiate every change and
// re-sync the full set on connect, so the two can't drift).
let expandedSubnets = new Set();

// The performance tier currently applied to the network options; re-applied via
// network.setOptions only when the node count crosses a tier boundary.
let currentTier = null;
// Edge labels are hidden above this node count (label text is the most expensive
// thing vis draws per edge).
const EDGE_LABEL_MAX_NODES = 100;
let edgeLabelsVisible = true;

// Traffic flow particles: small dots that travel along edges in the real packet
// direction, fed by the server's per-tick trafficFlows. Etherape-style.
let activeFlows = [];        // {from, to, color, progress, speed}
let flowAnimationActive = false;
const MAX_FLOW_PARTICLES = 220;
// Particles represent SIGNIFICANT traffic only: a flow needs at least this
// many packets in its ~100ms server tick (≈30 pkt/s) to spawn one, and speed
// scales with volume — light flows drift, heavy flows zip.
const FLOW_MIN_PACKETS = 3;
function flowParticleSpeed(packets) {
    return Math.min(0.05, Math.max(0.005, 0.005 + Math.log10((packets || 1) + 1) * 0.014));
}

const MAX_CACHED_PACKETS = 5000; // Keep last 5000 packets in memory

// Search worker for payload search
let searchWorker = null;
let searchRequestId = 0;
let pendingSearchCallback = null;
let serverSearchId = 0; // discards stale /api/search responses

function initSearchWorker() {
    try {
        searchWorker = new Worker('/static/search-worker.js');
        searchWorker.onmessage = function(e) {
            const { requestId, results } = e.data;
            if (pendingSearchCallback && requestId === searchRequestId) {
                pendingSearchCallback(results);
                pendingSearchCallback = null;
            }
        };
    } catch (err) {
        // Worker not available, payload search will be skipped
        searchWorker = null;
    }
}

// Performance optimization settings. Top-N selection now happens server-side
// (graph/view.go), so the client no longer caps or sorts nodes/edges itself.
let UPDATE_THROTTLE_MS = 150; // Base throttle (dynamically adjusted)
let lastUpdateTime = 0;
let pendingUpdate = null;
let updateScheduled = false;
let updateTimer = null;

let lastPacketPanelRefresh = 0;

// Physics damping control for burst node additions
let physicsDampingTimeout = null;

// Packet filter state
let packetFilterText = '';
let packetFilterProtocol = '';
let filteredPacketList = []; // Cached filtered+sorted packet list for virtual scroll
const PACKET_ROW_HEIGHT = 41; // Height of each packet row in pixels
const PACKET_RENDER_BUFFER = 10; // Extra rows to render above/below viewport


// Replay mode state
let replayMode = {
    active: false,
    currentFile: null,
    startTime: null,
    endTime: null,
    durationSeconds: 0,
    currentOffset: 0
};

// Initialize the application
function init() {
    initSearchWorker();
    loadOverrides();
    setupNetwork();
    setupLegend();
    setupDropdowns();
    setupModalHandlers();
    setupHeaderToggle();
    setupSearch();
    setupPacketPanel();
    setupTheme();
    setupClusterLayout();
    setupChimpyMode();
    setupGameMode();
    setupReplayMode();
    setupStreams();
    connectWebSocket();
    // Poll for new packets (the live table is fed by fetch now, not WS push).
    setInterval(pollPackets, 1000);
    // Position easing snaps (and its rAF loop pauses) while the tab is hidden;
    // resume smooth animation when the tab becomes visible again.
    document.addEventListener('visibilitychange', function() {
        if (!document.hidden) startPositionAnimation();
    });
}

// Performance tier thresholds
const PERF_TIER_LOW = 30;      // Below this: full quality
const PERF_TIER_MEDIUM = 100;  // Below this: reduced quality
const PERF_TIER_HIGH = 300;    // Below this: performance mode
const PERF_TIER_EXTREME = 500; // Above this: maximum performance

// Get performance tier based on node count
function getPerformanceTier(nodeCount) {
    if (nodeCount <= PERF_TIER_LOW) return 'low';
    if (nodeCount <= PERF_TIER_MEDIUM) return 'medium';
    if (nodeCount <= PERF_TIER_HIGH) return 'high';
    if (nodeCount <= PERF_TIER_EXTREME) return 'extreme';
    return 'maximum';
}

// Get theme-aware network options
function getNetworkOptions() {
    const isLightTheme = document.body.classList.contains('light-theme');
    const nodeCount = nodes.length;

    // Adaptive visual-quality settings based on node count. (Physics runs on the
    // server — see graph/layout.go — so there are no physics settings here.)
    const tier = getPerformanceTier(nodeCount);

    // Visual quality settings based on tier
    const shadowsEnabled = tier === 'low';
    const smoothEdges = tier === 'low' || tier === 'medium';
    const hoverEnabled = tier !== 'maximum';
    const hideLabelsOnZoom = tier === 'extreme' || tier === 'maximum';

    return {
        nodes: {
            shape: 'dot',
            size: 20,
            font: {
                size: 14,
                color: isLightTheme ? '#2c3e50' : '#ffffff',
                face: 'monospace'
            },
            borderWidth: tier === 'maximum' ? 1 : 2,
            borderWidthSelected: 4,
            color: {
                border: isLightTheme ? '#7f8c8d' : '#2c3e50',
                background: isLightTheme ? '#bdc3c7' : '#34495e',
                highlight: {
                    border: isLightTheme ? '#2980b9' : '#3498db',
                    background: isLightTheme ? '#3498db' : '#2980b9'
                }
            },
            shadow: {
                enabled: shadowsEnabled,
                color: isLightTheme ? 'rgba(0,0,0,0.15)' : 'rgba(0,0,0,0.5)',
                size: 10,
                x: 5,
                y: 5
            },
            scaling: {
                min: 20,          // base node size
                max: 30,          // high-traffic nodes only ever 1.5x the base size
                label: {
                    enabled: !hideLabelsOnZoom,
                    min: hideLabelsOnZoom ? 0 : 10,
                    max: 16
                }
            }
        },
        edges: {
            width: tier === 'maximum' ? 1 : 2,
            arrows: {
                to: { enabled: false },
                from: { enabled: false }
            },
            smooth: smoothEdges ? {
                type: 'continuous',
                roundness: 0.5
            } : false,
            font: {
                size: 11,
                color: isLightTheme ? '#2c3e50' : '#ecf0f1',
                strokeWidth: 3,
                strokeColor: isLightTheme ? '#ffffff' : '#2c3e50'
            },
            shadow: {
                enabled: shadowsEnabled,
                color: isLightTheme ? 'rgba(0,0,0,0.1)' : 'rgba(0,0,0,0.3)',
                size: 5,
                x: 3,
                y: 3
            }
        },
        // Physics is OFF: node positions are computed on the server (graph/
        // layout.go) and applied directly, so the browser never runs a force
        // simulation. This removes the biggest client-side CPU cost.
        physics: { enabled: false },
        layout: { improvedLayout: false, hierarchical: false },
        interaction: {
            hover: true,
            tooltipDelay: 100,
            zoomSpeed: 0.5,
            zoomView: true,
            navigationButtons: false,
            keyboard: {
                enabled: true,
                // Only pan the graph with arrow keys when the graph canvas itself
                // is focused, and require a click to focus it (not just hover) —
                // so arrow keys used in the packet analyzer don't move the graph.
                bindToWindow: false,
                autoFocus: false,
                speed: {
                    x: 10,
                    y: 10,
                    zoom: 0.02
                }
            }
        },
        manipulation: {
            enabled: false
        },
        configure: {
            enabled: false
        }
    };
}

// Setup the graph renderer: the WebGL renderer (static/glrenderer.js) is the
// DEFAULT wherever WebGL2 is available; vis.Network remains as the automatic
// fallback and can be forced with ?renderer=vis / localStorage.renderer='vis'.
// ?renderer=cosmos opts into the cosmos.gl renderer (GPU force layout in the
// browser — static/cosmosrenderer.js); it sets network.ownsLayout, which turns
// off everything that assumes server-owned positions (position frames, flow
// particles, subnet islands). All renderers implement the same API surface, so
// everything below is renderer-agnostic.
function setupNetwork() {
    const container = document.getElementById('network');
    const data = { nodes: nodes, edges: edges };
    const options = getNetworkOptions();

    const rendererParam = new URLSearchParams(window.location.search).get('renderer');
    const stored = localStorage.getItem('renderer');
    const wantCosmos = rendererParam === 'cosmos' ||
        (rendererParam == null && stored === 'cosmos');
    const wantVis = rendererParam === 'vis' ||
        (rendererParam !== 'gl' && !wantCosmos && stored === 'vis');
    if (wantCosmos && window.CosmosNetwork && CosmosNetwork.isSupported()) {
        network = new CosmosNetwork(container, data, options);
        console.log('Renderer: cosmos.gl (GPU force layout)');
    } else if (!wantVis && window.GLNetwork && GLNetwork.isSupported()) {
        network = new GLNetwork(container, data, options);
        console.log('Renderer: WebGL (GLNetwork)' + (wantCosmos ? ' [cosmos unavailable]' : ''));
    } else {
        network = new vis.Network(container, data, options);
        console.log('Renderer: vis-network (Canvas2D)' + (wantVis ? ' [forced]' : ' [WebGL2 unavailable]'));
    }

    // Draw the dotted blue subnet rings beneath the nodes/edges. Runs on every
    // redraw; cheap no-op unless the Clustered Subnet layout populated islands.
    network.on('beforeDrawing', function(ctx) {
        drawSubnetIslands(ctx);
    });
    // Traffic particles animate on a SEPARATE overlay canvas (see setupFlowOverlay)
    // so the heavy graph canvas only repaints when the graph actually changes,
    // instead of every frame just to move a few dots.
    setupFlowOverlay();

    // Physics is off and layout is server-side, so there is no stabilization
    // pass; the saved layout mode is sent to the server on WebSocket connect.

    // Handle node/edge selection. Clicking a node also pins focus on it.
    network.on('click', function(params) {
        if (params.nodes.length > 0) {
            showNodeDetails(params.nodes[0]);
            focusNode(params.nodes[0], true);
        } else if (params.edges.length > 0) {
            showEdgeDetails(params.edges[0]);
        } else {
            hideDetails();
            clearFocus();
        }
    });

    // Hover highlights a node + its neighbours and dims the rest, unless a click
    // has pinned focus on something. Tooltips are built lazily right here from
    // the meta maps — never precomputed per delta.
    network.on('hoverNode', function(params) {
        if (!focusPinned) focusNode(params.node, false);
        lastHoverNodeId = params.node;
        let meta = nodeMeta.get(params.node);
        if (!meta && network.rawMode) {
            // Raw-scale mode keeps no per-node meta; synthesize a minimal one on
            // hover (bounded by interaction) so the tooltip + lazy /api/node
            // enrichment work.
            meta = { id: params.node, label: params.node, ips: [params.node],
                packetCount: 0, byteCount: 0 };
            nodeMeta.set(params.node, meta);
        }
        if (meta) {
            showGraphTooltipAt(formatNodeTooltip(meta),
                network.canvasToDOM(network.getPosition(params.node)));
            // Enrich lazily: the stream is slim (no IPs/deviceInfo); fetch the
            // full record and refresh the tooltip if still hovering this node.
            if (!meta.detailLoaded && !meta.isSubnet) {
                fetchNodeDetail(params.node).then(m => {
                    if (m && lastHoverNodeId === params.node) {
                        showGraphTooltipAt(formatNodeTooltip(m),
                            network.canvasToDOM(network.getPosition(params.node)));
                    }
                });
            }
        }
    });
    network.on('blurNode', function() {
        if (!focusPinned) clearFocus();
        lastHoverNodeId = null;
        hideGraphTooltip();
    });
    network.on('hoverEdge', function(params) {
        const meta = edgeMeta.get(params.edge);
        if (!meta) return;
        const ps = network.getPositions([meta.from, meta.to]);
        const a = ps[meta.from], b = ps[meta.to];
        if (!a || !b) return;
        showGraphTooltipAt(formatEdgeTooltip(meta),
            network.canvasToDOM({ x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 }));
    });
    network.on('blurEdge', hideGraphTooltip);
    network.on('dragStart', hideGraphTooltip);
    network.on('zoom', hideGraphTooltip);
}

// --- Lazy graph tooltip --------------------------------------------------------
// One reusable div, filled on hover from the meta maps. Replaces vis's built-in
// title tooltips, which required building tooltip strings for every node/edge on
// every update whether or not anything was ever hovered.
let graphTooltipEl = null;
function ensureGraphTooltip() {
    if (!graphTooltipEl) {
        graphTooltipEl = document.createElement('div');
        graphTooltipEl.className = 'graph-tooltip';
        graphTooltipEl.style.display = 'none';
        document.body.appendChild(graphTooltipEl);
    }
    return graphTooltipEl;
}

// Show the tooltip near a DOM-space position (relative to the network container).
function showGraphTooltipAt(text, domPos) {
    const net = document.getElementById('network');
    if (!net) return;
    const el = ensureGraphTooltip();
    el.textContent = text;
    el.style.display = 'block';
    const rect = net.getBoundingClientRect();
    let x = rect.left + domPos.x + 14;
    let y = rect.top + domPos.y + 14;
    // Flip to keep the tooltip on screen.
    if (x + el.offsetWidth > window.innerWidth - 8) x = Math.max(8, x - el.offsetWidth - 28);
    if (y + el.offsetHeight > window.innerHeight - 8) y = Math.max(8, y - el.offsetHeight - 28);
    el.style.left = x + 'px';
    el.style.top = y + 'px';
}

function hideGraphTooltip() {
    if (graphTooltipEl) graphTooltipEl.style.display = 'none';
}

// Render the node-encoding legend (role shapes/colors, size meaning, and the
// color-mode toggle) at the top of the legend panel. Rebuilt on color-mode change.
function renderLegend() {
    const container = document.getElementById('protocolLegend');
    if (!container) return;
    let block = document.getElementById('nodeLegend');
    if (!block) {
        block = document.createElement('div');
        block.id = 'nodeLegend';
        container.prepend(block);
    }
    const roles = ['server', 'client', 'router', 'switch', 'gateway', 'iot', 'multicast'];
    // Role swatches are only meaningful when coloring by role.
    const rolesHTML = nodeColorMode === 'role'
        ? roles.map(r => `
            <div class="legend-item">
                <span class="color-box" style="background-color:${ROLE_COLOR[r]}"></span>
                <span>${ROLE_NAME[r]}</span>
            </div>`).join('')
        : `<div class="legend-note">grey → yellow → orange → red = rising traffic</div>`;
    block.innerHTML = `
        <div class="legend-layer-heading">Nodes — size = traffic</div>
        <div class="legend-colormode">
            <span>Color by:</span>
            <button class="cm-btn ${nodeColorMode === 'traffic' ? 'active' : ''}" onclick="setNodeColorMode('traffic')">Traffic</button>
            <button class="cm-btn ${nodeColorMode === 'role' ? 'active' : ''}" onclick="setNodeColorMode('role')">Role</button>
        </div>
        ${rolesHTML}
        <div class="legend-layer-heading">Protocols (edge color)</div>`;
}

// Setup protocol legend and filters, grouped by OSI layer
function setupLegend() {
    const legendContainer = document.getElementById('protocolLegend');
    const filtersContainer = document.getElementById('protocolFilters');

    renderLegend();

    PROTOCOL_LAYERS.forEach(group => {
        // Layer headings for both the legend and the filter list
        const legendHeading = document.createElement('div');
        legendHeading.className = 'legend-layer-heading';
        legendHeading.textContent = group.label;
        legendContainer.appendChild(legendHeading);

        const filterHeading = document.createElement('div');
        filterHeading.className = 'legend-layer-heading';
        filterHeading.textContent = group.label;
        filtersContainer.appendChild(filterHeading);

        group.protocols.forEach(protocol => {
            const color = PROTOCOL_COLORS[protocol];
            if (!color) return;

            // Add to legend. The count span shows this protocol's packet total
            // (filled live from server stats), even for hidden protocols.
            const legendItem = document.createElement('div');
            legendItem.className = 'legend-item';
            legendItem.innerHTML = `
                <span class="color-box" style="background-color: ${color}"></span>
                <span>${protocol}</span>
                <span class="legend-count" data-proto="${protocol}"></span>
            `;
            legendContainer.appendChild(legendItem);

            // Add to filters. Non-general protocols start unchecked and seed the
            // hidden set, so the default view is just general traffic.
            const showByDefault = DEFAULT_VISIBLE_PROTOCOLS.has(protocol);
            if (!showByDefault) {
                protocolFilters.add(protocol);
            }
            const filterItem = document.createElement('label');
            filterItem.className = 'filter-item';
            filterItem.innerHTML = `
                <input type="checkbox" value="${protocol}"${showByDefault ? ' checked' : ''}>
                <span>${protocol}</span>
                <span class="legend-count" data-proto="${protocol}"></span>
            `;
            filterItem.querySelector('input').addEventListener('change', handleFilterChange);
            filtersContainer.appendChild(filterItem);
        });
    });

    // Reflect the default-hidden protocols in the filter badge/indicator.
    updateFilterIndicator();
}

// Compact packet count, e.g. 1234 -> "1.2k", 2_500_000 -> "2.5M".
function formatCount(n) {
    if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'k';
    return String(n);
}

// Fill the per-protocol packet counts in the legend and filter lists from the
// server's filter-independent totals — so even unchecked (hidden) protocols show
// how much traffic they carry. The count elements are cached (they're built once)
// so this runs on every delta without re-querying the DOM.
let legendCountEls = null;
function updateProtocolCounts(stats) {
    if (!stats) return;
    protocolStats = stats;
    if (!legendCountEls) {
        legendCountEls = Array.from(document.querySelectorAll('.legend-count[data-proto]'))
            .map(el => [el, el.getAttribute('data-proto')]);
    }
    for (const [el, proto] of legendCountEls) {
        const c = stats[proto] || 0;
        el.textContent = c > 0 ? formatCount(c) : '';
    }
}

// Setup dropdown toggles (submenus)
function setupDropdowns() {
    const statsToggle = document.getElementById('statsToggle');
    const filterToggle = document.getElementById('filterToggle');
    const legendToggle = document.getElementById('legendToggle');
    const settingsToggle = document.getElementById('settingsToggle');
    const replayToggle = document.getElementById('replayToggle');

    const statsSubmenu = document.getElementById('statsSubmenu');
    const filterContent = document.getElementById('protocolFilters');
    const legendContent = document.getElementById('protocolLegend');
    const settingsContent = document.getElementById('settingsContent');
    const replaySubmenu = document.getElementById('replaySubmenu');

    // Toggle submenu function
    function toggleSubmenu(button, submenu) {
        const isActive = button.classList.contains('active');

        // Close all other submenus
        document.querySelectorAll('.nav-link').forEach(btn => {
            if (btn !== button) {
                btn.classList.remove('active');
            }
        });
        document.querySelectorAll('.submenu').forEach(sub => {
            if (sub !== submenu) {
                sub.classList.remove('show');
            }
        });

        // Toggle current submenu
        button.classList.toggle('active');
        submenu.classList.toggle('show');
    }

    // Add event listeners
    if (statsToggle && statsSubmenu) {
        statsToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleSubmenu(statsToggle, statsSubmenu);
        });
    }

    if (filterToggle && filterContent) {
        filterToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleSubmenu(filterToggle, filterContent);
        });
    }

    if (legendToggle && legendContent) {
        legendToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleSubmenu(legendToggle, legendContent);
        });
    }

    if (settingsToggle && settingsContent) {
        settingsToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleSubmenu(settingsToggle, settingsContent);
        });
    }

    if (replayToggle && replaySubmenu) {
        replayToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleSubmenu(replayToggle, replaySubmenu);
        });
    }

    // Streams toggle
    const streamsToggle = document.getElementById('streamsToggle');
    const streamsSubmenu = document.getElementById('streamsSubmenu');

    if (streamsToggle && streamsSubmenu) {
        streamsToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleSubmenu(streamsToggle, streamsSubmenu);
            // Load streams when opening - use saved protocol filter
            if (streamsSubmenu.classList.contains('show')) {
                const filter = document.getElementById('streamProtocolFilter');
                loadStreams(filter?.value || '');
            }
        });
    }

    // Settings sub-toggles
    const themeSubToggle = document.getElementById('themeSubToggle');
    const themeSubmenu = document.getElementById('themeSubmenu');
    const clustersSubToggle = document.getElementById('clustersSubToggle');
    const clustersSubmenu = document.getElementById('clustersSubmenu');

    if (themeSubToggle && themeSubmenu) {
        themeSubToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            themeSubToggle.classList.toggle('active');
            themeSubmenu.classList.toggle('show');
        });
    }

    if (clustersSubToggle && clustersSubmenu) {
        clustersSubToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            clustersSubToggle.classList.toggle('active');
            clustersSubmenu.classList.toggle('show');
        });
    }

    // Close submenus when clicking outside sidebar
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.sidebar')) {
            document.querySelectorAll('.nav-link').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelectorAll('.submenu').forEach(sub => {
                sub.classList.remove('show');
            });
            document.querySelectorAll('.settings-sublink').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelectorAll('.settings-submenu').forEach(sub => {
                sub.classList.remove('show');
            });
        }
    });

    // Prevent submenu from closing when clicking inside
    document.querySelectorAll('.submenu').forEach(submenu => {
        submenu.addEventListener('click', function(e) {
            e.stopPropagation();
        });
    });
}

// Setup modal handlers
function setupModalHandlers() {
    const closeButton = document.getElementById('closeButton');

    // Close button click
    closeButton.addEventListener('click', hideDetails);

    // Escape key to close modal and Chimpy mode
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            // Close Chimpy mode if active
            if (chimpyMode.active) {
                toggleChimpyMode();
            }
            // Close details panel
            hideDetails();
        }
    });

    // Global keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        const searchInput = document.getElementById('searchInput');
        const packetPanel = document.getElementById('packetPanel');
        const isPanelOpen = packetPanel.classList.contains('show');

        // Don't handle shortcuts if user is typing in an input
        const isTyping = e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA';

        // "/" to focus search (unless already typing)
        if (e.key === '/' && !isTyping) {
            e.preventDefault();
            searchInput.focus();
            return;
        }

        // Arrow keys for packet navigation when packet panel is open
        if (isPanelOpen && (e.key === 'ArrowUp' || e.key === 'ArrowDown')) {
            // Don't interfere if user is in search input
            if (e.target === searchInput) {
                return;
            }

            e.preventDefault();

            if (packets.length === 0) return;

            if (e.key === 'ArrowDown') {
                selectedPacketIndex = Math.min(selectedPacketIndex + 1, packets.length - 1);
            } else if (e.key === 'ArrowUp') {
                selectedPacketIndex = Math.max(selectedPacketIndex - 1, 0);
            }

            // Select and display the packet
            if (selectedPacketIndex >= 0 && selectedPacketIndex < packets.length) {
                const packet = packets[selectedPacketIndex];
                selectPacket(packet.id);
            }
        }
    });
}

// Setup sidebar toggle for collapse/expand
function setupHeaderToggle() {
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebarLogo = document.querySelector('.sidebar-logo');
    const sidebar = document.querySelector('.sidebar');
    const container = document.getElementById('network');

    // Function to toggle sidebar
    function toggleSidebar() {
        sidebar.classList.toggle('collapsed');

        // Close all submenus when collapsing
        if (sidebar.classList.contains('collapsed')) {
            document.querySelectorAll('.nav-link').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelectorAll('.submenu').forEach(sub => {
                sub.classList.remove('show');
            });
        }
    }

    if (sidebarToggle && sidebar) {
        // Toggle button click (only when sidebar is expanded)
        sidebarToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleSidebar();
        });

        // Logo click to reopen sidebar when collapsed
        if (sidebarLogo) {
            sidebarLogo.addEventListener('click', function(e) {
                if (sidebar.classList.contains('collapsed')) {
                    e.stopPropagation();
                    toggleSidebar();
                }
            });
        }

        // Handle the end of the CSS transition to update canvas size
        sidebar.addEventListener('transitionend', function(e) {
            // Only respond to width transitions on the sidebar itself
            if (e.propertyName === 'width' && e.target === sidebar) {
                if (network && container) {
                    // Update canvas size without repositioning nodes
                    const width = container.offsetWidth;
                    const height = container.offsetHeight;
                    network.setSize(width + 'px', height + 'px');
                }
            }
        });
    }
}

// Setup search functionality
function setupSearch() {
    const searchInput = document.getElementById('searchInput');
    const searchClear = document.getElementById('searchClear');
    const searchResults = document.getElementById('searchResults');
    let searchTimeout = null;

    // Handle input changes
    searchInput.addEventListener('input', function(e) {
        const query = e.target.value.trim();

        // Show/hide clear button
        searchClear.style.display = query ? 'flex' : 'none';

        // Debounce search
        clearTimeout(searchTimeout);
        if (query.length === 0) {
            searchResults.classList.remove('show');
            return;
        }

        searchTimeout = setTimeout(() => {
            performSearch(query);
        }, 300);
    });

    // Handle clear button
    searchClear.addEventListener('click', function() {
        searchInput.value = '';
        searchClear.style.display = 'none';
        searchResults.classList.remove('show');
        searchInput.focus();
    });

    // Close results and clear input when clicking outside
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.search-container')) {
            searchInput.value = '';
            searchClear.style.display = 'none';
            searchResults.classList.remove('show');
        }
    });

    // Keyboard navigation
    searchInput.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            searchInput.value = '';
            searchClear.style.display = 'none';
            searchResults.classList.remove('show');
        }
    });
}

// Perform search across nodes, edges, and packet payloads
function performSearch(query) {
    const searchResults = document.getElementById('searchResults');
    const results = [];
    const queryLower = query.toLowerCase();
    const isHexQuery = /^[0-9a-f\s]+$/i.test(query);

    // Search through nodes
    const allNodes = nodes.get();
    allNodes.forEach(node => {
        const matches = [];

        // Search IP address (node.id)
        if (node.id && node.id.toLowerCase().includes(queryLower)) {
            matches.push({ type: 'IP', value: node.id });
        }

        // Search hostname (node.label)
        if (node.label && node.label.toLowerCase().includes(queryLower)) {
            matches.push({ type: 'Hostname', value: node.label });
        }

        // Search through all IPs in the node's ips array (IPv4 and IPv6)
        if (node.ips && Array.isArray(node.ips)) {
            node.ips.forEach(ip => {
                if (ip && ip.toLowerCase().includes(queryLower)) {
                    matches.push({ type: 'IP Address', value: ip });
                }
            });
        }

        // Search the tooltip text (role, link info, packets, bytes, …), built on
        // demand from the meta map — vis items no longer carry a title.
        const meta = nodeMeta.get(node.id);
        if (meta) {
            const title = formatNodeTooltip(meta);
            if (title.toLowerCase().includes(queryLower)) {
                matches.push(...extractTitleMatches(title, query));
            }
        }

        if (matches.length > 0) {
            results.push({
                nodeId: node.id,
                label: node.label || node.id,
                ip: node.id,
                matches: matches,
                packetCount: meta ? (meta.packetCount || 0) : 0,
                byteCount: meta ? formatBytes(meta.byteCount || 0) : ''
            });
        }
    });

    // Search through edges for packet data
    const allEdges = edges.get();
    const edgeMatches = new Map(); // Group by node

    allEdges.forEach(edge => {
        // Search protocol name
        if (edge.protocol && edge.protocol.Name &&
            edge.protocol.Name.toLowerCase().includes(queryLower)) {
            addEdgeMatch(edgeMatches, edge, 'Protocol', edge.protocol.Name);
        }

        // Search edge label (contains packet count)
        if (edge.label && edge.label.toLowerCase().includes(queryLower)) {
            addEdgeMatch(edgeMatches, edge, 'Data', edge.label);
        }
    });

    // Add edge matches to results
    edgeMatches.forEach((matches, nodeId) => {
        const node = nodes.get(nodeId);
        if (node) {
            const existingResult = results.find(r => r.nodeId === nodeId);
            if (existingResult) {
                existingResult.matches.push(...matches);
            } else {
                const meta = nodeMeta.get(nodeId);
                results.push({
                    nodeId: nodeId,
                    label: node.label || node.id,
                    ip: node.id,
                    matches: matches,
                    packetCount: meta ? (meta.packetCount || 0) : 0,
                    byteCount: meta ? formatBytes(meta.byteCount || 0) : ''
                });
            }
        }
    });

    // Display node/edge results immediately
    displaySearchResults(results, query);

    // Server-side search over the WHOLE graph (Phase 5): hosts hidden inside
    // collapsed subnets or beyond the top-N view are invisible to the local
    // scan above, so merge the server's matches in asynchronously.
    const serverQueryId = ++serverSearchId;
    fetch('/api/search?q=' + encodeURIComponent(query) + '&limit=20')
        .then(r => r.ok ? r.json() : null)
        .then(data => {
            if (!data || !data.results || serverQueryId !== serverSearchId) return;
            let added = 0;
            for (const sr of data.results) {
                if (results.find(r => r.nodeId === sr.id)) continue;
                results.push({
                    nodeId: sr.id,
                    label: sr.label || sr.id,
                    ip: sr.id,
                    matches: [{ type: nodes.get(sr.id) ? 'Host' : 'Hidden host', value: (sr.ips || [sr.id]).join(', ') }],
                    packetCount: sr.packetCount || 0,
                    byteCount: formatBytes(sr.byteCount || 0),
                    // Subnet chain for un-collapsing when the user focuses it.
                    subnet24: sr.subnet24,
                    subnet16: sr.subnet16
                });
                added++;
            }
            if (added > 0) displaySearchResults(results, query);
        })
        .catch(() => { /* best-effort */ });

    // Search packet payloads asynchronously via Web Worker
    if (searchWorker && packetCache.size > 0) {
        const allCachedPackets = Array.from(packetCache.values());
        searchRequestId++;
        const currentRequestId = searchRequestId;

        pendingSearchCallback = function(workerResults) {
            if (currentRequestId !== searchRequestId) return; // Stale result

            // Merge worker results into existing displayed results
            for (const wr of workerResults) {
                let result = results.find(r => r.nodeId === wr.src);
                if (!result) {
                    const node = nodes.get(wr.src);
                    const meta = nodeMeta.get(wr.src);
                    result = {
                        nodeId: wr.src,
                        label: node ? (node.label || wr.src) : wr.src,
                        ip: wr.src,
                        matches: [],
                        packetCount: meta ? (meta.packetCount || 0) : 0,
                        byteCount: meta ? formatBytes(meta.byteCount || 0) : ''
                    };
                    results.push(result);
                }

                result.matches.push({
                    type: 'Payload',
                    value: `Found in packet #${wr.packetId}: "${wr.preview}"`,
                    packetId: wr.packetId
                });

                if (!result.packetIds) result.packetIds = [];
                result.packetIds.push(wr.packetId);
            }

            // Re-display with payload results merged in
            if (workerResults.length > 0) {
                displaySearchResults(results, query);
            }
        };

        searchWorker.postMessage({
            packets: allCachedPackets,
            query: query,
            requestId: currentRequestId
        });
    }
}

// Helper to convert string to bytes (lowercased for case-insensitive search)
function stringToBytes(str) {
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return bytes;
}

// Case-insensitive search in payload bytes
function searchInPayload(payloadBytes, queryBytes) {
    if (queryBytes.length === 0 || queryBytes.length > payloadBytes.length) {
        return false;
    }

    // Convert payload to lowercase for case-insensitive search
    const payloadLower = new Uint8Array(payloadBytes.length);
    for (let i = 0; i < payloadBytes.length; i++) {
        const byte = payloadBytes[i];
        // Convert A-Z to lowercase
        if (byte >= 65 && byte <= 90) {
            payloadLower[i] = byte + 32;
        } else {
            payloadLower[i] = byte;
        }
    }

    // Search for query bytes in payload
    for (let i = 0; i <= payloadLower.length - queryBytes.length; i++) {
        let found = true;
        for (let j = 0; j < queryBytes.length; j++) {
            if (payloadLower[i + j] !== queryBytes[j]) {
                found = false;
                break;
            }
        }
        if (found) return true;
    }
    return false;
}

// Get a preview of the payload around the matched query
function getPayloadPreview(payloadBytes, queryBytes) {
    // Find the match position
    const payloadLower = new Uint8Array(payloadBytes.length);
    for (let i = 0; i < payloadBytes.length; i++) {
        const byte = payloadBytes[i];
        if (byte >= 65 && byte <= 90) {
            payloadLower[i] = byte + 32;
        } else {
            payloadLower[i] = byte;
        }
    }

    let matchPos = -1;
    for (let i = 0; i <= payloadLower.length - queryBytes.length; i++) {
        let found = true;
        for (let j = 0; j < queryBytes.length; j++) {
            if (payloadLower[i + j] !== queryBytes[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            matchPos = i;
            break;
        }
    }

    if (matchPos === -1) return '';

    // Get context around the match (20 chars before and after)
    const contextStart = Math.max(0, matchPos - 20);
    const contextEnd = Math.min(payloadBytes.length, matchPos + queryBytes.length + 20);

    let preview = '';
    for (let i = contextStart; i < contextEnd; i++) {
        const byte = payloadBytes[i];
        if (byte >= 32 && byte <= 126) {
            preview += String.fromCharCode(byte);
        } else {
            preview += '.';
        }
    }

    // Truncate if too long
    if (preview.length > 50) {
        preview = preview.substring(0, 47) + '...';
    }

    return preview;
}

// Helper to add edge match
function addEdgeMatch(edgeMatches, edge, type, value) {
    const nodeId = edge.from; // Associate with source node
    if (!edgeMatches.has(nodeId)) {
        edgeMatches.set(nodeId, []);
    }
    edgeMatches.get(nodeId).push({ type, value });
}

// Extract matches from title
function extractTitleMatches(title, query) {
    const matches = [];
    const lines = title.split('\n');
    const queryLower = query.toLowerCase();

    lines.forEach(line => {
        if (line.toLowerCase().includes(queryLower)) {
            const parts = line.split(':');
            if (parts.length === 2) {
                matches.push({ type: parts[0].trim(), value: parts[1].trim() });
            }
        }
    });

    return matches;
}

// Live packet count for a vis node: the meta map has the freshest server value
// (vis items only refresh on visible style changes).
function metaPacketCount(node) {
    if (!node) return 0;
    const meta = nodeMeta.get(node.id);
    return (meta ? meta.packetCount : node.packetCount) || 0;
}

// Tooltip text for a node id, built on demand from the meta map (vis items no
// longer carry a precomputed title). Used by search and game mode.
function nodeTooltipFor(id) {
    const meta = nodeMeta.get(id);
    return meta ? formatNodeTooltip(meta) : '';
}

// --- Lazy node detail (Phase 5) -------------------------------------------
// The stream carries only render-relevant fields; IPs, deviceInfo and the
// connection summary are fetched from /api/node on demand (hover, details
// panel) and merged into the meta map. One in-flight fetch per node.
const nodeDetailPending = new Set();
async function fetchNodeDetail(nodeId) {
    const meta = nodeMeta.get(nodeId);
    if (meta && meta.detailLoaded) return meta;
    if (nodeDetailPending.has(nodeId)) return meta;
    nodeDetailPending.add(nodeId);
    try {
        const resp = await fetch('/api/node?id=' + encodeURIComponent(nodeId));
        if (!resp.ok) return meta;
        const d = await resp.json();
        const m = nodeMeta.get(nodeId);
        if (!m) return null; // node left the view while fetching
        m.ips = d.ips;
        m.deviceInfo = d.deviceInfo;
        m.role = m.role || d.role;
        m.peers = d.peers;
        m.detailEdges = d.edges;
        m.detailLoaded = true;
        return m;
    } catch (e) {
        return meta;
    } finally {
        nodeDetailPending.delete(nodeId);
    }
}

// Live formatted byte count for a vis node (game mode display). Reads the meta
// map directly — the old approach regex-parsed "Bytes: X" back out of a
// rendered tooltip string, a format-then-parse round trip that silently broke
// whenever the tooltip format drifted.
function metaByteCount(node) {
    if (!node) return '';
    const meta = nodeMeta.get(node.id);
    const bytes = (meta ? meta.byteCount : node.byteCount) || 0;
    return bytes ? formatBytes(bytes) : '';
}

// Display search results
function displaySearchResults(results, query) {
    const searchResults = document.getElementById('searchResults');

    if (results.length === 0) {
        searchResults.innerHTML = '<div class="search-no-results">No results found</div>';
        searchResults.classList.add('show');
        return;
    }

    // Sort by relevance (packet count)
    results.sort((a, b) => b.packetCount - a.packetCount);

    // Limit to top 10 results
    const topResults = results.slice(0, 10);

    const html = topResults.map(result => {
        const matchTags = result.matches
            .slice(0, 3) // Limit tags
            .map(m => `<span class="search-result-tag">${highlightMatch(m.value, query)}</span>`)
            .join('');

        const packetIdsAttr = result.packetIds && result.packetIds.length > 0
            ? `data-packet-ids="${result.packetIds.join(',')}"`
            : '';

        // Check if the first matching packet is part of a stream
        let streamIdAttr = '';
        let streamsTag = '';
        if (result.packetIds && result.packetIds.length > 0) {
            const firstPacket = packetCache.get(result.packetIds[0]);
            if (firstPacket && firstPacket.srcPort && firstPacket.dstPort && isStreamProtocol(firstPacket.protocol)) {
                const streamId = generateStreamId(firstPacket.src, firstPacket.srcPort, firstPacket.dst, firstPacket.dstPort, firstPacket.protocol);
                streamIdAttr = `data-stream-id="${streamId}"`;
                streamsTag = '<span class="search-result-tag search-stream-tag" style="background: rgba(155, 89, 182, 0.3); cursor: pointer;">Streams</span>';
            }
        }

        return `
            <div class="search-result-item" data-node-id="${result.nodeId}" ${packetIdsAttr} ${streamIdAttr}>
                <div class="search-result-title">
                    ${highlightMatch(result.label, query)}
                    ${result.packetIds && result.packetIds.length > 0 ? '<span class="search-result-tag" style="background: rgba(52, 152, 219, 0.3);">Packets</span>' : ''}
                    ${streamsTag}
                </div>
                <div class="search-result-subtitle">
                    <span class="search-result-tag">IP: ${highlightMatch(result.ip, query)}</span>
                    ${matchTags}
                    ${result.packetCount > 0 ? `<span class="search-result-tag">${result.packetCount} packets</span>` : ''}
                </div>
            </div>
        `;
    }).join('');

    searchResults.innerHTML = html;
    searchResults.classList.add('show');

    // Helper to clear search
    const clearSearch = () => {
        const searchInput = document.getElementById('searchInput');
        const searchClear = document.getElementById('searchClear');
        searchInput.value = '';
        searchClear.style.display = 'none';
        searchResults.classList.remove('show');
    };

    // Add click handlers for Streams tags
    searchResults.querySelectorAll('.search-stream-tag').forEach(tag => {
        tag.addEventListener('click', function(event) {
            event.stopPropagation(); // Prevent parent item click
            const item = this.closest('.search-result-item');
            const streamId = item.getAttribute('data-stream-id');
            if (streamId) {
                openStreamDetail(streamId);
                clearSearch();
            }
        });
    });

    // Add click handlers for result items
    searchResults.querySelectorAll('.search-result-item').forEach(item => {
        item.addEventListener('click', function() {
            const nodeId = this.getAttribute('data-node-id');
            const packetIdsStr = this.getAttribute('data-packet-ids');

            // If this result has packet matches, open packet panel and select first packet
            if (packetIdsStr) {
                const packetIds = packetIdsStr.split(',').map(id => parseInt(id));

                // Open packet panel
                const packetPanel = document.getElementById('packetPanel');
                if (!packetPanel.classList.contains('show')) {
                    packetPanel.classList.add('show');
                    // Load packets when opening panel via search
                    loadPackets();
                }

                // Select the first matching packet
                if (packetIds.length > 0) {
                    setTimeout(() => {
                        selectPacket(packetIds[0]);
                    }, 100);
                }
            }

            // Also focus on the node in the graph
            focusOnNode(nodeId);

            clearSearch();
        });
    });
}

// Highlight matching text
function highlightMatch(text, query) {
    if (!text || !query) return text;

    const regex = new RegExp(`(${escapeRegex(query)})`, 'gi');
    return text.replace(regex, '<span class="search-highlight">$1</span>');
}

// Escape regex special characters
function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Focus on a specific node. If the node is hidden inside collapsed subnet
// supernodes (Phase 5 server search can return such hosts), expand its /16 and
// /24 first and focus once the resynced view contains it.
function focusOnNode(nodeId) {
    if (!network) return;

    if (!nodes.get(nodeId)) {
        const fake = { id: nodeId, ips: [nodeId] };
        const c24 = hostSubnet24(fake);
        const c16 = subnet16Of(fake);
        if (!c24 && !c16) return; // not derivable; nothing to expand
        if (c16) expandedSubnets.add(c16);
        if (c24) expandedSubnets.add(c24);
        sendAggregation();
        // Focus when the expanded view arrives (poll briefly; full resync is
        // typically 1-2 ticks away).
        let tries = 0;
        const wait = setInterval(() => {
            if (nodes.get(nodeId)) {
                clearInterval(wait);
                focusOnNode(nodeId);
            } else if (++tries > 20) {
                clearInterval(wait);
            }
        }, 250);
        return;
    }

    // Select the node
    network.selectNodes([nodeId]);

    // Move to the node with animation
    network.focus(nodeId, {
        scale: 1.5,
        animation: {
            duration: 500,
            easingFunction: 'easeInOutQuad'
        }
    });

    // Show node details
    setTimeout(() => {
        showNodeDetails(nodeId);
    }, 500);

    // Clear search and hide results
    const searchInput = document.getElementById('searchInput');
    const searchClear = document.getElementById('searchClear');
    const searchResults = document.getElementById('searchResults');

    searchInput.value = '';
    searchClear.style.display = 'none';
    searchResults.classList.remove('show');
}

// Setup theme switching
function setupTheme() {
    const themeButtons = document.querySelectorAll('.theme-button');

    // Load saved theme from localStorage (default to light)
    const savedTheme = localStorage.getItem('theme') || 'light';
    applyTheme(savedTheme);

    // Add click handlers to theme buttons
    themeButtons.forEach(button => {
        button.addEventListener('click', function() {
            const theme = this.getAttribute('data-theme');
            applyTheme(theme);
            localStorage.setItem('theme', theme);
        });
    });
}

// Apply theme to the page
function applyTheme(theme) {
    const body = document.body;
    const html = document.documentElement;
    const themeButtons = document.querySelectorAll('.theme-button');

    // Remove/add light-theme class to both html and body
    if (theme === 'light') {
        body.classList.add('light-theme');
        html.classList.add('light-theme');
    } else {
        body.classList.remove('light-theme');
        html.classList.remove('light-theme');
    }

    // Update button active states
    themeButtons.forEach(button => {
        const buttonTheme = button.getAttribute('data-theme');
        if (buttonTheme === theme) {
            button.classList.add('active');
        } else {
            button.classList.remove('active');
        }
    });

    // Update network graph with new theme colors. recolorAllNodes restyles the
    // per-node colors in place and invalidates the render signatures (which embed
    // the theme-dependent color), so idle nodes don't keep the old palette.
    if (network) {
        const options = getNetworkOptions();
        network.setOptions(options);
        recolorAllNodes();
    }
}

// Setup packet panel functionality
// Apply + clamp a packet-window position, switching from the CSS right/bottom
// anchor to left/top so dragging and corner-resize behave like a normal window.
function movePacketWindow(left, top) {
    const panel = document.getElementById('packetPanel');
    if (!panel) return;
    const w = panel.offsetWidth, h = panel.offsetHeight;
    if (isNaN(left)) left = window.innerWidth - w - 16;
    if (isNaN(top)) top = window.innerHeight - h - 96;
    left = Math.max(0, Math.min(window.innerWidth - 80, left));   // keep a grab edge on-screen
    top = Math.max(0, Math.min(window.innerHeight - 50, top));
    panel.style.left = left + 'px';
    panel.style.top = top + 'px';
    panel.style.right = 'auto';
    panel.style.bottom = 'auto';
}

// Apply the saved size + position when the window opens (defaults: bottom-right).
function positionPacketWindow() {
    const panel = document.getElementById('packetPanel');
    if (!panel) return;
    let st = {};
    try { st = JSON.parse(localStorage.getItem('packetWindowState') || '{}'); } catch (e) {}
    const w = st.width || Math.min(900, Math.round(window.innerWidth * 0.86));
    const h = st.height || 440;
    panel.style.width = w + 'px';
    panel.style.height = h + 'px';
    const left = (typeof st.left === 'number') ? st.left : (window.innerWidth - w - 16);
    const top = (typeof st.top === 'number') ? st.top : (window.innerHeight - h - 96);
    movePacketWindow(left, top);
}

// Persist current size + position so the window reopens where you left it.
function savePacketWindow() {
    const panel = document.getElementById('packetPanel');
    if (!panel) return;
    localStorage.setItem('packetWindowState', JSON.stringify({
        left: parseFloat(panel.style.left) || 0,
        top: parseFloat(panel.style.top) || 0,
        width: panel.offsetWidth,
        height: panel.offsetHeight
    }));
}

function setupPacketPanel() {
    const packetToggle = document.getElementById('packetDataToggle');
    const packetPanel = document.getElementById('packetPanel');
    const packetPanelClose = document.getElementById('packetPanelClose');
    const hexTab = document.getElementById('hexTab');
    const asciiTab = document.getElementById('asciiTab');

    let currentView = 'hex';

    // Keep wheel/scroll inside the packet window: stop it propagating to the
    // document so it never reaches the graph's zoom handler. We don't
    // preventDefault, so the panel's own scroll areas still scroll normally.
    packetPanel.addEventListener('wheel', function(e) {
        e.stopPropagation();
    }, { passive: true });

    // Toggle packet panel
    packetToggle.addEventListener('click', function() {
        packetPanel.classList.toggle('show');
        const timeline = document.getElementById('timelineContainer');
        if (packetPanel.classList.contains('show')) {
            positionPacketWindow();
            loadPackets();
            if (timeline) {
                timeline.classList.add('packet-panel-open');
                // Clear inline styles that override CSS
                timeline.style.opacity = '';
                timeline.style.visibility = '';
            }
        } else {
            if (timeline) {
                timeline.classList.remove('packet-panel-open');
                // Restore timeline visibility if in replay mode
                if (replayMode.active) {
                    timeline.style.opacity = '1';
                    timeline.style.visibility = 'visible';
                }
            }
        }
    });

    // Close packet panel
    packetPanelClose.addEventListener('click', function(e) {
        e.stopPropagation();
        e.preventDefault();
        packetPanel.classList.remove('show');
        const timeline = document.getElementById('timelineContainer');
        if (timeline) {
            timeline.classList.remove('packet-panel-open');
            // Restore timeline visibility if in replay mode
            if (replayMode.active) {
                timeline.style.opacity = '1';
                timeline.style.visibility = 'visible';
            }
        }
    }, true); // Use capture phase to ensure it fires first

    // Escape key to close packet panel
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && packetPanel.classList.contains('show')) {
            packetPanel.classList.remove('show');
            const timeline = document.getElementById('timelineContainer');
            if (timeline) {
                timeline.classList.remove('packet-panel-open');
                // Restore timeline visibility if in replay mode
                if (replayMode.active) {
                    timeline.style.opacity = '1';
                    timeline.style.visibility = 'visible';
                }
            }
        }
    });

    // The window is moved by dragging its header and resized from the corner
    // (CSS resize). Position + size persist across sessions.
    const packetHeader = packetPanel.querySelector('.packet-panel-header');
    let dragging = false, dragOffX = 0, dragOffY = 0;

    packetHeader.addEventListener('mousedown', function(e) {
        // Don't drag when interacting with header controls.
        if (e.target.closest('button') || e.target.closest('.packet-tab') ||
            e.target.closest('.packet-inspector-tabs')) {
            return;
        }
        dragging = true;
        const rect = packetPanel.getBoundingClientRect();
        dragOffX = e.clientX - rect.left;
        dragOffY = e.clientY - rect.top;
        document.body.style.userSelect = 'none';
        e.preventDefault();
    });

    document.addEventListener('mousemove', function(e) {
        if (!dragging) return;
        movePacketWindow(e.clientX - dragOffX, e.clientY - dragOffY);
    });

    document.addEventListener('mouseup', function() {
        if (dragging) {
            dragging = false;
            document.body.style.userSelect = '';
            savePacketWindow();
        }
    });

    // On corner-resize: re-render the virtual packet list to fill the new height
    // (only scroll triggers it otherwise) and persist the size (debounced).
    if (window.ResizeObserver) {
        let rzTimer = null;
        new ResizeObserver(function() {
            if (!packetPanel.classList.contains('show')) return;
            renderVisiblePackets();
            clearTimeout(rzTimer);
            rzTimer = setTimeout(savePacketWindow, 250);
        }).observe(packetPanel);
    }

    // Keep the window on-screen if the browser window shrinks.
    window.addEventListener('resize', function() {
        if (packetPanel.classList.contains('show')) {
            movePacketWindow(parseFloat(packetPanel.style.left), parseFloat(packetPanel.style.top));
        }
    });

    // Tab switching
    hexTab.addEventListener('click', function() {
        window.currentPacketView = 'hex';
        hexTab.classList.add('active');
        asciiTab.classList.remove('active');
        updatePacketView();
    });

    asciiTab.addEventListener('click', function() {
        window.currentPacketView = 'ascii';
        asciiTab.classList.add('active');
        hexTab.classList.remove('active');
        updatePacketView();
    });

    // Initialize current view globally
    if (!window.currentPacketView) {
        window.currentPacketView = 'hex';
    }

    // Virtual scroll: re-render on scroll
    const packetListContainer = document.getElementById('packetListContainer');
    if (packetListContainer) {
        let scrollRafPending = false;
        packetListContainer.addEventListener('scroll', function() {
            if (!scrollRafPending) {
                scrollRafPending = true;
                requestAnimationFrame(() => {
                    renderVisiblePackets();
                    scrollRafPending = false;
                });
            }
        });
    }

    // Packet filter handlers
    const filterInput = document.getElementById('packetFilterInput');
    const filterSelect = document.getElementById('packetProtocolSelect');
    const filterClear = document.getElementById('packetFilterClear');
    let filterTimeout = null;

    if (filterInput) {
        filterInput.addEventListener('input', function() {
            clearTimeout(filterTimeout);
            filterTimeout = setTimeout(() => {
                packetFilterText = filterInput.value.trim();
                filterClear.style.display = (packetFilterText || packetFilterProtocol) ? 'block' : 'none';
                loadPackets();
            }, 200);
        });
    }

    if (filterSelect) {
        filterSelect.addEventListener('change', function() {
            packetFilterProtocol = filterSelect.value;
            filterClear.style.display = (packetFilterText || packetFilterProtocol) ? 'block' : 'none';
            loadPackets();
        });
    }

    if (filterClear) {
        filterClear.addEventListener('click', function() {
            packetFilterText = '';
            packetFilterProtocol = '';
            if (filterInput) filterInput.value = '';
            if (filterSelect) filterSelect.value = '';
            filterClear.style.display = 'none';
            loadPackets();
        });
    }
}

// Update packet view based on selected tab
function updatePacketView() {
    const hexView = document.getElementById('hexView');
    const asciiView = document.getElementById('asciiView');

    if (!hexView || !asciiView) return;

    if (window.currentPacketView === 'hex') {
        hexView.classList.add('active');
        asciiView.classList.remove('active');
    } else {
        hexView.classList.remove('active');
        asciiView.classList.add('active');
    }
}

// Build the filtered+sorted packet list (cached for virtual scroll)
function buildFilteredPacketList() {
    if (!packets || packets.length === 0) {
        filteredPacketList = [];
        return;
    }

    let filtered = packets;

    // Apply protocol filter
    if (packetFilterProtocol) {
        filtered = filtered.filter(p => p.protocol === packetFilterProtocol);
    }

    // Apply text filter (IP, port, protocol name)
    if (packetFilterText) {
        const q = packetFilterText.toLowerCase();
        filtered = filtered.filter(p => {
            const srcDisplay = p.srcPort ? `${p.src}:${p.srcPort}` : p.src;
            const dstDisplay = p.dstPort ? `${p.dst}:${p.dstPort}` : p.dst;
            return srcDisplay.toLowerCase().includes(q) ||
                   dstDisplay.toLowerCase().includes(q) ||
                   p.protocol.toLowerCase().includes(q) ||
                   (p.summary && p.summary.toLowerCase().includes(q));
        });
    }

    // Sort by timestamp (newest first)
    filteredPacketList = filtered.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

// Render a single packet row HTML
function renderPacketRow(packet) {
    const time = new Date(packet.timestamp).toLocaleTimeString();
    const srcDisplay = packet.srcPort ? `${packet.src}:${packet.srcPort}` : packet.src;
    const dstDisplay = packet.dstPort ? `${packet.dst}:${packet.dstPort}` : packet.dst;
    const selected = packet.id === selectedPacketId ? ' selected' : '';
    return `<div class="packet-item${selected}" data-packet-id="${packet.id}" style="height:${PACKET_ROW_HEIGHT}px;box-sizing:border-box;">` +
        `<div class="packet-item-number">#${packet.id}</div>` +
        `<div class="packet-item-info">` +
        `<div class="packet-item-time">${time}</div>` +
        `<div class="packet-item-src">${srcDisplay}</div>` +
        `<div>→</div>` +
        `<div class="packet-item-dst">${dstDisplay}</div>` +
        `<div class="packet-item-protocol">${packet.protocol}</div>` +
        `<div class="packet-item-length">${packet.length} bytes</div>` +
        `<div class="packet-item-summary">${packet.summary}</div>` +
        `</div></div>`;
}

// Virtual scroll: only render visible packet rows
function renderVisiblePackets() {
    const container = document.getElementById('packetListContainer');
    const packetList = document.getElementById('packetList');
    if (!container || !packetList) return;

    const totalCount = filteredPacketList.length;
    if (totalCount === 0) {
        packetList.innerHTML = '<div class="packet-list-placeholder">No packets match filters</div>';
        return;
    }

    const scrollTop = container.scrollTop;
    const viewportHeight = container.clientHeight;
    const totalHeight = totalCount * PACKET_ROW_HEIGHT;

    // Calculate visible range with buffer
    const startIdx = Math.max(0, Math.floor(scrollTop / PACKET_ROW_HEIGHT) - PACKET_RENDER_BUFFER);
    const endIdx = Math.min(totalCount, Math.ceil((scrollTop + viewportHeight) / PACKET_ROW_HEIGHT) + PACKET_RENDER_BUFFER);

    const topSpacer = startIdx * PACKET_ROW_HEIGHT;
    const bottomSpacer = (totalCount - endIdx) * PACKET_ROW_HEIGHT;

    // Build HTML for visible rows only
    let html = `<div class="packet-list-spacer" style="height:${topSpacer}px"></div>`;
    for (let i = startIdx; i < endIdx; i++) {
        html += renderPacketRow(filteredPacketList[i]);
    }
    html += `<div class="packet-list-spacer" style="height:${bottomSpacer}px"></div>`;

    packetList.innerHTML = html;

    // Add click handlers for visible rows
    packetList.querySelectorAll('.packet-item').forEach(item => {
        item.addEventListener('click', function() {
            const packetId = parseInt(this.getAttribute('data-packet-id'));
            selectPacket(packetId);
        });
    });
}

// Load and display packets (entry point - rebuilds filter cache then renders)
function loadPackets() {
    buildFilteredPacketList();
    renderVisiblePackets();

    // Populate protocol dropdown if empty
    const select = document.getElementById('packetProtocolSelect');
    if (select && select.options.length <= 1 && packets.length > 0) {
        const protocols = new Set(packets.map(p => p.protocol));
        [...protocols].sort().forEach(proto => {
            const opt = document.createElement('option');
            opt.value = proto;
            opt.textContent = proto;
            select.appendChild(opt);
        });
    }
}

// Select and inspect a packet
function selectPacket(packetId) {
    selectedPacketId = packetId;

    // Try to find packet in cache first (persistent), then in current packets array
    let packet = packetCache.get(packetId);
    if (!packet) {
        packet = packets.find(p => p.id === packetId);
    }

    if (!packet) {
        return;
    }

    // Update selected packet index for keyboard navigation
    selectedPacketIndex = filteredPacketList.findIndex(p => p.id === packetId);

    // Scroll virtual list to bring the selected packet into view
    const container = document.getElementById('packetListContainer');
    if (container && selectedPacketIndex >= 0) {
        const targetTop = selectedPacketIndex * PACKET_ROW_HEIGHT;
        const viewTop = container.scrollTop;
        const viewBottom = viewTop + container.clientHeight;
        if (targetTop < viewTop || targetTop + PACKET_ROW_HEIGHT > viewBottom) {
            container.scrollTop = targetTop - container.clientHeight / 2;
        }
    }

    // Re-render to update selected state
    renderVisiblePackets();

    // Show packet inspector in left sidebar
    showPacketInspector(packet);
}

// Show packet inspector
function showPacketInspector(packet) {
    const packetInspectorContent = document.getElementById('packetInspectorContent');

    // Generate hex dump and ASCII view
    const hexDump = generateHexDump(packet);
    const asciiView = generateAsciiView(packet);

    const currentView = window.currentPacketView || 'hex';

    const html = `
        <div class="packet-detail-section">
            <h4>Frame ${packet.id}</h4>
            <div class="packet-detail-field">
                <div class="packet-detail-label">Timestamp:</div>
                <div class="packet-detail-value">${new Date(packet.timestamp).toLocaleString()}</div>
            </div>
            <div class="packet-detail-field">
                <div class="packet-detail-label">Length:</div>
                <div class="packet-detail-value">${packet.length} bytes</div>
            </div>
        </div>

        ${packet.vlanId ? `
        <div class="packet-detail-section">
            <h4>Data Link Layer</h4>
            <div class="packet-detail-field">
                <div class="packet-detail-label">VLAN ID:</div>
                <div class="packet-detail-value">${packet.vlanId}</div>
            </div>
        </div>
        ` : ''}

        <div class="packet-detail-section">
            <h4>Network Layer</h4>
            <div class="packet-detail-field">
                <div class="packet-detail-label">Source IP:</div>
                <div class="packet-detail-value">${packet.src}</div>
            </div>
            ${packet.srcPort ? `
            <div class="packet-detail-field">
                <div class="packet-detail-label">Source Port:</div>
                <div class="packet-detail-value">${packet.srcPort}</div>
            </div>
            ` : ''}
            <div class="packet-detail-field">
                <div class="packet-detail-label">Destination IP:</div>
                <div class="packet-detail-value">${packet.dst}</div>
            </div>
            ${packet.dstPort ? `
            <div class="packet-detail-field">
                <div class="packet-detail-label">Destination Port:</div>
                <div class="packet-detail-value">${packet.dstPort}</div>
            </div>
            ` : ''}
            <div class="packet-detail-field">
                <div class="packet-detail-label">Protocol:</div>
                <div class="packet-detail-value">${packet.protocol}</div>
            </div>
        </div>

        <div class="packet-detail-section">
            <h4>Packet Information</h4>
            <div class="packet-detail-field">
                <div class="packet-detail-label">Packet ID:</div>
                <div class="packet-detail-value">${packet.id}</div>
            </div>
        </div>

        <div class="packet-detail-section">
            <h4>Packet Data</h4>
            <div class="packet-view ${currentView === 'hex' ? 'active' : ''}" id="hexView">
                <div class="packet-hex-dump">${hexDump}</div>
            </div>
            <div class="packet-view ${currentView === 'ascii' ? 'active' : ''}" id="asciiView">
                <div class="packet-ascii-view">${asciiView}</div>
            </div>
        </div>

        <div class="packet-detail-section">
            <h4>Summary</h4>
            <div class="packet-detail-field">
                <div class="packet-detail-value">${packet.summary}</div>
            </div>
        </div>
    `;

    packetInspectorContent.innerHTML = html;
}

// Generate hex dump
function generateHexDump(packet) {
    if (!packet.payload) {
        return 'No payload data available';
    }

    // Decode base64 payload
    const payloadBytes = base64ToBytes(packet.payload);
    const lines = [];
    const bytesPerLine = 16;
    const totalBytes = payloadBytes.length;
    const displayBytes = Math.min(totalBytes, 512); // Show first 512 bytes

    for (let offset = 0; offset < displayBytes; offset += bytesPerLine) {
        const hexOffset = offset.toString(16).padStart(4, '0');
        const bytes = [];
        const ascii = [];

        for (let i = 0; i < bytesPerLine && offset + i < displayBytes; i++) {
            const byte = payloadBytes[offset + i];
            bytes.push(byte.toString(16).padStart(2, '0'));
            ascii.push(byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.');
        }

        // Pad hex bytes to ensure consistent alignment (16 bytes = 47 chars with spaces)
        const hexBytes = bytes.join(' ').padEnd(47, ' ');
        const asciiStr = ascii.join('');

        lines.push(
            `<div class="hex-line">` +
            `<span class="hex-offset">${hexOffset}</span>  ` +
            `<span class="hex-bytes">${hexBytes}</span>  ` +
            `<span class="hex-ascii">${asciiStr}</span>` +
            `</div>`
        );
    }

    if (displayBytes < totalBytes) {
        lines.push(`<div class="hex-line"><span class="hex-offset">...</span> (${totalBytes - displayBytes} more bytes)</div>`);
    }

    return lines.join('\n');
}

// Helper function to decode base64 to byte array
function base64ToBytes(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

// Generate ASCII view
function generateAsciiView(packet) {
    if (!packet.payload) {
        return 'No payload data available';
    }

    // Decode base64 payload
    const payloadBytes = base64ToBytes(packet.payload);
    let ascii = '';

    // Add packet header info
    ascii += `Packet #${packet.id} - ${packet.protocol} Protocol\n`;
    ascii += `${packet.src} → ${packet.dst}\n`;
    ascii += `Length: ${packet.length} bytes\n`;
    ascii += `Timestamp: ${new Date(packet.timestamp).toLocaleString()}\n`;
    ascii += `${'='.repeat(60)}\n\n`;

    // Convert payload bytes to ASCII (show first 2048 bytes)
    const displayBytes = Math.min(payloadBytes.length, 2048);
    let payloadAscii = '';

    for (let i = 0; i < displayBytes; i++) {
        const byte = payloadBytes[i];
        // Show printable ASCII or a dot for non-printable
        if (byte >= 32 && byte <= 126) {
            payloadAscii += String.fromCharCode(byte);
        } else if (byte === 10) { // newline
            payloadAscii += '\n';
        } else if (byte === 13) { // carriage return
            payloadAscii += '\r';
        } else if (byte === 9) { // tab
            payloadAscii += '\t';
        } else {
            payloadAscii += '.';
        }
    }

    ascii += 'Payload (ASCII):\n';
    ascii += '─'.repeat(60) + '\n';
    ascii += payloadAscii;

    if (displayBytes < payloadBytes.length) {
        ascii += `\n\n... (${payloadBytes.length - displayBytes} more bytes)`;
    }

    return ascii;
}

// Handle protocol filter changes. Filtering is computed server-side now: we
// just track the hidden set locally (for the badge + to re-send on reconnect)
// and push it to the server, which recomputes this client's view — dropping
// hidden edges and any node whose only traffic was filtered out (incl. group
// identifiers like the mDNS group).
function handleFilterChange(event) {
    const protocol = event.target.value;
    if (event.target.checked) {
        protocolFilters.delete(protocol);
    } else {
        protocolFilters.add(protocol);
    }
    sendFilters();
    updateFilterIndicator();
    // Re-center on the displayed nodes once the filtered view comes back.
    fitOnNextFull = true;
}

// Send the current hidden-protocol set to the server over the WebSocket.
function sendFilters() {
    sendControl({ type: 'setFilters', data: { hidden: [...protocolFilters] } });
}

// Sync the full Phase 4 aggregation state: activation threshold (0 = server
// default of 300 hosts; override via localStorage.aggThreshold) and the set of
// expanded /24s. Idempotent, so it's safe to resend on reconnect.
function sendAggregation() {
    const threshold = parseInt(localStorage.getItem('aggThreshold') || '0', 10) || 0;
    sendControl({ type: 'setAggregation', data: { threshold: threshold, expanded: [...expandedSubnets] } });
}

// Expand a collapsed subnet supernode into its member hosts / collapse it back.
function handleSubnetExpand(cidr) {
    expandedSubnets.add(cidr);
    sendAggregation();
    hideDetails();
}
function handleSubnetCollapse(cidr) {
    expandedSubnets.delete(cidr);
    sendAggregation();
    hideDetails();
}

// The /24 CIDR for a host node's primary IPv4 address ('' when not IPv4).
function hostSubnet24(node) {
    const ips = (node.ips && node.ips.length ? node.ips : [node.id]) || [];
    for (const ip of ips) {
        const m = /^(\d+)\.(\d+)\.(\d+)\.\d+$/.exec(ip);
        if (m) return `${m[1]}.${m[2]}.${m[3]}.0/24`;
    }
    return '';
}

// The /16 CIDR above a host node or a /24 CIDR string ('' when not IPv4).
function subnet16Of(cidrOrNode) {
    const s = typeof cidrOrNode === 'string' ? cidrOrNode : hostSubnet24(cidrOrNode);
    const m = /^(\d+)\.(\d+)\./.exec(s);
    return m ? `${m[1]}.${m[2]}.0.0/16` : '';
}

// Send a control message to the server if the socket is open.
function sendControl(msg) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(msg));
    }
}

// Update filter badge and floating indicator
function updateFilterIndicator() {
    const count = protocolFilters.size;
    const badge = document.getElementById('filterBadge');
    const indicator = document.getElementById('filterActiveIndicator');
    const indicatorText = document.getElementById('filterActiveText');

    if (badge) {
        if (count > 0) {
            badge.textContent = count;
            badge.style.display = '';
        } else {
            badge.style.display = 'none';
        }
    }

    if (indicator && indicatorText) {
        if (count > 0) {
            const names = [...protocolFilters].join(', ');
            indicatorText.textContent = `${count} protocol${count > 1 ? 's' : ''} hidden: ${names}`;
            indicator.style.display = '';
        } else {
            indicator.style.display = 'none';
        }
    }
}

// Connect to WebSocket
function connectWebSocket() {
    // Don't connect if in replay mode
    if (replayMode.active) {
        return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    // Set initial connecting status
    updateConnectionStatus('Connecting...', false);

    ws = new WebSocket(wsUrl);
    // Position frames arrive as binary (see applyPositionFrame).
    ws.binaryType = 'arraybuffer';

    ws.onopen = function() {
        console.log('WebSocket connected');
        updateConnectionStatus('Connected', true);
        // Sync our filter set, layout mode and aggregation state so the
        // server's view of this client matches the UI (and survives reconnects).
        sendFilters();
        sendLayout(localStorage.getItem('clusterLayout') || 'force');
        sendAggregation();
        // Restore timeline mode across reconnects (module at end of file).
        if (typeof timeline !== 'undefined' && timeline.active) {
            sendTimelinePosition(true);
        }
        // Raw-scale mode (?scale=raw, cosmos renderer only): ask the server to
        // stream the full unaggregated topology as binary frames.
        if (network && network.ownsLayout &&
            new URLSearchParams(window.location.search).get('scale') === 'raw') {
            sendControl({ type: 'setViewMode', data: { mode: 'raw' } });
        }
    };

    // Three message kinds (Phase 2 wire split):
    //  - binary        -> position frame, fast path, no JSON parse
    //  - {type:counts} -> 1s counter refresh for meta/stats/legend
    //  - anything else -> style/topology delta (or full snapshot)
    ws.onmessage = function(event) {
        try {
            if (event.data instanceof ArrayBuffer) {
                wireStats.bytesIn += event.data.byteLength;
                // Dispatch on the frame-type byte: 1 = positions, 2 = raw topology.
                if (new DataView(event.data).getUint8(0) === 2) {
                    applyRawTopologyFrame(event.data);
                } else {
                    applyPositionFrame(event.data);
                }
                return;
            }
            wireStats.bytesIn += event.data.length;
            const data = JSON.parse(event.data);
            if (data.type === 'counts') {
                applyCountsFrame(data);
                return;
            }
            if (data.type === 'rawMeta') {
                // Protocol table + stats preceding each raw topology frame.
                rawProtoTable = data.protos || [];
                if (data.stats) {
                    updateStatistics(data.stats.nodeCount, data.stats.edgeCount, data.stats.totalPackets);
                }
                return;
            }
            wireStats.deltas++;
            throttledUpdateGraph(data);
        } catch (e) {
            console.error('Error processing WebSocket message:', e);
        }
    };

    ws.onerror = function(error) {
        console.error('WebSocket error:', error);
        updateConnectionStatus('Error', false);
    };

    ws.onclose = function() {
        updateConnectionStatus('Disconnected', false);
        // Only attempt to reconnect if not in replay mode
        if (!replayMode.active) {
            setTimeout(connectWebSocket, 3000);
        }
    };
}

// --- Phase 2 wire protocol: binary position frames + 1s counts frames ----------

const wireTextDecoder = new TextDecoder();
// Lightweight wire instrumentation; inspect via window.__wireStats in devtools.
const wireStats = { deltas: 0, posFrames: 0, posNodes: 0, countsFrames: 0, bytesIn: 0, rawFrames: 0 };
window.__wireStats = wireStats;

// Raw-scale mode: protoIdx -> {name, color} table from the last rawMeta message.
let rawProtoTable = [];

// Decode a raw topology frame (msgType=2, see server/rawstream.go) and hand it
// to the cosmos renderer as typed arrays — no DataSets, no per-node objects.
// Format (little-endian): [u8=2][u32 n]{[u16 idLen][id][u8 tier][u8 flags]}
//                          [u32 m]{[u32 a][u32 b][u8 protoIdx]}
function applyRawTopologyFrame(buf) {
    if (!network || typeof network.setRawTopology !== 'function') return;
    const dv = new DataView(buf);
    let off = 1;
    const n = dv.getUint32(off, true); off += 4;
    const ids = new Array(n);
    const tiers = new Uint8Array(n);
    const flags = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
        const idLen = dv.getUint16(off, true); off += 2;
        ids[i] = wireTextDecoder.decode(new Uint8Array(buf, off, idLen)); off += idLen;
        tiers[i] = dv.getUint8(off);
        flags[i] = dv.getUint8(off + 1);
        off += 2;
    }
    const m = dv.getUint32(off, true); off += 4;
    const links = new Float32Array(m * 2); // cosmos setLinks takes float indices
    const protoIdx = new Uint8Array(m);
    for (let i = 0; i < m; i++) {
        links[i * 2] = dv.getUint32(off, true);
        links[i * 2 + 1] = dv.getUint32(off + 4, true);
        protoIdx[i] = dv.getUint8(off + 8);
        off += 9;
    }
    wireStats.rawFrames++;
    network.setRawTopology({ ids, tiers, flags, links, protoIdx }, rawProtoTable);
}

// Seed-or-ease one node toward a fresh server position, shared by the JSON
// delta path (updateGraph) and the binary position-frame path. Pinned nodes
// snap; a position for a node not yet rendered just seeds its spawn point
// (written straight into the live vis body node so no DataSet touch is
// needed); anything else becomes a target for the 60fps easing loop.
// Returns 'moved' | 'snapped' | null for the caller to aggregate.
function applyTargetPosition(id, x, y, pinned, bodyNodes) {
    nodeTargetPos.set(id, { x: x, y: y });
    if (pinned || !nodeRenderPos.has(id)) {
        nodeRenderPos.set(id, { x: x, y: y });
        const bn = bodyNodes[id];
        if (bn && (bn.x !== x || bn.y !== y)) {
            bn.x = x;
            bn.y = y;
            return 'snapped';
        }
        return null;
    }
    return 'moved';
}

// Decode a binary position frame and feed the easing loop directly — no JSON,
// no DataSet. Format (little-endian, must mirror buildPosFrame in
// server/websocket.go): [u8 type=1][u16 count] then per node
// [u16 idLen][id utf8][f32 x][f32 y].
function applyPositionFrame(buf) {
    // cosmos.gl mode: the GPU owns positions; server frames are irrelevant.
    if (network && network.ownsLayout) return;
    const dv = new DataView(buf);
    if (dv.getUint8(0) !== 1) return; // unknown binary frame type
    const count = dv.getUint16(1, true);
    let off = 3;
    let moved = false, snapped = false;
    const bodyNodes = network ? network.body.nodes : {};
    for (let i = 0; i < count; i++) {
        const idLen = dv.getUint16(off, true); off += 2;
        const id = wireTextDecoder.decode(new Uint8Array(buf, off, idLen)); off += idLen;
        const x = dv.getFloat32(off, true); off += 4;
        const y = dv.getFloat32(off, true); off += 4;
        const meta = nodeMeta.get(id);
        const r = applyTargetPosition(id, x, y, !!(meta && meta.pinned), bodyNodes);
        if (r === 'moved') moved = true;
        else if (r === 'snapped') snapped = true;
    }
    wireStats.posFrames++;
    wireStats.posNodes += count;
    if (moved) startPositionAnimation();
    else if (snapped && network) network.redraw();
}

// Merge a 1s counts frame into the meta maps (tooltips/details/search read
// these) and refresh the stats bar + protocol legend. Never touches the
// DataSet: counters don't change how anything is drawn.
function applyCountsFrame(data) {
    wireStats.countsFrames++;
    if (data.nodes) {
        for (const id in data.nodes) {
            const meta = nodeMeta.get(id);
            if (!meta) continue;
            meta.packetCount = data.nodes[id][0];
            meta.byteCount = data.nodes[id][1];
        }
    }
    if (data.edges) {
        for (const id in data.edges) {
            const meta = edgeMeta.get(id);
            if (!meta) continue;
            const v = data.edges[id];
            meta.packetCount = v[0];
            meta.byteCount = v[1];
            meta.forwardPackets = v[2];
            meta.reversePackets = v[3];
            meta.forwardBytes = v[4];
            meta.reverseBytes = v[5];
        }
    }
    if (data.stats) {
        updateStatistics(data.stats.nodeCount, data.stats.edgeCount, data.stats.totalPackets);
    }
    if (data.protocolStats) updateProtocolCounts(data.protocolStats);
}

// Helper function to update packet cache
// Packets are fetched on demand now (not pushed over the WebSocket). Poll the
// server for packets newer than our cursor and feed them into the same cache the
// live table reads. Skipped in replay mode, which loads packets via /api/replay.
async function pollPackets() {
    if (replayMode.active) return;
    try {
        // limit=1000 matches the server ring-buffer size, so each poll catches up
        // to the newest packet and the cursor never falls permanently behind.
        const resp = await fetch('/api/packets?since=' + packetCursor + '&limit=1000');
        if (!resp.ok) return;
        const data = await resp.json();
        if (typeof data.cursor === 'number' && data.cursor > packetCursor) packetCursor = data.cursor;
        if (data.packets && data.packets.length) updatePacketCache(data.packets);
    } catch (e) { /* best-effort */ }
}

function updatePacketCache(newPackets) {
    if (!newPackets || newPackets.length === 0) return;

    packets = newPackets;

    // Add new packets to persistent cache
    newPackets.forEach(packet => {
        if (!packetCache.has(packet.id)) {
            packetCache.set(packet.id, packet);
        }
    });

    // Maintain cache size limit (keep most recent packets). Evict by id, not
    // Map insertion order: replay loads and capture/timeline switches insert
    // older-id packets after newer live ones, so insertion order isn't age.
    if (packetCache.size > MAX_CACHED_PACKETS) {
        let excess = packetCache.size - MAX_CACHED_PACKETS;
        const ids = Array.from(packetCache.keys()).sort((a, b) => a - b);
        for (const id of ids) {
            if (excess-- <= 0) break;
            packetCache.delete(id);
        }
    }

    // Update protocol dropdown with any new protocols
    const select = document.getElementById('packetProtocolSelect');
    if (select) {
        const existing = new Set([...select.options].map(o => o.value));
        newPackets.forEach(p => {
            if (p.protocol && !existing.has(p.protocol)) {
                const opt = document.createElement('option');
                opt.value = p.protocol;
                opt.textContent = p.protocol;
                select.appendChild(opt);
                existing.add(p.protocol);
            }
        });
    }

    // Debounced packet panel refresh (max once per 500ms)
    // Virtual scroll means this only re-renders visible rows, preserving scroll position
    const now = Date.now();
    const packetPanel = document.getElementById('packetPanel');
    if (packetPanel && packetPanel.classList.contains('show') && (now - lastPacketPanelRefresh) > 500) {
        lastPacketPanelRefresh = now;
        buildFilteredPacketList();
        renderVisiblePackets();
    }
}

// Throttled update to prevent overwhelming the visualization
function throttledUpdateGraph(data) {
    // Full snapshots are authoritative (initial sync, filter/layout change). They
    // must NOT be coalesced: apply immediately and cancel any pending throttled
    // delta, otherwise a delta arriving right after could overwrite the pending
    // full and drop the nodes that full was adding (e.g. on a filter change).
    // Chunked-full messages (partial) are likewise applied immediately — the
    // throttle keeps only the newest pending delta, which would drop chunks.
    if (data && data.partial && !data.isFull) {
        updateGraph(data);
        return;
    }
    if (data && data.isFull) {
        if (updateTimer) { clearTimeout(updateTimer); updateTimer = null; }
        updateScheduled = false;
        pendingUpdate = null;
        lastUpdateTime = Date.now();
        updateGraph(data);
        return;
    }

    // Dynamic throttle based on current node count - keeps things responsive.
    const nodeCount = nodes.length;
    if (nodeCount > 50) {
        UPDATE_THROTTLE_MS = 200;  // 50+ nodes: update every 200ms
    } else if (nodeCount > 25) {
        UPDATE_THROTTLE_MS = 150;  // 25-50 nodes: update every 150ms
    } else {
        UPDATE_THROTTLE_MS = 100;  // <25 nodes: update every 100ms (fluid)
    }

    pendingUpdate = data;

    if (updateScheduled) {
        return; // a delta is already scheduled; this one coalesces into it
    }

    const now = Date.now();
    const timeSinceLastUpdate = now - lastUpdateTime;

    if (timeSinceLastUpdate >= UPDATE_THROTTLE_MS) {
        // Enough time has passed, update immediately
        lastUpdateTime = now;
        updateGraph(data);
        pendingUpdate = null;
    } else {
        // Schedule update for later
        updateScheduled = true;
        updateTimer = setTimeout(() => {
            updateTimer = null;
            lastUpdateTime = Date.now();
            if (pendingUpdate) updateGraph(pendingUpdate);
            pendingUpdate = null;
            updateScheduled = false;
        }, UPDATE_THROTTLE_MS - timeSinceLastUpdate);
    }
}

// Muted styling for group (multicast/broadcast) nodes — a dashed box, not a dot.
const GROUP_NODE_COLOR = {
    border: '#7f8c8d',
    background: 'rgba(127, 140, 141, 0.20)',
    highlight: { border: '#95a5a6', background: 'rgba(149, 165, 166, 0.35)' }
};

// Collapsed /24 supernodes (Phase 4): blue boxes, visually distinct from both
// hosts (dots) and multicast groups (grey dashed boxes).
const SUBNET_NODE_COLOR = {
    border: '#1d4ed8',
    background: 'rgba(59, 130, 246, 0.35)',
    highlight: { border: '#3b82f6', background: 'rgba(59, 130, 246, 0.55)' }
};

// Map a server-computed traffic tier (0..3) to a theme-aware vis color object.
// The server decides the tier; the client only resolves the palette so theme
// toggling stays instant without a round-trip.
function tierColor(tier, isLightTheme) {
    switch (tier) {
        case 1: // low - yellow
            return {
                background: isLightTheme ? '#f1c40f' : '#f39c12',
                border: isLightTheme ? '#f39c12' : '#e67e22',
                highlight: { background: isLightTheme ? '#f39c12' : '#f1c40f', border: isLightTheme ? '#e67e22' : '#f39c12' }
            };
        case 2: // medium - orange
            return {
                background: isLightTheme ? '#e67e22' : '#d35400',
                border: isLightTheme ? '#d35400' : '#ca6f1e',
                highlight: { background: isLightTheme ? '#d35400' : '#e67e22', border: isLightTheme ? '#ca6f1e' : '#dc7633' }
            };
        case 3: // high - red
            return {
                background: isLightTheme ? '#e74c3c' : '#c0392b',
                border: isLightTheme ? '#c0392b' : '#a93226',
                highlight: { background: isLightTheme ? '#c0392b' : '#e74c3c', border: isLightTheme ? '#a93226' : '#cb4335' }
            };
        default: // 0 - grey
            return {
                background: isLightTheme ? '#95a5a6' : '#7f8c8d',
                border: isLightTheme ? '#7f8c8d' : '#5d6d7e',
                highlight: { background: isLightTheme ? '#7f8c8d' : '#95a5a6', border: isLightTheme ? '#5d6d7e' : '#b2bec3' }
            };
    }
}

// Resolve the vis color for a server-styled view node. An explicit override
// color (Phase D) wins; group nodes get the muted palette; otherwise the tier.
function viewNodeColor(node, isLightTheme) {
    if (node.color) return node.color; // user override wins
    if (node.isSubnet) return SUBNET_NODE_COLOR;
    if (node.isGroup) return GROUP_NODE_COLOR;
    if (nodeColorMode === 'role') return roleColor(node.role);
    return tierColor(node.colorTier || 0, isLightTheme);
}

// Per-node customizations live server-side now (persisted, shared across clients).
// This is a client cache of /api/overrides, loaded on startup; edits PATCH one
// node and the server resyncs the view to reflect them.
let nodeOverrides = {};

// Load the override map from the server (called on init).
async function loadOverrides() {
    try {
        const resp = await fetch('/api/overrides');
        if (resp.ok) nodeOverrides = await resp.json();
    } catch (e) { /* overrides are best-effort */ }
}

// Merge a patch into a node's override and POST the result. Keys set to null/''
// are dropped so the server can treat them as "no override". The server persists
// and triggers a resync, so the graph updates without a manual refresh.
async function applyOverrideEdit(nodeId, patch) {
    const current = Object.assign({}, nodeOverrides[nodeId] || {});
    for (const [k, v] of Object.entries(patch)) {
        if (v === null || v === '' || v === false) delete current[k];
        else current[k] = v;
    }
    nodeOverrides[nodeId] = current;
    try {
        await fetch('/api/overrides', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nodeId: nodeId, override: current })
        });
    } catch (e) { /* best-effort */ }
}

// Remove all customizations for a node.
async function clearOverride(nodeId) {
    delete nodeOverrides[nodeId];
    try {
        await fetch('/api/overrides?id=' + encodeURIComponent(nodeId), { method: 'DELETE' });
    } catch (e) { /* best-effort */ }
    showNodeDetails(nodeId);
}

// Toggle a node's user "group" designation server-side (compact box styling +
// excluded from traffic popularity).
function handleGroupToggle(nodeId) {
    const isGroup = !!(nodeOverrides[nodeId] && nodeOverrides[nodeId].isGroup);
    applyOverrideEdit(nodeId, { isGroup: !isGroup }).then(() => showNodeDetails(nodeId));
}

// Pin a node at its current on-screen position (or unpin it).
function handlePinToggle(nodeId) {
    const pinned = !!(nodeOverrides[nodeId] && nodeOverrides[nodeId].pinnedX != null);
    if (pinned) {
        applyOverrideEdit(nodeId, { pinnedX: null, pinnedY: null }).then(() => showNodeDetails(nodeId));
    } else if (network) {
        const p = network.getPosition(nodeId);
        applyOverrideEdit(nodeId, { pinnedX: p.x, pinnedY: p.y }).then(() => showNodeDetails(nodeId));
    }
}

// Rename / recolor from the node-details inputs.
function handleRename(nodeId, value) {
    applyOverrideEdit(nodeId, { label: value.trim() });
}
function handleRecolor(nodeId, value) {
    applyOverrideEdit(nodeId, { color: value });
}

// Styling, thresholds, top-N selection and protocol filtering are now computed
// server-side (see graph/view.go). The client renders the styled ViewNodes it
// receives — see updateGraph below.

function updateGraph(data) {
    if (!data) {
        console.error('Invalid data received:', data);
        return;
    }
    // Go marshals nil slices as null, so a packets/flows-only delta can arrive
    // with nodes/edges absent — coerce to arrays so a thin update still works.
    const incomingNodes = data.nodes || [];
    const incomingEdges = data.edges || [];

    // The server now sends fully-styled ViewNodes/ViewEdges. isFull replaces the
    // whole graph (initial sync, filter or layout change); otherwise this is a
    // delta of changed/removed items. The client just renders what it's given.
    const isFull = !!data.isFull;
    // fullDone marks the message that COMPLETES a full snapshot: the only
    // message of an unchunked full, or the last chunk of a chunked one.
    const fullDone = !!data.fullDone;
    const isLight = document.body.classList.contains('light-theme');

    // Chunked fulls stream as [isFull+partial, partial..., partial+fullDone].
    // Accumulate the ids applied across the chunks so stale reconciliation and
    // the deferred camera fit can run over the COMPLETE view when it lands.
    if (isFull) {
        fullSyncIds = data.partial ? { nodes: new Set(), edges: new Set() } : null;
    }
    if (fullSyncIds) {
        for (const n of incomingNodes) fullSyncIds.nodes.add(n.id);
        for (const e of incomingEdges) fullSyncIds.edges.add(e.id);
    }

    // Explicit removals (deltas carry these; full snapshots reconcile below).
    if (data.removedNodes && data.removedNodes.length > 0) {
        nodes.remove(data.removedNodes);
        data.removedNodes.forEach(forgetNodePosition);
    }
    if (data.removedEdges && data.removedEdges.length > 0) {
        edges.remove(data.removedEdges);
        data.removedEdges.forEach(id => { edgeMeta.delete(id); lastEdgeSig.delete(id); });
    }

    // Build vis nodes from the server-styled ViewNodes. The server computes the
    // layout position; rather than snap the node there (which looks jittery at the
    // ~10/s update rate), we record it as a target and let a 60fps animation loop
    // ease the node toward it (see stepPositionAnimation). A brand-new node is
    // placed at its target immediately so it doesn't fly in from the origin.
    //
    // Only items whose RENDER signature changed touch the DataSet: DataSet.update
    // deep-merges, re-parses options and repaints per item, so count-only churn
    // (the common case under traffic) must bypass it. Latest counts live in
    // nodeMeta/edgeMeta for tooltips, details, and search.
    let movedTargets = false;
    let snappedBody = false;
    const bodyNodes = network ? network.body.nodes : {};
    const nodeUpdates = [];
    for (const node of incomingNodes) {
        // Carry lazily-fetched detail (/api/node) across meta replacement —
        // a style delta would otherwise wipe it and re-trigger fetches.
        const prevMeta = nodeMeta.get(node.id);
        if (prevMeta && prevMeta.detailLoaded) {
            node.detailLoaded = true;
            if (!node.ips || !node.ips.length) node.ips = prevMeta.ips;
            if (!node.deviceInfo) node.deviceInfo = prevMeta.deviceInfo;
            node.peers = prevMeta.peers;
            node.detailEdges = prevMeta.detailEdges;
        }
        nodeMeta.set(node.id, node);

        let renderPos = null;
        if (typeof node.x === 'number' && typeof node.y === 'number' &&
            network && network.ownsLayout) {
            // cosmos.gl mode: the GPU sim owns positions. The server coordinate
            // is only a spawn seed for brand-new nodes (the adapter ignores
            // x/y updates for nodes it already simulates).
            renderPos = { x: node.x, y: node.y };
        } else if (typeof node.x === 'number' && typeof node.y === 'number') {
            const r = applyTargetPosition(node.id, node.x, node.y, !!node.pinned, bodyNodes);
            if (r === 'moved') movedTargets = true;
            else if (r === 'snapped') snappedBody = true;
            renderPos = nodeRenderPos.get(node.id);
        }

        const label = formatNodeLabel(node);
        const shape = viewNodeShape(node);
        const color = viewNodeColor(node, isLight);
        // Quantize the size driver to ~5% steps: node size only spans 20..30px, so
        // sub-5% growth is invisible and shouldn't trigger a restyle.
        const valueQ = Math.round(Math.log((node.value || 0) + 1) * 20);
        const sig = label + '~' + shape + '~' + valueQ + '~' + (node.isGroup ? 1 : 0) +
            '~' + (node.role || '') + '~' + JSON.stringify(color);
        if (lastNodeSig.get(node.id) === sig && nodes.get(node.id)) {
            continue; // data-only change; meta map already updated
        }
        lastNodeSig.set(node.id, sig);

        const nodeData = {
            id: node.id,
            label: label,
            // Slim stream omits IPs; only treat the id as one when it IS one
            // (a hostname-merged node's id is the hostname, not an address).
            ips: node.ips || (looksLikeIP(node.id) ? [node.id] : []),
            hostname: node.label,
            isGroup: node.isGroup,
            isSubnet: node.isSubnet,
            hostCount: node.hostCount,
            role: node.role,
            packetCount: node.packetCount,
            byteCount: node.byteCount,
            value: node.value,
            colorTier: node.colorTier,
            shape: shape,
            color: color,
            shapeProperties: node.isGroup ? { borderDashes: [4, 4] } : { borderDashes: false },
            font: node.isGroup ? { color: '#95a5a6' } : null
        };
        // Always carry the current RENDERED position so a style update re-applies
        // the position the node is actually at (vis re-applies item x/y on update;
        // a stale stored position would teleport the node).
        if (renderPos) {
            nodeData.x = renderPos.x;
            nodeData.y = renderPos.y;
        }
        nodeUpdates.push(nodeData);
    }
    if (nodeUpdates.length > 0) {
        nodes.update(nodeUpdates);
    }
    if (movedTargets) {
        startPositionAnimation();
    } else if (snappedBody && network) {
        network.redraw();
    }

    // Build vis edges from server-styled ViewEdges. Hidden edges are already
    // omitted server-side, so there is no client-side protocol filtering. Same
    // signature scheme as nodes: width is quantized to 0.25px steps so packet
    // churn on an existing edge almost never restyles it.
    const edgeUpdates = [];
    for (const edge of incomingEdges) {
        edgeMeta.set(edge.id, edge);
        const label = edgeLabelsVisible ? formatEdgeLabel(edge) : '';
        const width = Math.round((Math.log(edge.packetCount + 1) * 0.5 + 1) * 4) / 4;
        const sig = edge.from + '~' + edge.to + '~' + edge.protocol.Color + '~' + width + '~' + label;
        if (lastEdgeSig.get(edge.id) === sig && edges.get(edge.id)) {
            continue; // data-only change; meta map already updated
        }
        lastEdgeSig.set(edge.id, sig);
        edgeUpdates.push({
            id: edge.id,
            from: edge.from,
            to: edge.to,
            label: label,
            color: { color: edge.protocol.Color },
            width: width,
            protocol: edge.protocol,
            packetCount: edge.packetCount,
            byteCount: edge.byteCount
        });
    }
    if (edgeUpdates.length > 0) {
        edges.update(edgeUpdates);
    }

    // DataSet updates re-parse item options, which resets any focus dimming on the
    // touched items — reapply it in one pass.
    if (focusActive && (nodeUpdates.length > 0 || edgeUpdates.length > 0)) {
        applyFocusDim();
    }

    // Once a full snapshot is COMPLETE, drop anything the server no longer
    // lists. For chunked fulls this uses the ids accumulated across all chunks.
    // Doing our own reconciliation matters on reconnect: the server's
    // removedNodes are diffed against per-client state that is empty for a
    // fresh connection, so nodes that decayed during the disconnect would
    // otherwise linger on screen forever.
    if (fullDone) {
        const keepNodes = fullSyncIds ? fullSyncIds.nodes : new Set(incomingNodes.map(n => n.id));
        const keepEdges = fullSyncIds ? fullSyncIds.edges : new Set(incomingEdges.map(e => e.id));
        fullSyncIds = null;
        const staleNodes = nodes.getIds().filter(id => !keepNodes.has(id));
        if (staleNodes.length > 0) {
            nodes.remove(staleNodes);
            staleNodes.forEach(forgetNodePosition);
        }
        const staleEdges = edges.getIds().filter(id => !keepEdges.has(id));
        if (staleEdges.length > 0) {
            edges.remove(staleEdges);
            staleEdges.forEach(id => { edgeMeta.delete(id); lastEdgeSig.delete(id); });
        }

        // After a filter change, fit the camera to just the displayed nodes so
        // the view centers on what's shown, not the gaps left by hidden nodes.
        // Deferred to fullDone so a chunked full fits the WHOLE view, not the
        // ~150 busiest nodes of the first chunk.
        if (fitOnNextFull && network && nodes.length > 0) {
            network.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
        }
        fitOnNextFull = false;
    }

    // Subnet islands (dotted rings) are computed server-side in subnet mode.
    // Update them whenever the server includes them; the beforeDrawing hook
    // renders whatever is in subnetIslands.
    if (data.subnetIslands) {
        subnetIslands = data.subnetIslands;
        if (network) {
            if (network.invalidateOverlay) network.invalidateOverlay();
            else network.redraw();
        }
    } else if (currentClusterLayout !== 'subnet' && subnetIslands.length > 0) {
        subnetIslands = [];
        if (network) {
            if (network.invalidateOverlay) network.invalidateOverlay();
            else network.redraw();
        }
    }

    // Packets are still pushed in Phase A (moves to fetch-on-demand in Phase E).
    updatePacketCache(data.packets);

    // Statistics come from the server (computed on the view it just built);
    // fall back to the meta maps — never a full DataSet copy — if absent.
    if (data.stats) {
        updateStatistics(data.stats.nodeCount, data.stats.edgeCount, data.stats.totalPackets);
    } else {
        let totalPackets = 0;
        nodeMeta.forEach(n => { totalPackets += n.packetCount || 0; });
        updateStatistics(nodes.length, edges.length, totalPackets);
    }

    // Re-apply tier-based quality options when the node count crosses a tier
    // boundary (this used to happen only on theme change, so a growing graph
    // kept full-quality settings forever).
    maybeApplyPerformanceTier();

    // Per-protocol breakdown in the legend/filters (includes hidden protocols).
    if (data.protocolStats) updateProtocolCounts(data.protocolStats);

    // Feed flow particles (etherape-style moving traffic) unless game mode, which
    // has its own 3D visualization of the same flows.
    if (!gameMode.active && data.trafficFlows && data.trafficFlows.length > 0) {
        feedFlowParticles(data.trafficFlows);
    }

    // Game mode: refresh on change + feed the traffic-flow animation queue.
    if (gameMode.active) {
        const removed = (data.removedNodes && data.removedNodes.length) ||
                        (data.removedEdges && data.removedEdges.length);
        if (nodeUpdates.length > 0 || edgeUpdates.length > 0 || removed) {
            refreshGameNodes();
        }
        if (data.trafficFlows && data.trafficFlows.length > 0) {
            for (const flow of data.trafficFlows) {
                gameMode.trafficEvents.push({
                    src: flow.from,
                    dst: flow.to,
                    protocol: flow.protocol,
                    color: flow.color || PROTOCOL_COLORS[flow.protocol] || '#ecf0f1',
                    timestamp: Date.now(),
                    bytes: flow.bytes || 100,
                    packets: flow.packets || 1
                });
            }
            if (gameMode.trafficEvents.length > 200) {
                gameMode.trafficEvents.splice(0, gameMode.trafficEvents.length - 200);
            }
        }
    }
}

// Drop every client-side per-item cache. Must accompany nodes.clear()/
// edges.clear() (replay transitions) so no stale meta, signature, or
// interpolation state survives into the new graph.
function resetGraphCaches() {
    nodeTargetPos.clear();
    nodeRenderPos.clear();
    nodeMeta.clear();
    edgeMeta.clear();
    lastNodeSig.clear();
    lastEdgeSig.clear();
}

// Forget a removed node's interpolation state, meta and render signature.
function forgetNodePosition(id) {
    nodeTargetPos.delete(id);
    nodeRenderPos.delete(id);
    nodeMeta.delete(id);
    lastNodeSig.delete(id);
}

// Re-apply quality options when the node count crosses a performance-tier
// boundary. setOptions is moderately expensive, so it runs only on crossings.
function maybeApplyPerformanceTier() {
    if (!network) return;
    const tier = getPerformanceTier(nodes.length);
    if (tier === currentTier) return;
    currentTier = tier;
    network.setOptions(getNetworkOptions());

    // Edge label visibility follows the node count too: label text is the most
    // expensive per-edge draw. Toggle by writing straight into the live edge
    // options — vis silently ignores a DataSet update that sets an existing
    // label to ''/null, so the DataSet route cannot clear rendered labels.
    const show = nodes.length <= EDGE_LABEL_MAX_NODES;
    if (show !== edgeLabelsVisible) {
        edgeLabelsVisible = show;
        const bodyEdges = network.body.edges;
        for (const id in bodyEdges) {
            const meta = edgeMeta.get(id);
            bodyEdges[id].options.label = (show && meta) ? formatEdgeLabel(meta) : undefined;
        }
        network.redraw();
    }
}

// Kick off the position-easing loop if it isn't already running.
function startPositionAnimation() {
    if (positionAnimationActive || !network) return;
    positionAnimationActive = true;
    requestAnimationFrame(stepPositionAnimation);
}

// One animation frame: ease every node's rendered position toward its server
// target, writing straight into the live vis node objects and repainting once.
// Never goes through the DataSet — DataSet.update deep-merges and re-parses every
// item, which is what used to make this loop stutter at high node counts. Stops
// itself once everything is within half a pixel of its target, so an idle graph
// costs nothing; snaps instantly while the tab is hidden.
function stepPositionAnimation() {
    if (!network) { positionAnimationActive = false; return; }
    const bodyNodes = network.body.nodes;
    const hidden = document.hidden;
    let moving = false;
    let moved = false;
    nodeTargetPos.forEach((t, id) => {
        let r = nodeRenderPos.get(id);
        if (!r) { r = { x: t.x, y: t.y }; nodeRenderPos.set(id, r); }
        const dx = t.x - r.x, dy = t.y - r.y;
        if (hidden || (dx * dx + dy * dy) < 0.25) {
            if (r.x !== t.x || r.y !== t.y) {
                r.x = t.x; r.y = t.y;
                const bn = bodyNodes[id];
                if (bn) { bn.x = t.x; bn.y = t.y; moved = true; }
            }
            return;
        }
        r.x += dx * POSITION_EASE;
        r.y += dy * POSITION_EASE;
        const bn = bodyNodes[id];
        if (bn) { bn.x = r.x; bn.y = r.y; moved = true; }
        moving = true;
    });
    if (moved) network.redraw();
    if (moving && !hidden) {
        requestAnimationFrame(stepPositionAnimation);
    } else {
        positionAnimationActive = false;
    }
}

// --- Focus mode: highlight a node + its neighbours, dim everything else --------

// Highlight nodeId and its directly-connected nodes/edges; fade the rest so you
// can read who a host talks to in a busy graph. pin=true locks it (from a click).
function focusNode(nodeId, pin) {
    if (!network || !nodes.get(nodeId)) return;
    focusPinned = pin;
    focusActive = true;
    focusKeepNodes = new Set([nodeId, ...network.getConnectedNodes(nodeId)]);
    focusKeepEdges = new Set(network.getConnectedEdges(nodeId));
    applyFocusDim();
}

// Restore full opacity to everything.
function clearFocus() {
    if (!focusActive) return;
    focusActive = false;
    focusPinned = false;
    focusKeepNodes = null;
    focusKeepEdges = null;
    applyFocusDim();
}

// Write the dim state straight into the live vis node/edge options and repaint
// once. The old DataSet-based version deep-merged and re-parsed every node and
// edge on each hover, which alone could stall a busy graph.
function applyFocusDim() {
    if (!network) return;
    const bodyNodes = network.body.nodes;
    for (const id in bodyNodes) {
        bodyNodes[id].options.opacity = (!focusActive || focusKeepNodes.has(id)) ? 1 : 0.12;
    }
    const bodyEdges = network.body.edges;
    for (const id in bodyEdges) {
        const opts = bodyEdges[id].options;
        if (opts.color) {
            opts.color.opacity = (!focusActive || focusKeepEdges.has(id)) ? 1 : 0.06;
        }
    }
    network.redraw();
}

// --- Traffic flow particles ---------------------------------------------------

// Spawn particles for this tick's flows so traffic visibly moves along edges in
// its real direction. Only flows between currently-visible nodes are drawn.
// The WebGL renderer draws particles inside its own scene (no 2D overlay, no
// separate rAF loop — the Safari-friendly path); the 2D overlay below remains
// as the vis-network fallback.
function feedFlowParticles(flows) {
    // cosmos.gl mode: positions live on the GPU; neither the GL particle scene
    // nor the 2D overlay can follow them, so particles are off (v1).
    if (network && network.ownsLayout) return;
    // Gate on traffic volume: quiet flows spawn nothing (the graph should not
    // be a snow globe), and speed encodes intensity.
    const significant = flows.filter(f => (f.packets || 0) >= FLOW_MIN_PACKETS);
    if (significant.length === 0) return;
    if (network && typeof network.spawnParticles === 'function') {
        network.spawnParticles(significant.map(f => ({
            fromId: f.from,
            toId: f.to,
            color: f.color || PROTOCOL_COLORS[f.protocol] || '#7fd3ff',
            speed: flowParticleSpeed(f.packets)
        })));
        return;
    }
    for (const f of significant) {
        if (!nodes.get(f.from) || !nodes.get(f.to)) continue;
        activeFlows.push({
            edgeId: f.edgeId, // so the particle can follow the edge's actual curve
            from: f.from,
            to: f.to,
            color: f.color || PROTOCOL_COLORS[f.protocol] || '#7fd3ff',
            progress: 0,
            speed: flowParticleSpeed(f.packets)
        });
    }
    if (activeFlows.length > MAX_FLOW_PARTICLES) {
        activeFlows.splice(0, activeFlows.length - MAX_FLOW_PARTICLES);
    }
    startFlowAnimation();
}

// Create the transparent overlay canvas the flow particles draw on, sized to and
// stacked above the graph canvas. Keeping particles off the vis canvas means the
// graph only repaints on real changes, not 60fps just to move dots.
let flowOverlay = null;
let flowOverlayCtx = null;
function setupFlowOverlay() {
    const net = document.getElementById('network');
    if (!net || flowOverlay) return;
    if (getComputedStyle(net).position === 'static') net.style.position = 'relative';
    flowOverlay = document.createElement('canvas');
    flowOverlay.style.cssText = 'position:absolute;top:0;left:0;pointer-events:none;z-index:4;';
    net.appendChild(flowOverlay);
    flowOverlayCtx = flowOverlay.getContext('2d');
    resizeFlowOverlay();
    if (window.ResizeObserver) {
        new ResizeObserver(resizeFlowOverlay).observe(net);
    } else {
        window.addEventListener('resize', resizeFlowOverlay);
    }
}

function resizeFlowOverlay() {
    const net = document.getElementById('network');
    if (!flowOverlay || !net) return;
    const dpr = window.devicePixelRatio || 1;
    flowOverlay.width = Math.round(net.clientWidth * dpr);
    flowOverlay.height = Math.round(net.clientHeight * dpr);
    flowOverlay.style.width = net.clientWidth + 'px';
    flowOverlay.style.height = net.clientHeight + 'px';
}

function clearFlowOverlay() {
    if (!flowOverlayCtx) return;
    flowOverlayCtx.setTransform(1, 0, 0, 1, 0, 0);
    flowOverlayCtx.clearRect(0, 0, flowOverlay.width, flowOverlay.height);
}

function startFlowAnimation() {
    if (flowAnimationActive || !network) return;
    flowAnimationActive = true;
    requestAnimationFrame(stepFlowAnimation);
}

// Advance the particles and repaint ONLY the overlay (no network.redraw()).
function stepFlowAnimation() {
    if (!network || activeFlows.length === 0) { flowAnimationActive = false; clearFlowOverlay(); return; }
    for (const f of activeFlows) f.progress += f.speed;
    activeFlows = activeFlows.filter(f => f.progress < 1);
    drawFlowOverlay();
    if (activeFlows.length > 0) {
        requestAnimationFrame(stepFlowAnimation);
    } else {
        flowAnimationActive = false;
        clearFlowOverlay();
    }
}

// Draw the particles on the overlay. Each rides the edge's real geometry via
// vis's edge.getPoint(t) (so it curves with the edge and follows a dragged node),
// then we map graph coords -> screen with canvasToDOM so it tracks pan/zoom.
function drawFlowOverlay() {
    const ctx = flowOverlayCtx;
    if (!ctx) return;
    const dpr = window.devicePixelRatio || 1;
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, flowOverlay.width, flowOverlay.height);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); // draw in CSS pixels
    const edges = network.body && network.body.edges;
    const scale = network.getScale ? network.getScale() : 1;
    const r = 3.5 * scale; // keep particles the same on-screen size as before (scale with zoom)
    for (const f of activeFlows) {
        let gp = null;
        const edge = edges ? edges[f.edgeId] : null;
        if (edge && edge.edgeType && typeof edge.edgeType.getPoint === 'function') {
            const t = (edge.fromId === f.from) ? f.progress : (1 - f.progress);
            try { gp = edge.edgeType.getPoint(t); } catch (e) { gp = null; }
        }
        if (!gp) {
            const ps = network.getPositions([f.from, f.to]);
            const a = ps[f.from], b = ps[f.to];
            if (!a || !b) continue;
            gp = { x: a.x + (b.x - a.x) * f.progress, y: a.y + (b.y - a.y) * f.progress };
        }
        const dom = network.canvasToDOM(gp);
        ctx.beginPath();
        ctx.arc(dom.x, dom.y, r, 0, 2 * Math.PI);
        ctx.fillStyle = f.color;
        ctx.globalAlpha = 0.9 * (1 - f.progress * 0.4);
        ctx.fill();
    }
    ctx.globalAlpha = 1;
}

// Server-computed device role -> a small glyph + display name. Keep role keys in
// sync with graph/classify.go. Group/unknown get no glyph.
const ROLE_GLYPH = {
    server: '🖥', client: '💻', router: '🔀', switch: '▦',
    gateway: '🛡', iot: '📟', multicast: '📡'
};
const ROLE_NAME = {
    server: 'Server', client: 'Client', router: 'Router', switch: 'Switch',
    gateway: 'Gateway', iot: 'IoT', multicast: 'Multicast/Broadcast', unknown: 'Unknown'
};

// Device role -> base color, used when "color by role" is enabled.
const ROLE_COLOR = {
    server: '#3498db', client: '#2ecc71', router: '#9b59b6', switch: '#0e7490',
    gateway: '#e74c3c', iot: '#e67e22', multicast: '#95a5a6', unknown: '#7f8c8d'
};

// How nodes are colored: 'traffic' (tier) or 'role'. Persisted.
let nodeColorMode = localStorage.getItem('nodeColorMode') || 'traffic';

// Build a vis color object from a single base hex (used for role coloring).
function roleColor(role) {
    const hex = ROLE_COLOR[role] || ROLE_COLOR.unknown;
    return { background: hex, border: hex, highlight: { background: hex, border: hex } };
}

// Switch the node color encoding and restyle every node in place.
function setNodeColorMode(mode) {
    nodeColorMode = mode;
    localStorage.setItem('nodeColorMode', mode);
    recolorAllNodes();
    renderLegend();
}

// Recolor all existing nodes for the current color mode without waiting for a
// server update (reads role/colorTier/override that we stash on each vis node).
function recolorAllNodes() {
    const isLight = document.body.classList.contains('light-theme');
    const updates = nodes.get().map(n => ({
        id: n.id,
        color: viewNodeColor({
            color: (nodeOverrides[n.id] || {}).color,
            isGroup: n.isGroup, colorTier: n.colorTier, role: n.role
        }, isLight)
    }));
    if (updates.length) {
        nodes.update(updates);
        // Render signatures embed the computed color; drop them so the next delta
        // re-syncs each node against the new palette instead of a stale signature.
        lastNodeSig.clear();
    }
}

// The shape for a node: groups and collapsed subnets are boxes; every real
// (connected) host is a circle. Role is conveyed by color/legend, not shape.
function viewNodeShape(node) {
    return (node.isGroup || node.isSubnet) ? 'box' : 'dot';
}

// Format node label. The role is encoded by node shape now, so the label stays
// clean (no glyph prefix); the glyph still appears in tooltips/details.
function formatNodeLabel(node) {
    if (node.isSubnet) return `${node.label} (${node.hostCount})`;
    return node.label !== node.id ? node.label : node.id;
}

// Format node tooltip
function formatNodeTooltip(node) {
    let tooltip = '';

    // Collapsed /24 supernode: summary + how to open it.
    if (node.isSubnet) {
        tooltip += `⬚ Collapsed subnet — ${node.hostCount} hosts\n`;
        tooltip += `CIDR: ${node.label}\n`;
        tooltip += `Packets: ${node.packetCount}\nBytes: ${formatBytes(node.byteCount)}\n`;
        tooltip += `Click for details / expand`;
        return tooltip;
    }

    // Flag multicast/broadcast rendezvous points so they aren't mistaken for a host
    if (node.isGroup) {
        tooltip += `⚲ Multicast/broadcast group (not a host)\n`;
    }

    // Server-classified device role.
    if (node.role && node.role !== 'unknown' && !node.isGroup) {
        tooltip += `Role: ${ROLE_NAME[node.role] || node.role}\n`;
    }
    // LLDP/CDP hardware details (port you're connected to, mgmt address).
    if (node.deviceInfo) {
        tooltip += `Link: ${node.deviceInfo}\n`;
    }

    // Display hostname if different from ID
    if (node.label && node.label !== node.id) {
        tooltip += `Hostname: ${node.label}\n`;
    }

    // Display all IPs
    if (node.ips && node.ips.length > 0) {
        if (node.ips.length === 1) {
            tooltip += `IP: ${node.ips[0]}\n`;
        } else {
            tooltip += `IPs:\n`;
            node.ips.forEach(ip => {
                tooltip += `  ${ip}\n`;
            });
        }
    } else if (looksLikeIP(node.id)) {
        // Fallback to ID only when the id is itself an address; a hostname id
        // is already shown on the Hostname line and isn't an IP.
        tooltip += `IP: ${node.id}\n`;
    }

    tooltip += `Packets: ${node.packetCount}\nBytes: ${formatBytes(node.byteCount)}`;
    return tooltip;
}

// Format edge label. Protocol name only: embedding the live packet count meant
// every packet changed the label, forcing a text re-render of ~every edge on
// every update under load. Counts live in the tooltip and details panel.
function formatEdgeLabel(edge) {
    return edge.protocol.Name;
}

// Format edge tooltip (bidirectional)
function formatEdgeTooltip(edge) {
    let tooltip = `${edge.from} ↔ ${edge.to}\nProtocol: ${edge.protocol.Name}\n`;
    tooltip += `Total: ${edge.packetCount} pkts, ${formatBytes(edge.byteCount)}\n`;
    // Show directional breakdown if available
    if (edge.forwardPackets !== undefined || edge.reversePackets !== undefined) {
        const fwdPkts = edge.forwardPackets || 0;
        const revPkts = edge.reversePackets || 0;
        const fwdBytes = edge.forwardBytes || 0;
        const revBytes = edge.reverseBytes || 0;
        tooltip += `→ ${fwdPkts} pkts (${formatBytes(fwdBytes)})\n`;
        tooltip += `← ${revPkts} pkts (${formatBytes(revBytes)})`;
    }
    return tooltip;
}

// looksLikeIP reports whether a node id is itself an address (unresolved nodes
// use their IP as id; IPv6 and MAC ids contain ':'). Hostname-merged nodes use
// the hostname as id, which must never be presented or matched as an IP — the
// real IP list arrives with the lazy /api/node detail fetch.
function looksLikeIP(s) {
    return typeof s === 'string' &&
        (/^[0-9]{1,3}(\.[0-9]{1,3}){3}$/.test(s) || s.includes(':'));
}

// Format bytes for display
function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

// Show node details
function showNodeDetails(nodeId) {
    // Guard: vis DataSet.get(null) returns ALL items (an array), not null.
    if (!nodeId || typeof nodeId !== 'string') return;
    let node = nodes.get(nodeId);
    if (!node || Array.isArray(node)) return;
    // Merge live counts/fields from the meta map — the vis item only refreshes on
    // visible style changes, so its counters may be stale.
    const meta = nodeMeta.get(nodeId);
    if (meta) {
        node = Object.assign({}, node, {
            packetCount: meta.packetCount,
            byteCount: meta.byteCount,
            role: meta.role,
            deviceInfo: meta.deviceInfo,
            ips: meta.ips || node.ips
        });
    }
    // Slim stream: IPs/deviceInfo/connections come from /api/node on demand.
    // Render what we have now, re-render once the detail arrives (unless the
    // panel has moved on to another node meanwhile).
    detailsNodeId = nodeId;
    if (meta && !meta.detailLoaded && !node.isSubnet && !node.isGroup) {
        fetchNodeDetail(nodeId).then(m => {
            if (m && detailsNodeId === nodeId &&
                document.getElementById('detailsPanel').classList.contains('active')) {
                showNodeDetails(nodeId);
            }
        });
    }
    const connectedEdges = edges.get({
        filter: edge => edge.from === nodeId || edge.to === nodeId
    });

    const detailsPanel = document.getElementById('detailsPanel');
    const detailsContent = document.getElementById('detailsContent');

    detailsPanel.classList.add('active');

    // Collapsed subnet supernode (Phase 4/5, /24 or /16): summary + expand,
    // plus re-collapse of the parent /16 when viewing a /24 inside one.
    if (node.isSubnet) {
        const cidr = (node.hostname || nodeId).replace(/'/g, "\\'");
        const parent16 = cidr.endsWith('/24') ? subnet16Of(cidr) : '';
        const collapseParentHTML = (parent16 && expandedSubnets.has(parent16))
            ? `<button class="group-toggle-btn" onclick="handleSubnetCollapse('${parent16}')">⊟ Collapse ${parent16}</button>`
            : '';
        detailsContent.innerHTML = `
            <h4>Subnet Details</h4>
            <div class="detail-item"><strong>CIDR:</strong> ${node.hostname || nodeId}</div>
            <div class="detail-item"><strong>Hosts inside:</strong> ${node.hostCount || '?'}</div>
            <div class="detail-item"><strong>Total Packets:</strong> ${node.packetCount || 0}</div>
            <div class="detail-item"><strong>Total Bytes:</strong> ${formatBytes(node.byteCount || 0)}</div>
            <div class="detail-item"><strong>Active Connections:</strong> ${connectedEdges.length}</div>
            <div class="customize-buttons">
                <button class="group-toggle-btn" onclick="handleSubnetExpand('${cidr}')">⊞ Expand subnet</button>
                ${collapseParentHTML}
            </div>`;
        return;
    }

    // Format IP addresses
    let ipAddressHTML = '';
    if (node.ips && node.ips.length > 0) {
        if (node.ips.length === 1) {
            ipAddressHTML = `<strong>IP Address:</strong> ${node.ips[0]}`;
        } else {
            // Multiple IPs (IPv4 + IPv6)
            const ipv4 = node.ips.filter(ip => ip.includes('.'));
            const ipv6 = node.ips.filter(ip => ip.includes(':'));

            if (ipv4.length > 0) {
                ipAddressHTML += `<strong>IPv4:</strong> ${ipv4.join(', ')}<br>`;
            }
            if (ipv6.length > 0) {
                ipAddressHTML += `<strong>IPv6:</strong> ${ipv6.join(', ')}`;
            }
            if (ipv4.length === 0 && ipv6.length === 0) {
                ipAddressHTML = `<strong>IP Addresses:</strong> ${node.ips.join(', ')}`;
            }
        }
    } else {
        ipAddressHTML = `<strong>IP Address:</strong> ${nodeId}`;
    }

    // Format hostname (only show if different from node ID)
    const hostnameHTML = (node.hostname && node.hostname !== nodeId)
        ? `<div class="detail-item"><strong>Hostname:</strong> ${node.hostname}</div>`
        : '';

    // Server-classified device role.
    const roleHTML = (node.role && node.role !== 'unknown' && !node.isGroup)
        ? `<div class="detail-item"><strong>Role:</strong> ${ROLE_GLYPH[node.role] || ''} ${ROLE_NAME[node.role] || node.role}</div>`
        : '';
    // LLDP/CDP hardware details (switch/router port + mgmt address).
    const deviceHTML = node.deviceInfo
        ? `<div class="detail-item"><strong>Link:</strong> ${node.deviceInfo}</div>`
        : '';

    // Per-node customization editor (server-backed, persisted, shared). Auto
    // multicast/broadcast groups are inherent and not editable as groups.
    const ov = nodeOverrides[nodeId] || {};
    const escId = nodeId.replace(/'/g, "\\'");
    let customizeHTML;
    if (node.isGroup && !ov.isGroup) {
        customizeHTML = `<div class="detail-item"><strong>Group:</strong> multicast/broadcast (auto)</div>`;
    } else {
        const isUserGroup = !!ov.isGroup;
        const isPinned = ov.pinnedX != null;
        const colorVal = ov.color || '#3498db';
        customizeHTML = `
            <div class="detail-item node-customize">
                <label>Name <input type="text" value="${(ov.label || '').replace(/"/g, '&quot;')}"
                    placeholder="${(node.hostname || nodeId).replace(/"/g, '&quot;')}"
                    onchange="handleRename('${escId}', this.value)"></label>
                <label>Color <input type="color" value="${colorVal}"
                    onchange="handleRecolor('${escId}', this.value)"></label>
                <div class="customize-buttons">
                    <button class="group-toggle-btn" onclick="handleGroupToggle('${escId}')">
                        ${isUserGroup ? '✕ Ungroup' : '⚲ Group'}
                    </button>
                    <button class="group-toggle-btn" onclick="handlePinToggle('${escId}')">
                        ${isPinned ? '📌 Unpin' : '📍 Pin'}
                    </button>
                    <button class="group-toggle-btn" onclick="clearOverride('${escId}')">↺ Reset</button>
                </div>
            </div>`;
    }

    // Phase 4/5: offer to re-collapse the subnets this host was expanded out of.
    let subnetHTML = '';
    if (!node.isGroup) {
        const buttons = [];
        for (const cidr of [hostSubnet24(node), subnet16Of(node)]) {
            if (cidr && expandedSubnets.has(cidr)) {
                buttons.push(`<button class="group-toggle-btn"
                    onclick="handleSubnetCollapse('${cidr}')">⊟ Collapse ${cidr}</button>`);
            }
        }
        if (buttons.length) {
            subnetHTML = `<div class="detail-item">${buttons.join(' ')}</div>`;
        }
    }

    detailsContent.innerHTML = `
        <h4>Node Details</h4>
        ${hostnameHTML}
        ${roleHTML}
        ${deviceHTML}
        <div class="detail-item">
            ${ipAddressHTML}
        </div>
        ${subnetHTML}
        ${customizeHTML}
        <div class="detail-item">
            <strong>Total Packets:</strong> ${node.packetCount || 0}
        </div>
        <div class="detail-item">
            <strong>Total Bytes:</strong> ${formatBytes(node.byteCount || 0)}
        </div>
        <div class="detail-item">
            <strong>Active Connections:</strong> ${connectedEdges.length}
        </div>
        <h5>Connections:</h5>
        <div class="connections-list">
            ${connectedEdges.map(edge => `
                <div class="connection-item">
                    <span class="color-box" style="background-color: ${edge.color.color}"></span>
                    ${edge.from === nodeId ? '→ ' + edge.to : '← ' + edge.from}
                    (${edge.protocol.Name})
                </div>
            `).join('')}
        </div>
    `;
}

// Show edge details
function showEdgeDetails(edgeId) {
    detailsNodeId = null;
    let edge = edges.get(edgeId);
    if (!edge) return;
    // Live counts come from the meta map (vis item counters refresh lazily).
    const meta = edgeMeta.get(edgeId);
    if (meta) {
        edge = Object.assign({}, edge, {
            packetCount: meta.packetCount,
            byteCount: meta.byteCount
        });
    }
    const detailsPanel = document.getElementById('detailsPanel');
    const detailsContent = document.getElementById('detailsContent');

    detailsPanel.classList.add('active');

    detailsContent.innerHTML = `
        <h4>Connection Details</h4>
        <div class="detail-item">
            <strong>From:</strong> ${edge.from}
        </div>
        <div class="detail-item">
            <strong>To:</strong> ${edge.to}
        </div>
        <div class="detail-item">
            <strong>Protocol:</strong>
            <span class="color-box" style="background-color: ${edge.color.color}"></span>
            ${edge.protocol.Name}
        </div>
        <div class="detail-item">
            <strong>Packets:</strong> ${edge.packetCount}
        </div>
        <div class="detail-item">
            <strong>Bytes:</strong> ${formatBytes(edge.byteCount)}
        </div>
    `;
}

// Hide details panel
function hideDetails() {
    detailsNodeId = null;
    const detailsPanel = document.getElementById('detailsPanel');
    detailsPanel.classList.remove('active');
    document.getElementById('detailsContent').innerHTML = '<p class="placeholder">Click on a node or edge to view details</p>';
}

// Update statistics
function updateStatistics(nodeCount, edgeCount, totalPackets = 0) {
    document.getElementById('nodeCount').textContent = nodeCount;
    document.getElementById('edgeCount').textContent = edgeCount;

    // Update total packets if element exists
    const totalPacketsElement = document.getElementById('totalPackets');
    if (totalPacketsElement) {
        totalPacketsElement.textContent = totalPackets.toLocaleString();
    }
}

// Update connection status
function updateConnectionStatus(status, connected) {
    const statusElement = document.getElementById('connectionStatus');
    const statsIcon = document.querySelector('#statsToggle .nav-icon');

    statusElement.textContent = status;
    statusElement.className = 'stat-value ' + (connected ? 'connected' : 'disconnected');

    // Update stats icon color based on connection status
    if (statsIcon) {
        // Remove all status classes
        statsIcon.classList.remove('status-connecting', 'status-connected', 'status-disconnected');

        // Add appropriate status class
        if (status === 'Connecting...' || status === 'Connecting') {
            statsIcon.classList.add('status-connecting');
        } else if (connected) {
            statsIcon.classList.add('status-connected');
        } else {
            statsIcon.classList.add('status-disconnected');
        }
    }
}

// Setup theme toggle
function setupTheme() {
    const themeButtons = document.querySelectorAll('[data-theme]');

    themeButtons.forEach(button => {
        button.addEventListener('click', function() {
            const theme = this.getAttribute('data-theme');

            // Remove active class from all theme buttons
            themeButtons.forEach(btn => btn.classList.remove('active'));

            // Add active class to clicked button
            this.classList.add('active');

            // Apply theme
            if (theme === 'light') {
                document.body.classList.add('light-theme');
            } else {
                document.body.classList.remove('light-theme');
            }

            // Update network with new theme-aware options and restyle per-node
            // colors (render signatures embed the theme-dependent color).
            if (network) {
                network.setOptions(getNetworkOptions());
                recolorAllNodes();
            }
        });
    });
}

// Setup cluster layout toggle
function setupClusterLayout() {
    const clusterButtons = document.querySelectorAll('[data-cluster]');

    // Load saved cluster layout from localStorage (default to 'force')
    const savedLayout = localStorage.getItem('clusterLayout') || 'force';

    // Set initial active state based on saved preference
    clusterButtons.forEach(button => {
        const layout = button.getAttribute('data-cluster');
        if (layout === savedLayout) {
            button.classList.add('active');
        } else {
            button.classList.remove('active');
        }
    });

    // Apply the saved layout (will be applied once network is ready)
    currentClusterLayout = savedLayout;

    clusterButtons.forEach(button => {
        button.addEventListener('click', function() {
            const layout = this.getAttribute('data-cluster');

            // Remove active class from all cluster buttons
            clusterButtons.forEach(btn => btn.classList.remove('active'));

            // Add active class to clicked button
            this.classList.add('active');

            // Save to localStorage
            localStorage.setItem('clusterLayout', layout);

            // Tell the server which layout to position nodes for.
            sendLayout(layout);
        });
    });
}

// Render the dotted blue ring + CIDR/VLAN label around each subnet island.
// Invoked from the network's beforeDrawing hook so the rings sit behind the
// nodes and edges. Coordinates are already in canvas space (vis applies the
// view transform before this fires), so we draw directly in graph units.
function drawSubnetIslands(ctx) {
    if (!subnetIslands.length) return;

    const ringColor = '#3b82f6'; // blue
    ctx.save();
    subnetIslands.forEach(island => {
        // Dotted blue circle.
        ctx.beginPath();
        ctx.setLineDash([8, 6]);
        ctx.lineWidth = 2;
        ctx.strokeStyle = ringColor;
        ctx.arc(island.x, island.y, island.radius, 0, 2 * Math.PI);
        ctx.stroke();

        // Faint fill so islands read as distinct regions.
        ctx.setLineDash([]);
        ctx.fillStyle = 'rgba(59, 130, 246, 0.05)';
        ctx.fill();

        // CIDR label centred at the top of the ring, with VLAN tag when known.
        const label = island.vlanId ? `${island.cidr}  ·  VLAN ${island.vlanId}` : island.cidr;
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'bottom';
        ctx.fillStyle = ringColor;
        ctx.fillText(label, island.x, island.y - island.radius - 6);
    });
    ctx.restore();
}

// Layout is computed on the server now. Switching layout just tells the server
// which mode to position nodes for; the new positions arrive in the next view
// and updateGraph() applies them. Subnet islands also arrive in the view.
function sendLayout(mode) {
    currentClusterLayout = mode;
    if (mode !== 'subnet') {
        subnetIslands = [];
        if (network) network.redraw();
    }
    sendControl({ type: 'setLayout', data: { mode: mode } });
}

// Chimpy Mode Implementation
let chimpyMode = {
    active: false,
    currentEdgeIndex: 0,
    currentProgress: 0,
    speed: 0.01, // Progress per frame (0-1)
    animationFrame: null,
    currentEdge: null,
    edgePath: []
};

// Setup Chimpy Mode
function setupChimpyMode() {
    const chimpyToggle = document.getElementById('chimpyToggle');

    if (chimpyToggle) {
        chimpyToggle.addEventListener('click', function() {
            toggleChimpyMode();
        });
    }
}

// Toggle Chimpy Mode on/off
function toggleChimpyMode() {
    const chimpyToggle = document.getElementById('chimpyToggle');
    const chimpyContainer = document.getElementById('chimpyContainer');

    chimpyMode.active = !chimpyMode.active;

    if (chimpyMode.active) {
        // Activate Chimpy Mode
        chimpyToggle.classList.add('chimpy-active');
        chimpyContainer.style.display = 'block';

        // Build edge path for Chimpy to follow
        buildChimpyPath();

        // Start animation
        startChimpyAnimation();
    } else {
        // Deactivate Chimpy Mode
        chimpyToggle.classList.remove('chimpy-active');
        chimpyContainer.style.display = 'none';

        // Stop animation
        stopChimpyAnimation();

        // Reset camera zoom
        if (network) {
            network.moveTo({
                scale: 1.0,
                animation: {
                    duration: 500,
                    easingFunction: 'easeInOutQuad'
                }
            });
        }
    }
}

// Build a path of edges for Chimpy to ride
function buildChimpyPath() {
    if (!network) {
        chimpyMode.edgePath = [];
        return;
    }

    // Get all visible edges
    const allEdges = edges.get().filter(e => !e.hidden);

    if (allEdges.length === 0) {
        chimpyMode.edgePath = [];
        console.warn('Chimpy: No visible edges found');
        return;
    }

    // Validate that edges have valid nodes with positions
    const validEdges = allEdges.filter(edge => {
        const fromNode = nodes.get(edge.from);
        const toNode = nodes.get(edge.to);

        if (!fromNode || !toNode) {
            return false;
        }

        // Check if we can get positions for these nodes
        try {
            const positions = network.getPositions([edge.from, edge.to]);
            return positions[edge.from] && positions[edge.to];
        } catch (e) {
            return false;
        }
    });

    if (validEdges.length === 0) {
        chimpyMode.edgePath = [];
        console.warn('Chimpy: No valid edges with positions found');
        return;
    }

    console.log(`Chimpy: Found ${validEdges.length} valid edges to ride`);

    // Sort edges by packet count (most active first) to make it interesting
    const sortedEdges = validEdges.sort((a, b) => {
        const bp = (edgeMeta.get(b.id) || b).packetCount || 0;
        const ap = (edgeMeta.get(a.id) || a).packetCount || 0;
        return bp - ap;
    });

    // Take top edges and shuffle for variety
    const topEdges = sortedEdges.slice(0, Math.min(20, sortedEdges.length));
    chimpyMode.edgePath = shuffleArray([...topEdges]);
    chimpyMode.currentEdgeIndex = 0;
    chimpyMode.currentProgress = 0;
}

// Shuffle array helper
function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

// Start Chimpy animation
function startChimpyAnimation() {
    if (chimpyMode.edgePath.length === 0) {
        console.warn('No edges available for Chimpy to ride');
        return;
    }

    function animate() {
        if (!chimpyMode.active) return;

        updateChimpyPosition();
        chimpyMode.animationFrame = requestAnimationFrame(animate);
    }

    animate();
}

// Stop Chimpy animation
function stopChimpyAnimation() {
    if (chimpyMode.animationFrame) {
        cancelAnimationFrame(chimpyMode.animationFrame);
        chimpyMode.animationFrame = null;
    }
}

// Update Chimpy's position along the edge
function updateChimpyPosition() {
    if (!network || chimpyMode.edgePath.length === 0) return;

    // Get current edge
    const edge = chimpyMode.edgePath[chimpyMode.currentEdgeIndex];
    if (!edge) {
        moveToNextEdge();
        return;
    }

    chimpyMode.currentEdge = edge;

    // Validate nodes exist
    const fromNode = nodes.get(edge.from);
    const toNode = nodes.get(edge.to);

    if (!fromNode || !toNode) {
        console.warn(`Chimpy: Nodes not found for edge ${edge.id}, skipping`);
        moveToNextEdge();
        return;
    }

    // Get positions in canvas coordinates
    let positions;
    try {
        positions = network.getPositions([edge.from, edge.to]);
    } catch (e) {
        console.error('Chimpy: Error getting positions', e);
        moveToNextEdge();
        return;
    }

    const fromPos = positions[edge.from];
    const toPos = positions[edge.to];

    if (!fromPos || !toPos) {
        console.warn(`Chimpy: Invalid positions for edge ${edge.id}`);
        moveToNextEdge();
        return;
    }

    // Interpolate position along the edge (linear interpolation)
    const progress = chimpyMode.currentProgress;
    const canvasX = fromPos.x + (toPos.x - fromPos.x) * progress;
    const canvasY = fromPos.y + (toPos.y - fromPos.y) * progress;

    // Convert canvas coordinates to DOM coordinates
    let domPosition;
    try {
        domPosition = network.canvasToDOM({ x: canvasX, y: canvasY });
    } catch (e) {
        console.error('Chimpy: Error converting coordinates', e);
        moveToNextEdge();
        return;
    }

    // Get the network container offset to position Chimpy correctly
    const networkContainer = document.getElementById('network');
    const containerRect = networkContainer.getBoundingClientRect();

    // Calculate absolute position on screen
    const screenX = containerRect.left + domPosition.x;
    const screenY = containerRect.top + domPosition.y;

    // Update Chimpy character position
    const chimpyCharacter = document.getElementById('chimpyCharacter');
    if (chimpyCharacter) {
        chimpyCharacter.style.left = screenX + 'px';
        chimpyCharacter.style.top = screenY + 'px';
    }

    // Update packet window position (offset to the right and down)
    const chimpyPacketWindow = document.getElementById('chimpyPacketWindow');
    if (chimpyPacketWindow) {
        chimpyPacketWindow.style.left = (screenX + 60) + 'px';
        chimpyPacketWindow.style.top = (screenY - 20) + 'px';
    }

    // Update packet info in the window
    updateChimpyPacketInfo(edge);

    // Follow Chimpy with camera (medium zoom)
    network.moveTo({
        position: { x: canvasX, y: canvasY },
        scale: 1.5, // Medium zoom
        animation: false // Smooth following without animation delay
    });

    // Increment progress
    chimpyMode.currentProgress += chimpyMode.speed;

    // Move to next edge when current edge is complete
    if (chimpyMode.currentProgress >= 1.0) {
        moveToNextEdge();
    }
}

// Move to the next edge in the path
function moveToNextEdge() {
    chimpyMode.currentEdgeIndex = (chimpyMode.currentEdgeIndex + 1) % chimpyMode.edgePath.length;
    chimpyMode.currentProgress = 0;

    // Rebuild path occasionally to get new edges
    if (chimpyMode.currentEdgeIndex === 0) {
        buildChimpyPath();
    }
}

// Update packet information in Chimpy's window
function updateChimpyPacketInfo(edge) {
    const chimpyPacketContent = document.getElementById('chimpyPacketContent');
    const chimpyHexDump = document.getElementById('chimpyHexDump');

    if (!edge) return;

    // Live counts come from the meta map (vis item counters refresh lazily).
    const em = edgeMeta.get(edge.id);
    if (em) {
        edge = Object.assign({}, edge, { packetCount: em.packetCount, byteCount: em.byteCount });
    }

    // Get the actual nodes to access their IP addresses
    const fromNode = nodes.get(edge.from);
    const toNode = nodes.get(edge.to);

    if (!fromNode || !toNode) {
        document.querySelector('.chimpy-packet-info').innerHTML = `
<strong>Riding:</strong> ${edge.from} → ${edge.to}
<strong>Protocol:</strong> ${edge.protocol.Name}
<strong>Packets:</strong> ${edge.packetCount}

Loading node data...
        `;
        chimpyHexDump.innerHTML = '';
        return;
    }

    // Get all IPs for both nodes (handles both IPv4 and IPv6, plus hostname consolidation)
    const fromIPs = fromNode.ips || [edge.from];
    const toIPs = toNode.ips || [edge.to];

    // Find packets that match this edge by checking if packet src/dst match any IPs
    const edgePackets = packets.filter(p => {
        const srcMatch = fromIPs.includes(p.src);
        const dstMatch = toIPs.includes(p.dst);
        const reverseSrcMatch = toIPs.includes(p.src);
        const reverseDstMatch = fromIPs.includes(p.dst);

        return (srcMatch && dstMatch) || (reverseSrcMatch && reverseDstMatch);
    });

    if (edgePackets.length > 0) {
        // Pick the most recent packet from this edge
        const packet = edgePackets[edgePackets.length - 1];

        // Update info
        const infoHTML = `
<strong>Riding:</strong> ${edge.from} → ${edge.to}
<strong>Protocol:</strong> ${edge.protocol.Name}
<strong>Packets:</strong> ${edge.packetCount}
<strong>Bytes:</strong> ${formatBytes(edge.byteCount)}

<strong>Current Packet #${packet.id}:</strong>
${packet.src}:${packet.srcPort || '?'} → ${packet.dst}:${packet.dstPort || '?'}
Length: ${packet.length} bytes
        `;

        document.querySelector('.chimpy-packet-info').innerHTML = infoHTML;

        // Generate mini hex dump (first 8 lines only)
        if (packet.payload) {
            const payloadBytes = base64ToBytes(packet.payload);
            const lines = [];
            const bytesPerLine = 16;
            const displayBytes = Math.min(payloadBytes.length, 128); // Show first 128 bytes

            for (let offset = 0; offset < displayBytes; offset += bytesPerLine) {
                const hexOffset = offset.toString(16).padStart(4, '0');
                const bytes = [];
                const ascii = [];

                for (let i = 0; i < bytesPerLine && offset + i < displayBytes; i++) {
                    const byte = payloadBytes[offset + i];
                    bytes.push(byte.toString(16).padStart(2, '0'));
                    ascii.push(byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.');
                }

                const hexBytes = bytes.join(' ').padEnd(47, ' ');
                const asciiStr = ascii.join('');

                lines.push(
                    `<span class="hex-offset">${hexOffset}</span>  ` +
                    `<span class="hex-bytes">${hexBytes}</span>  ` +
                    `<span class="hex-ascii">${asciiStr}</span>`
                );
            }

            if (displayBytes < payloadBytes.length) {
                lines.push(`... (${payloadBytes.length - displayBytes} more bytes)`);
            }

            chimpyHexDump.innerHTML = lines.join('\n');
        } else {
            chimpyHexDump.innerHTML = 'No payload data available';
        }
    } else {
        // No packets found for this edge in current packet buffer
        const totalPacketsInBuffer = packets.length;
        document.querySelector('.chimpy-packet-info').innerHTML = `
<strong>Riding:</strong> ${edge.from} → ${edge.to}
<strong>Protocol:</strong> ${edge.protocol.Name}
<strong>Total Packets:</strong> ${edge.packetCount}
<strong>Bytes:</strong> ${formatBytes(edge.byteCount)}

<strong>IPs:</strong>
From: ${fromIPs.join(', ')}
To: ${toIPs.join(', ')}

Searching ${totalPacketsInBuffer} packets...
No matching packets in buffer yet.
        `;
        chimpyHexDump.innerHTML = 'Packet payloads will appear here once captured';
    }
}

// ========== Replay Mode Functions ==========

// Setup replay mode functionality
function setupReplayMode() {
    const replayToggle = document.getElementById('replayToggle');
    const replaySubmenu = document.getElementById('replaySubmenu');
    const returnToLiveButton = document.getElementById('returnToLiveButton');
    const downloadPcapButton = document.getElementById('downloadPcapButton');
    const timelineSlider = document.getElementById('timelineSlider');

    // Load pcap file list
    loadPcapFileList();

    // Reload list every 30 seconds when not in replay mode
    setInterval(() => {
        if (!replayMode.active) {
            loadPcapFileList();
        }
    }, 30000);

    // Return to live mode
    returnToLiveButton.addEventListener('click', () => {
        exitReplayMode();
    });

    // Download current pcap
    downloadPcapButton.addEventListener('click', () => {
        downloadCurrentPcap();
    });

    // Timeline slider
    timelineSlider.addEventListener('input', (e) => {
        const offsetSeconds = (e.target.value / 100) * replayMode.durationSeconds;
        replayMode.currentOffset = offsetSeconds;
        updateTimelineDisplay();
        loadReplayDataAtOffset(offsetSeconds);
    });
}

// Load list of available pcap files
async function loadPcapFileList() {
    try {
        const response = await fetch('/api/pcaps');
        const pcapFiles = await response.json();

        const fileList = document.getElementById('replayFileList');

        if (pcapFiles.length === 0) {
            fileList.innerHTML = '<div class="no-files">No pcap files available</div>';
            return;
        }

        // Show only 3 most recent
        const recentFiles = pcapFiles.slice(0, 3);

        fileList.innerHTML = recentFiles.map(file => `
            <div class="replay-file-item" data-filename="${file.path}">
                <div class="replay-file-name">${file.filename}</div>
                <div class="replay-file-meta">
                    <span>${file.packetCount} packets</span>
                    <span>${formatDuration(file.durationSec)}</span>
                </div>
            </div>
        `).join('');

        // Add click handlers
        fileList.querySelectorAll('.replay-file-item').forEach(item => {
            item.addEventListener('click', () => {
                const filename = item.getAttribute('data-filename');
                console.log('Pcap file clicked:', filename);
                enterReplayMode(filename);
            });
        });

        console.log('Loaded', recentFiles.length, 'pcap files with click handlers');

    } catch (error) {
        console.error('Failed to load pcap files:', error);
        document.getElementById('replayFileList').innerHTML =
            '<div class="error">Failed to load files</div>';
    }
}

// Enter replay mode with selected pcap file
async function enterReplayMode(filename) {
    try {
        console.log('Entering replay mode with file:', filename);

        // Disconnect WebSocket
        if (ws) {
            ws.close();
            ws = null;
        }

        // Load pcap metadata
        const response = await fetch(`/api/pcaps`);
        const pcapFiles = await response.json();
        const fileInfo = pcapFiles.find(f => f.path === filename);

        if (!fileInfo) {
            console.error('File not found:', filename);
            return;
        }

        console.log('File info:', fileInfo);

        // Update replay state
        replayMode.active = true;
        replayMode.currentFile = filename;
        replayMode.startTime = new Date(fileInfo.startTime);
        replayMode.endTime = new Date(fileInfo.endTime);
        replayMode.durationSeconds = fileInfo.durationSec;
        replayMode.currentOffset = 0;

        console.log('Replay state updated:', replayMode);

        // Clear current graph
        nodes.clear();
        edges.clear();
        resetGraphCaches();
        packets = [];

        // Update UI
        const indicator = document.getElementById('replayModeIndicator');
        const returnButton = document.getElementById('returnToLiveButton');
        const timeline = document.getElementById('timelineContainer');
        const mainContent = document.querySelector('.main-content');

        console.log('UI elements:', { indicator, returnButton, timeline, mainContent });

        if (indicator) indicator.style.display = 'flex';
        if (returnButton) returnButton.style.display = 'block';
        if (timeline) {
            timeline.style.display = 'block';
            timeline.style.visibility = 'visible';
            timeline.style.opacity = '1';
            console.log('Timeline display set to block');
            console.log('Timeline computed style:', window.getComputedStyle(timeline).display, window.getComputedStyle(timeline).visibility, window.getComputedStyle(timeline).zIndex);
        }
        if (mainContent) mainContent.classList.add('timeline-visible');

        // Highlight selected file
        document.querySelectorAll('.replay-file-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector(`[data-filename="${filename}"]`).classList.add('active');

        // Update timeline
        const slider = document.getElementById('timelineSlider');
        slider.value = 0;
        updateTimelineDisplay();

        // Update connection status
        updateConnectionStatus('Replay Mode', false);

        // Load initial data (at time 0)
        await loadReplayDataAtOffset(0);

    } catch (error) {
        console.error('Failed to enter replay mode:', error);
        exitReplayMode();
    }
}

// Exit replay mode and return to live capture
function exitReplayMode() {
    // Reset replay state
    replayMode.active = false;
    replayMode.currentFile = null;

    // Clear graph
    nodes.clear();
    edges.clear();
    resetGraphCaches();
    packets = [];

    // Update UI
    document.getElementById('replayModeIndicator').style.display = 'none';
    document.getElementById('returnToLiveButton').style.display = 'none';
    document.getElementById('timelineContainer').style.display = 'none';
    document.querySelector('.main-content').classList.remove('timeline-visible');

    // Remove active state from files
    document.querySelectorAll('.replay-file-item').forEach(item => {
        item.classList.remove('active');
    });

    // Reconnect WebSocket
    connectWebSocket();

    // Reload pcap list
    loadPcapFileList();
}

// Load replay data at specific time offset
async function loadReplayDataAtOffset(offsetSeconds) {
    if (!replayMode.active || !replayMode.currentFile) {
        return;
    }

    try {
        const response = await fetch(
            `/api/replay?filename=${encodeURIComponent(replayMode.currentFile)}&offset=${offsetSeconds}`
        );

        if (!response.ok) {
            throw new Error('Failed to load replay data');
        }

        const data = await response.json();

        // Update graph with replay data
        updateGraph(data);

    } catch (error) {
        console.error('Failed to load replay data:', error);
    }
}

// Update timeline display
function updateTimelineDisplay() {
    const currentTime = document.getElementById('timelineCurrentTime');
    const totalTime = document.getElementById('timelineTotalTime');
    const startLabel = document.getElementById('timelineStartLabel');
    const endLabel = document.getElementById('timelineEndLabel');

    if (replayMode.active) {
        currentTime.textContent = formatTime(replayMode.currentOffset);
        totalTime.textContent = formatTime(replayMode.durationSeconds);

        if (replayMode.startTime && replayMode.endTime) {
            startLabel.textContent = replayMode.startTime.toLocaleTimeString();
            endLabel.textContent = replayMode.endTime.toLocaleTimeString();
        }
    }
}

// Download current pcap file
function downloadCurrentPcap() {
    window.location.href = '/api/download';
}

// Format seconds as MM:SS
function formatTime(seconds) {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

// Format duration for display
function formatDuration(seconds) {
    if (seconds < 60) {
        return `${Math.floor(seconds)}s`;
    } else if (seconds < 3600) {
        const mins = Math.floor(seconds / 60);
        return `${mins}m`;
    } else {
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${mins}m`;
    }
}

// ==================== Streams Functionality ====================

// Streams state
let currentStreamData = null;
let currentStreamTab = 'decoded';

// Generate stream ID from packet data (matches backend logic)
function generateStreamId(srcIP, srcPort, dstIP, dstPort, protocol) {
    // Determine stream type based on protocol
    let streamType = 'TCP';
    if (protocol === 'UDP' || protocol === 'DNS') {
        streamType = 'UDP';
    }

    // Normalize direction (lower IP:port first)
    let src = `${srcIP}:${srcPort}`;
    let dst = `${dstIP}:${dstPort}`;

    if (src > dst) {
        [src, dst] = [dst, src];
    }

    return `${streamType}-${src}-${dst}`;
}

// Check if a protocol is stream-capable (TCP or UDP based)
function isStreamProtocol(protocol) {
    const streamProtocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP', 'SMTP', 'MySQL', 'PostgreSQL', 'Telnet', 'Redis', 'Slurm'];
    return streamProtocols.includes(protocol);
}

// Setup streams functionality
function setupStreams() {
    const protocolFilter = document.getElementById('streamProtocolFilter');
    const refreshButton = document.getElementById('refreshStreamsButton');
    const detailClose = document.getElementById('streamDetailClose');

    // Restore saved protocol filter from localStorage
    if (protocolFilter) {
        const savedProtocol = localStorage.getItem('streamProtocolFilter') || '';
        protocolFilter.value = savedProtocol;
    }

    // Protocol filter change - save to localStorage
    if (protocolFilter) {
        protocolFilter.addEventListener('change', () => {
            localStorage.setItem('streamProtocolFilter', protocolFilter.value);
            loadStreams(protocolFilter.value);
        });
    }

    // Refresh button
    if (refreshButton) {
        refreshButton.addEventListener('click', () => {
            const filter = document.getElementById('streamProtocolFilter');
            loadStreams(filter?.value || '');
        });
    }

    // Stream detail close button
    if (detailClose) {
        detailClose.addEventListener('click', closeStreamDetail);
    }

    // Setup stream detail tabs
    document.querySelectorAll('.stream-tab[data-stream-tab]').forEach(tab => {
        tab.addEventListener('click', () => {
            const tabName = tab.dataset.streamTab;
            switchStreamTab(tabName);
        });
    });
}

// Load streams from API
async function loadStreams(protocol = '') {
    const streamsList = document.getElementById('streamsList');
    const streamCount = document.getElementById('streamCount');

    if (!streamsList) return;

    streamsList.innerHTML = '<div class="loading">Loading streams...</div>';

    try {
        let url = '/api/streams';
        if (protocol) {
            url += `?protocol=${encodeURIComponent(protocol)}`;
        }

        const response = await fetch(url);
        if (!response.ok) {
            throw new Error('Failed to load streams');
        }

        const streams = await response.json();

        if (streamCount) {
            streamCount.textContent = streams.length;
        }

        if (streams.length === 0) {
            streamsList.innerHTML = '<div class="streams-empty">No streams captured yet</div>';
            return;
        }

        streamsList.innerHTML = streams.map(stream => renderStreamItem(stream)).join('');

        // Add click handlers
        streamsList.querySelectorAll('.stream-item').forEach(item => {
            item.addEventListener('click', () => {
                const streamId = item.dataset.streamId;
                openStreamDetail(streamId);
            });
        });

    } catch (error) {
        console.error('Failed to load streams:', error);
        streamsList.innerHTML = '<div class="streams-empty">Failed to load streams</div>';
    }
}

// Render a stream item for the list
function renderStreamItem(stream) {
    const protocolClass = stream.protocol.toLowerCase().replace(/\s+/g, '');
    const timeAgo = formatTimeAgo(new Date(stream.lastSeen));

    return `
        <div class="stream-item" data-stream-id="${escapeHtml(stream.id)}">
            <div class="stream-item-header">
                <span class="stream-protocol ${protocolClass}">${escapeHtml(stream.protocol)}</span>
                <span class="stream-type">${escapeHtml(stream.type)}</span>
            </div>
            <div class="stream-endpoints">
                ${escapeHtml(stream.srcIp)}:${stream.srcPort} → ${escapeHtml(stream.dstIp)}:${stream.dstPort}
            </div>
            <div class="stream-summary">${escapeHtml(stream.summary || 'No summary')}</div>
            <div class="stream-meta">
                <span>${stream.packetCount} packets</span>
                <span>${formatBytes(stream.byteCount)}</span>
                <span>${timeAgo}</span>
            </div>
        </div>
    `;
}

// Open stream detail panel
async function openStreamDetail(streamId) {
    const panel = document.getElementById('streamDetailPanel');
    const backdrop = document.getElementById('modalBackdrop');

    if (!panel) return;

    try {
        const response = await fetch(`/api/stream?id=${encodeURIComponent(streamId)}`);
        if (!response.ok) {
            throw new Error('Failed to load stream details');
        }

        currentStreamData = await response.json();

        // Update panel header
        document.getElementById('streamDetailTitle').textContent =
            `${currentStreamData.srcIp}:${currentStreamData.srcPort} → ${currentStreamData.dstIp}:${currentStreamData.dstPort}`;

        const badge = document.getElementById('streamProtocolBadge');
        badge.textContent = currentStreamData.protocol;
        badge.className = 'stream-protocol-badge ' + currentStreamData.protocol.toLowerCase();

        // Update metadata
        const metaContainer = document.getElementById('streamDetailMeta');
        metaContainer.innerHTML = `
            <div class="stream-meta-item">
                <span class="stream-meta-label">Type</span>
                <span class="stream-meta-value">${escapeHtml(currentStreamData.type)}</span>
            </div>
            <div class="stream-meta-item">
                <span class="stream-meta-label">Packets</span>
                <span class="stream-meta-value">${currentStreamData.packetCount}</span>
            </div>
            <div class="stream-meta-item">
                <span class="stream-meta-label">Bytes</span>
                <span class="stream-meta-value">${formatBytes(currentStreamData.byteCount)}</span>
            </div>
            <div class="stream-meta-item">
                <span class="stream-meta-label">Started</span>
                <span class="stream-meta-value">${new Date(currentStreamData.startTime).toLocaleString()}</span>
            </div>
            <div class="stream-meta-item">
                <span class="stream-meta-label">Last Seen</span>
                <span class="stream-meta-value">${new Date(currentStreamData.lastSeen).toLocaleString()}</span>
            </div>
        `;

        // Reset to decoded tab
        currentStreamTab = 'decoded';
        document.querySelectorAll('.stream-tab[data-stream-tab]').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.streamTab === 'decoded');
        });

        // Render content
        renderStreamContent();

        // Show panel
        panel.style.display = 'flex';
        backdrop.style.display = 'block';

    } catch (error) {
        console.error('Failed to load stream details:', error);
    }
}

// Close stream detail panel
function closeStreamDetail() {
    const panel = document.getElementById('streamDetailPanel');
    const backdrop = document.getElementById('modalBackdrop');
    const detailsPanel = document.getElementById('detailsPanel');

    if (panel) {
        panel.style.display = 'none';
    }
    // Only hide backdrop if details panel is also closed
    if (backdrop && (!detailsPanel || !detailsPanel.classList.contains('open'))) {
        backdrop.style.display = 'none';
    }
    currentStreamData = null;
}

// Switch stream detail tab
function switchStreamTab(tabName) {
    currentStreamTab = tabName;

    document.querySelectorAll('.stream-tab[data-stream-tab]').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.streamTab === tabName);
    });

    renderStreamContent();
}

// Render stream content based on current tab
function renderStreamContent() {
    if (!currentStreamData) return;

    const content = document.getElementById('streamContentPre');
    if (!content) return;

    switch (currentStreamTab) {
        case 'decoded':
            content.textContent = currentStreamData.decodedContent || 'No decoded content available';
            break;

        case 'raw':
            // Show hex dump of request and response
            let rawContent = '';
            if (currentStreamData.requestPayload) {
                rawContent += '=== REQUEST DATA ===\n';
                rawContent += formatBase64AsHex(currentStreamData.requestPayload);
            }
            if (currentStreamData.responsePayload) {
                rawContent += '\n=== RESPONSE DATA ===\n';
                rawContent += formatBase64AsHex(currentStreamData.responsePayload);
            }
            content.textContent = rawContent || 'No raw data available';
            break;

        case 'packets':
            // Render packets list
            if (currentStreamData.packets && currentStreamData.packets.length > 0) {
                const packetsHtml = currentStreamData.packets.map((pkt, idx) => {
                    const direction = pkt.direction === 'request' ? 'Request' : 'Response';
                    const time = new Date(pkt.timestamp).toLocaleTimeString();
                    const dataPreview = pkt.payload ?
                        truncateBase64(pkt.payload, 100) : '(empty)';

                    return `[${idx + 1}] ${direction} - ${time} - ${pkt.length} bytes\n${dataPreview}\n`;
                }).join('\n');
                content.textContent = packetsHtml;
            } else {
                content.textContent = 'No packets recorded';
            }
            break;
    }
}

// Format base64 data as hex dump
function formatBase64AsHex(base64Data) {
    try {
        const binary = atob(base64Data);
        let result = '';
        const lineWidth = 16;

        for (let i = 0; i < binary.length && i < 4096; i += lineWidth) {
            // Offset
            result += i.toString(16).padStart(8, '0') + '  ';

            // Hex bytes
            let hexPart = '';
            let asciiPart = '';
            for (let j = 0; j < lineWidth; j++) {
                if (i + j < binary.length) {
                    const byte = binary.charCodeAt(i + j);
                    hexPart += byte.toString(16).padStart(2, '0') + ' ';
                    asciiPart += (byte >= 32 && byte < 127) ? binary[i + j] : '.';
                } else {
                    hexPart += '   ';
                }
                if (j === 7) hexPart += ' ';
            }

            result += hexPart + ' |' + asciiPart + '|\n';
        }

        if (binary.length > 4096) {
            result += `\n... (${binary.length - 4096} more bytes truncated)`;
        }

        return result;
    } catch (e) {
        return '(Unable to decode data)';
    }
}

// Truncate base64 and show as ASCII
function truncateBase64(base64Data, maxChars) {
    try {
        const binary = atob(base64Data);
        let result = '';
        for (let i = 0; i < binary.length && i < maxChars; i++) {
            const byte = binary.charCodeAt(i);
            result += (byte >= 32 && byte < 127) ? binary[i] : '.';
        }
        if (binary.length > maxChars) {
            result += '...';
        }
        return result;
    } catch (e) {
        return '(Unable to decode)';
    }
}

// Format time ago
function formatTimeAgo(date) {
    const now = new Date();
    const diffMs = now - date;
    const diffSec = Math.floor(diffMs / 1000);

    if (diffSec < 60) return `${diffSec}s ago`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    return `${Math.floor(diffSec / 86400)}d ago`;
}

// Format bytes
function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

// ==================== Game Mode Implementation ====================

// Game mode state
const gameMode = {
    active: false,
    scene: null,
    camera: null,
    renderer: null,
    raycaster: null,
    mouse: new THREE.Vector2(),
    nodeMeshes: [],
    nodeDataMap: new Map(), // mesh.uuid -> node data
    nodeIdToMesh: new Map(), // node.id -> mesh (for incremental updates)
    stars: null,
    nebulae: [],
    ambientDust: null,
    asteroids: [],
    animationId: null,
    moveForward: false,
    moveBackward: false,
    moveLeft: false,
    moveRight: false,
    moveUp: false,
    moveDown: false,
    velocity: new THREE.Vector3(),
    currentSpeed: 0,
    euler: new THREE.Euler(0, 0, 0, 'YXZ'),
    PI_2: Math.PI / 2,
    lockedTarget: null,
    laserCooldown: false,
    speedLinesActive: false,
    autoLockPosition: null,
    boosting: false,
    spaceElevators: [],
    elevatorParticles: [],
    warpDriveActive: false,
    warpSelectedIndex: 0,
    warpResults: [],
    isWarping: false,
    // Real-time traffic visualization
    trafficEvents: [],          // Queue of { src, dst, protocol, color, timestamp }
    trafficBursts: [],          // Active burst particles traveling along elevators
    planetPulses: new Map(),    // nodeId -> { intensity, startTime } for glow pulses
    lastElevatorEdgeHash: '',   // Track edge state to detect changes
    elevatorEdgeMap: new Map()  // edgeId -> elevator index for fast lookup
};

// Setup game mode
function setupGameMode() {
    const gameModeToggle = document.getElementById('gameModeToggle');

    if (gameModeToggle) {
        gameModeToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleGameMode();
        });
    }
}

// Toggle game mode on/off
function toggleGameMode() {
    const container = document.getElementById('gameModeContainer');
    const toggle = document.getElementById('gameModeToggle');

    if (gameMode.active) {
        // Deactivate game mode
        gameMode.active = false;
        container.style.display = 'none';
        toggle.classList.remove('game-active');

        // Stop animation loop
        if (gameMode.animationId) {
            cancelAnimationFrame(gameMode.animationId);
            gameMode.animationId = null;
        }

        // Cleanup space elevators first (before scene disposal)
        gameMode.spaceElevators.forEach(elevator => {
            if (elevator.line) {
                gameMode.scene.remove(elevator.line);
                if (elevator.line.geometry) elevator.line.geometry.dispose();
                if (elevator.line.material) elevator.line.material.dispose();
            }
            if (elevator.glow) {
                gameMode.scene.remove(elevator.glow);
                if (elevator.glow.geometry) elevator.glow.geometry.dispose();
                if (elevator.glow.material) elevator.glow.material.dispose();
            }
            if (elevator.particles) {
                gameMode.scene.remove(elevator.particles);
                if (elevator.particles.geometry) elevator.particles.geometry.dispose();
                if (elevator.particles.material) elevator.particles.material.dispose();
            }
        });
        gameMode.spaceElevators = [];

        // Cleanup node meshes
        gameMode.nodeMeshes.forEach(mesh => {
            if (mesh.children) {
                mesh.children.forEach(child => {
                    if (child.geometry) child.geometry.dispose();
                    if (child.material) child.material.dispose();
                });
            }
            if (mesh.geometry) mesh.geometry.dispose();
            if (mesh.material) mesh.material.dispose();
            gameMode.scene.remove(mesh);
        });
        gameMode.nodeMeshes = [];
        gameMode.nodeDataMap.clear();
        gameMode.nodeIdToMesh.clear();

        // Cleanup nebulae
        gameMode.nebulae.forEach(nebula => {
            if (nebula.geometry) nebula.geometry.dispose();
            if (nebula.material) nebula.material.dispose();
            gameMode.scene.remove(nebula);
        });
        gameMode.nebulae = [];

        // Cleanup stars
        if (gameMode.stars) {
            if (gameMode.stars.geometry) gameMode.stars.geometry.dispose();
            if (gameMode.stars.material) gameMode.stars.material.dispose();
            gameMode.scene.remove(gameMode.stars);
            gameMode.stars = null;
        }

        // Cleanup ambient dust
        if (gameMode.ambientDust) {
            if (gameMode.ambientDust.geometry) gameMode.ambientDust.geometry.dispose();
            if (gameMode.ambientDust.material) gameMode.ambientDust.material.dispose();
            gameMode.scene.remove(gameMode.ambientDust);
            gameMode.ambientDust = null;
        }

        // Cleanup sun flares
        if (gameMode.sunFlares) {
            if (gameMode.sunFlares.geometry) gameMode.sunFlares.geometry.dispose();
            if (gameMode.sunFlares.material) gameMode.sunFlares.material.dispose();
            gameMode.scene.remove(gameMode.sunFlares);
            gameMode.sunFlares = null;
        }

        // Cleanup shooting star
        if (gameMode.shootingStar) {
            if (gameMode.shootingStar.mesh) {
                if (gameMode.shootingStar.mesh.geometry) gameMode.shootingStar.mesh.geometry.dispose();
                if (gameMode.shootingStar.mesh.material) gameMode.shootingStar.mesh.material.dispose();
                gameMode.scene.remove(gameMode.shootingStar.mesh);
            }
            gameMode.shootingStar = null;
        }

        // Clear all remaining scene children
        while (gameMode.scene && gameMode.scene.children.length > 0) {
            const child = gameMode.scene.children[0];
            if (child.geometry) child.geometry.dispose();
            if (child.material) {
                if (Array.isArray(child.material)) {
                    child.material.forEach(m => m.dispose());
                } else {
                    child.material.dispose();
                }
            }
            gameMode.scene.remove(child);
        }

        // Cleanup Three.js renderer
        if (gameMode.renderer) {
            gameMode.renderer.dispose();
            gameMode.renderer = null;
        }

        // Clear scene and camera references
        gameMode.scene = null;
        gameMode.camera = null;
        gameMode.raycaster = null;
        gameMode.starTwinkleData = null;
        gameMode.asteroids = [];
        if (gameMode.asteroidMesh) {
            gameMode.scene.remove(gameMode.asteroidMesh);
            gameMode.asteroidMesh.geometry.dispose();
            gameMode.asteroidMesh.material.dispose();
            gameMode.asteroidMesh = null;
            gameMode.asteroidOrbits = null;
        }
        gameMode.elevatorParticles = [];
        gameMode.warpResults = [];
        gameMode.warpSelectedIndex = 0;

        // Cleanup burst pool
        if (gameMode.burstPool) {
            gameMode.scene.remove(gameMode.burstPool.mesh);
            gameMode.burstPool.mesh.geometry.dispose();
            gameMode.burstPool.mesh.material.dispose();
            gameMode.burstPool = null;
        }
        gameMode.trafficBursts = [];
        gameMode.trafficEvents = [];
        gameMode.planetPulses.clear();
        gameMode.elevatorEdgeMap.clear();
        gameMode.lastElevatorEdgeHash = '';

        // Reset movement state
        gameMode.moveForward = false;
        gameMode.moveBackward = false;
        gameMode.moveLeft = false;
        gameMode.moveRight = false;
        gameMode.moveUp = false;
        gameMode.moveDown = false;
        gameMode.boosting = false;
        gameMode.currentSpeed = 0;
        gameMode.velocity = new THREE.Vector3();
        gameMode.euler = new THREE.Euler(0, 0, 0, 'YXZ');
        gameMode.lockedTarget = null;
        gameMode.laserCooldown = false;
        gameMode.autoLockPosition = null;

        // Close warp drive if open
        if (gameMode.warpDriveActive) {
            closeWarpDrive();
        }
        gameMode.isWarping = false;

        // Hide HUD elements
        const cockpitHud = document.getElementById('cockpitHud');
        const targetingReticle = document.getElementById('targetingReticle');
        const crosshairEl = document.getElementById('crosshair');
        if (cockpitHud) cockpitHud.style.display = 'none';
        if (targetingReticle) targetingReticle.style.display = 'none';
        if (crosshairEl) crosshairEl.style.display = 'none';

        // Remove resize listener
        window.removeEventListener('resize', handleGameResize);

        // Unlock pointer
        document.exitPointerLock();

        // Remove event listeners
        document.removeEventListener('keydown', handleGameKeyDown);
        document.removeEventListener('keyup', handleGameKeyUp);
        document.removeEventListener('mousemove', handleGameMouseMove);
        document.removeEventListener('click', handleGameClick);

    } else {
        // Activate game mode
        gameMode.active = true;
        container.style.display = 'block';
        toggle.classList.add('game-active');

        // Cancel any lingering animation frame from previous session
        if (gameMode.animationId) {
            cancelAnimationFrame(gameMode.animationId);
            gameMode.animationId = null;
        }

        // Reset movement and camera state for fresh start
        gameMode.euler = new THREE.Euler(0, 0, 0, 'YXZ');
        gameMode.velocity = new THREE.Vector3();
        gameMode.currentSpeed = 0;
        gameMode.moveForward = false;
        gameMode.moveBackward = false;
        gameMode.moveLeft = false;
        gameMode.moveRight = false;
        gameMode.moveUp = false;
        gameMode.moveDown = false;
        gameMode.boosting = false;
        gameMode.lockedTarget = null;

        // Initialize Three.js scene
        initGameScene();

        // Add event listeners
        document.addEventListener('keydown', handleGameKeyDown);
        document.addEventListener('keyup', handleGameKeyUp);
        document.addEventListener('mousemove', handleGameMouseMove);
        document.addEventListener('click', handleGameClick);

        // Request pointer lock
        const canvas = document.getElementById('gameCanvas');
        canvas.requestPointerLock();

        // Start animation loop
        animateGameScene();
    }
}

function createCyberpunkCockpit() {
    // Minimal 3D cockpit - most HUD elements are CSS overlays
    const cockpit = new THREE.Group();

    const glowMaterial = new THREE.MeshBasicMaterial({
        color: 0x00ffcc,
        transparent: true,
        opacity: 0.6
    });

    // Just subtle 3D frame hints at the very edges
    const frameGeom = new THREE.BoxGeometry(0.05, 8, 0.05);

    // Far corner accents only
    const leftFrame = new THREE.Mesh(frameGeom, glowMaterial);
    leftFrame.position.set(-12, 0, -15);
    cockpit.add(leftFrame);

    const rightFrame = new THREE.Mesh(frameGeom, glowMaterial);
    rightFrame.position.set(12, 0, -15);
    cockpit.add(rightFrame);

    return cockpit;
}

// Initialize the Three.js scene
function initGameScene() {
    const oldCanvas = document.getElementById('gameCanvas');
    const width = window.innerWidth;
    const height = window.innerHeight;

    // Replace canvas to ensure clean WebGL context
    const newCanvas = document.createElement('canvas');
    newCanvas.id = 'gameCanvas';
    newCanvas.width = width;
    newCanvas.height = height;
    oldCanvas.parentNode.replaceChild(newCanvas, oldCanvas);
    const canvas = newCanvas;

    // Create scene
    gameMode.scene = new THREE.Scene();
    gameMode.scene.background = new THREE.Color(0x000208);
    gameMode.scene.fog = new THREE.FogExp2(0x000510, 0.000005); // Slightly more fog to hide reduced particle density

    // Create camera
    gameMode.camera = new THREE.PerspectiveCamera(75, width / height, 10, 600000);
    gameMode.camera.position.set(0, 5000, 35000);
    const cockpit = createCyberpunkCockpit();
    gameMode.camera.add(cockpit);
    gameMode.scene.add(gameMode.camera);

    // Create renderer with fresh canvas
    gameMode.renderer = new THREE.WebGLRenderer({
        canvas: canvas,
        antialias: true,
        alpha: false,
        powerPreference: 'high-performance'
    });
    gameMode.renderer.setSize(width, height);
    gameMode.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    document.getElementById('cockpitHud').style.display = 'block';
    document.getElementById('targetingReticle').style.display = 'block';
    document.getElementById('crosshair').style.display = 'block';
    document.querySelector('.cockpit-frame').style.display = 'none';
    document.getElementById('cockpitStats').style.display = 'none';


    // Create raycaster for targeting
    gameMode.raycaster = new THREE.Raycaster();
    gameMode.raycaster.far = 20000;

    // Create space atmosphere layers (back to front)
    createGalacticPlane();      // Milky Way band
    createNebulae();            // Colorful nebulae
    createCosmicDust();         // Dark dust lanes
    createStarfield();          // Multi-layer stars
    createDistantGalaxies();    // Spiral galaxies

    // Create sun (central light source)
    createSun();

    // Create asteroid belt
    createAsteroidBelt();

    // Create ambient dust near camera
    createAmbientDust();

    // Add ambient light
    const ambientLight = new THREE.AmbientLight(0x334466, 0.6);
    gameMode.scene.add(ambientLight);

    // Add directional light for better planet shading
    const dirLight = new THREE.DirectionalLight(0xffffff, 0.5);
    dirLight.position.set(100, 100, 100);
    gameMode.scene.add(dirLight);

    // Create nodes as planets
    createNodeSpheres();

    // Create space elevators between connected planets
    createSpaceElevators();

    // Initialize traffic burst particle pool
    initBurstPool();

    // Initialize speed lines
    initSpeedLines();

    // Update HUD stats
    updateGameHUD();

    // Handle window resize
    window.addEventListener('resize', handleGameResize);
}

// Create nebulae for space atmosphere - vast and immersive
function createNebulae() {
    const nebulaColors = [
        { r: 0.6, g: 0.1, b: 0.8 },  // Deep Purple
        { r: 0.1, g: 0.5, b: 0.8 },  // Cosmic Blue
        { r: 0.8, g: 0.2, b: 0.5 },  // Magenta/Pink
        { r: 0.1, g: 0.7, b: 0.6 },  // Teal/Cyan
        { r: 0.7, g: 0.5, b: 0.1 },  // Gold/Orange
        { r: 0.4, g: 0.1, b: 0.6 },  // Violet
        { r: 0.1, g: 0.3, b: 0.5 },  // Deep Blue
        { r: 0.6, g: 0.1, b: 0.4 },  // Crimson
        { r: 0.2, g: 0.8, b: 0.3 },  // Emerald
        { r: 0.9, g: 0.4, b: 0.1 },  // Flame Orange
    ];

    // Create massive nebula clouds spanning the scene
    for (let n = 0; n < 5; n++) {
        const particleCount = 800;
        const positions = new Float32Array(particleCount * 3);
        const colors = new Float32Array(particleCount * 3);

        // Spread nebulae across vast distances
        const nebulaX = (Math.random() - 0.5) * 180000;
        const nebulaY = (Math.random() - 0.5) * 80000;
        const nebulaZ = (Math.random() - 0.5) * 180000;
        const nebulaSize = 15000 + Math.random() * 30000;

        const baseColor = nebulaColors[Math.floor(Math.random() * nebulaColors.length)];
        const secondaryColor = nebulaColors[Math.floor(Math.random() * nebulaColors.length)];
        const tertiaryColor = nebulaColors[Math.floor(Math.random() * nebulaColors.length)];

        for (let i = 0; i < particleCount; i++) {
            // Gaussian-like distribution with wispy tendrils
            const r = nebulaSize * Math.pow(Math.random(), 0.35);
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);

            // Multiple tendril layers for organic look
            const tendril1 = Math.sin(theta * 4 + phi * 2) * 0.4 + 1;
            const tendril2 = Math.cos(theta * 2 - phi * 3) * 0.3 + 1;
            const tendrilFactor = (tendril1 + tendril2) / 2;

            positions[i * 3] = nebulaX + r * Math.sin(phi) * Math.cos(theta) * tendrilFactor;
            positions[i * 3 + 1] = nebulaY + r * Math.sin(phi) * Math.sin(theta) * 0.5;
            positions[i * 3 + 2] = nebulaZ + r * Math.cos(phi) * tendrilFactor;

            // Rich color gradients blending three colors
            const distFromCenter = r / nebulaSize;
            const colorBlend = Math.random();
            const colorVar = 0.3;

            let finalColor;
            if (colorBlend < 0.4) {
                finalColor = baseColor;
            } else if (colorBlend < 0.7) {
                finalColor = secondaryColor;
            } else {
                finalColor = tertiaryColor;
            }

            const brightness = 1 - distFromCenter * 0.4;
            colors[i * 3] = finalColor.r * brightness + (Math.random() - 0.5) * colorVar;
            colors[i * 3 + 1] = finalColor.g * brightness + (Math.random() - 0.5) * colorVar;
            colors[i * 3 + 2] = finalColor.b * brightness + (Math.random() - 0.5) * colorVar;
        }

        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

        const nebulaOpacity = 0.02 + Math.random() * 0.03; // Reduced for less mist
        const material = new THREE.PointsMaterial({
            size: 40 + Math.random() * 60,
            vertexColors: true,
            transparent: true,
            opacity: nebulaOpacity,
            sizeAttenuation: true,
            blending: THREE.AdditiveBlending
        });

        const nebula = new THREE.Points(geometry, material);
        nebula.userData.baseOpacity = nebulaOpacity;
        gameMode.scene.add(nebula);
        gameMode.nebulae.push(nebula);
    }

    // Add bright emission nebulae (star-forming regions)
    for (let n = 0; n < 3; n++) {
        const particleCount = 500;
        const positions = new Float32Array(particleCount * 3);
        const colors = new Float32Array(particleCount * 3);

        const nebulaX = (Math.random() - 0.5) * 150000;
        const nebulaY = (Math.random() - 0.5) * 60000;
        const nebulaZ = (Math.random() - 0.5) * 150000;
        const coreSize = 8000 + Math.random() * 15000;

        // Emission nebula colors (ionized gas)
        const emissionColors = [
            { r: 1.0, g: 0.3, b: 0.4 },  // H-alpha red
            { r: 0.3, g: 0.9, b: 1.0 },  // OIII cyan
            { r: 0.5, g: 0.7, b: 1.0 },  // Blue reflection
            { r: 1.0, g: 0.6, b: 0.8 },  // Pink hydrogen
            { r: 0.4, g: 1.0, b: 0.5 },  // Green oxygen
        ];
        const baseColor = emissionColors[Math.floor(Math.random() * emissionColors.length)];

        for (let i = 0; i < particleCount; i++) {
            const r = coreSize * Math.pow(Math.random(), 0.6);
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);

            // Add pillar-like structures
            const pillarEffect = Math.pow(Math.abs(Math.sin(theta * 3)), 2) * 0.5 + 0.5;

            positions[i * 3] = nebulaX + r * Math.sin(phi) * Math.cos(theta);
            positions[i * 3 + 1] = nebulaY + r * Math.sin(phi) * Math.sin(theta) * pillarEffect;
            positions[i * 3 + 2] = nebulaZ + r * Math.cos(phi);

            const brightness = 1 - (r / coreSize) * 0.4;
            colors[i * 3] = baseColor.r * brightness;
            colors[i * 3 + 1] = baseColor.g * brightness;
            colors[i * 3 + 2] = baseColor.b * brightness;
        }

        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

        const material = new THREE.PointsMaterial({
            size: 25,
            vertexColors: true,
            transparent: true,
            opacity: 0.06,
            sizeAttenuation: true,
            blending: THREE.AdditiveBlending
        });

        const emissionNebula = new THREE.Points(geometry, material);
        emissionNebula.userData.baseOpacity = 0.06;
        gameMode.scene.add(emissionNebula);
        gameMode.nebulae.push(emissionNebula);
    }

    // Add dark nebulae (dust clouds that obscure background)
    for (let n = 0; n < 2; n++) {
        const particleCount = 400;
        const positions = new Float32Array(particleCount * 3);
        const colors = new Float32Array(particleCount * 3);

        const nebulaX = (Math.random() - 0.5) * 120000;
        const nebulaY = (Math.random() - 0.5) * 50000;
        const nebulaZ = (Math.random() - 0.5) * 120000;
        const cloudSize = 10000 + Math.random() * 20000;

        for (let i = 0; i < particleCount; i++) {
            const r = cloudSize * Math.pow(Math.random(), 0.5);
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);

            positions[i * 3] = nebulaX + r * Math.sin(phi) * Math.cos(theta);
            positions[i * 3 + 1] = nebulaY + r * Math.sin(phi) * Math.sin(theta) * 0.4;
            positions[i * 3 + 2] = nebulaZ + r * Math.cos(phi);

            // Dark brownish-red colors
            const darkness = 0.15 + Math.random() * 0.1;
            colors[i * 3] = darkness * 1.2;
            colors[i * 3 + 1] = darkness * 0.8;
            colors[i * 3 + 2] = darkness * 0.6;
        }

        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

        const material = new THREE.PointsMaterial({
            size: 80,
            vertexColors: true,
            transparent: true,
            opacity: 0.08,
            sizeAttenuation: true,
            blending: THREE.NormalBlending
        });

        const darkNebula = new THREE.Points(geometry, material);
        darkNebula.userData.baseOpacity = 0.08;
        gameMode.scene.add(darkNebula);
        gameMode.nebulae.push(darkNebula);
    }
}

// Create distant galaxies
function createDistantGalaxies() {
    for (let g = 0; g < 3; g++) {
        const galaxyParticles = 300;
        const positions = new Float32Array(galaxyParticles * 3);
        const colors = new Float32Array(galaxyParticles * 3);

        const galaxyX = (Math.random() - 0.5) * 80000;
        const galaxyY = (Math.random() - 0.5) * 40000;
        const galaxyZ = -30000 - Math.random() * 30000;

        for (let i = 0; i < galaxyParticles; i++) {
            // Spiral galaxy shape
            const arm = Math.floor(Math.random() * 2);
            const distance = Math.random() * 2000;
            const angle = (distance / 300) + arm * Math.PI + (Math.random() - 0.5) * 0.5;

            positions[i * 3] = galaxyX + Math.cos(angle) * distance;
            positions[i * 3 + 1] = galaxyY + (Math.random() - 0.5) * 150;
            positions[i * 3 + 2] = galaxyZ + Math.sin(angle) * distance;

            // Galaxy colors (warm center, blue edges)
            const t = distance / 300;
            colors[i * 3] = 1 - t * 0.3;
            colors[i * 3 + 1] = 0.8 - t * 0.2;
            colors[i * 3 + 2] = 0.6 + t * 0.4;
        }

        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

        const material = new THREE.PointsMaterial({
            size: 3,
            vertexColors: true,
            transparent: true,
            opacity: 0.6,
            sizeAttenuation: true,
            blending: THREE.AdditiveBlending
        });

        const galaxy = new THREE.Points(geometry, material);
        gameMode.scene.add(galaxy);
    }
}

// Create realistic starfield background with multiple layers
function createStarfield() {
    // Layer 0: Ultra-distant faint stars (creates depth)
    const ultraDistantCount = 8000;
    const ultraDistantPositions = new Float32Array(ultraDistantCount * 3);
    const ultraDistantColors = new Float32Array(ultraDistantCount * 3);

    for (let i = 0; i < ultraDistantCount; i++) {
        const radius = 90000 + Math.random() * 50000;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);

        ultraDistantPositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
        ultraDistantPositions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
        ultraDistantPositions[i * 3 + 2] = radius * Math.cos(phi);

        const brightness = 0.2 + Math.random() * 0.3;
        ultraDistantColors[i * 3] = brightness;
        ultraDistantColors[i * 3 + 1] = brightness;
        ultraDistantColors[i * 3 + 2] = brightness * 1.1;
    }

    const ultraDistantGeometry = new THREE.BufferGeometry();
    ultraDistantGeometry.setAttribute('position', new THREE.BufferAttribute(ultraDistantPositions, 3));
    ultraDistantGeometry.setAttribute('color', new THREE.BufferAttribute(ultraDistantColors, 3));

    const ultraDistantMaterial = new THREE.PointsMaterial({
        size: 1.5,
        vertexColors: true,
        transparent: true,
        opacity: 0.5,
        sizeAttenuation: true
    });

    const ultraDistantStars = new THREE.Points(ultraDistantGeometry, ultraDistantMaterial);
    gameMode.scene.add(ultraDistantStars);

    // Layer 1: Distant dim stars (most numerous)
    const distantStarCount = 6000;
    const distantPositions = new Float32Array(distantStarCount * 3);
    const distantColors = new Float32Array(distantStarCount * 3);

    for (let i = 0; i < distantStarCount; i++) {
        const radius = 50000 + Math.random() * 70000;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);

        distantPositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
        distantPositions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
        distantPositions[i * 3 + 2] = radius * Math.cos(phi);

        // Realistic stellar classification colors
        const colorChoice = Math.random();
        const brightness = 0.5 + Math.random() * 0.5;
        if (colorChoice < 0.03) {
            // O-type: Blue (rare, very hot)
            distantColors[i * 3] = 0.6 * brightness;
            distantColors[i * 3 + 1] = 0.7 * brightness;
            distantColors[i * 3 + 2] = 1.0 * brightness;
        } else if (colorChoice < 0.13) {
            // B-type: Blue-white
            distantColors[i * 3] = 0.75 * brightness;
            distantColors[i * 3 + 1] = 0.85 * brightness;
            distantColors[i * 3 + 2] = 1.0 * brightness;
        } else if (colorChoice < 0.20) {
            // A-type: White
            distantColors[i * 3] = 0.95 * brightness;
            distantColors[i * 3 + 1] = 0.95 * brightness;
            distantColors[i * 3 + 2] = 1.0 * brightness;
        } else if (colorChoice < 0.27) {
            // F-type: Yellow-white
            distantColors[i * 3] = 1.0 * brightness;
            distantColors[i * 3 + 1] = 0.95 * brightness;
            distantColors[i * 3 + 2] = 0.85 * brightness;
        } else if (colorChoice < 0.40) {
            // G-type: Yellow (sun-like)
            distantColors[i * 3] = 1.0 * brightness;
            distantColors[i * 3 + 1] = 0.92 * brightness;
            distantColors[i * 3 + 2] = 0.7 * brightness;
        } else if (colorChoice < 0.60) {
            // K-type: Orange
            distantColors[i * 3] = 1.0 * brightness;
            distantColors[i * 3 + 1] = 0.75 * brightness;
            distantColors[i * 3 + 2] = 0.5 * brightness;
        } else {
            // M-type: Red (most common)
            distantColors[i * 3] = 1.0 * brightness;
            distantColors[i * 3 + 1] = 0.6 * brightness;
            distantColors[i * 3 + 2] = 0.45 * brightness;
        }
    }

    const distantGeometry = new THREE.BufferGeometry();
    distantGeometry.setAttribute('position', new THREE.BufferAttribute(distantPositions, 3));
    distantGeometry.setAttribute('color', new THREE.BufferAttribute(distantColors, 3));

    const distantMaterial = new THREE.PointsMaterial({
        size: 3,
        vertexColors: true,
        transparent: true,
        opacity: 0.8,
        sizeAttenuation: true
    });

    const distantStars = new THREE.Points(distantGeometry, distantMaterial);
    gameMode.scene.add(distantStars);

    // Layer 2: Mid-range stars
    const midStarCount = 3000;
    const midPositions = new Float32Array(midStarCount * 3);
    const midColors = new Float32Array(midStarCount * 3);

    for (let i = 0; i < midStarCount; i++) {
        const radius = 25000 + Math.random() * 35000;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);

        midPositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
        midPositions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
        midPositions[i * 3 + 2] = radius * Math.cos(phi);

        // Slightly brighter colors
        const colorChoice = Math.random();
        if (colorChoice < 0.5) {
            midColors[i * 3] = 1; midColors[i * 3 + 1] = 1; midColors[i * 3 + 2] = 1;
        } else if (colorChoice < 0.7) {
            midColors[i * 3] = 1; midColors[i * 3 + 1] = 0.95; midColors[i * 3 + 2] = 0.8;
        } else if (colorChoice < 0.85) {
            midColors[i * 3] = 0.8; midColors[i * 3 + 1] = 0.9; midColors[i * 3 + 2] = 1;
        } else {
            midColors[i * 3] = 1; midColors[i * 3 + 1] = 0.7; midColors[i * 3 + 2] = 0.5;
        }
    }

    const midGeometry = new THREE.BufferGeometry();
    midGeometry.setAttribute('position', new THREE.BufferAttribute(midPositions, 3));
    midGeometry.setAttribute('color', new THREE.BufferAttribute(midColors, 3));

    const midMaterial = new THREE.PointsMaterial({
        size: 5,
        vertexColors: true,
        transparent: true,
        opacity: 0.9,
        sizeAttenuation: true
    });

    gameMode.stars = new THREE.Points(midGeometry, midMaterial);
    gameMode.scene.add(gameMode.stars);

    // Layer 3: Bright foreground stars
    const brightStarCount = 600;
    const brightPositions = new Float32Array(brightStarCount * 3);
    const brightColors = new Float32Array(brightStarCount * 3);

    for (let i = 0; i < brightStarCount; i++) {
        const radius = 12000 + Math.random() * 20000;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);

        brightPositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
        brightPositions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
        brightPositions[i * 3 + 2] = radius * Math.cos(phi);

        // Bright star colors
        const colorChoice = Math.random();
        if (colorChoice < 0.4) {
            brightColors[i * 3] = 1; brightColors[i * 3 + 1] = 1; brightColors[i * 3 + 2] = 1;
        } else if (colorChoice < 0.6) {
            brightColors[i * 3] = 0.85; brightColors[i * 3 + 1] = 0.92; brightColors[i * 3 + 2] = 1;
        } else if (colorChoice < 0.8) {
            brightColors[i * 3] = 1; brightColors[i * 3 + 1] = 0.98; brightColors[i * 3 + 2] = 0.85;
        } else {
            brightColors[i * 3] = 1; brightColors[i * 3 + 1] = 0.8; brightColors[i * 3 + 2] = 0.6;
        }
    }

    const brightGeometry = new THREE.BufferGeometry();
    brightGeometry.setAttribute('position', new THREE.BufferAttribute(brightPositions, 3));
    brightGeometry.setAttribute('color', new THREE.BufferAttribute(brightColors, 3));

    const brightMaterial = new THREE.PointsMaterial({
        size: 10,
        vertexColors: true,
        transparent: true,
        opacity: 1,
        sizeAttenuation: true,
        blending: THREE.AdditiveBlending
    });

    const brightStars = new THREE.Points(brightGeometry, brightMaterial);
    gameMode.scene.add(brightStars);
    gameMode.brightStars = brightStars;

    // Layer 4: Very bright "named" stars (like Sirius, Vega) with glow
    const superBrightCount = 80;
    const superBrightPositions = new Float32Array(superBrightCount * 3);
    const superBrightColors = new Float32Array(superBrightCount * 3);

    for (let i = 0; i < superBrightCount; i++) {
        const radius = 15000 + Math.random() * 35000;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);

        superBrightPositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
        superBrightPositions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
        superBrightPositions[i * 3 + 2] = radius * Math.cos(phi);

        // Give super bright stars slight color variation
        const colorVar = Math.random();
        if (colorVar < 0.4) {
            superBrightColors[i * 3] = 1;
            superBrightColors[i * 3 + 1] = 1;
            superBrightColors[i * 3 + 2] = 1;
        } else if (colorVar < 0.6) {
            superBrightColors[i * 3] = 0.9;
            superBrightColors[i * 3 + 1] = 0.95;
            superBrightColors[i * 3 + 2] = 1;
        } else if (colorVar < 0.8) {
            superBrightColors[i * 3] = 1;
            superBrightColors[i * 3 + 1] = 0.95;
            superBrightColors[i * 3 + 2] = 0.85;
        } else {
            superBrightColors[i * 3] = 1;
            superBrightColors[i * 3 + 1] = 0.85;
            superBrightColors[i * 3 + 2] = 0.7;
        }
    }

    const superBrightGeometry = new THREE.BufferGeometry();
    superBrightGeometry.setAttribute('position', new THREE.BufferAttribute(superBrightPositions, 3));
    superBrightGeometry.setAttribute('color', new THREE.BufferAttribute(superBrightColors, 3));

    const superBrightMaterial = new THREE.PointsMaterial({
        size: 20,
        vertexColors: true,
        transparent: true,
        opacity: 1,
        sizeAttenuation: true,
        blending: THREE.AdditiveBlending
    });

    const superBrightStars = new THREE.Points(superBrightGeometry, superBrightMaterial);
    gameMode.scene.add(superBrightStars);
    gameMode.superBrightStars = superBrightStars;

    // Store original sizes for twinkling animation
    gameMode.starTwinkleData = {
        brightStars: {
            material: brightMaterial,
            baseSize: 10,
            positions: brightPositions,
            phases: new Float32Array(brightStarCount).map(() => Math.random() * Math.PI * 2)
        },
        superBright: {
            material: superBrightMaterial,
            baseSize: 20,
            positions: superBrightPositions,
            phases: new Float32Array(superBrightCount).map(() => Math.random() * Math.PI * 2)
        }
    };
}

// Create the galactic plane (Milky Way band)
function createGalacticPlane() {
    const particleCount = 5000;
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount; i++) {
        // Create a band across the sky
        const distance = 40000 + Math.random() * 60000;
        const angle = Math.random() * Math.PI * 2;

        // Flatten into a disk/band shape
        const bandWidth = 8000 + Math.random() * 12000;
        const heightVariation = (Math.random() - 0.5) * bandWidth * 0.3;

        positions[i * 3] = Math.cos(angle) * distance;
        positions[i * 3 + 1] = heightVariation;
        positions[i * 3 + 2] = Math.sin(angle) * distance;

        // Milky way colors - mostly dim white/cream with some variation
        const brightness = 0.3 + Math.random() * 0.5;
        const colorVar = Math.random();
        if (colorVar < 0.7) {
            // Cream/white
            colors[i * 3] = brightness;
            colors[i * 3 + 1] = brightness * 0.95;
            colors[i * 3 + 2] = brightness * 0.85;
        } else if (colorVar < 0.85) {
            // Slight blue tint (young stars)
            colors[i * 3] = brightness * 0.85;
            colors[i * 3 + 1] = brightness * 0.9;
            colors[i * 3 + 2] = brightness;
        } else {
            // Slight red/orange (old stars)
            colors[i * 3] = brightness;
            colors[i * 3 + 1] = brightness * 0.7;
            colors[i * 3 + 2] = brightness * 0.5;
        }
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const material = new THREE.PointsMaterial({
        size: 8,
        vertexColors: true,
        transparent: true,
        opacity: 0.25,
        sizeAttenuation: true,
        blending: THREE.AdditiveBlending
    });

    const galacticPlane = new THREE.Points(geometry, material);
    galacticPlane.rotation.x = Math.PI * 0.15; // Tilt the band
    galacticPlane.rotation.z = Math.PI * 0.1;
    gameMode.scene.add(galacticPlane);

    // Add denser core region
    const coreCount = 2000;
    const corePositions = new Float32Array(coreCount * 3);
    const coreColors = new Float32Array(coreCount * 3);

    for (let i = 0; i < coreCount; i++) {
        const distance = 50000 + Math.random() * 30000;
        const angle = (Math.random() - 0.5) * 0.8; // Concentrated in one direction
        const spread = (Math.random() - 0.5) * 15000;

        corePositions[i * 3] = Math.cos(angle) * distance + spread * 0.3;
        corePositions[i * 3 + 1] = (Math.random() - 0.5) * 5000;
        corePositions[i * 3 + 2] = Math.sin(angle) * distance + spread;

        const brightness = 0.4 + Math.random() * 0.4;
        coreColors[i * 3] = brightness;
        coreColors[i * 3 + 1] = brightness * 0.9;
        coreColors[i * 3 + 2] = brightness * 0.75;
    }

    const coreGeometry = new THREE.BufferGeometry();
    coreGeometry.setAttribute('position', new THREE.BufferAttribute(corePositions, 3));
    coreGeometry.setAttribute('color', new THREE.BufferAttribute(coreColors, 3));

    const coreMaterial = new THREE.PointsMaterial({
        size: 10,
        vertexColors: true,
        transparent: true,
        opacity: 0.35,
        sizeAttenuation: true,
        blending: THREE.AdditiveBlending
    });

    const galacticCore = new THREE.Points(coreGeometry, coreMaterial);
    galacticCore.rotation.x = Math.PI * 0.15;
    galacticCore.rotation.z = Math.PI * 0.1;
    gameMode.scene.add(galacticCore);
}

// Create cosmic dust clouds and floating debris
function createCosmicDust() {
    // Vast dust lanes spanning the scene
    for (let d = 0; d < 3; d++) {
        const dustCount = 600;
        const positions = new Float32Array(dustCount * 3);
        const colors = new Float32Array(dustCount * 3);

        const centerX = (Math.random() - 0.5) * 160000;
        const centerY = (Math.random() - 0.5) * 40000;
        const centerZ = (Math.random() - 0.5) * 160000;
        const cloudSize = 15000 + Math.random() * 25000;

        for (let i = 0; i < dustCount; i++) {
            const r = cloudSize * Math.pow(Math.random(), 0.6);
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);

            // Create streaky, filament-like structures
            const streakFactor = Math.sin(theta * 5) * 0.5 + 1;

            positions[i * 3] = centerX + r * Math.sin(phi) * Math.cos(theta) * streakFactor;
            positions[i * 3 + 1] = centerY + r * Math.sin(phi) * Math.sin(theta) * 0.25;
            positions[i * 3 + 2] = centerZ + r * Math.cos(phi) * streakFactor;

            // Varied dust colors - some darker, some with slight tint
            const dustType = Math.random();
            if (dustType < 0.6) {
                // Dark brown dust
                const darkness = 0.08 + Math.random() * 0.12;
                colors[i * 3] = darkness * 1.1;
                colors[i * 3 + 1] = darkness * 0.9;
                colors[i * 3 + 2] = darkness * 0.7;
            } else if (dustType < 0.8) {
                // Reddish dust
                const darkness = 0.1 + Math.random() * 0.1;
                colors[i * 3] = darkness * 1.5;
                colors[i * 3 + 1] = darkness * 0.6;
                colors[i * 3 + 2] = darkness * 0.4;
            } else {
                // Slight blue reflection dust
                const darkness = 0.05 + Math.random() * 0.08;
                colors[i * 3] = darkness * 0.8;
                colors[i * 3 + 1] = darkness * 0.9;
                colors[i * 3 + 2] = darkness * 1.2;
            }
        }

        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

        const material = new THREE.PointsMaterial({
            size: 100 + Math.random() * 50,
            vertexColors: true,
            transparent: true,
            opacity: 0.12 + Math.random() * 0.08,
            sizeAttenuation: true
        });

        const dustCloud = new THREE.Points(geometry, material);
        gameMode.scene.add(dustCloud);
    }

    // Add floating ice/debris particles throughout the system
    const debrisCount = 2000;
    const debrisPositions = new Float32Array(debrisCount * 3);
    const debrisColors = new Float32Array(debrisCount * 3);

    for (let i = 0; i < debrisCount; i++) {
        const radius = 3000 + Math.random() * 100000;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);

        debrisPositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
        debrisPositions[i * 3 + 1] = (Math.random() - 0.5) * 20000;
        debrisPositions[i * 3 + 2] = radius * Math.cos(phi);

        // Icy/metallic debris colors
        const type = Math.random();
        if (type < 0.5) {
            // Ice
            debrisColors[i * 3] = 0.7 + Math.random() * 0.3;
            debrisColors[i * 3 + 1] = 0.8 + Math.random() * 0.2;
            debrisColors[i * 3 + 2] = 0.9 + Math.random() * 0.1;
        } else {
            // Rock/metal
            const gray = 0.3 + Math.random() * 0.3;
            debrisColors[i * 3] = gray;
            debrisColors[i * 3 + 1] = gray * 0.9;
            debrisColors[i * 3 + 2] = gray * 0.8;
        }
    }

    const debrisGeometry = new THREE.BufferGeometry();
    debrisGeometry.setAttribute('position', new THREE.BufferAttribute(debrisPositions, 3));
    debrisGeometry.setAttribute('color', new THREE.BufferAttribute(debrisColors, 3));

    const debrisMaterial = new THREE.PointsMaterial({
        size: 8,
        vertexColors: true,
        transparent: true,
        opacity: 0.6,
        sizeAttenuation: true,
        blending: THREE.AdditiveBlending
    });

    const debris = new THREE.Points(debrisGeometry, debrisMaterial);
    gameMode.scene.add(debris);
    gameMode.floatingDebris = debris;
}

// Create asteroid belt using InstancedMesh (1 draw call instead of thousands)
function createAsteroidBelt() {
    const asteroidCount = 1500; // Reduced count, instanced = still looks dense
    const beltRadius = 60000;
    const beltWidth = 15000;

    // Shared geometry - single icosahedron, unit size
    const baseGeom = new THREE.IcosahedronGeometry(1, 0);

    const material = new THREE.MeshPhongMaterial({
        color: 0x555555,
        emissive: 0x0a0a0a,
        emissiveIntensity: 0.15,
        flatShading: true,
        shininess: 10
    });

    const instancedMesh = new THREE.InstancedMesh(baseGeom, material, asteroidCount);
    const dummy = new THREE.Object3D();
    const color = new THREE.Color();

    // Store orbit data for animation
    gameMode.asteroidOrbits = new Float32Array(asteroidCount * 4); // angle, radius, speed, unused

    for (let i = 0; i < asteroidCount; i++) {
        const angle = Math.random() * Math.PI * 2;
        const radius = beltRadius + (Math.random() - 0.5) * beltWidth;
        const height = (Math.random() - 0.5) * 2000;
        const size = 10 + Math.random() * 60;

        dummy.position.set(
            Math.cos(angle) * radius,
            height,
            Math.sin(angle) * radius
        );
        dummy.rotation.set(Math.random() * Math.PI, Math.random() * Math.PI, Math.random() * Math.PI);
        dummy.scale.setScalar(size);
        dummy.updateMatrix();
        instancedMesh.setMatrixAt(i, dummy.matrix);

        // Varied colors per instance
        const t = Math.random();
        if (t < 0.4) {
            color.setHex(0x333333 + Math.floor(Math.random() * 0x111111));
        } else if (t < 0.7) {
            color.setHex(0x665544 + Math.floor(Math.random() * 0x222211));
        } else {
            color.setHex(0x888888 + Math.floor(Math.random() * 0x222222));
        }
        instancedMesh.setColorAt(i, color);

        // Store orbit data
        gameMode.asteroidOrbits[i * 4] = angle;
        gameMode.asteroidOrbits[i * 4 + 1] = radius;
        gameMode.asteroidOrbits[i * 4 + 2] = 0.00005 + Math.random() * 0.0001;
        gameMode.asteroidOrbits[i * 4 + 3] = height;
    }

    instancedMesh.instanceMatrix.needsUpdate = true;
    instancedMesh.instanceColor.needsUpdate = true;
    gameMode.asteroidMesh = instancedMesh;
    gameMode.asteroidCount = asteroidCount;
    gameMode.scene.add(instancedMesh);
}

// Create ambient space dust particles near camera
function createAmbientDust() {
    const dustCount = 400;
    const positions = new Float32Array(dustCount * 3);
    const colors = new Float32Array(dustCount * 3);

    for (let i = 0; i < dustCount; i++) {
        // Distribute around camera starting position
        positions[i * 3] = (Math.random() - 0.5) * 5000;
        positions[i * 3 + 1] = (Math.random() - 0.5) * 3000 + 500;
        positions[i * 3 + 2] = (Math.random() - 0.5) * 5000 + 2000;

        const brightness = 0.3 + Math.random() * 0.4;
        colors[i * 3] = brightness;
        colors[i * 3 + 1] = brightness;
        colors[i * 3 + 2] = brightness;
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const material = new THREE.PointsMaterial({
        size: 1.5,
        vertexColors: true,
        transparent: true,
        opacity: 0.3,
        sizeAttenuation: true
    });

    gameMode.ambientDust = new THREE.Points(geometry, material);
    gameMode.scene.add(gameMode.ambientDust);
}

// Create a shooting star effect
function createShootingStar() {
    if (gameMode.shootingStar) return;

    // Random starting position in the sky
    const camPos = gameMode.camera.position;
    const startDistance = 8000 + Math.random() * 15000;
    const startTheta = Math.random() * Math.PI * 2;
    const startPhi = Math.PI * 0.1 + Math.random() * Math.PI * 0.4; // Upper hemisphere

    const startPos = new THREE.Vector3(
        camPos.x + startDistance * Math.sin(startPhi) * Math.cos(startTheta),
        camPos.y + startDistance * Math.cos(startPhi),
        camPos.z + startDistance * Math.sin(startPhi) * Math.sin(startTheta)
    );

    // Direction of travel (downward and across)
    const direction = new THREE.Vector3(
        (Math.random() - 0.5) * 2,
        -0.8 - Math.random() * 0.4,
        (Math.random() - 0.5) * 2
    ).normalize();

    // Create the shooting star trail
    const trailLength = 20;
    const positions = new Float32Array(trailLength * 3);
    const colors = new Float32Array(trailLength * 3);

    for (let i = 0; i < trailLength; i++) {
        const t = i / trailLength;
        positions[i * 3] = startPos.x - direction.x * i * 50;
        positions[i * 3 + 1] = startPos.y - direction.y * i * 50;
        positions[i * 3 + 2] = startPos.z - direction.z * i * 50;

        // Fade from white to blue
        const brightness = 1 - t * 0.8;
        colors[i * 3] = brightness;
        colors[i * 3 + 1] = brightness;
        colors[i * 3 + 2] = brightness * 1.2;
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const material = new THREE.PointsMaterial({
        size: 15,
        vertexColors: true,
        transparent: true,
        opacity: 1,
        sizeAttenuation: true,
        blending: THREE.AdditiveBlending
    });

    const shootingStar = new THREE.Points(geometry, material);
    gameMode.scene.add(shootingStar);

    gameMode.shootingStar = {
        mesh: shootingStar,
        direction: direction,
        speed: 150 + Math.random() * 100,
        life: 0,
        maxLife: 80 + Math.random() * 40
    };
}

// Update shooting star position
function updateShootingStar() {
    if (!gameMode.shootingStar) return;

    const star = gameMode.shootingStar;
    star.life++;

    // Move the shooting star
    const positions = star.mesh.geometry.attributes.position.array;
    for (let i = 0; i < positions.length / 3; i++) {
        positions[i * 3] += star.direction.x * star.speed;
        positions[i * 3 + 1] += star.direction.y * star.speed;
        positions[i * 3 + 2] += star.direction.z * star.speed;
    }
    star.mesh.geometry.attributes.position.needsUpdate = true;

    // Fade out near end of life
    const fadeStart = star.maxLife * 0.6;
    if (star.life > fadeStart) {
        const fadeProgress = (star.life - fadeStart) / (star.maxLife - fadeStart);
        star.mesh.material.opacity = 1 - fadeProgress;
    }

    // Remove when dead
    if (star.life >= star.maxLife) {
        gameMode.scene.remove(star.mesh);
        star.mesh.geometry.dispose();
        star.mesh.material.dispose();
        gameMode.shootingStar = null;
    }
}

// Initialize speed lines for motion effect
function initSpeedLines() {
    const speedLinesContainer = document.getElementById('speedLines');
    speedLinesContainer.innerHTML = '';

    // Create 30 speed lines
    for (let i = 0; i < 30; i++) {
        const line = document.createElement('div');
        line.className = 'speed-line';
        line.style.left = Math.random() * 100 + '%';
        line.style.top = Math.random() * 100 + '%';
        line.style.animationDelay = Math.random() * 0.3 + 's';
        speedLinesContainer.appendChild(line);
    }
}

// Create central sun
function createSun() {
    // Sun geometry - MASSIVE central star (10x bigger)
    const sunGeometry = new THREE.SphereGeometry(8000, 64, 64);
    const sunMaterial = new THREE.MeshBasicMaterial({
        color: 0xffaa00,
        transparent: true,
        opacity: 0.95
    });
    const sun = new THREE.Mesh(sunGeometry, sunMaterial);
    sun.position.set(0, 0, 0);
    gameMode.scene.add(sun);

    // Sun corona (outer glow)
    const coronaGeometry = new THREE.SphereGeometry(12000, 64, 64);
    const coronaMaterial = new THREE.MeshBasicMaterial({
        color: 0xff6600,
        transparent: true,
        opacity: 0.25,
        side: THREE.BackSide
    });
    const corona = new THREE.Mesh(coronaGeometry, coronaMaterial);
    corona.position.set(0, 0, 0);
    gameMode.scene.add(corona);

    // Inner glow
    const glowGeometry = new THREE.SphereGeometry(9500, 64, 64);
    const glowMaterial = new THREE.MeshBasicMaterial({
        color: 0xffcc44,
        transparent: true,
        opacity: 0.18,
        side: THREE.BackSide
    });
    const glow = new THREE.Mesh(glowGeometry, glowMaterial);
    glow.position.set(0, 0, 0);
    gameMode.scene.add(glow);

    // Outer halo
    const haloGeometry = new THREE.SphereGeometry(15000, 32, 32);
    const haloMaterial = new THREE.MeshBasicMaterial({
        color: 0xffdd88,
        transparent: true,
        opacity: 0.08,
        side: THREE.BackSide
    });
    const halo = new THREE.Mesh(haloGeometry, haloMaterial);
    halo.position.set(0, 0, 0);
    gameMode.scene.add(halo);

    // Solar flare particles around the sun
    const flareCount = 5000;
    const flarePositions = new Float32Array(flareCount * 3);
    const flareColors = new Float32Array(flareCount * 3);

    for (let i = 0; i < flareCount; i++) {
        const radius = 8000 + Math.random() * 6000;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);

        flarePositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
        flarePositions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
        flarePositions[i * 3 + 2] = radius * Math.cos(phi);

        // Yellow-orange-white colors
        const heat = Math.random();
        flareColors[i * 3] = 1;
        flareColors[i * 3 + 1] = 0.5 + heat * 0.5;
        flareColors[i * 3 + 2] = heat * 0.5;
    }

    const flareGeometry = new THREE.BufferGeometry();
    flareGeometry.setAttribute('position', new THREE.BufferAttribute(flarePositions, 3));
    flareGeometry.setAttribute('color', new THREE.BufferAttribute(flareColors, 3));

    const flareMaterial = new THREE.PointsMaterial({
        size: 80,
        vertexColors: true,
        transparent: true,
        opacity: 0.6,
        blending: THREE.AdditiveBlending
    });

    const flares = new THREE.Points(flareGeometry, flareMaterial);
    gameMode.scene.add(flares);
    gameMode.sunFlares = flares;

    // Point light from sun - intense light flooding the vast system
    const sunLight = new THREE.PointLight(0xffdd66, 10, 300000);
    sunLight.position.set(0, 0, 0);
    gameMode.scene.add(sunLight);

    // Secondary warm light for fill
    const sunLight2 = new THREE.PointLight(0xffaa33, 5, 200000);
    sunLight2.position.set(0, 0, 0);
    gameMode.scene.add(sunLight2);

    // Add hemisphere light for overall illumination
    const hemiLight = new THREE.HemisphereLight(0xffffcc, 0x222244, 1.5);
    gameMode.scene.add(hemiLight);
}

// Planet type configurations for variety
const PLANET_TYPES = [
    { name: 'terrestrial', colors: [0x4488aa, 0x448866, 0x886644], hasAtmosphere: true, atmosphereColor: 0x88ccff },
    { name: 'gas_giant', colors: [0xddaa66, 0xcc8844, 0xbb9955], hasAtmosphere: true, atmosphereColor: 0xffddaa, hasRings: true },
    { name: 'ice_giant', colors: [0x66aacc, 0x5599bb, 0x4488aa], hasAtmosphere: true, atmosphereColor: 0xaaddff },
    { name: 'desert', colors: [0xcc9966, 0xbb8855, 0xaa7744], hasAtmosphere: true, atmosphereColor: 0xffccaa },
    { name: 'volcanic', colors: [0x884422, 0x662211, 0x993322], hasAtmosphere: true, atmosphereColor: 0xff6644 },
    { name: 'ocean', colors: [0x2266aa, 0x3377bb, 0x1155aa], hasAtmosphere: true, atmosphereColor: 0x66aaff },
    { name: 'barren', colors: [0x666666, 0x555555, 0x777777], hasAtmosphere: false },
    { name: 'toxic', colors: [0x668844, 0x557733, 0x779955], hasAtmosphere: true, atmosphereColor: 0xaaff66 },
];

// Create spherical nodes from network data as realistic planets
function createNodeSpheres() {
    // Get current nodes from vis.js BEFORE clearing existing ones
    const allNodes = nodes.get();
    if (allNodes.length === 0) return;  // Don't clear if no new nodes to display

    // Clear existing nodes
    gameMode.nodeMeshes.forEach(mesh => {
        // Remove all children (atmosphere, rings, moons)
        while (mesh.children.length > 0) {
            const child = mesh.children[0];
            mesh.remove(child);
            if (child.geometry) child.geometry.dispose();
            if (child.material) child.material.dispose();
        }
        gameMode.scene.remove(mesh);
        // Only dispose geometry/material if they exist (Groups don't have them)
        if (mesh.geometry) mesh.geometry.dispose();
        if (mesh.material) mesh.material.dispose();
    });
    gameMode.nodeMeshes = [];
    gameMode.nodeDataMap.clear();
    gameMode.nodeIdToMesh.clear();

    // Position nodes in orbital rings around the sun
    const nodeCount = allNodes.length;
    const rings = Math.ceil(Math.sqrt(nodeCount));

    allNodes.forEach((node, index) => {
        // Determine ring and position within ring
        const ring = Math.floor(index / Math.max(1, Math.ceil(nodeCount / rings)));
        const positionInRing = index % Math.max(1, Math.ceil(nodeCount / rings));
        const nodesInRing = Math.ceil(nodeCount / rings);

        // Calculate orbital position - vast solar system with huge sun
        const orbitRadius = 25000 + ring * 25000;  // Start further out, more spacing
        const angle = (positionInRing / nodesInRing) * Math.PI * 2 + ring * 0.5;
        const verticalOffset = (seededRandom(node.id, 'voff') - 0.5) * 8000;
        const orbitTilt = (seededRandom(node.id, 'tilt') - 0.5) * 0.4; // Slight orbital plane tilt

        // Size based on packet count - MASSIVE planets (10x original)
        const packetCount = metaPacketCount(node) || 1;
        const baseSize = 1500;  // Minimum planet size
        const maxSize = 6000;   // Maximum planet size
        const size = Math.min(maxSize, baseSize + Math.log10(packetCount + 1) * 1200);

        // Select planet type based on hash of node ID for consistency
        const planetTypeIndex = hashCode(node.id) % PLANET_TYPES.length;
        const planetType = PLANET_TYPES[Math.abs(planetTypeIndex)];

        // Create planet group
        const planetGroup = new THREE.Group();

        // Main planet body with high detail
        const geometry = new THREE.SphereGeometry(size, 64, 64);
        const baseColor = planetType.colors[Math.abs(hashCode(node.id + 'color')) % planetType.colors.length];

        // Create procedural surface variation
        const material = new THREE.MeshPhongMaterial({
            color: baseColor,
            emissive: baseColor,
            emissiveIntensity: 0.12,
            shininess: 40,
            transparent: false
        });

        const planet = new THREE.Mesh(geometry, material);
        planet.rotation.x = seededRandom(node.id, 'rotx') * 0.5;
        planet.rotation.z = seededRandom(node.id, 'rotz') * 0.3;
        planetGroup.add(planet);

        // Add surface features layer (continents/storms/terrain)
        const featureGeometry = new THREE.SphereGeometry(size * 1.002, 64, 64);
        const featureColor = new THREE.Color(baseColor).offsetHSL(0.05, 0.1, 0.15);
        const featureMaterial = new THREE.MeshPhongMaterial({
            color: featureColor,
            emissive: featureColor,
            emissiveIntensity: 0.08,
            transparent: true,
            opacity: 0.6,
            blending: THREE.AdditiveBlending
        });
        const features = new THREE.Mesh(featureGeometry, featureMaterial);
        features.rotation.y = seededRandom(node.id, 'feat') * Math.PI;
        planetGroup.add(features);

        // Add cloud layer for atmospheric planets
        if (planetType.hasAtmosphere && seededRandom(node.id, 'cloud') > 0.3) {
            const cloudGeometry = new THREE.SphereGeometry(size * 1.02, 48, 48);
            const cloudMaterial = new THREE.MeshPhongMaterial({
                color: 0xffffff,
                emissive: 0x222222,
                transparent: true,
                opacity: 0.25,
                blending: THREE.NormalBlending
            });
            const clouds = new THREE.Mesh(cloudGeometry, cloudMaterial);
            clouds.userData.rotationSpeed = 0.0002 + seededRandom(node.id, 'cloudspd') * 0.0003;
            planetGroup.add(clouds);
        }

        // Add polar ice caps for terrestrial planets
        if (planetType.name === 'terrestrial' || planetType.name === 'ocean') {
            const capSize = size * 0.25;
            const northCapGeometry = new THREE.SphereGeometry(capSize, 32, 16, 0, Math.PI * 2, 0, Math.PI * 0.3);
            const capMaterial = new THREE.MeshPhongMaterial({
                color: 0xeeffff,
                emissive: 0x446688,
                emissiveIntensity: 0.2,
                transparent: true,
                opacity: 0.8
            });
            const northCap = new THREE.Mesh(northCapGeometry, capMaterial);
            northCap.position.y = size * 0.92;
            planetGroup.add(northCap);

            const southCap = new THREE.Mesh(northCapGeometry, capMaterial);
            southCap.position.y = -size * 0.92;
            southCap.rotation.x = Math.PI;
            planetGroup.add(southCap);
        }

        // Add storm bands for gas giants
        if (planetType.name === 'gas_giant') {
            for (let b = 0; b < 5; b++) {
                const bandGeometry = new THREE.TorusGeometry(size * (0.7 + b * 0.12), size * 0.02, 8, 64);
                const bandColor = new THREE.Color(baseColor).offsetHSL(b * 0.02, -0.1, b % 2 === 0 ? 0.1 : -0.1);
                const bandMaterial = new THREE.MeshBasicMaterial({
                    color: bandColor,
                    transparent: true,
                    opacity: 0.4
                });
                const band = new THREE.Mesh(bandGeometry, bandMaterial);
                band.rotation.x = Math.PI / 2;
                band.position.y = size * (0.6 - b * 0.25);
                planetGroup.add(band);
            }

            // Great storm spot
            if (seededRandom(node.id, 'storm') > 0.5) {
                const stormGeometry = new THREE.SphereGeometry(size * 0.15, 32, 32);
                const stormMaterial = new THREE.MeshBasicMaterial({
                    color: 0xff6644,
                    transparent: true,
                    opacity: 0.7
                });
                const storm = new THREE.Mesh(stormGeometry, stormMaterial);
                storm.position.set(size * 0.8, size * 0.2, size * 0.4);
                planetGroup.add(storm);
            }
        }

        // Add volcanic activity for volcanic planets
        if (planetType.name === 'volcanic') {
            for (let v = 0; v < 8; v++) {
                const volcanoGlow = new THREE.PointLight(0xff4400, 0.5, size * 0.8);
                const theta = seededRandom(node.id, 'vtheta' + v) * Math.PI * 2;
                const phi = seededRandom(node.id, 'vphi' + v) * Math.PI;
                volcanoGlow.position.set(
                    size * Math.sin(phi) * Math.cos(theta),
                    size * Math.cos(phi),
                    size * Math.sin(phi) * Math.sin(theta)
                );
                planetGroup.add(volcanoGlow);
            }
        }

        // Add atmosphere glow
        if (planetType.hasAtmosphere) {
            const atmosphereGeometry = new THREE.SphereGeometry(size * 1.15, 32, 32);
            const atmosphereMaterial = new THREE.MeshBasicMaterial({
                color: planetType.atmosphereColor,
                transparent: true,
                opacity: 0.15,
                side: THREE.BackSide
            });
            const atmosphere = new THREE.Mesh(atmosphereGeometry, atmosphereMaterial);
            planetGroup.add(atmosphere);

            // Inner glow
            const innerGlowGeometry = new THREE.SphereGeometry(size * 1.05, 32, 32);
            const innerGlowMaterial = new THREE.MeshBasicMaterial({
                color: planetType.atmosphereColor,
                transparent: true,
                opacity: 0.08,
                side: THREE.FrontSide
            });
            const innerGlow = new THREE.Mesh(innerGlowGeometry, innerGlowMaterial);
            planetGroup.add(innerGlow);
        }

        // Add rings to some planets (gas giants or random chance)
        const hasRings = planetType.hasRings || (size > 1500 && seededRandom(node.id, 'rings') > 0.5);
        if (hasRings) {
            const ringInnerRadius = size * 1.4;
            const ringOuterRadius = size * 2.2;
            const ringGeometry = new THREE.RingGeometry(ringInnerRadius, ringOuterRadius, 64);
            const ringMaterial = new THREE.MeshBasicMaterial({
                color: 0xccbb99,
                transparent: true,
                opacity: 0.4,
                side: THREE.DoubleSide
            });
            const rings = new THREE.Mesh(ringGeometry, ringMaterial);
            rings.rotation.x = Math.PI / 2 + (seededRandom(node.id, 'ringtilt') - 0.5) * 0.3;
            planetGroup.add(rings);
        }

        // Add moons to larger planets
        if (size > 200 && seededRandom(node.id, 'hasmoon') > 0.4) {
            const moonCount = Math.floor(seededRandom(node.id, 'moonct') * 4) + 1;
            for (let m = 0; m < moonCount; m++) {
                const moonSize = size * (0.08 + seededRandom(node.id, 'moonsz' + m) * 0.12);
                const moonDistance = size * (1.4 + m * 0.5 + seededRandom(node.id, 'moondst' + m) * 0.3);
                const moonGeometry = new THREE.SphereGeometry(moonSize, 24, 24);
                const moonMaterial = new THREE.MeshPhongMaterial({
                    color: 0x999999,
                    emissive: 0x333333,
                    emissiveIntensity: 0.15
                });
                const moon = new THREE.Mesh(moonGeometry, moonMaterial);
                moon.userData.moonOrbitRadius = moonDistance;
                moon.userData.moonOrbitSpeed = 0.008 + seededRandom(node.id, 'moonspd' + m) * 0.012;
                // Spread moons evenly around planet, plus small random offset
                const baseAngle = (m / moonCount) * Math.PI * 2;
                const randomOffset = (seededRandom(node.id, 'moonang' + m) - 0.5) * 0.5;
                moon.userData.moonOrbitAngle = baseAngle + randomOffset;
                // Position moon using its orbit angle
                moon.position.set(
                    Math.cos(moon.userData.moonOrbitAngle) * moonDistance,
                    0,
                    Math.sin(moon.userData.moonOrbitAngle) * moonDistance
                );
                planetGroup.add(moon);
            }
        }

        // Position the planet group
        planetGroup.position.set(
            Math.cos(angle) * orbitRadius,
            verticalOffset + Math.sin(angle * 2) * orbitTilt * orbitRadius,
            Math.sin(angle) * orbitRadius
        );

        // Store node data
        gameMode.nodeDataMap.set(planetGroup.uuid, {
            id: node.id,
            label: node.label,
            title: nodeTooltipFor(node.id),
            packetCount: packetCount,
            orbitRadius: orbitRadius,
            orbitAngle: angle,
            orbitTilt: orbitTilt,
            orbitSpeed: 0.0003 + seededRandom(node.id, 'orbspd') * 0.0008,
            rotationSpeed: 0.005 + seededRandom(node.id, 'rotspd') * 0.01,
            planetType: planetType.name,
            size: size
        });

        gameMode.scene.add(planetGroup);
        gameMode.nodeMeshes.push(planetGroup);
        gameMode.nodeIdToMesh.set(node.id, planetGroup);
    });
}

// Simple hash function for consistent planet types
function hashCode(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return hash;
}

// Seeded random function for deterministic "random" values based on node ID
function seededRandom(nodeId, seed) {
    const hash = hashCode(nodeId + seed);
    // Convert hash to 0-1 range
    return (Math.abs(hash) % 10000) / 10000;
}

// Create space elevators between connected planets
function createSpaceElevators() {
    // Clear existing elevators
    gameMode.spaceElevators.forEach(elevator => {
        if (elevator.line) {
            gameMode.scene.remove(elevator.line);
            elevator.line.geometry.dispose();
            elevator.line.material.dispose();
        }
        if (elevator.glow) {
            gameMode.scene.remove(elevator.glow);
            elevator.glow.geometry.dispose();
            elevator.glow.material.dispose();
        }
        if (elevator.particles) {
            gameMode.scene.remove(elevator.particles);
            elevator.particles.geometry.dispose();
            elevator.particles.material.dispose();
        }
    });
    gameMode.spaceElevators = [];
    gameMode.elevatorEdgeMap.clear();

    // Build a map from node ID to planet mesh
    const nodeIdToMesh = new Map();
    gameMode.nodeMeshes.forEach(mesh => {
        const data = gameMode.nodeDataMap.get(mesh.uuid);
        if (data) {
            nodeIdToMesh.set(data.id, mesh);
        }
    });

    // Get all edges
    const allEdges = edges.get();
    if (!allEdges || allEdges.length === 0) return;

    // Limit elevators to prevent performance issues
    const maxElevators = 50;
    const sortedEdges = allEdges
        .filter(edge => !edge.hidden)
        .sort((a, b) => (b.packetCount || 0) - (a.packetCount || 0))
        .slice(0, maxElevators);

    sortedEdges.forEach(edge => {
        const fromMesh = nodeIdToMesh.get(edge.from);
        const toMesh = nodeIdToMesh.get(edge.to);

        if (!fromMesh || !toMesh) return;

        // Get positions
        const fromPos = fromMesh.position.clone();
        const toPos = toMesh.position.clone();

        // Get planet sizes for offset
        const fromData = gameMode.nodeDataMap.get(fromMesh.uuid);
        const toData = gameMode.nodeDataMap.get(toMesh.uuid);
        const fromSize = fromData ? fromData.size : 1500;
        const toSize = toData ? toData.size : 1500;

        // Calculate direction and offset from planet surfaces
        const direction = new THREE.Vector3().subVectors(toPos, fromPos).normalize();
        const startPos = fromPos.clone().add(direction.clone().multiplyScalar(fromSize * 1.1));
        const endPos = toPos.clone().sub(direction.clone().multiplyScalar(toSize * 1.1));

        // Create the elevator beam
        const points = [];
        const segments = 32;
        for (let i = 0; i <= segments; i++) {
            const t = i / segments;
            // Add slight curve for visual interest
            const midHeight = Math.sin(t * Math.PI) * 500;
            const perpendicular = new THREE.Vector3(-direction.z, 0, direction.x).normalize();
            const point = new THREE.Vector3().lerpVectors(startPos, endPos, t);
            point.add(perpendicular.clone().multiplyScalar(midHeight * 0.3));
            point.y += midHeight;
            points.push(point);
        }

        const curve = new THREE.CatmullRomCurve3(points);
        const curvePoints = curve.getPoints(64);

        // Main beam (tube-like appearance)
        const beamGeometry = new THREE.BufferGeometry().setFromPoints(curvePoints);
        const protocolColor = edge.protocol ? new THREE.Color(edge.protocol.Color) : new THREE.Color(0x00ffcc);
        const beamMaterial = new THREE.LineBasicMaterial({
            color: protocolColor,
            transparent: true,
            opacity: 0.6,
            linewidth: 2
        });
        const beam = new THREE.Line(beamGeometry, beamMaterial);

        // Outer glow effect
        const glowMaterial = new THREE.LineBasicMaterial({
            color: protocolColor,
            transparent: true,
            opacity: 0.15,
            linewidth: 4
        });
        const glow = new THREE.Line(beamGeometry.clone(), glowMaterial);

        // Create particles traveling along the beam
        const particleCount = Math.min(20, Math.max(5, Math.floor((edge.packetCount || 1) / 10)));
        const particleGeometry = new THREE.BufferGeometry();
        const particlePositions = new Float32Array(particleCount * 3);
        const particleSizes = new Float32Array(particleCount);
        const particleProgress = new Float32Array(particleCount);

        for (let i = 0; i < particleCount; i++) {
            particleProgress[i] = Math.random(); // Random starting position along curve
            particleSizes[i] = 80 + Math.random() * 120;

            // Initial position
            const point = curve.getPoint(particleProgress[i]);
            particlePositions[i * 3] = point.x;
            particlePositions[i * 3 + 1] = point.y;
            particlePositions[i * 3 + 2] = point.z;
        }

        particleGeometry.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
        particleGeometry.setAttribute('size', new THREE.BufferAttribute(particleSizes, 1));

        const particleMaterial = new THREE.PointsMaterial({
            color: protocolColor,
            size: 100,
            transparent: true,
            opacity: 0.9,
            blending: THREE.AdditiveBlending,
            sizeAttenuation: true
        });

        const particles = new THREE.Points(particleGeometry, particleMaterial);

        // Add to scene
        gameMode.scene.add(beam);
        gameMode.scene.add(glow);
        gameMode.scene.add(particles);

        // Store elevator data for animation
        const elevatorIndex = gameMode.spaceElevators.length;
        gameMode.spaceElevators.push({
            line: beam,
            glow: glow,
            particles: particles,
            curve: curve,
            particleProgress: particleProgress,
            particleCount: particleCount,
            speed: 0.002 + (edge.packetCount || 1) * 0.00001,
            fromMesh: fromMesh,
            toMesh: toMesh,
            edge: edge,
            baseOpacity: 0.6,
            trafficIntensity: 0,  // 0-1, boosted by real-time traffic
            lastTrafficTime: 0
        });

        // Build lookup maps (both directions) for real-time traffic matching
        gameMode.elevatorEdgeMap.set(edge.from + '->' + edge.to, elevatorIndex);
        gameMode.elevatorEdgeMap.set(edge.to + '->' + edge.from, elevatorIndex);
    });
}

// Animate space elevator particles
function animateSpaceElevators() {
    gameMode.spaceElevators.forEach(elevator => {
        // Update particle positions along the curve
        const positions = elevator.particles.geometry.attributes.position.array;

        for (let i = 0; i < elevator.particleCount; i++) {
            // Move particle along curve
            elevator.particleProgress[i] += elevator.speed;
            if (elevator.particleProgress[i] > 1) {
                elevator.particleProgress[i] = 0;
            }

            // Get new position on curve
            const point = elevator.curve.getPoint(elevator.particleProgress[i]);
            positions[i * 3] = point.x;
            positions[i * 3 + 1] = point.y;
            positions[i * 3 + 2] = point.z;
        }

        elevator.particles.geometry.attributes.position.needsUpdate = true;

        // Update beam endpoints to follow planet positions
        const fromPos = elevator.fromMesh.position.clone();
        const toPos = elevator.toMesh.position.clone();

        const fromData = gameMode.nodeDataMap.get(elevator.fromMesh.uuid);
        const toData = gameMode.nodeDataMap.get(elevator.toMesh.uuid);
        const fromSize = fromData ? fromData.size : 1500;
        const toSize = toData ? toData.size : 1500;

        const direction = new THREE.Vector3().subVectors(toPos, fromPos).normalize();
        const startPos = fromPos.clone().add(direction.clone().multiplyScalar(fromSize * 1.1));
        const endPos = toPos.clone().sub(direction.clone().multiplyScalar(toSize * 1.1));

        // Rebuild curve with new endpoints
        const points = [];
        const segments = 32;
        for (let j = 0; j <= segments; j++) {
            const t = j / segments;
            const midHeight = Math.sin(t * Math.PI) * 500;
            const perpendicular = new THREE.Vector3(-direction.z, 0, direction.x).normalize();
            const point = new THREE.Vector3().lerpVectors(startPos, endPos, t);
            point.add(perpendicular.clone().multiplyScalar(midHeight * 0.3));
            point.y += midHeight;
            points.push(point);
        }

        elevator.curve = new THREE.CatmullRomCurve3(points);
        const curvePoints = elevator.curve.getPoints(64);

        // Update line geometry
        elevator.line.geometry.setFromPoints(curvePoints);
        elevator.glow.geometry.setFromPoints(curvePoints);
    });
}

// Process queued traffic events and spawn burst particles
function processTrafficEvents() {
    const now = Date.now();
    const events = gameMode.trafficEvents;
    if (events.length === 0) return;

    // Process up to 15 events per frame to keep framerate smooth
    const batch = events.splice(0, Math.min(15, events.length));

    for (const evt of batch) {
        // Server sends node IDs (already resolved), try direct lookup first
        let srcId = evt.src;
        let dstId = evt.dst;

        // If not found, try IP-to-node resolution
        if (!gameMode.nodeIdToMesh.has(srcId)) srcId = findGameNodeId(srcId);
        if (!gameMode.nodeIdToMesh.has(dstId)) dstId = findGameNodeId(dstId);
        if (!srcId || !dstId) continue;

        const elevatorIdx = gameMode.elevatorEdgeMap.get(srcId + '->' + dstId);
        if (elevatorIdx === undefined) continue;

        const elevator = gameMode.spaceElevators[elevatorIdx];
        if (!elevator) continue;

        // Boost elevator traffic intensity (scale with packet count from aggregated flow)
        const intensity = Math.min(0.5, (evt.packets || 1) * 0.05);
        elevator.trafficIntensity = Math.min(1.0, elevator.trafficIntensity + intensity);
        elevator.lastTrafficTime = now;

        // Determine direction
        const isForward = (srcId === elevator.edge.from);

        // Spawn burst(s) - one per flow, not per packet
        spawnTrafficBurst(elevator, evt.color, isForward, evt.bytes);

        // Pulse destination planet
        const destId = isForward ? elevator.edge.to : elevator.edge.from;
        triggerPlanetPulse(destId, evt.color);
    }
}

// Find the game mode node ID for a given IP (may be mapped to hostname)
function findGameNodeId(ip) {
    if (gameMode.nodeIdToMesh.has(ip)) return ip;
    // Check if any node has this IP in its ips array
    for (const [nodeId, mesh] of gameMode.nodeIdToMesh) {
        const visNode = nodes.get(nodeId);
        if (visNode && visNode.ips && visNode.ips.includes(ip)) {
            return nodeId;
        }
    }
    return null;
}

// Traffic burst pool - pre-allocated particles, no create/destroy per packet
const BURST_POOL_SIZE = 100;

function initBurstPool() {
    if (gameMode.burstPool) return; // Already initialized

    const positions = new Float32Array(BURST_POOL_SIZE * 3);
    const colors = new Float32Array(BURST_POOL_SIZE * 3);
    const sizes = new Float32Array(BURST_POOL_SIZE);

    // Place all particles off-screen initially
    for (let i = 0; i < BURST_POOL_SIZE; i++) {
        positions[i * 3] = 0;
        positions[i * 3 + 1] = -999999;
        positions[i * 3 + 2] = 0;
        sizes[i] = 0;
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));
    geometry.setAttribute('size', new THREE.BufferAttribute(sizes, 1));

    const material = new THREE.PointsMaterial({
        size: 120,
        vertexColors: true,
        transparent: true,
        opacity: 0.9,
        blending: THREE.AdditiveBlending,
        sizeAttenuation: true
    });

    const mesh = new THREE.Points(geometry, material);
    gameMode.scene.add(mesh);

    gameMode.burstPool = {
        mesh: mesh,
        slots: new Array(BURST_POOL_SIZE).fill(null), // null = free, object = active burst
        nextSlot: 0
    };
}

// Spawn a burst using a pool slot
function spawnTrafficBurst(elevator, colorHex, forward, bytes) {
    if (!gameMode.burstPool) initBurstPool();

    const pool = gameMode.burstPool;
    // Find a free slot (round-robin with overwrite of oldest)
    let slot = -1;
    for (let tries = 0; tries < BURST_POOL_SIZE; tries++) {
        const idx = (pool.nextSlot + tries) % BURST_POOL_SIZE;
        if (!pool.slots[idx]) { slot = idx; break; }
    }
    if (slot === -1) {
        // All full - overwrite the next slot
        slot = pool.nextSlot;
    }
    pool.nextSlot = (slot + 1) % BURST_POOL_SIZE;

    const color = new THREE.Color(colorHex);
    const startPoint = elevator.curve.getPoint(forward ? 0 : 1);

    const positions = pool.mesh.geometry.attributes.position.array;
    const colors = pool.mesh.geometry.attributes.color.array;

    positions[slot * 3] = startPoint.x;
    positions[slot * 3 + 1] = startPoint.y;
    positions[slot * 3 + 2] = startPoint.z;
    colors[slot * 3] = color.r;
    colors[slot * 3 + 1] = color.g;
    colors[slot * 3 + 2] = color.b;

    pool.slots[slot] = {
        elevator: elevator,
        progress: forward ? 0 : 1,
        speed: (forward ? 1 : -1) * (0.015 + Math.random() * 0.01),
        startTime: Date.now(),
        lifetime: 2000 + Math.random() * 1000
    };
}

// Animate pooled traffic bursts (zero allocation per frame)
function animateTrafficBursts() {
    if (!gameMode.burstPool) return;

    const pool = gameMode.burstPool;
    const positions = pool.mesh.geometry.attributes.position.array;
    const now = Date.now();
    let dirty = false;

    for (let i = 0; i < BURST_POOL_SIZE; i++) {
        const burst = pool.slots[i];
        if (!burst) continue;

        const age = now - burst.startTime;
        if (age > burst.lifetime || burst.progress < 0 || burst.progress > 1) {
            // Return to pool - hide offscreen
            positions[i * 3 + 1] = -999999;
            pool.slots[i] = null;
            dirty = true;
            continue;
        }

        burst.progress += burst.speed;
        const clampedProgress = Math.max(0, Math.min(1, burst.progress));

        try {
            const point = burst.elevator.curve.getPoint(clampedProgress);
            positions[i * 3] = point.x;
            positions[i * 3 + 1] = point.y;
            positions[i * 3 + 2] = point.z;
            dirty = true;
        } catch (e) {
            positions[i * 3 + 1] = -999999;
            pool.slots[i] = null;
        }
    }

    if (dirty) {
        pool.mesh.geometry.attributes.position.needsUpdate = true;
    }
}

// Trigger a glow pulse on a destination planet
function triggerPlanetPulse(nodeId, colorHex) {
    const existing = gameMode.planetPulses.get(nodeId);
    if (existing && Date.now() - existing.startTime < 200) return; // Don't stack too fast

    gameMode.planetPulses.set(nodeId, {
        intensity: 1.0,
        startTime: Date.now(),
        color: new THREE.Color(colorHex),
        duration: 600
    });
}

// Animate planet pulse glows
function animatePlanetPulses() {
    const now = Date.now();

    gameMode.planetPulses.forEach((pulse, nodeId) => {
        const age = now - pulse.startTime;
        if (age > pulse.duration) {
            // Reset planet emissive
            const mesh = gameMode.nodeIdToMesh.get(nodeId);
            if (mesh && mesh.children[0] && mesh.children[0].material) {
                mesh.children[0].material.emissiveIntensity = 0.15;
            }
            gameMode.planetPulses.delete(nodeId);
            return;
        }

        // Pulse intensity: quick rise, slow fade
        const t = age / pulse.duration;
        const intensity = t < 0.15 ? (t / 0.15) : (1 - (t - 0.15) / 0.85);

        const mesh = gameMode.nodeIdToMesh.get(nodeId);
        if (mesh && mesh.children[0] && mesh.children[0].material) {
            const mat = mesh.children[0].material;
            // Boost emissive with the traffic color
            mat.emissive = pulse.color;
            mat.emissiveIntensity = 0.15 + intensity * 0.8;
        }
    });
}

// Update elevator beam intensity based on recent traffic
function updateElevatorIntensity() {
    const now = Date.now();

    gameMode.spaceElevators.forEach(elevator => {
        // Decay traffic intensity over time
        const timeSinceTraffic = now - elevator.lastTrafficTime;
        if (timeSinceTraffic > 100) {
            elevator.trafficIntensity *= 0.95; // Smooth decay
            if (elevator.trafficIntensity < 0.01) elevator.trafficIntensity = 0;
        }

        // Update beam opacity based on traffic intensity
        const baseOpacity = 0.3;
        const maxOpacity = 0.9;
        const currentOpacity = baseOpacity + elevator.trafficIntensity * (maxOpacity - baseOpacity);
        elevator.line.material.opacity = currentOpacity;
        elevator.glow.material.opacity = currentOpacity * 0.3;

        // Update particle speed based on traffic
        elevator.speed = 0.002 + elevator.trafficIntensity * 0.008;
    });
}

// ==================== WARP DRIVE SYSTEM ====================

// Open warp drive search overlay
function openWarpDrive() {
    if (gameMode.isWarping) return;

    gameMode.warpDriveActive = true;
    gameMode.warpSelectedIndex = 0;
    gameMode.warpResults = [];

    const overlay = document.getElementById('warpDriveOverlay');
    const input = document.getElementById('warpSearchInput');
    const results = document.getElementById('warpDriveResults');
    const status = document.getElementById('warpDriveStatus');

    if (overlay) {
        overlay.classList.add('active');
        status.textContent = 'READY';
        status.className = 'warp-drive-status';
        results.innerHTML = '<div class="warp-no-results">Type to search for a destination...</div>';
    }

    if (input) {
        input.value = '';
        input.focus();

        // Add input listener
        input.oninput = () => updateWarpSearch(input.value);
    }

    // Exit pointer lock for typing
    document.exitPointerLock();
}

// Close warp drive overlay
function closeWarpDrive() {
    gameMode.warpDriveActive = false;
    gameMode.warpResults = [];

    const overlay = document.getElementById('warpDriveOverlay');
    const input = document.getElementById('warpSearchInput');

    if (overlay) {
        overlay.classList.remove('active');
    }

    if (input) {
        input.oninput = null;
        input.value = '';
    }
}

// Update warp search results
function updateWarpSearch(query) {
    const results = document.getElementById('warpDriveResults');
    if (!results) return;

    if (!query || query.length < 1) {
        results.innerHTML = '<div class="warp-no-results">Type to search for a destination...</div>';
        gameMode.warpResults = [];
        return;
    }

    const queryLower = query.toLowerCase();
    const matches = [];

    // Search through all nodes
    const allNodes = nodes.get();
    allNodes.forEach(node => {
        const nodeMatches = [];

        // Check ID (IP address)
        if (node.id && node.id.toLowerCase().includes(queryLower)) {
            nodeMatches.push({ type: 'IP', value: node.id });
        }

        // Check label (hostname)
        if (node.label && node.label.toLowerCase().includes(queryLower)) {
            nodeMatches.push({ type: 'Hostname', value: node.label });
        }

        // Check MAC addresses
        if (node.macs) {
            node.macs.forEach(mac => {
                if (mac.toLowerCase().includes(queryLower)) {
                    nodeMatches.push({ type: 'MAC', value: mac });
                }
            });
        }

        // Check tooltip data (built on demand from the meta map)
        const nodeTitle = nodeTooltipFor(node.id);
        if (nodeTitle && nodeTitle.toLowerCase().includes(queryLower)) {
            nodeMatches.push({ type: 'Data', value: 'Packet data match' });
        }

        if (nodeMatches.length > 0) {
            matches.push({
                node: node,
                matches: nodeMatches
            });
        }
    });

    // Also search edges for protocol matches
    const allEdges = edges.get();
    allEdges.forEach(edge => {
        if (edge.protocol && edge.protocol.Name && edge.protocol.Name.toLowerCase().includes(queryLower)) {
            // Find the source node for this edge
            const sourceNode = allNodes.find(n => n.id === edge.from);
            if (sourceNode && !matches.find(m => m.node.id === sourceNode.id)) {
                matches.push({
                    node: sourceNode,
                    matches: [{ type: 'Protocol', value: edge.protocol.Name }]
                });
            }
        }
    });

    // Search through packet payloads
    const allCachedPackets = Array.from(packetCache.values());
    if (allCachedPackets && allCachedPackets.length > 0 && query.length >= 2) {
        const queryBytes = stringToBytes(queryLower);

        allCachedPackets.forEach(packet => {
            if (!packet.payload) return;

            try {
                const payloadBytes = base64ToBytes(packet.payload);

                if (searchInPayload(payloadBytes, queryBytes)) {
                    // Find the source node for this packet
                    const sourceNode = allNodes.find(n => n.id === packet.src ||
                        (n.ips && n.ips.includes(packet.src)));

                    if (sourceNode) {
                        let existingMatch = matches.find(m => m.node.id === sourceNode.id);
                        if (!existingMatch) {
                            existingMatch = {
                                node: sourceNode,
                                matches: []
                            };
                            matches.push(existingMatch);
                        }

                        // Add payload match if not already present
                        if (!existingMatch.matches.find(m => m.type === 'Payload')) {
                            const payloadPreview = getPayloadPreview(payloadBytes, queryBytes);
                            existingMatch.matches.push({
                                type: 'Payload',
                                value: `"${payloadPreview}"`
                            });
                        }
                    }
                }
            } catch (e) {
                // Skip packets with invalid payload data
            }
        });
    }

    gameMode.warpResults = matches.slice(0, 10); // Limit to 10 results
    gameMode.warpSelectedIndex = 0;

    if (matches.length === 0) {
        results.innerHTML = '<div class="warp-no-results">No destinations found for "' + query + '"</div>';
        return;
    }

    // Render results
    results.innerHTML = gameMode.warpResults.map((result, index) => {
        const node = result.node;
        const packetCount = metaPacketCount(node) || 0;
        const matchText = result.matches.map(m => `${m.type}: ${m.value}`).join(' | ');

        return `
            <div class="warp-result-item ${index === 0 ? 'selected' : ''}" data-index="${index}">
                <div class="warp-result-hostname">${node.label || node.id}</div>
                <div class="warp-result-details">
                    <span>IP: ${node.id}</span>
                    <span>Packets: ${packetCount.toLocaleString()}</span>
                </div>
                <div class="warp-result-match">${matchText}</div>
            </div>
        `;
    }).join('');

    // Add click handlers
    results.querySelectorAll('.warp-result-item').forEach(item => {
        item.onclick = () => {
            const index = parseInt(item.dataset.index);
            selectWarpDestination(index);
        };
    });
}

// Update selected result highlight
function updateWarpSelection() {
    const results = document.getElementById('warpDriveResults');
    if (!results) return;

    results.querySelectorAll('.warp-result-item').forEach((item, index) => {
        if (index === gameMode.warpSelectedIndex) {
            item.classList.add('selected');
            item.scrollIntoView({ block: 'nearest' });
        } else {
            item.classList.remove('selected');
        }
    });
}

// Select and warp to destination
function selectWarpDestination(index) {
    if (index === undefined) index = gameMode.warpSelectedIndex;
    if (!gameMode.warpResults[index]) return;

    const result = gameMode.warpResults[index];
    const targetNode = result.node;

    // Find the planet mesh for this node
    let targetMesh = null;
    for (const mesh of gameMode.nodeMeshes) {
        const data = gameMode.nodeDataMap.get(mesh.uuid);
        if (data && data.id === targetNode.id) {
            targetMesh = mesh;
            break;
        }
    }

    if (!targetMesh) {
        console.warn('Could not find planet for node:', targetNode.id);
        closeWarpDrive();
        return;
    }

    // Start warp sequence
    initiateWarp(targetMesh, targetNode);
}

// Initiate warp travel to destination
function initiateWarp(targetMesh, targetNode) {
    gameMode.isWarping = true;

    const status = document.getElementById('warpDriveStatus');
    if (status) {
        status.textContent = 'ENGAGING';
        status.className = 'warp-drive-status warping';
    }

    // Close search overlay after brief delay
    setTimeout(() => {
        closeWarpDrive();
    }, 300);

    // Show warp effect
    const effectOverlay = document.getElementById('warpEffectOverlay');
    const streaksContainer = document.getElementById('warpStreaks');
    const destinationLabel = document.getElementById('warpDestination');

    if (effectOverlay) {
        effectOverlay.classList.add('active');

        // Create warp streaks
        if (streaksContainer) {
            streaksContainer.innerHTML = '';
            for (let i = 0; i < 60; i++) {
                const streak = document.createElement('div');
                streak.className = 'warp-streak';
                const angle = (Math.random() * 360);
                const delay = Math.random() * 0.3;
                streak.style.transform = `rotate(${angle}deg)`;
                streak.style.animationDelay = `${delay}s`;
                streak.style.left = `${50 + (Math.random() - 0.5) * 20}%`;
                streak.style.top = `${50 + (Math.random() - 0.5) * 20}%`;
                streaksContainer.appendChild(streak);
            }
        }

        // Show destination name
        if (destinationLabel) {
            destinationLabel.textContent = targetNode.label || targetNode.id;
        }
    }

    // Get target position (slightly in front of planet)
    const targetData = gameMode.nodeDataMap.get(targetMesh.uuid);
    const planetSize = targetData ? targetData.size : 2000;
    const targetPos = targetMesh.position.clone();

    // Calculate viewing position (in front of and slightly above the planet)
    const cameraOffset = planetSize * 3;
    const viewDirection = new THREE.Vector3()
        .subVectors(gameMode.camera.position, targetPos)
        .normalize();

    const finalPosition = targetPos.clone().add(viewDirection.multiplyScalar(cameraOffset));
    finalPosition.y += planetSize * 0.5;

    // Store starting position
    const startPosition = gameMode.camera.position.clone();
    const startTime = Date.now();
    const warpDuration = 2000; // 2 seconds

    // Animate warp travel
    function animateWarp() {
        const elapsed = Date.now() - startTime;
        const progress = Math.min(elapsed / warpDuration, 1);

        // Easing function for smooth acceleration/deceleration
        const easeProgress = progress < 0.5
            ? 4 * progress * progress * progress
            : 1 - Math.pow(-2 * progress + 2, 3) / 2;

        // Update camera position
        gameMode.camera.position.lerpVectors(startPosition, finalPosition, easeProgress);

        // Make camera look at target during warp
        const lookAtProgress = Math.min(progress * 1.5, 1);
        if (lookAtProgress < 1) {
            const currentTarget = new THREE.Vector3().lerpVectors(
                startPosition.clone().add(new THREE.Vector3(0, 0, -1000)),
                targetPos,
                lookAtProgress
            );
            gameMode.camera.lookAt(currentTarget);
        } else {
            gameMode.camera.lookAt(targetPos);
        }

        if (progress < 1) {
            requestAnimationFrame(animateWarp);
        } else {
            // Warp complete
            completeWarp(targetMesh, targetNode);
        }
    }

    animateWarp();
}

// Complete warp sequence
function completeWarp(targetMesh, targetNode) {
    // Flash effect
    const container = document.getElementById('gameModeContainer');
    const flash = document.createElement('div');
    flash.className = 'warp-flash active';
    container.appendChild(flash);

    setTimeout(() => {
        flash.remove();
    }, 600);

    // Hide warp effect
    const effectOverlay = document.getElementById('warpEffectOverlay');
    if (effectOverlay) {
        effectOverlay.classList.remove('active');
        const streaksContainer = document.getElementById('warpStreaks');
        if (streaksContainer) streaksContainer.innerHTML = '';
    }

    // Lock onto the target
    gameMode.lockedTarget = { mesh: targetMesh, data: targetNode };

    // Update targeting UI
    const reticle = document.getElementById('targetingReticle');
    const targetPanel = document.querySelector('.hud-panel-right');
    if (reticle) reticle.classList.add('locked');
    if (targetPanel) targetPanel.classList.add('locked');

    // Show planet info
    const planetInfoScreen = document.getElementById('planetInfoScreen');
    if (planetInfoScreen) {
        planetInfoScreen.classList.add('show');
        const packetCount = metaPacketCount(targetNode) || 0;
        planetInfoScreen.innerHTML = `
            <h4>DESTINATION REACHED</h4>
            <div class="info-item"><strong>ID:</strong> ${targetNode.id}</div>
            <div class="info-item"><strong>HOST:</strong> ${targetNode.label || 'Unknown'}</div>
            <div class="info-item"><strong>PACKETS:</strong> ${packetCount.toLocaleString()}</div>
        `;
    }

    gameMode.isWarping = false;

    // Reset camera velocity
    gameMode.currentSpeed = 0;
    gameMode.velocity.set(0, 0, 0);
}

// Handle warp drive keyboard input
function handleWarpKeyDown(e) {
    if (!gameMode.warpDriveActive) return false;

    switch (e.key) {
        case 'Escape':
            closeWarpDrive();
            return true;

        case 'ArrowDown':
            e.preventDefault();
            if (gameMode.warpResults.length > 0) {
                gameMode.warpSelectedIndex = (gameMode.warpSelectedIndex + 1) % gameMode.warpResults.length;
                updateWarpSelection();
            }
            return true;

        case 'ArrowUp':
            e.preventDefault();
            if (gameMode.warpResults.length > 0) {
                gameMode.warpSelectedIndex = (gameMode.warpSelectedIndex - 1 + gameMode.warpResults.length) % gameMode.warpResults.length;
                updateWarpSelection();
            }
            return true;

        case 'Enter':
            e.preventDefault();
            if (gameMode.warpResults.length > 0) {
                selectWarpDestination();
            }
            return true;
    }

    return false;
}

// ==================== END WARP DRIVE SYSTEM ====================

// Get node color based on traffic
function getNodeColor(node) {
    const packets = metaPacketCount(node);

    // Color gradient based on traffic intensity
    if (packets > 1000) return 0xff4444; // Red - high traffic
    if (packets > 500) return 0xff8844; // Orange
    if (packets > 100) return 0xffcc44; // Yellow
    if (packets > 10) return 0x44ff88; // Green
    return 0x4488ff; // Blue - low traffic
}

// Animation loop
function animateGameScene() {
    if (!gameMode.active) return;

    gameMode.animationId = requestAnimationFrame(animateGameScene);

    // Handle movement with realistic spacecraft physics
    const maxSpeed = 150;  // Cruising speed for vast distances
    const boostSpeed = 400; // When holding shift
    const acceleration = 0.02;  // Slow, realistic acceleration
    const deceleration = 0.015; // Gradual slowdown (space has no friction but thrusters)
    const direction = new THREE.Vector3();

    // Calculate target speed - slower, more deliberate movement
    let targetForwardSpeed = 0;
    const currentMaxSpeed = gameMode.boosting ? boostSpeed : maxSpeed;
    if (gameMode.moveForward) targetForwardSpeed = -currentMaxSpeed;
    if (gameMode.moveBackward) targetForwardSpeed = currentMaxSpeed * 0.5; // Reverse is slower

    // Very smooth speed interpolation for realistic feel
    if (targetForwardSpeed !== 0) {
        gameMode.currentSpeed += (targetForwardSpeed - gameMode.currentSpeed) * acceleration;
    } else {
        gameMode.currentSpeed *= (1 - deceleration);
        if (Math.abs(gameMode.currentSpeed) < 0.5) gameMode.currentSpeed = 0;
    }

    direction.z = gameMode.currentSpeed;
    // Strafe is slower than forward movement
    if (gameMode.moveLeft) direction.x -= currentMaxSpeed * 0.3;
    if (gameMode.moveRight) direction.x += currentMaxSpeed * 0.3;
    if (gameMode.moveUp) direction.y += currentMaxSpeed * 0.2;
    if (gameMode.moveDown) direction.y -= currentMaxSpeed * 0.2;

    // Apply camera rotation to movement
    direction.applyQuaternion(gameMode.camera.quaternion);
    gameMode.camera.position.add(direction);

    // Update speed effects
    updateSpeedEffects();

    // Animate planets with realistic motion
    gameMode.nodeMeshes.forEach(planetGroup => {
        const data = gameMode.nodeDataMap.get(planetGroup.uuid);
        if (data) {
            // Orbital motion
            data.orbitAngle += data.orbitSpeed;
            planetGroup.position.x = Math.cos(data.orbitAngle) * data.orbitRadius;
            planetGroup.position.z = Math.sin(data.orbitAngle) * data.orbitRadius;
            planetGroup.position.y += Math.sin(data.orbitAngle * 2) * data.orbitTilt * 0.5;

            // Planet self-rotation
            if (planetGroup.children[0]) {
                planetGroup.children[0].rotation.y += data.rotationSpeed;
            }

            // Animate moons
            planetGroup.children.forEach(child => {
                if (child.userData.moonOrbitRadius) {
                    child.userData.moonOrbitAngle += child.userData.moonOrbitSpeed;
                    child.position.x = Math.cos(child.userData.moonOrbitAngle) * child.userData.moonOrbitRadius;
                    child.position.z = Math.sin(child.userData.moonOrbitAngle) * child.userData.moonOrbitRadius;
                }
            });
        }
    });

    // Animate space elevators (node-to-node communication beams)
    animateSpaceElevators();

    // Real-time traffic visualization
    processTrafficEvents();
    animateTrafficBursts();
    animatePlanetPulses();
    updateElevatorIntensity();

    // Slowly rotate starfield for parallax effect
    if (gameMode.stars) {
        gameMode.stars.rotation.y += 0.00003;
        gameMode.stars.rotation.x += 0.00001;
    }

    // Animate star twinkling
    if (gameMode.starTwinkleData) {
        const time = Date.now() * 0.001;

        // Twinkle bright stars
        if (gameMode.starTwinkleData.brightStars) {
            const { material, baseSize, phases } = gameMode.starTwinkleData.brightStars;
            const twinkleFactor = 0.3;
            let avgTwinkle = 0;
            for (let i = 0; i < Math.min(phases.length, 100); i++) {
                avgTwinkle += Math.sin(time * (1 + (i % 10) * 0.1) + phases[i]);
            }
            avgTwinkle = avgTwinkle / 100;
            material.size = baseSize * (1 + avgTwinkle * twinkleFactor);
        }

        // Twinkle super bright stars more dramatically
        if (gameMode.starTwinkleData.superBright) {
            const { material, baseSize, phases } = gameMode.starTwinkleData.superBright;
            const twinkleFactor = 0.4;
            let avgTwinkle = 0;
            for (let i = 0; i < Math.min(phases.length, 50); i++) {
                avgTwinkle += Math.sin(time * 0.8 * (1 + (i % 5) * 0.2) + phases[i]);
            }
            avgTwinkle = avgTwinkle / 50;
            material.size = baseSize * (1 + avgTwinkle * twinkleFactor);
            material.opacity = 0.85 + avgTwinkle * 0.15;
        }
    }

    // Occasional shooting stars
    if (Math.random() < 0.002 && !gameMode.shootingStar) {
        createShootingStar();
    }

    // Update shooting star if active
    if (gameMode.shootingStar) {
        updateShootingStar();
    }

    // Animate nebulae with subtle drift
    gameMode.nebulae.forEach((nebula, i) => {
        nebula.rotation.y += 0.00002 * (i % 2 === 0 ? 1 : -1);
        nebula.rotation.z += 0.00001;
        // Subtle pulsing
        nebula.material.opacity = nebula.userData.baseOpacity * (0.9 + 0.1 * Math.sin(Date.now() * 0.0005 + i));
    });

    // Animate sun flares - rotate and pulse
    if (gameMode.sunFlares) {
        gameMode.sunFlares.rotation.y += 0.0003;
        gameMode.sunFlares.rotation.x += 0.0001;
        gameMode.sunFlares.material.opacity = 0.5 + 0.2 * Math.sin(Date.now() * 0.001);
    }

    // Animate instanced asteroids (single draw call)
    if (gameMode.asteroidMesh && gameMode.asteroidOrbits) {
        const dummy = new THREE.Object3D();
        const orbits = gameMode.asteroidOrbits;
        // Only update a subset each frame for performance (stagger over 4 frames)
        const frameSlice = gameMode.asteroidCount >> 2; // /4
        const frameOffset = (Math.floor(Date.now() / 16) % 4) * frameSlice;
        const end = Math.min(frameOffset + frameSlice, gameMode.asteroidCount);

        for (let i = frameOffset; i < end; i++) {
            orbits[i * 4] += orbits[i * 4 + 2]; // angle += speed
            gameMode.asteroidMesh.getMatrixAt(i, dummy.matrix);
            dummy.matrix.decompose(dummy.position, dummy.quaternion, dummy.scale);
            dummy.position.x = Math.cos(orbits[i * 4]) * orbits[i * 4 + 1];
            dummy.position.z = Math.sin(orbits[i * 4]) * orbits[i * 4 + 1];
            dummy.rotation.y += 0.005;
            dummy.updateMatrix();
            gameMode.asteroidMesh.setMatrixAt(i, dummy.matrix);
        }
        gameMode.asteroidMesh.instanceMatrix.needsUpdate = true;
    }

    // Move ambient dust with camera for parallax
    if (gameMode.ambientDust) {
        gameMode.ambientDust.position.x = gameMode.camera.position.x;
        gameMode.ambientDust.position.y = gameMode.camera.position.y;
        gameMode.ambientDust.position.z = gameMode.camera.position.z;
        gameMode.ambientDust.rotation.y += 0.0001;
    }

    // Animate blinky buttons
    for (let i = 0; i < 8; i++) {
        const button = gameMode.camera.getObjectByName("blinky_button_" + i);
        if (button) {
            button.material.emissiveIntensity = 0.4 + Math.abs(Math.sin(Date.now() * 0.003 * (i + 1))) * 0.6;
        }
    }

    // Animate warning lights
    for (let i = 0; i < 4; i++) {
        const warning = gameMode.camera.getObjectByName("warning_light_" + i);
        if (warning) {
            warning.material.opacity = 0.5 + Math.abs(Math.sin(Date.now() * 0.004 + i * 1.5)) * 0.5;
        }
    }

    // Animate holographic display
    const holoDisplay = gameMode.camera.getObjectByName("holo_display");
    if (holoDisplay) {
        holoDisplay.material.opacity = 0.08 + Math.abs(Math.sin(Date.now() * 0.002)) * 0.07;
    }

    // Auto-lock targeting - find nearest planet to screen center
    const reticle = document.getElementById('targetingReticle');
    const targetPanel = document.querySelector('.hud-panel-right');
    const targetIp = document.getElementById('targetIp');
    const targetPackets = document.getElementById('targetPackets');
    const hostnameLabel = document.getElementById('planetHostnameLabel');
    const hostnameText = document.getElementById('hostnameText');
    const hostnameIpText = document.getElementById('hostnameIp');

    const screenCenterX = window.innerWidth / 2;
    const screenCenterY = window.innerHeight / 2;
    const autoLockRadius = 300; // Pixels from center to auto-lock

    let nearestPlanet = null;
    let nearestDistance = Infinity;
    let nearestScreenPos = null;

    // Check all planets and find the nearest one to screen center
    gameMode.nodeMeshes.forEach(group => {
        const nodeData = gameMode.nodeDataMap.get(group.uuid);
        if (!nodeData) return;

        // Project planet position to screen
        const vector = group.position.clone();
        vector.project(gameMode.camera);

        // Check if in front of camera
        if (vector.z > 1) return;

        const screenX = (vector.x * 0.5 + 0.5) * window.innerWidth;
        const screenY = (-(vector.y * 0.5) + 0.5) * window.innerHeight;

        // Calculate distance from screen center
        const dx = screenX - screenCenterX;
        const dy = screenY - screenCenterY;
        const distance = Math.sqrt(dx * dx + dy * dy);

        // Check if within auto-lock radius and closer than current nearest
        if (distance < autoLockRadius && distance < nearestDistance) {
            nearestDistance = distance;
            nearestPlanet = { mesh: group, data: nodeData };
            nearestScreenPos = { x: screenX, y: screenY };
        }
    });

    if (nearestPlanet) {
        // Lock onto nearest planet
        reticle.classList.add('locked');
        if (targetPanel) targetPanel.classList.add('locked');
        gameMode.lockedTarget = nearestPlanet;
        gameMode.autoLockPosition = nearestScreenPos;

        // Move reticle to planet position
        reticle.style.left = nearestScreenPos.x + 'px';
        reticle.style.top = nearestScreenPos.y + 'px';
        reticle.style.transform = 'translate(-50%, -50%)';

        // Update target info in Shodan HUD style
        if (targetIp) targetIp.textContent = nearestPlanet.data.id;
        if (targetPackets) targetPackets.textContent = nearestPlanet.data.packetCount.toLocaleString();

        // Show floating hostname label above the reticle
        if (hostnameLabel) {
            hostnameLabel.classList.add('visible', 'locked');
            hostnameLabel.style.left = nearestScreenPos.x + 'px';
            hostnameLabel.style.top = (nearestScreenPos.y - 50) + 'px';

            // Get hostname (label) and IP
            const hostname = nearestPlanet.data.label || nearestPlanet.data.id;
            const ip = nearestPlanet.data.id;

            if (hostnameText) hostnameText.textContent = hostname;
            if (hostnameIpText) hostnameIpText.textContent = ip !== hostname ? ip : '';
        }
    } else {
        // No target - reset reticle to center
        reticle.classList.remove('locked');
        if (targetPanel) targetPanel.classList.remove('locked');
        if (targetIp) targetIp.textContent = '---';
        if (targetPackets) targetPackets.textContent = '---';
        gameMode.lockedTarget = null;
        gameMode.autoLockPosition = { x: screenCenterX, y: screenCenterY };

        // Reset reticle to center
        reticle.style.left = '50%';
        reticle.style.top = '50%';
        reticle.style.transform = 'translate(-50%, -50%)';

        // Hide hostname label
        if (hostnameLabel) {
            hostnameLabel.classList.remove('visible', 'locked');
        }
    }

    // Render
    gameMode.renderer.render(gameMode.scene, gameMode.camera);
}

// Update speed visual effects
function updateSpeedEffects() {
    const speedLines = document.getElementById('speedLines');
    const warpTunnel = document.getElementById('warpTunnel');
    const speedFill = document.getElementById('speedFill');
    const speedValue = document.getElementById('speedValue');
    const velocityBar = document.querySelector('.hud-velocity-bar');

    const absSpeed = Math.abs(gameMode.currentSpeed);
    const maxDisplaySpeed = gameMode.boosting ? 400 : 150;
    const speedPercent = Math.min((absSpeed / maxDisplaySpeed) * 100, 100);

    // Update speed bar
    if (speedFill) {
        speedFill.style.width = speedPercent + '%';
        // Change color when boosting
        if (gameMode.boosting && absSpeed > 100) {
            speedFill.style.background = 'linear-gradient(90deg, rgba(255, 100, 50, 0.8), rgba(255, 200, 50, 1), rgba(255, 255, 150, 1))';
            speedFill.style.boxShadow = '0 0 15px rgba(255, 150, 50, 0.8), inset 0 0 5px rgba(255, 255, 255, 0.5)';
        } else {
            speedFill.style.background = '';
            speedFill.style.boxShadow = '';
        }
    }
    if (speedValue) speedValue.textContent = Math.round(absSpeed);

    // Determine direction
    const isReverse = gameMode.currentSpeed > 0;
    if (speedFill) speedFill.classList.toggle('reverse', isReverse);
    if (speedLines) speedLines.classList.toggle('reverse', isReverse);
    if (warpTunnel) warpTunnel.classList.toggle('reverse', isReverse);

    // Activate effects based on speed
    if (absSpeed > 50) {
        if (speedLines) speedLines.classList.add('active');
        if (!gameMode.speedLinesActive) {
            gameMode.speedLinesActive = true;
            // Regenerate speed lines with random positions
            if (speedLines) {
                const lines = speedLines.querySelectorAll('.speed-line');
                lines.forEach(line => {
                    line.style.left = Math.random() * 100 + '%';
                    line.style.animationDelay = Math.random() * 0.3 + 's';
                });
            }
        }
    } else {
        if (speedLines) speedLines.classList.remove('active');
        gameMode.speedLinesActive = false;
    }

    // Warp tunnel at high speed or when boosting
    if (absSpeed > 200 || (gameMode.boosting && absSpeed > 100)) {
        if (warpTunnel) warpTunnel.classList.add('active');
    } else {
        if (warpTunnel) warpTunnel.classList.remove('active');
    }
}

// Handle keyboard input for movement
function handleGameKeyDown(e) {
    if (!gameMode.active) return;

    // Handle warp drive input first
    if (gameMode.warpDriveActive) {
        if (handleWarpKeyDown(e)) return;
    }

    // Check for "/" key to open warp drive
    if (e.key === '/' && !gameMode.warpDriveActive && !gameMode.isWarping) {
        e.preventDefault();
        openWarpDrive();
        return;
    }

    switch (e.code) {
        case 'KeyW':
            gameMode.moveForward = true;
            break;
        case 'KeyS':
            gameMode.moveBackward = true;
            break;
        case 'KeyA':
            gameMode.moveLeft = true;
            break;
        case 'KeyD':
            gameMode.moveRight = true;
            break;
        case 'Space':
            gameMode.moveUp = true;
            break;
        case 'ControlLeft':
        case 'ControlRight':
        case 'KeyC':
            gameMode.moveDown = true;
            break;
        case 'ShiftLeft':
        case 'ShiftRight':
            gameMode.boosting = true;
            break;
        case 'Escape':
            // Close warp drive if open, otherwise exit game mode
            if (gameMode.warpDriveActive) {
                closeWarpDrive();
            } else {
                toggleGameMode();
            }
            break;
    }
}

function handleGameKeyUp(e) {
    if (!gameMode.active) return;

    switch (e.code) {
        case 'KeyW':
            gameMode.moveForward = false;
            break;
        case 'KeyS':
            gameMode.moveBackward = false;
            break;
        case 'KeyA':
            gameMode.moveLeft = false;
            break;
        case 'KeyD':
            gameMode.moveRight = false;
            break;
        case 'Space':
            gameMode.moveUp = false;
            break;
        case 'ControlLeft':
        case 'ControlRight':
        case 'KeyC':
            gameMode.moveDown = false;
            break;
        case 'ShiftLeft':
        case 'ShiftRight':
            gameMode.boosting = false;
            break;
    }
}

// Handle mouse movement for camera rotation
function handleGameMouseMove(e) {
    if (!gameMode.active) return;
    if (document.pointerLockElement !== document.getElementById('gameCanvas')) return;

    const movementX = e.movementX || 0;
    const movementY = e.movementY || 0;

    gameMode.euler.setFromQuaternion(gameMode.camera.quaternion);

    gameMode.euler.y -= movementX * 0.002;
    gameMode.euler.x -= movementY * 0.002;

    // Clamp vertical rotation
    gameMode.euler.x = Math.max(-gameMode.PI_2, Math.min(gameMode.PI_2, gameMode.euler.x));

    gameMode.camera.quaternion.setFromEuler(gameMode.euler);
}

// Handle click for shooting laser
function handleGameClick(e) {
    if (!gameMode.active) return;
    if (gameMode.laserCooldown) return;

    // Request pointer lock if not locked
    if (document.pointerLockElement !== document.getElementById('gameCanvas')) {
        document.getElementById('gameCanvas').requestPointerLock();
        return;
    }

    // Fire laser
    fireLaser();
}

// Fire laser effect - moving projectile beams from bottom corners to reticle
function fireLaser() {
    if (gameMode.laserCooldown) return;
    gameMode.laserCooldown = true;

    const container = document.getElementById('gameModeContainer');
    const reticle = document.getElementById('targetingReticle');
    const containerRect = container.getBoundingClientRect();

    // Get reticle position (center of screen or locked target position)
    let targetX = containerRect.width / 2;
    let targetY = containerRect.height / 2;

    if (reticle && gameMode.autoLockPosition) {
        targetX = gameMode.autoLockPosition.x;
        targetY = gameMode.autoLockPosition.y;
    }

    // Bottom corner positions
    const leftStart = { x: 40, y: containerRect.height - 60 };
    const rightStart = { x: containerRect.width - 40, y: containerRect.height - 60 };

    // Create and animate left laser
    const laserLeft = document.createElement('div');
    laserLeft.className = 'laser-beam laser-left';
    container.appendChild(laserLeft);
    animateLaserProjectile(laserLeft, leftStart, { x: targetX, y: targetY }, 200);

    // Create and animate right laser
    const laserRight = document.createElement('div');
    laserRight.className = 'laser-beam laser-right';
    container.appendChild(laserRight);
    animateLaserProjectile(laserRight, rightStart, { x: targetX, y: targetY }, 200);

    // Remove after animation
    setTimeout(() => {
        laserLeft.remove();
        laserRight.remove();
        gameMode.laserCooldown = false;
    }, 250);

    // Check if we hit a target
    if (gameMode.lockedTarget) {
        const { mesh, data } = gameMode.lockedTarget;

        // Create hit effect in 3D scene
        createHitEffect(mesh.position.clone(), data);

        // Flash the planet
        if (mesh.children && mesh.children[0] && mesh.children[0].material) {
            const planet = mesh.children[0];
            const originalEmissive = planet.material.emissiveIntensity;
            planet.material.emissiveIntensity = 1;
            setTimeout(() => {
                planet.material.emissiveIntensity = originalEmissive;
            }, 200);
        }

        // Create packet data explosion
        createPacketExplosion(mesh.position.clone(), data);

        // Show detailed stats
        showNodeScanResult(data);

        // Show planet info screen
        const planetInfoScreen = document.getElementById('planetInfoScreen');
        planetInfoScreen.classList.add('show');
        planetInfoScreen.innerHTML = `
            <h4>PLANET SCAN</h4>
            <div class="info-item"><strong>ID:</strong> ${data.id}</div>
            <div class="info-item"><strong>HOST:</strong> ${data.label || 'Unknown'}</div>
            <div class="info-item"><strong>PACKETS:</strong> ${data.packetCount.toLocaleString()}</div>
            <div class="info-item"><strong>BYTES:</strong> ${metaByteCount(data) || 'N/A'}</div>
        `;

        // Fetch and display a random TCP stream
        displayRandomStream(data);
    }
}

// Fetch and display a random TCP stream in tail-like fashion
async function displayRandomStream(nodeData) {
    const terminal = document.getElementById('streamTerminal');
    const title = document.getElementById('streamTerminalTitle');
    const status = document.getElementById('streamTerminalStatus');
    const content = document.getElementById('streamTerminalContent');

    if (!terminal || !content) return;

    // Show terminal
    terminal.style.display = 'block';
    content.innerHTML = '<span class="stream-cursor">_</span>';
    status.textContent = 'CONNECTING...';
    status.className = 'stream-terminal-status connecting';

    try {
        // Fetch available streams
        const streamsResponse = await fetch('/api/streams');
        if (!streamsResponse.ok) throw new Error('Failed to fetch streams');

        const streams = await streamsResponse.json();
        if (!streams || streams.length === 0) {
            content.innerHTML = '<span class="stream-error">NO STREAMS AVAILABLE</span>';
            status.textContent = 'NO DATA';
            return;
        }

        // Pick a random stream
        const randomStream = streams[Math.floor(Math.random() * streams.length)];

        // Update title with stream info
        title.textContent = `// TCP STREAM [${randomStream.src_port || '?'} → ${randomStream.dst_port || '?'}]`;
        status.textContent = 'STREAMING';
        status.className = 'stream-terminal-status active';

        // Fetch the stream content
        const streamResponse = await fetch(`/api/stream?id=${randomStream.id}`);
        if (!streamResponse.ok) throw new Error('Failed to fetch stream content');

        const streamData = await streamResponse.json();
        const streamText = streamData.data || streamData.content || JSON.stringify(streamData, null, 2);

        // Display in tail-like fashion (character by character)
        content.innerHTML = '';
        displayStreamText(content, streamText, 0);

    } catch (error) {
        console.error('Stream fetch error:', error);
        content.innerHTML = `<span class="stream-error">ERROR: ${error.message}</span>`;
        status.textContent = 'ERROR';
        status.className = 'stream-terminal-status error';
    }
}

// Display text character by character like tail
function displayStreamText(container, text, index) {
    if (index >= text.length || index >= 2000) { // Limit to 2000 chars
        // Add blinking cursor at end
        const cursor = document.createElement('span');
        cursor.className = 'stream-cursor';
        cursor.textContent = '_';
        container.appendChild(cursor);

        // Update status
        const status = document.getElementById('streamTerminalStatus');
        if (status) {
            status.textContent = 'COMPLETE';
            status.className = 'stream-terminal-status complete';
        }
        return;
    }

    const char = text[index];

    if (char === '\n') {
        container.appendChild(document.createElement('br'));
    } else if (char === ' ') {
        container.appendChild(document.createTextNode('\u00A0'));
    } else {
        const span = document.createElement('span');
        span.textContent = char;
        span.className = 'stream-char';
        container.appendChild(span);
    }

    // Auto-scroll to bottom
    container.scrollTop = container.scrollHeight;

    // Speed varies: faster for spaces/newlines, slower for other chars
    const delay = (char === ' ' || char === '\n') ? 5 : 15;

    setTimeout(() => {
        displayStreamText(container, text, index + 1);
    }, delay);
}

// Animate laser projectile from start to end position
function animateLaserProjectile(laser, start, end, duration) {
    const startTime = performance.now();

    // Calculate angle from start to end
    const dx = end.x - start.x;
    const dy = end.y - start.y;
    const angle = Math.atan2(dy, dx) * (180 / Math.PI);
    const distance = Math.sqrt(dx * dx + dy * dy);

    // Set initial position and rotation
    laser.style.left = start.x + 'px';
    laser.style.top = start.y + 'px';
    laser.style.transform = `rotate(${angle}deg)`;
    laser.style.transformOrigin = 'center center';

    function animate(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Ease out for smooth deceleration
        const easeProgress = 1 - Math.pow(1 - progress, 2);

        // Calculate current position along the path
        const currentX = start.x + dx * easeProgress;
        const currentY = start.y + dy * easeProgress;

        laser.style.left = currentX + 'px';
        laser.style.top = currentY + 'px';

        // Fade out near the end
        if (progress > 0.7) {
            laser.style.opacity = 1 - ((progress - 0.7) / 0.3);
        }

        if (progress < 1) {
            requestAnimationFrame(animate);
        }
    }

    requestAnimationFrame(animate);
}

// Create hit effect at position
function createHitEffect(position, data) {
    // Project 3D position to 2D screen
    const vector = position.clone();
    vector.project(gameMode.camera);

    const x = (vector.x * 0.5 + 0.5) * window.innerWidth;
    const y = (-(vector.y * 0.5) + 0.5) * window.innerHeight;

    // Create hit effect element
    const container = document.getElementById('gameModeContainer');
    const hit = document.createElement('div');
    hit.className = 'hit-effect';
    hit.style.left = x + 'px';
    hit.style.top = y + 'px';
    container.appendChild(hit);

    // Remove after animation
    setTimeout(() => hit.remove(), 300);
}

// Create packet data explosion effect
function createPacketExplosion(position, data) {
    // Project 3D position to 2D screen
    const vector = position.clone();
    vector.project(gameMode.camera);

    const centerX = (vector.x * 0.5 + 0.5) * window.innerWidth;
    const centerY = (-(vector.y * 0.5) + 0.5) * window.innerHeight;

    const container = document.getElementById('gameModeContainer');

    // Create explosion container
    const explosion = document.createElement('div');
    explosion.className = 'packet-explosion';
    explosion.style.left = centerX + 'px';
    explosion.style.top = centerY + 'px';

    // Generate packet data particles
    const particleData = [
        { text: data.id, type: 'ip', delay: 0 },
        { text: data.label || 'Unknown Host', type: 'hostname', delay: 50 },
        { text: `${data.packetCount.toLocaleString()} packets`, type: 'packets', delay: 100 },
        { text: metaByteCount(data) || 'N/A bytes', type: 'bytes', delay: 150 },
        { text: data.planetType ? data.planetType.toUpperCase() : 'UNKNOWN', type: 'protocol', delay: 200 },
    ];

    // Add port info if available from title
    const portMatch = data.title?.match(/Port:\s*(\d+)/);
    if (portMatch) {
        particleData.push({ text: `Port ${portMatch[1]}`, type: 'port', delay: 250 });
    }

    // Add additional random packet info
    const extraInfo = [
        'TCP SYN',
        'ACK',
        'PSH',
        'FIN',
        'RST',
        'HTTP/1.1',
        'TLS 1.3',
        'DNS Query',
        'ICMP Echo'
    ];

    // Add 3-5 random extra particles
    const extraCount = 3 + Math.floor(Math.random() * 3);
    for (let i = 0; i < extraCount; i++) {
        particleData.push({
            text: extraInfo[Math.floor(Math.random() * extraInfo.length)],
            type: ['packets', 'bytes', 'protocol', 'port'][Math.floor(Math.random() * 4)],
            delay: 300 + i * 80
        });
    }

    particleData.forEach((item, index) => {
        setTimeout(() => {
            const particle = document.createElement('div');
            particle.className = `packet-particle ${item.type}`;
            particle.textContent = item.text;

            // Random explosion direction
            const angle = (index / particleData.length) * Math.PI * 2 + (Math.random() - 0.5) * 0.5;
            const distance = 60 + Math.random() * 80;
            const tx = Math.cos(angle) * distance;
            const ty = Math.sin(angle) * distance;

            particle.style.setProperty('--tx', tx + 'px');
            particle.style.setProperty('--ty', ty + 'px');

            explosion.appendChild(particle);
        }, item.delay);
    });

    container.appendChild(explosion);

    // Remove explosion container after all animations complete
    setTimeout(() => explosion.remove(), 2500);
}

// Show detailed node scan result
function showNodeScanResult(data) {
    const targetPanel = document.querySelector('.hud-panel-right');

    // Flash the target panel on hit
    if (targetPanel) {
        targetPanel.style.animation = 'none';
        targetPanel.offsetHeight; // Trigger reflow
        targetPanel.style.animation = 'hudHitFlash 0.3s ease-out';
        setTimeout(() => targetPanel.style.animation = '', 300);
    }

    // Could show more detailed packet info here
    console.log('Scanned node:', data);
}

// Update game HUD with current stats
function updateGameHUD() {
    const nodeCount = nodes.length;
    let totalPackets = 0;

    // Sum packets from the meta map (no DataSet copy)
    nodeMeta.forEach(meta => {
        totalPackets += meta.packetCount || 0;
    });

    document.getElementById('gameNodeCount').textContent = nodeCount;
    document.getElementById('gamePacketCount').textContent = totalPackets.toLocaleString();

    // Live traffic rate (events in the last second)
    const now = Date.now();
    const recentBursts = gameMode.trafficBursts.filter(b => now - b.startTime < 1000).length;
    const rateEl = document.getElementById('gameTrafficRate');
    if (rateEl) {
        rateEl.textContent = recentBursts + '/s';
        rateEl.style.color = recentBursts > 10 ? '#e74c3c' : recentBursts > 3 ? '#f39c12' : '#2ecc71';
    }
}

// Handle window resize for game mode
function handleGameResize() {
    if (!gameMode.active || !gameMode.camera || !gameMode.renderer) return;

    const width = window.innerWidth;
    const height = window.innerHeight;

    gameMode.camera.aspect = width / height;
    gameMode.camera.updateProjectionMatrix();
    gameMode.renderer.setSize(width, height);
}

// Refresh game nodes when network data updates - INCREMENTAL version
function refreshGameNodes() {
    if (!gameMode.active) return;

    const allNodes = nodes.get();
    if (allNodes.length === 0) return;

    const currentNodeIds = new Set(allNodes.map(n => n.id));
    const existingNodeIds = new Set(gameMode.nodeIdToMesh.keys());

    // Find nodes to add and remove
    const nodesToAdd = allNodes.filter(n => !existingNodeIds.has(n.id));
    const nodeIdsToRemove = [...existingNodeIds].filter(id => !currentNodeIds.has(id));

    // Remove deleted nodes
    nodeIdsToRemove.forEach(nodeId => {
        const mesh = gameMode.nodeIdToMesh.get(nodeId);
        if (mesh) {
            // Clean up mesh
            while (mesh.children.length > 0) {
                const child = mesh.children[0];
                mesh.remove(child);
                if (child.geometry) child.geometry.dispose();
                if (child.material) child.material.dispose();
            }
            gameMode.scene.remove(mesh);
            if (mesh.geometry) mesh.geometry.dispose();
            if (mesh.material) mesh.material.dispose();

            // Remove from tracking
            const meshIndex = gameMode.nodeMeshes.indexOf(mesh);
            if (meshIndex > -1) gameMode.nodeMeshes.splice(meshIndex, 1);
            gameMode.nodeDataMap.delete(mesh.uuid);
            gameMode.nodeIdToMesh.delete(nodeId);
        }
    });

    // Add new nodes
    if (nodesToAdd.length > 0) {
        addNewGameNodes(nodesToAdd);
    }

    // Update data for existing nodes (packet counts, titles)
    allNodes.forEach(node => {
        const mesh = gameMode.nodeIdToMesh.get(node.id);
        if (mesh) {
            const data = gameMode.nodeDataMap.get(mesh.uuid);
            if (data) {
                const packetCount = metaPacketCount(node) || 1;
                data.packetCount = packetCount;
                data.title = nodeTooltipFor(node.id);
                data.label = node.label;
            }
        }
    });

    // Rebuild elevators if nodes changed OR if the set of edges changed (new connections)
    const allEdges = edges.get().filter(e => !e.hidden);
    const edgeSetHash = allEdges.map(e => e.id).sort().join(',');
    if (nodesToAdd.length > 0 || nodeIdsToRemove.length > 0 || edgeSetHash !== gameMode.lastElevatorEdgeHash) {
        gameMode.lastElevatorEdgeHash = edgeSetHash;
        createSpaceElevators();
    }

    updateGameHUD();
}

// Add new nodes to game mode without rebuilding everything
function addNewGameNodes(newNodes) {
    const allNodes = nodes.get();
    const nodeCount = allNodes.length;
    const rings = Math.ceil(Math.sqrt(nodeCount));

    newNodes.forEach(node => {
        // Find this node's index in the full list for positioning
        const index = allNodes.findIndex(n => n.id === node.id);
        if (index === -1) return;

        const ring = Math.floor(index / Math.max(1, Math.ceil(nodeCount / rings)));
        const positionInRing = index % Math.max(1, Math.ceil(nodeCount / rings));
        const nodesInRing = Math.ceil(nodeCount / rings);

        const orbitRadius = 25000 + ring * 25000;
        const angle = (positionInRing / nodesInRing) * Math.PI * 2 + ring * 0.5;
        const verticalOffset = (seededRandom(node.id, 'voff') - 0.5) * 8000;
        const orbitTilt = (seededRandom(node.id, 'tilt') - 0.5) * 0.4;

        const packetCount = metaPacketCount(node) || 1;
        const baseSize = 1500;
        const maxSize = 6000;
        const size = Math.min(maxSize, baseSize + Math.log10(packetCount + 1) * 1200);

        const planetTypeIndex = hashCode(node.id) % PLANET_TYPES.length;
        const planetType = PLANET_TYPES[Math.abs(planetTypeIndex)];

        const planetGroup = createPlanetMesh(node.id, size, planetType);

        planetGroup.position.set(
            Math.cos(angle) * orbitRadius,
            verticalOffset + Math.sin(angle * 2) * orbitTilt * orbitRadius,
            Math.sin(angle) * orbitRadius
        );

        gameMode.nodeDataMap.set(planetGroup.uuid, {
            id: node.id,
            label: node.label,
            title: nodeTooltipFor(node.id),
            packetCount: packetCount,
            orbitRadius: orbitRadius,
            orbitAngle: angle,
            orbitTilt: orbitTilt,
            orbitSpeed: 0.0003 + seededRandom(node.id, 'orbspd') * 0.0008,
            rotationSpeed: 0.005 + seededRandom(node.id, 'rotspd') * 0.01,
            planetType: planetType.name,
            size: size
        });

        gameMode.scene.add(planetGroup);
        gameMode.nodeMeshes.push(planetGroup);
        gameMode.nodeIdToMesh.set(node.id, planetGroup);
    });
}

// Create a planet mesh for a node (extracted helper)
function createPlanetMesh(nodeId, size, planetType) {
    const planetGroup = new THREE.Group();
    const baseColor = planetType.colors[Math.abs(hashCode(nodeId + 'color')) % planetType.colors.length];

    // Main planet body
    const geometry = new THREE.SphereGeometry(size, 64, 64);
    const material = new THREE.MeshPhongMaterial({
        color: baseColor,
        emissive: baseColor,
        emissiveIntensity: 0.12,
        shininess: 40,
        transparent: false
    });
    const planet = new THREE.Mesh(geometry, material);
    planet.rotation.x = seededRandom(nodeId, 'rotx') * 0.5;
    planet.rotation.z = seededRandom(nodeId, 'rotz') * 0.3;
    planetGroup.add(planet);

    // Surface features
    const featureGeometry = new THREE.SphereGeometry(size * 1.002, 64, 64);
    const featureColor = new THREE.Color(baseColor).offsetHSL(0.05, 0.1, 0.15);
    const featureMaterial = new THREE.MeshPhongMaterial({
        color: featureColor,
        emissive: featureColor,
        emissiveIntensity: 0.08,
        transparent: true,
        opacity: 0.6,
        blending: THREE.AdditiveBlending
    });
    const features = new THREE.Mesh(featureGeometry, featureMaterial);
    features.rotation.y = seededRandom(nodeId, 'feat') * Math.PI;
    planetGroup.add(features);

    // Clouds for atmospheric planets
    if (planetType.hasAtmosphere && seededRandom(nodeId, 'cloud') > 0.3) {
        const cloudGeometry = new THREE.SphereGeometry(size * 1.02, 48, 48);
        const cloudMaterial = new THREE.MeshPhongMaterial({
            color: 0xffffff,
            emissive: 0x222222,
            transparent: true,
            opacity: 0.25,
            blending: THREE.NormalBlending
        });
        const clouds = new THREE.Mesh(cloudGeometry, cloudMaterial);
        clouds.userData.rotationSpeed = 0.0002 + seededRandom(nodeId, 'cloudspd') * 0.0003;
        planetGroup.add(clouds);
    }

    // Atmosphere glow
    if (planetType.hasAtmosphere) {
        const atmosphereGeometry = new THREE.SphereGeometry(size * 1.15, 32, 32);
        const atmosphereMaterial = new THREE.MeshBasicMaterial({
            color: planetType.atmosphereColor,
            transparent: true,
            opacity: 0.15,
            side: THREE.BackSide
        });
        planetGroup.add(new THREE.Mesh(atmosphereGeometry, atmosphereMaterial));
    }

    // Rings
    const hasRings = planetType.hasRings || (size > 1500 && seededRandom(nodeId, 'rings') > 0.5);
    if (hasRings) {
        const ringGeometry = new THREE.RingGeometry(size * 1.4, size * 2.2, 64);
        const ringMaterial = new THREE.MeshBasicMaterial({
            color: 0xccbb99,
            transparent: true,
            opacity: 0.4,
            side: THREE.DoubleSide
        });
        const rings = new THREE.Mesh(ringGeometry, ringMaterial);
        rings.rotation.x = Math.PI / 2 + (seededRandom(nodeId, 'ringtilt') - 0.5) * 0.3;
        planetGroup.add(rings);
    }

    // Moons
    if (size > 200 && seededRandom(nodeId, 'hasmoon') > 0.4) {
        const moonCount = Math.floor(seededRandom(nodeId, 'moonct') * 4) + 1;
        for (let m = 0; m < moonCount; m++) {
            const moonSize = size * (0.08 + seededRandom(nodeId, 'moonsz' + m) * 0.12);
            const moonDistance = size * (1.4 + m * 0.5 + seededRandom(nodeId, 'moondst' + m) * 0.3);
            const moonGeometry = new THREE.SphereGeometry(moonSize, 24, 24);
            const moonMaterial = new THREE.MeshPhongMaterial({
                color: 0x999999,
                emissive: 0x333333,
                emissiveIntensity: 0.15
            });
            const moon = new THREE.Mesh(moonGeometry, moonMaterial);
            moon.userData.moonOrbitRadius = moonDistance;
            moon.userData.moonOrbitSpeed = 0.008 + seededRandom(nodeId, 'moonspd' + m) * 0.012;
            // Spread moons evenly around planet, plus small random offset
            const baseAngle = (m / moonCount) * Math.PI * 2;
            const randomOffset = (seededRandom(nodeId, 'moonang' + m) - 0.5) * 0.5;
            moon.userData.moonOrbitAngle = baseAngle + randomOffset;
            // Position moon using its orbit angle
            moon.position.set(
                Math.cos(moon.userData.moonOrbitAngle) * moonDistance,
                0,
                Math.sin(moon.userData.moonOrbitAngle) * moonDistance
            );
            planetGroup.add(moon);
        }
    }

    return planetGroup;
}

// Start the application when DOM is ready
document.addEventListener('DOMContentLoaded', init);

// ============================================================================
// History + Timeline (SQLite persistence): browse stored capture sessions and
// scrub/play through one. The server rebuilds the graph from time-bucketed
// flow stats over a sliding window ending at the scrub position (setTimeline
// control message), so the view morphs through time like the live view would
// have looked. Hidden entirely unless the server runs with -db.

const timeline = {
    active: false,
    captureId: 0,
    first: 0,          // capture bounds, unix seconds
    last: 0,
    t: 0,              // current scrub position (unix seconds)
    window: 60,        // sliding window (matches live decay)
    step: 1,
    points: [],        // overview series for the sparkline
    playing: false,
    playTimer: null,
    lastSent: 0,
    sendTimer: null,
};

async function initHistoryUI() {
    // Probe the history API: 501 means the server runs without -db and the
    // whole feature stays hidden.
    let resp;
    try {
        resp = await fetch('/api/history/captures');
    } catch (e) {
        return;
    }
    if (!resp.ok) return;

    const navItem = document.getElementById('historyNavItem');
    if (navItem) navItem.style.display = '';

    const toggle = document.getElementById('historyToggle');
    const submenu = document.getElementById('historySubmenu');
    if (toggle && submenu) {
        toggle.addEventListener('click', function(e) {
            e.stopPropagation();
            // Same behavior as setupDropdowns' toggleSubmenu (not in scope here).
            document.querySelectorAll('.nav-link').forEach(btn => {
                if (btn !== toggle) btn.classList.remove('active');
            });
            document.querySelectorAll('.submenu').forEach(sub => {
                if (sub !== submenu) sub.classList.remove('show');
            });
            toggle.classList.toggle('active');
            submenu.classList.toggle('show');
            if (submenu.classList.contains('show')) loadCaptureHistory();
        });
    }

    const playBtn = document.getElementById('timelinePlayButton');
    const exitBtn = document.getElementById('timelineExitButton');
    const slider = document.getElementById('historyTimelineSlider');
    if (playBtn) playBtn.addEventListener('click', toggleTimelinePlay);
    if (exitBtn) exitBtn.addEventListener('click', exitTimeline);
    if (slider) slider.addEventListener('input', onTimelineSlider);
    window.addEventListener('resize', () => {
        if (timeline.active) drawTimelineSparkline();
    });
}

async function loadCaptureHistory() {
    const list = document.getElementById('historyList');
    if (!list) return;
    try {
        const resp = await fetch('/api/history/captures');
        const data = await resp.json();
        const captures = (data.captures || []).filter(c => c.lastBucket > c.firstBucket);
        if (!captures.length) {
            list.innerHTML = '<div class="loading">No stored captures yet</div>';
            return;
        }
        list.innerHTML = '';
        captures.forEach(c => {
            const item = document.createElement('div');
            item.className = 'history-item';
            const span = c.lastBucket - c.firstBucket;
            const when = new Date(c.firstBucket * 1000).toLocaleString();
            item.innerHTML =
                `<div class="history-item-title"><span>${escapeHtml(c.source)}</span>` +
                `<span class="history-item-kind">${escapeHtml(c.kind)}</span></div>` +
                `<div class="history-item-meta">${when} · ${formatTimelineDuration(span)} · ` +
                `${c.nodes} hosts · ${c.packets.toLocaleString()} pkts</div>`;
            item.addEventListener('click', () => enterTimeline(c));
            list.appendChild(item);
        });
    } catch (e) {
        list.innerHTML = '<div class="loading">Failed to load captures</div>';
    }
}

async function enterTimeline(capture) {
    // Overview resolution: aim for ~300 sparkline buckets across the capture.
    const span = Math.max(1, capture.lastBucket - capture.firstBucket);
    const step = Math.max(1, Math.ceil(span / 300));
    let d;
    try {
        const resp = await fetch(`/api/timeline?capture=${capture.id}&step=${step}`);
        d = await resp.json();
    } catch (e) {
        return;
    }
    if (!d.points || !d.points.length) return;

    stopTimelinePlay();
    timeline.active = true;
    timeline.captureId = d.captureId;
    timeline.first = d.first;
    timeline.last = d.last + 1; // scrub end = after the final bucket
    timeline.step = d.step;
    timeline.points = d.points;
    timeline.t = timeline.last;

    const bar = document.getElementById('timelineBar');
    if (bar) bar.style.display = '';
    const slider = document.getElementById('historyTimelineSlider');
    if (slider) slider.value = 1000;
    drawTimelineSparkline();
    updateTimelineLabel();
    sendTimelinePosition(true);
}

function exitTimeline() {
    if (!timeline.active) return;
    stopTimelinePlay();
    timeline.active = false;
    timeline.captureId = 0;
    const bar = document.getElementById('timelineBar');
    if (bar) bar.style.display = 'none';
    sendControl({ type: 'setTimeline', data: { captureId: 0 } });
}

function onTimelineSlider() {
    if (!timeline.active) return;
    stopTimelinePlay();
    const slider = document.getElementById('historyTimelineSlider');
    const frac = Number(slider.value) / Number(slider.max);
    timeline.t = Math.round(timeline.first + frac * (timeline.last - timeline.first));
    updateTimelineLabel();
    sendTimelinePosition(false);
}

function toggleTimelinePlay() {
    if (!timeline.active) return;
    if (timeline.playing) {
        stopTimelinePlay();
        return;
    }
    // Play traverses the whole capture in ~60s of wall time (min 1s of capture
    // per tick), restarting from the beginning when already at the end.
    if (timeline.t >= timeline.last) timeline.t = timeline.first;
    timeline.playing = true;
    setTimelinePlayIcon(true);
    const advance = Math.max(1, Math.round((timeline.last - timeline.first) / 240));
    timeline.playTimer = setInterval(() => {
        timeline.t = Math.min(timeline.last, timeline.t + advance);
        syncTimelineSlider();
        updateTimelineLabel();
        sendTimelinePosition(false);
        if (timeline.t >= timeline.last) stopTimelinePlay();
    }, 250);
}

function stopTimelinePlay() {
    if (timeline.playTimer) clearInterval(timeline.playTimer);
    timeline.playTimer = null;
    timeline.playing = false;
    setTimelinePlayIcon(false);
}

function setTimelinePlayIcon(playing) {
    const play = document.getElementById('timelinePlayIcon');
    const pause = document.getElementById('timelinePauseIcon');
    if (play) play.style.display = playing ? 'none' : '';
    if (pause) pause.style.display = playing ? '' : 'none';
}

function syncTimelineSlider() {
    const slider = document.getElementById('historyTimelineSlider');
    if (!slider) return;
    const span = timeline.last - timeline.first;
    slider.value = span > 0 ? Math.round((timeline.t - timeline.first) / span * Number(slider.max)) : 0;
}

function updateTimelineLabel() {
    const label = document.getElementById('timelineLabel');
    if (label) label.textContent = new Date(timeline.t * 1000).toLocaleTimeString();
}

// Throttle scrub positions to one control message per 150ms; the server also
// coalesces (it only rebuilds when the quantized position changed).
function sendTimelinePosition(immediate) {
    const send = () => {
        timeline.lastSent = Date.now();
        sendControl({
            type: 'setTimeline',
            data: { captureId: timeline.captureId, t: timeline.t, window: timeline.window },
        });
    };
    const elapsed = Date.now() - timeline.lastSent;
    clearTimeout(timeline.sendTimer);
    if (immediate || elapsed >= 150) {
        send();
    } else {
        timeline.sendTimer = setTimeout(send, 150 - elapsed);
    }
}

function drawTimelineSparkline() {
    const canvas = document.getElementById('timelineSparkline');
    if (!canvas || !timeline.points.length) return;
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    canvas.width = Math.max(1, Math.round(w * dpr));
    canvas.height = Math.max(1, Math.round(h * dpr));
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);
    const span = Math.max(1, timeline.last - timeline.first);
    let maxP = 0;
    timeline.points.forEach(p => { if (p.packets > maxP) maxP = p.packets; });
    if (maxP === 0) return;
    const barW = Math.max(1, (timeline.step / span) * w - 0.5);
    ctx.fillStyle = getComputedStyle(document.documentElement)
        .getPropertyValue('--accent-primary').trim() || '#3498db';
    timeline.points.forEach(p => {
        const x = ((p.t - timeline.first) / span) * w;
        const bh = Math.max(1, (p.packets / maxP) * (h - 2));
        ctx.fillRect(x, h - bh, barW, bh);
    });
}

function formatTimelineDuration(sec) {
    if (sec >= 3600) return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
    if (sec >= 60) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
    return `${sec}s`;
}

document.addEventListener('DOMContentLoaded', initHistoryUI);
