# Etherchimp

EtherChimp was created/inspired from EtherApe https://etherape.sourceforge.io/
The tool originated from CTFs with python3 scapy scripts that was converted into a fun web interface with claude

![](docs/images/Etherchimp001.png)

Live network traffic visualizer. Etherchimp captures packets from a network
interface (or replays a pcap), builds a real-time graph of hosts and the traffic
between them, and streams it to a browser over WebSocket — an interactive,
force-directed map of what's talking to what on your network.

## Features

- **Live capture** from a local interface, or **replay** from a pcap file
- **Real-time graph** of hosts and connections, streamed to the browser as deltas
- **Protocol-aware** classification (TCP/UDP, HTTP/S, DNS, SSH, ARP, ICMP, and more)
- **Multiple layouts** — force, circular, subnet, gravity, hierarchical
- **Remote capture** over SSH
- **Multi-interface capture** by subnet (`-interface-filter`) and **kernel BPF subnet filtering** (`-net`)
- **Capture persistence** to SQLite — pcap cache, flow timeline, per-packet index (`-db`)
- **Synthetic traffic generator** for scale testing (`-synth`)
- **Runs as a daemon** with automatic log rotation
- Served over **HTTPS** with a self-signed certificate

## Requirements

- Go 1.24+
- libpcap (`libpcap-dev` on Debian/Ubuntu, `libpcap` on macOS via Homebrew)
- Root/sudo for live capture (raw socket access)
- Etherchimp can also run in userspace 

## Build

```sh
go build -o etherchimp .
```

## Usage

Capture live from an interface:

```sh
sudo ./etherchimp -i eth0
```

Replay a capture file (no live capture, no root needed):

```sh
./etherchimp -f capture.pcap
```

Then open **https://localhost:8443** and accept the self-signed certificate warning.

### Running in userspace (without root)

Live capture does not require running Etherchimp as root. Instead of `sudo`, you
can grant the raw-capture privilege directly to the binary (or your user) and run
it as an unprivileged user:

**Linux** — give the binary the capabilities libpcap needs:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip ./etherchimp
./etherchimp -i eth0          # now runs as a normal user
```

**macOS** — grant your user read access to the BPF devices, then run normally:

```sh
sudo chmod o+r /dev/bpf*
./etherchimp -i en0
```

Replay mode (`-f capture.pcap`) reads from a file and never needs any of this —
it always runs in userspace.

## Flags

Run `./etherchimp --help` for the authoritative list. Every flag is documented
below, grouped by what it does.

### Capture sources

Exactly one source is used: `-i`, `-interface-filter`, `-f`, `-ssh`, or `-synth`.

| Flag | Default | Description |
|------|---------|-------------|
| `-i` | — | Network interface to capture from, or `any` for all interfaces (required for capture mode) |
| `-interface-filter` | — | CIDR (e.g. `192.168.0.0/16`); capture on **every** local interface holding an IP in that subnet. Local capture only; mutually exclusive with `-i`/`-f`/`-ssh`/`-synth` |
| `-f` | — | Pcap file path for replay-only mode (disables live capture) |
| `-ssh` | — | SSH host for remote capture, `host:port` (e.g. `192.168.1.1:22`) |
| `-net` | — | Subnet CIDR(s) to keep, comma-separated (e.g. `192.168.1.0/24,10.0.0.0/8`). Kernel BPF `net` filter — only packets touching one of these subnets are recorded to the pcap and shown in the graph. Combinable with `-i`/`-f`/`-ssh`; slims captures in large environments |

`-net` is applied in the kernel, so filtered packets never reach userspace — use
it to keep captures manageable on busy links. `-interface-filter` is the opposite
knob: it *widens* capture to every NIC on a given subnet.

```sh
# Capture on every interface that has an address in 192.168.0.0/16
sudo ./etherchimp -interface-filter 192.168.0.0/16

# Capture eth0, but keep only traffic touching two subnets
sudo ./etherchimp -i eth0 -net 192.168.1.0/24,10.0.0.0/8
```

### Remote capture (SSH)

| Flag | Default | Description |
|------|---------|-------------|
| `-ssh` | — | SSH host for remote capture (`host:port`) |
| `-user` | — | SSH username |
| `-pass` | — | SSH password (password-based authentication) |
| `-pkey` | — | Path to SSH private key file (key-based authentication) |

```sh
./etherchimp -ssh 192.168.1.1:22 -user admin -pkey ~/.ssh/id_ed25519
```

### Server / TLS

| Flag | Default | Description |
|------|---------|-------------|
| `-p` | `8443` | HTTPS server port |
| `-ip` | `0.0.0.0` | IP address to bind the server to |
| `-hostname` | — | Hostname or IP for the TLS certificate; repeatable |
| `-rate-limit` | `10` | API requests per second per client |
| `-rate-burst` | `50` | Maximum burst size for rate limiting |

```sh
sudo ./etherchimp -i eth0 -p 9443 -hostname etherchimp.lan -hostname 10.0.0.5
```

### Graph & protocols

| Flag | Default | Description |
|------|---------|-------------|
| `-node-ttl` | `60` | Seconds a node/edge may go silent before it decays out of the graph. Raise it for bursty traffic so hosts don't flicker away between packets |
| `-protocols` | `protocols.json` | Protocol catalog JSON; created with the embedded defaults if missing |
| `-chimpy` | `false` | Show the Chimpy Mode and Game Mode sidebar items (hidden otherwise) |

### Capture persistence (SQLite)

Setting `-db` turns on capture persistence: a pcap cache, a flow timeline, and a
per-packet index stored in one SQLite file. Leave it empty (the default) and
nothing is written to disk.

| Flag | Default | Description |
|------|---------|-------------|
| `-db` | — | SQLite database path for capture persistence (pcap cache, timeline, packet index). Empty = disabled |
| `-db-retention` | `168h` | Prune stored captures older than this |
| `-db-packets` | `true` | Per-packet index: `true`, `false`, or `1/N` sampling |
| `-db-bucket` | `1` | Flow-bucket width in seconds for the timeline |

`-db-packets` accepts `true`/`1`/`all` to index every packet, `false`/`0`/`off`/`none`
to skip the packet index entirely, or `1/N` (e.g. `1/10`) to index one packet in
every N. On high-throughput links, sampling plus a wider `-db-bucket` keeps the
database small while preserving the timeline shape.

```sh
sudo ./etherchimp -i eth0 -db captures.db -db-packets 1/10 -db-bucket 5 -db-retention 72h
```

### Daemon & logging

| Flag | Default | Description |
|------|---------|-------------|
| `-daemon` | — | Daemon command: `start`, `stop`, `pause`, `resume`, `status`, `rotate-logs`, `log-status`, `cleanup-logs` |
| `-background` | `false` | Run in background (internal use — set by `-daemon start`, not meant to be passed by hand) |
| `-enable-log-rotation` | `true` | Enable automatic log rotation |
| `-log-max-size` | `10MB` | Maximum log file size before rotation (e.g. `10MB`, `1GB`) |
| `-log-max-backups` | `5` | Maximum number of backup log files to keep |
| `-log-max-age` | `30` | Maximum age of backup log files in days (`0` = no limit) |
| `-log-compress` | `true` | Compress rotated log files |
| `-log-check-interval` | `60` | Log rotation check interval in seconds |

```sh
sudo ./etherchimp -i eth0 -daemon start
./etherchimp -daemon status
./etherchimp -daemon pause      # stop ingesting, keep the server up
./etherchimp -daemon resume
./etherchimp -daemon stop
```

### Synthetic traffic (development)

These flags serve a fake graph instead of capturing anything — useful for testing
rendering and layout performance without a live network.

| Flag | Default | Description |
|------|---------|-------------|
| `-synth` | `0` | Serve a synthetic graph of N hosts with continuous random traffic (no capture; for scale testing) |
| `-synth-rate` | `2000` | Synthetic packets per second |
| `-synth-burst` | `0` | About 15s in, simulate an NMAP-style scan of N fresh hosts from a single scanner IP (one packet per host, then quiet) |

```sh
./etherchimp -synth 500 -synth-rate 5000 -synth-burst 200
```

## License

See repository for license details.
