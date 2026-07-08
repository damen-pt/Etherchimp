package store

// Schema migrations, applied in order by comparing PRAGMA user_version. Each
// entry is one version step; Open runs every step above the file's current
// version inside a single transaction and bumps user_version to len(migrations).
var migrations = []string{
	// v1 — full schema. Later milestones fill tables the early ones leave empty
	// (packets, flow_buckets) so a v1 file never needs migrating for them.
	`
CREATE TABLE captures (
    id         INTEGER PRIMARY KEY,
    kind       TEXT    NOT NULL,          -- 'live' | 'ssh' | 'pcap' | 'synth'
    source     TEXT    NOT NULL,          -- interface name or pcap basename
    file_hash  TEXT,                      -- pcap identity: sha256 of first 1 MiB
    file_size  INTEGER,
    file_mtime INTEGER,                   -- unix seconds (informational, not part of the key)
    started_at INTEGER NOT NULL,          -- unix millis (pcap: first packet ts)
    ended_at   INTEGER,
    complete   INTEGER NOT NULL DEFAULT 0 -- pcap fully ingested / session closed cleanly
);
CREATE UNIQUE INDEX cap_pcap_key ON captures(source, file_size, file_hash) WHERE kind = 'pcap';

CREATE TABLE nodes (
    capture_id   INTEGER NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
    id           TEXT    NOT NULL,        -- raw IP / L2 endpoint id (pre DNS-merge)
    hostname     TEXT,
    packet_count INTEGER NOT NULL,
    byte_count   INTEGER NOT NULL,
    first_seen   INTEGER,                 -- unix millis
    last_seen    INTEGER,
    is_group     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (capture_id, id)
) WITHOUT ROWID;

CREATE TABLE edges (
    capture_id   INTEGER NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
    id           TEXT    NOT NULL,        -- canonical "a<->b" over raw endpoint ids
    from_id      TEXT    NOT NULL,
    to_id        TEXT    NOT NULL,
    protocol     TEXT    NOT NULL,
    packet_count INTEGER NOT NULL,
    byte_count   INTEGER NOT NULL,
    fwd_packets  INTEGER NOT NULL DEFAULT 0,
    rev_packets  INTEGER NOT NULL DEFAULT 0,
    fwd_bytes    INTEGER NOT NULL DEFAULT 0,
    rev_bytes    INTEGER NOT NULL DEFAULT 0,
    first_seen   INTEGER,
    last_seen    INTEGER,
    PRIMARY KEY (capture_id, id)
) WITHOUT ROWID;

CREATE TABLE flow_buckets (
    capture_id  INTEGER NOT NULL,
    bucket_ts   INTEGER NOT NULL,         -- unix seconds, floored to bucket size
    edge_id     TEXT    NOT NULL,
    protocol    TEXT    NOT NULL,
    packets     INTEGER NOT NULL,
    bytes       INTEGER NOT NULL,
    fwd_packets INTEGER NOT NULL DEFAULT 0,
    rev_packets INTEGER NOT NULL DEFAULT 0,
    fwd_bytes   INTEGER NOT NULL DEFAULT 0,
    rev_bytes   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (capture_id, bucket_ts, edge_id)
) WITHOUT ROWID;

CREATE TABLE packets (
    id          INTEGER PRIMARY KEY,
    capture_id  INTEGER NOT NULL,
    ts          INTEGER NOT NULL,         -- unix micros
    src         TEXT,
    dst         TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    protocol    TEXT,
    length      INTEGER,
    vlan        INTEGER,
    pcap_offset INTEGER                   -- byte offset into the backing pcap, NULL/-1 unknown
);
CREATE INDEX pkt_time ON packets(capture_id, ts);
CREATE INDEX pkt_src  ON packets(capture_id, src, ts);
CREATE INDEX pkt_dst  ON packets(capture_id, dst, ts);
`,

	// v2 — flow buckets are keyed by protocol too. v1 kept one row per
	// (bucket, edge) stamped with the edge's cumulative protocol at bucket
	// creation, so mixed-protocol traffic was misattributed (e.g. TCP packets
	// recorded under "SSH") and the timeline couldn't pick an edge's dominant
	// protocol by real volume.
	`
CREATE TABLE flow_buckets_v2 (
    capture_id  INTEGER NOT NULL,
    bucket_ts   INTEGER NOT NULL,
    edge_id     TEXT    NOT NULL,
    protocol    TEXT    NOT NULL,
    packets     INTEGER NOT NULL,
    bytes       INTEGER NOT NULL,
    fwd_packets INTEGER NOT NULL DEFAULT 0,
    rev_packets INTEGER NOT NULL DEFAULT 0,
    fwd_bytes   INTEGER NOT NULL DEFAULT 0,
    rev_bytes   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (capture_id, bucket_ts, edge_id, protocol)
) WITHOUT ROWID;
INSERT INTO flow_buckets_v2 SELECT capture_id, bucket_ts, edge_id, protocol,
    packets, bytes, fwd_packets, rev_packets, fwd_bytes, rev_bytes FROM flow_buckets;
DROP TABLE flow_buckets;
ALTER TABLE flow_buckets_v2 RENAME TO flow_buckets;
`,
}
