// Package store persists processed capture data to SQLite: per-capture
// node/edge aggregates (the pcap cache), time-bucketed flow stats (the
// timeline), and an optional per-packet metadata index. Payload bytes are
// never stored — packets reference their byte offset in the backing pcap file.
//
// Concurrency model: RecordPacket is called from the packet hot path and only
// touches in-memory aggregate maps under a mutex plus a non-blocking channel
// send; a single writer goroutine owns all SQL writes, batching them into one
// transaction every flushInterval or batchSize events. A separate read-only
// connection pool serves API queries so they never contend with the writer
// beyond WAL semantics.
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Options configures a Store.
type Options struct {
	// BucketSeconds is the flow-bucket width. 0 -> 1s.
	BucketSeconds int
	// PacketEvery controls the per-packet index: 0 = disabled, 1 = every
	// packet, N = one in N (deterministic sampling).
	PacketEvery int
	// Retention prunes captures whose ended_at is older than this. 0 disables
	// pruning. (The pruner goroutine starts in Open when non-zero.)
	Retention time.Duration
}

// PacketEvent is one processed packet, as recorded from the hot path. Src/Dst
// are the raw endpoint IDs (IP or L2 id) before any DNS merging.
type PacketEvent struct {
	CaptureID        int64
	TS               time.Time
	Src, Dst         string
	SrcHost, DstHost string // resolved/friendly names when known ("" otherwise)
	SrcPort, DstPort uint16
	Proto            string
	Length           int
	VLAN             uint16
	PcapOffset       int64 // byte offset in the backing pcap file; -1 unknown
}

// FileMeta identifies a pcap file for cache lookups. The hash covers only the
// first MiB — enough to disambiguate, cheap on multi-hundred-MB files. MTime is
// stored but deliberately not part of the cache key (copying a file preserves
// content, not mtime).
type FileMeta struct {
	Size  int64
	MTime time.Time
	Hash  string
}

// ComputeFileMeta stats and head-hashes a pcap file.
func ComputeFileMeta(path string) (FileMeta, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return FileMeta{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return FileMeta{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 1<<20)); err != nil {
		return FileMeta{}, err
	}
	return FileMeta{
		Size:  fi.Size(),
		MTime: fi.ModTime(),
		Hash:  hex.EncodeToString(h.Sum(nil)),
	}, nil
}

// Store is the SQLite persistence backend. Zero-value is not usable; construct
// with Open. A nil *Store is safe to pass around — all methods no-op on nil —
// so callers don't need to guard every call site on whether -db was given.
type Store struct {
	writeDB *sql.DB
	readDB  *sql.DB
	opts    Options

	events chan PacketEvent
	done   chan struct{} // closed by Close to stop the writer
	flushd chan struct{} // closed by the writer once its final flush committed

	agg *aggregator // in-memory cumulative aggregates (writer.go)
}

// Open opens (creating if needed) the SQLite database at path and starts the
// writer goroutine.
func Open(path string, opts Options) (*Store, error) {
	if opts.BucketSeconds <= 0 {
		opts.BucketSeconds = 1
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return nil, fmt.Errorf("store: create db dir: %w", err)
	}

	// The writer connection: exactly one, so batched transactions never fight
	// each other. busy_timeout guards the rare checkpoint overlap.
	dsn := "file:" + path + "?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000&_auto_vacuum=incremental&_foreign_keys=1"
	writeDB, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	writeDB.SetMaxOpenConns(1)

	if err := migrate(writeDB); err != nil {
		writeDB.Close()
		return nil, err
	}

	readDB, err := sql.Open("sqlite3", "file:"+path+"?mode=ro&_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		writeDB.Close()
		return nil, fmt.Errorf("store: open read pool: %w", err)
	}

	s := &Store{
		writeDB: writeDB,
		readDB:  readDB,
		opts:    opts,
		events:  make(chan PacketEvent, 16384),
		done:    make(chan struct{}),
		flushd:  make(chan struct{}),
		agg:     newAggregator(int64(opts.BucketSeconds)),
	}
	go s.writerLoop()
	if opts.Retention > 0 {
		go s.retentionLoop()
	}
	return s, nil
}

func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("store: read user_version: %w", err)
	}
	if version >= len(migrations) {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for i := version; i < len(migrations); i++ {
		if _, err := tx.Exec(migrations[i]); err != nil {
			return fmt.Errorf("store: migration %d: %w", i+1, err)
		}
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", len(migrations))); err != nil {
		return err
	}
	return tx.Commit()
}

// BeginCapture inserts a session row and returns its id.
func (s *Store) BeginCapture(kind, source string, fm FileMeta) (int64, error) {
	if s == nil {
		return 0, nil
	}
	var hash, size, mtime interface{}
	if fm.Hash != "" {
		hash, size, mtime = fm.Hash, fm.Size, fm.MTime.Unix()
	}
	res, err := s.writeDB.Exec(
		`INSERT INTO captures (kind, source, file_hash, file_size, file_mtime, started_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		kind, source, hash, size, mtime, time.Now().UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("store: begin capture: %w", err)
	}
	return res.LastInsertId()
}

// EndCapture flushes everything recorded for the session and stamps ended_at.
// complete=true marks a fully-ingested pcap (the cache-hit criterion) or a
// cleanly closed live session.
func (s *Store) EndCapture(id int64, complete bool) error {
	if s == nil || id == 0 {
		return nil
	}
	s.Flush()
	s.agg.dropCapture(id)
	c := 0
	if complete {
		c = 1
	}
	_, err := s.writeDB.Exec(
		`UPDATE captures SET ended_at = ?, complete = ? WHERE id = ?`,
		time.Now().UnixMilli(), c, id)
	return err
}

// FindCompletePcap returns the capture id of a fully-ingested pcap matching
// this file identity, if one exists.
func (s *Store) FindCompletePcap(source string, fm FileMeta) (int64, bool) {
	if s == nil {
		return 0, false
	}
	var id int64
	err := s.readDB.QueryRow(
		`SELECT id FROM captures
		 WHERE kind = 'pcap' AND source = ? AND file_size = ? AND file_hash = ? AND complete = 1
		 ORDER BY id DESC LIMIT 1`,
		source, fm.Size, fm.Hash).Scan(&id)
	if err != nil {
		return 0, false
	}
	return id, true
}

// RecordPacket records one packet from the hot path. Aggregates are updated
// synchronously (cheap map ops under a dedicated mutex, so they are never
// lost); the per-packet index row rides the channel to the writer and is
// dropped (counted) if the writer can't keep up.
func (s *Store) RecordPacket(ev PacketEvent) {
	if s == nil || ev.CaptureID == 0 {
		return
	}
	s.agg.apply(ev)
	if s.opts.PacketEvery <= 0 {
		return
	}
	if s.opts.PacketEvery > 1 && s.agg.sampleTick()%uint64(s.opts.PacketEvery) != 0 {
		return
	}
	select {
	case s.events <- ev:
	default:
		s.agg.droppedPacketRow()
	}
}

// RecordPacketSync is RecordPacket for offline ingest (pcap replay): it blocks
// when the writer is behind instead of sampling the index row out, so a bulk
// ingest produces a complete packet index. Never call it from a live path.
func (s *Store) RecordPacketSync(ev PacketEvent) {
	if s == nil || ev.CaptureID == 0 {
		return
	}
	s.agg.apply(ev)
	if s.opts.PacketEvery <= 0 {
		return
	}
	if s.opts.PacketEvery > 1 && s.agg.sampleTick()%uint64(s.opts.PacketEvery) != 0 {
		return
	}
	select {
	case s.events <- ev:
	case <-s.done:
	}
}

// Flush synchronously forces one writer flush cycle (used by EndCapture and
// tests). It is a no-op after Close.
func (s *Store) Flush() {
	if s == nil {
		return
	}
	reply := make(chan struct{})
	select {
	case s.agg.flushReq <- reply:
		<-reply
	case <-s.done:
	}
}

// Close flushes and shuts down. Safe to call once.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	close(s.done)
	<-s.flushd // writer's final flush committed
	s.readDB.Close()
	return s.writeDB.Close()
}

// ReadDB exposes the read-only pool for query helpers in other files of this
// package and for ad-hoc server handlers.
func (s *Store) ReadDB() *sql.DB {
	if s == nil {
		return nil
	}
	return s.readDB
}

// Enabled reports whether persistence is active (nil-safe).
func (s *Store) Enabled() bool { return s != nil }

// retentionLoop prunes captures older than the retention window once an hour.
func (s *Store) retentionLoop() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-s.opts.Retention).UnixMilli()
			res, err := s.writeDB.Exec(`DELETE FROM captures WHERE ended_at IS NOT NULL AND ended_at < ?`, cutoff)
			if err != nil {
				log.Printf("store: retention prune failed: %v", err)
				continue
			}
			if n, _ := res.RowsAffected(); n > 0 {
				// captures cascade to nodes/edges; flow_buckets and packets lack
				// FK constraints on purpose (write speed), so sweep them too.
				s.writeDB.Exec(`DELETE FROM flow_buckets WHERE capture_id NOT IN (SELECT id FROM captures)`)
				s.writeDB.Exec(`DELETE FROM packets WHERE capture_id NOT IN (SELECT id FROM captures)`)
				s.writeDB.Exec(`PRAGMA incremental_vacuum`)
				log.Printf("store: pruned %d expired capture(s)", n)
			}
		}
	}
}
