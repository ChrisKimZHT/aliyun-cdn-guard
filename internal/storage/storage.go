package storage

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aliyun-cdn-guard/internal/model"
	_ "modernc.org/sqlite"
)

type Storage struct{ db *sql.DB }

func Open(path string) (*Storage, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Storage{db: db}
	if err := s.initialize(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Storage) initialize() error {
	for _, statement := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		`CREATE TABLE IF NOT EXISTS events (
			event_id TEXT PRIMARY KEY, occurred_at INTEGER NOT NULL, domain TEXT NOT NULL,
			client_ip TEXT NOT NULL, ua_key TEXT NOT NULL, uri_key TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_events_window ON events(domain, client_ip, ua_key, uri_key, occurred_at)`,
		`CREATE TABLE IF NOT EXISTS blocks (
			domain TEXT NOT NULL, client_ip TEXT NOT NULL, first_blocked_at INTEGER NOT NULL,
			blocked_until INTEGER NOT NULL, offense_count INTEGER NOT NULL, cdn_owned INTEGER,
			PRIMARY KEY(domain, client_ip))`,
		`CREATE TABLE IF NOT EXISTS permanent_blocks (
			domain TEXT NOT NULL, entry TEXT NOT NULL, cdn_owned INTEGER,
			PRIMARY KEY(domain, entry))`,
	} {
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("initialize storage: %w", err)
		}
	}
	return nil
}

type DetectionOptions struct {
	Threshold, WindowSeconds, BaseDuration, MaxDuration int
	Multiplier                                          float64
	UseUA, UseURI                                       bool
	Now                                                 int64
}

func (s *Storage) RecordAndMaybeBlock(ctx context.Context, event model.AccessEvent, uaKey, uriKey string, opts DetectionOptions) (*model.BlockDecision, error) {
	if opts.Now == 0 {
		opts.Now = time.Now().Unix()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?, ?)", event.EventID, event.Timestamp, event.Domain, event.ClientIP, uaKey, uriKey)
	if err != nil {
		return nil, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if inserted == 0 {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, nil
	}

	clauses := []string{"domain = ?", "client_ip = ?", "occurred_at >= ?", "occurred_at <= ?"}
	args := []any{event.Domain, event.ClientIP, event.Timestamp - int64(opts.WindowSeconds) + 1, event.Timestamp}
	if opts.UseUA {
		clauses = append(clauses, "ua_key = ?")
		args = append(args, uaKey)
	}
	if opts.UseURI {
		clauses = append(clauses, "uri_key = ?")
		args = append(args, uriKey)
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE "+strings.Join(clauses, " AND "), args...).Scan(&count); err != nil {
		return nil, err
	}

	var firstBlocked, blockedUntil int64
	var offense int
	err = tx.QueryRowContext(ctx, "SELECT first_blocked_at, blocked_until, offense_count FROM blocks WHERE domain = ? AND client_ip = ?", event.Domain, event.ClientIP).Scan(&firstBlocked, &blockedUntil, &offense)
	hasExisting := err == nil
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if count < opts.Threshold || (hasExisting && blockedUntil > opts.Now) {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if hasExisting {
		offense++
	} else {
		offense = 1
		firstBlocked = opts.Now
	}
	durationFloat := float64(opts.BaseDuration) * math.Pow(opts.Multiplier, float64(offense-1))
	duration := opts.MaxDuration
	if durationFloat < float64(opts.MaxDuration) {
		duration = int(durationFloat)
	}
	blockedUntil = opts.Now + int64(duration)
	_, err = tx.ExecContext(ctx, `INSERT INTO blocks(domain, client_ip, first_blocked_at, blocked_until, offense_count, cdn_owned)
		VALUES (?, ?, ?, ?, ?, NULL)
		ON CONFLICT(domain, client_ip) DO UPDATE SET blocked_until=excluded.blocked_until, offense_count=excluded.offense_count, cdn_owned=NULL`,
		event.Domain, event.ClientIP, firstBlocked, blockedUntil, offense)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &model.BlockDecision{Domain: event.Domain, ClientIP: event.ClientIP, Count: count, BlockedUntil: blockedUntil, OffenseCount: offense, BlockedAt: opts.Now}, nil
}

func (s *Storage) BlocksForDomain(ctx context.Context, domain string) ([]model.BlockRecord, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT domain, client_ip, blocked_until, offense_count, cdn_owned FROM blocks WHERE domain = ?", domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.BlockRecord
	for rows.Next() {
		var r model.BlockRecord
		var owned sql.NullInt64
		if err := rows.Scan(&r.Domain, &r.ClientIP, &r.BlockedUntil, &r.OffenseCount, &owned); err != nil {
			return nil, err
		}
		if owned.Valid {
			v := owned.Int64 != 0
			r.CDNOwned = &v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Storage) ActiveBlockEntries(ctx context.Context, domain string, now int64) (map[string]struct{}, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT client_ip FROM blocks WHERE domain = ? AND blocked_until > ?", domain, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]struct{}{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out[ip] = struct{}{}
	}
	return out, rows.Err()
}

func (s *Storage) SetOwnership(ctx context.Context, domain string, values map[string]bool) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		for ip, owned := range values {
			if _, err := tx.ExecContext(ctx, "UPDATE blocks SET cdn_owned = ? WHERE domain = ? AND client_ip = ?", owned, domain, ip); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Storage) PermanentForDomain(ctx context.Context, domain string) (map[string]*bool, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT entry, cdn_owned FROM permanent_blocks WHERE domain = ?", domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*bool{}
	for rows.Next() {
		var entry string
		var owned sql.NullInt64
		if err := rows.Scan(&entry, &owned); err != nil {
			return nil, err
		}
		if owned.Valid {
			v := owned.Int64 != 0
			out[entry] = &v
		} else {
			out[entry] = nil
		}
	}
	return out, rows.Err()
}

func (s *Storage) SyncPermanentPolicy(ctx context.Context, domain string, entries map[string]struct{}) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		for entry := range entries {
			if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO permanent_blocks(domain, entry, cdn_owned) VALUES (?, ?, NULL)", domain, entry); err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *Storage) SetPermanentOwnership(ctx context.Context, domain string, values map[string]bool) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		for entry, owned := range values {
			if _, err := tx.ExecContext(ctx, "UPDATE permanent_blocks SET cdn_owned = ? WHERE domain = ? AND entry = ?", owned, domain, entry); err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *Storage) DeletePermanentRecords(ctx context.Context, domain string, entries map[string]struct{}) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		for entry := range entries {
			if _, err := tx.ExecContext(ctx, "DELETE FROM permanent_blocks WHERE domain = ? AND entry = ?", domain, entry); err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *Storage) PruneEvents(ctx context.Context, before int64) (int64, error) {
	r, e := s.db.ExecContext(ctx, "DELETE FROM events WHERE occurred_at < ?", before)
	if e != nil {
		return 0, e
	}
	return r.RowsAffected()
}
func (s *Storage) withTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = fn(tx); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Storage) Close() error { return s.db.Close() }
