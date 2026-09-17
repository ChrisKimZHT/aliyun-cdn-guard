package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"aliyun-cdn-guard/internal/model"
	_ "modernc.org/sqlite"
)

func TestOpenLegacyDatabaseAndDetect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := []string{
		`CREATE TABLE events (event_id TEXT PRIMARY KEY, occurred_at INTEGER NOT NULL, domain TEXT NOT NULL, client_ip TEXT NOT NULL, ua_key TEXT NOT NULL, uri_key TEXT NOT NULL)`,
		`CREATE INDEX idx_events_window ON events(domain, client_ip, ua_key, uri_key, occurred_at)`,
		`CREATE TABLE blocks (domain TEXT NOT NULL, client_ip TEXT NOT NULL, first_blocked_at INTEGER NOT NULL, blocked_until INTEGER NOT NULL, offense_count INTEGER NOT NULL, cdn_owned INTEGER, PRIMARY KEY(domain, client_ip))`,
		`CREATE TABLE permanent_blocks (domain TEXT NOT NULL, entry TEXT NOT NULL, cdn_owned INTEGER, PRIMARY KEY(domain, entry))`,
	}
	for _, q := range legacy {
		if _, err = db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	opts := DetectionOptions{Threshold: 2, WindowSeconds: 60, BaseDuration: 10, Multiplier: 2, MaxDuration: 60, Now: 100}
	first := model.AccessEvent{EventID: "1", Timestamp: 100, Domain: "cdn.example.com", ClientIP: "192.0.2.1"}
	if d, err := s.RecordAndMaybeBlock(ctx, first, "", "", opts); err != nil || d != nil {
		t.Fatalf("first decision=%v err=%v", d, err)
	}
	second := first
	second.EventID = "2"
	d, err := s.RecordAndMaybeBlock(ctx, second, "", "", opts)
	if err != nil {
		t.Fatal(err)
	}
	if d == nil || d.Count != 2 || d.BlockedUntil != 110 {
		t.Fatalf("decision=%+v", d)
	}
	if d, err = s.RecordAndMaybeBlock(ctx, second, "", "", opts); err != nil || d != nil {
		t.Fatalf("duplicate decision=%v err=%v", d, err)
	}
}

func TestOwnershipTriState(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err = s.SyncPermanentPolicy(ctx, "d", map[string]struct{}{"192.0.2.1": {}}); err != nil {
		t.Fatal(err)
	}
	state, err := s.PermanentForDomain(ctx, "d")
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := state["192.0.2.1"]; !ok || value != nil {
		t.Fatalf("state=%v", state)
	}
	if err = s.SetPermanentOwnership(ctx, "d", map[string]bool{"192.0.2.1": true}); err != nil {
		t.Fatal(err)
	}
	state, _ = s.PermanentForDomain(ctx, "d")
	if state["192.0.2.1"] == nil || !*state["192.0.2.1"] {
		t.Fatalf("state=%v", state)
	}
}
