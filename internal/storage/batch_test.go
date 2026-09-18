package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"aliyun-cdn-guard/internal/model"
)

func TestBatchMatchesSequentialAcrossDimensions(t *testing.T) {
	for _, ua := range []bool{false, true} {
		for _, uri := range []bool{false, true} {
			t.Run(fmt.Sprintf("ua=%t/uri=%t", ua, uri), func(t *testing.T) {
				batch, err := Open(filepath.Join(t.TempDir(), "batch.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer batch.Close()
				single, err := Open(filepath.Join(t.TempDir(), "single.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer single.Close()
				ctx := context.Background()
				opts := DetectionOptions{Threshold: 3, WindowSeconds: 10, BaseDuration: 10, Multiplier: 2, MaxDuration: 30, UseUA: ua, UseURI: uri, Now: 100}
				var records []Record
				for i, ts := range []int64{90, 91, 100, 99, 100, 101, 100, 100, 100, 100, 100, 100} {
					r := Record{Event: model.AccessEvent{EventID: fmt.Sprint(i), Timestamp: ts, Domain: "d", ClientIP: "192.0.2.1"}, UAKey: fmt.Sprint(i % 2), URIKey: fmt.Sprint(i % 3)}
					records = append(records, r, r) // Duplicate delivery in the same batch.
				}
				var want []*model.BlockDecision
				for _, r := range records {
					d, err := single.RecordAndMaybeBlock(ctx, r.Event, r.UAKey, r.URIKey, opts)
					if err != nil {
						t.Fatal(err)
					}
					want = append(want, d)
				}
				got, err := batch.RecordBatch(ctx, records, opts)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("batch decisions differ: got=%v want=%v", got, want)
				}
				var count int
				if err := batch.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != len(records)/2 {
					t.Fatalf("count=%d err=%v", count, err)
				}
			})
		}
	}
}

func TestBlockedEventsCountAfterExpiryAndRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "guard.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	opts := DetectionOptions{Threshold: 2, WindowSeconds: 60, BaseDuration: 10, Multiplier: 2, MaxDuration: 30, Now: 100}
	record := func(id string, ts int64) Record {
		return Record{Event: model.AccessEvent{EventID: id, Timestamp: ts, Domain: "d", ClientIP: "192.0.2.1"}}
	}
	d, err := s.RecordBatch(ctx, []Record{record("1", 100), record("2", 100), record("3", 101)}, opts)
	if err != nil || d[0] != nil || d[1] == nil || d[1].Count != 2 || d[2] != nil {
		t.Fatalf("decisions=%v err=%v", d, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	opts.Now = 110
	d, err = s.RecordBatch(ctx, []Record{record("3", 101), record("4", 110)}, opts)
	if err != nil || d[0] != nil || d[1] == nil || d[1].Count != 4 || d[1].OffenseCount != 2 || d[1].BlockedUntil != 130 {
		t.Fatalf("decisions=%v err=%v", d, err)
	}
	if _, err := s.PruneEvents(ctx, 102); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&count); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

func TestBatchRollsBackEventsAndDecisionsOnFailure(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.db.Exec(`CREATE TRIGGER fail_event BEFORE INSERT ON events WHEN NEW.event_id = 'bad' BEGIN SELECT RAISE(ABORT, 'injected failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
	records := []Record{{Event: model.AccessEvent{EventID: "good", Timestamp: 100, Domain: "d", ClientIP: "192.0.2.1"}}, {Event: model.AccessEvent{EventID: "bad", Timestamp: 100, Domain: "d", ClientIP: "192.0.2.1"}}}
	d, err := s.RecordBatch(context.Background(), records, DetectionOptions{Threshold: 1, WindowSeconds: 60, BaseDuration: 10, Multiplier: 2, MaxDuration: 60, Now: 100})
	if err == nil || d != nil {
		t.Fatalf("decisions=%v err=%v", d, err)
	}
	for _, table := range []string{"events", "blocks"} {
		var n int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s count=%d err=%v", table, n, err)
		}
	}
}

func TestWindowBoundsAndDimensionIsolation(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	records := []Record{}
	for i, ts := range []int64{90, 101, 91, 100} {
		records = append(records, Record{Event: model.AccessEvent{EventID: fmt.Sprint(i), Timestamp: ts, Domain: "d", ClientIP: "192.0.2.1"}, UAKey: "ua", URIKey: "/a"})
	}
	opts := DetectionOptions{Threshold: 3, WindowSeconds: 10, BaseDuration: 10, Multiplier: 2, MaxDuration: 60, UseUA: true, UseURI: true, Now: 100}
	d, err := s.RecordBatch(context.Background(), records, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, decision := range d {
		if decision != nil {
			t.Fatalf("unexpected decision: %+v", decision)
		}
	}
	r := records[3]
	r.Event.EventID = "other-uri"
	r.URIKey = "/b"
	if d, err := s.RecordBatch(context.Background(), []Record{r}, opts); err != nil || d[0] != nil {
		t.Fatalf("decision=%v err=%v", d, err)
	}
	r.Event.EventID = "threshold"
	r.URIKey = "/a"
	d, err = s.RecordBatch(context.Background(), []Record{r}, opts)
	if err != nil || d[0] == nil || d[0].Count != 3 {
		t.Fatalf("decision=%v err=%v", d, err)
	}
}
