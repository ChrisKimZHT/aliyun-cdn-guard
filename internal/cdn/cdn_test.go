package cdn

import (
	"context"
	"path/filepath"
	"testing"

	"aliyun-cdn-guard/internal/config"
	"aliyun-cdn-guard/internal/model"
	"aliyun-cdn-guard/internal/storage"
)

type memoryGateway struct {
	entries map[string]struct{}
	sets    int
}

func (g *memoryGateway) GetBlacklist(context.Context, string) (map[string]struct{}, error) {
	return cloneSet(g.entries), nil
}

func (g *memoryGateway) SetBlacklist(_ context.Context, _ string, entries map[string]struct{}) error {
	g.entries = cloneSet(entries)
	g.sets++
	return nil
}

func TestReconcilerPreservesManualEntriesAndRemovesOwnedExpiry(t *testing.T) {
	ctx := context.Background()
	s, err := storage.Open(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	event := model.AccessEvent{EventID: "1", Timestamp: 100, Domain: "cdn.example.com", ClientIP: "192.0.2.10"}
	decision, err := s.RecordAndMaybeBlock(ctx, event, "", "", storage.DetectionOptions{
		Threshold: 1, WindowSeconds: 60, BaseDuration: 10, Multiplier: 2, MaxDuration: 60, Now: 100,
	})
	if err != nil || decision == nil {
		t.Fatalf("decision=%v err=%v", decision, err)
	}

	gateway := &memoryGateway{entries: map[string]struct{}{"198.51.100.20": {}}}
	cfg := &config.Config{CDN: config.CDNConfig{Domains: []string{"cdn.example.com"}}, PermanentBlocklist: map[string][]string{}}
	reconciler := NewReconciler(cfg, s, gateway)
	if err = reconciler.ReconcileDomain(ctx, "cdn.example.com", 100); err != nil {
		t.Fatal(err)
	}
	if _, ok := gateway.entries["192.0.2.10"]; !ok {
		t.Fatalf("managed entry not added: %v", gateway.entries)
	}
	if _, ok := gateway.entries["198.51.100.20"]; !ok {
		t.Fatalf("manual entry not preserved: %v", gateway.entries)
	}

	if err = reconciler.ReconcileDomain(ctx, "cdn.example.com", 111); err != nil {
		t.Fatal(err)
	}
	if _, ok := gateway.entries["192.0.2.10"]; ok {
		t.Fatalf("expired managed entry not removed: %v", gateway.entries)
	}
	if _, ok := gateway.entries["198.51.100.20"]; !ok {
		t.Fatalf("manual entry removed: %v", gateway.entries)
	}
	if gateway.sets != 2 {
		t.Fatalf("set calls=%d", gateway.sets)
	}
}
