package detector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"aliyun-cdn-guard/internal/audit"
	"aliyun-cdn-guard/internal/config"
	"aliyun-cdn-guard/internal/model"
	"aliyun-cdn-guard/internal/storage"
)

func TestBatchWhitelistAndAuditEventAlignment(t *testing.T) {
	dir := t.TempDir()
	s, err := storage.Open(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b, err := audit.New(filepath.Join(dir, "blocks.jsonl"), true)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{CDN: config.CDNConfig{Domains: []string{"d"}}, Detection: config.DetectionConfig{Threshold: 2, WindowSeconds: 60, URI: config.URIConfig{QueryMode: "ignore_all"}}, Penalty: config.PenaltyConfig{BaseDurationSeconds: 10, Multiplier: 2, MaxDurationSeconds: 60}, Whitelist: config.WhitelistConfig{URIRegexes: []*regexp.Regexp{regexp.MustCompile(`^/health$`)}}}
	d := New(cfg, s, b)
	e := model.AccessEvent{EventID: "1", Timestamp: 100, Domain: "d", ClientIP: "2001:db8::1", URI: "/asset"}
	ignored := e
	ignored.EventID = "ignored"
	ignored.URI = "/health?x=1"
	second := e
	second.EventID = "2"
	second.URI = "/trigger"
	decisions, err := d.ProcessBatch(context.Background(), []model.AccessEvent{ignored, e, second, second}, 100)
	if err != nil || len(decisions) != 1 || decisions[0].Count != 2 {
		t.Fatalf("decisions=%v err=%v", decisions, err)
	}
	if got := d.Snapshot(false)["d"][1]; got != 3 {
		t.Fatalf("processed=%d", got)
	}
	data, err := os.ReadFile(b.Path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record["event_id"] != "2" || record["uri"] != "/trigger" || record["client_ip"] != "2001:0db8:0000:0000:0000:0000:0000:0001" {
		t.Fatalf("record=%v", record)
	}
}
