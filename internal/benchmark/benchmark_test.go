package benchmark

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunIsolatedFromProductionPaths(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.StoragePath = filepath.Join(dir, "production.db")
	cfg.BlockLogPath = filepath.Join(dir, "production.jsonl")
	for _, p := range []string{cfg.StoragePath, cfg.BlockLogPath} {
		if err := os.WriteFile(p, []byte("untouched"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	err := Run(context.Background(), cfg, Options{Duration: 10 * time.Millisecond, Scenario: "unique", Directory: dir, BatchSize: 16, IPs: 4}, &out)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Events <= 0 || result.QPS <= 0 || result.Processed != result.Events {
		t.Fatalf("result=%+v", result)
	}
	for _, p := range []string{cfg.StoragePath, cfg.BlockLogPath} {
		data, err := os.ReadFile(p)
		if err != nil || string(data) != "untouched" {
			t.Fatalf("production file changed: %s: %v", p, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("temporary files not cleaned: %v %v", entries, err)
	}
}

func TestInvalidOptionsAndCancellation(t *testing.T) {
	for _, opts := range []Options{{}, {Duration: time.Second, Scenario: "bad", BatchSize: 1, IPs: 1}, {Duration: time.Second, Scenario: "hot", BatchSize: 257, IPs: 1}} {
		if err := Run(context.Background(), DefaultConfig(), opts, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %+v", opts)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, DefaultConfig(), Options{Duration: time.Second, Scenario: "hot", Directory: t.TempDir(), BatchSize: 1, IPs: 1}, &bytes.Buffer{}); err != context.Canceled {
		t.Fatalf("err=%v", err)
	}
}
