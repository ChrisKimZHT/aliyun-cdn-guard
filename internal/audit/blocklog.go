package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"aliyun-cdn-guard/internal/model"
)

type BlockLog struct {
	Path   string
	DryRun bool
	mu     sync.Mutex
}

func New(path string, dryRun bool) (*BlockLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return &BlockLog{Path: path, DryRun: dryRun}, nil
}

func (b *BlockLog) Append(event model.AccessEvent, d model.BlockDecision) error {
	record := map[string]any{"schema_version": 1, "recorded_at": time.Now().UTC().Format(time.RFC3339Nano), "dry_run": b.DryRun, "event_id": event.EventID, "event_timestamp": event.Timestamp, "domain": d.Domain, "client_ip": d.ClientIP, "user_agent": event.UserAgent, "uri": event.URI, "uri_param": event.URIParam, "request_count": d.Count, "offense_count": d.OffenseCount, "blocked_at": d.BlockedAt, "blocked_until": d.BlockedUntil, "duration_seconds": d.BlockedUntil - d.BlockedAt}
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	b.mu.Lock()
	defer b.mu.Unlock()
	f, err := os.OpenFile(b.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(line); err != nil {
		return err
	}
	return nil
}
