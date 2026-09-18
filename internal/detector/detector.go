package detector

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"aliyun-cdn-guard/internal/audit"
	"aliyun-cdn-guard/internal/config"
	"aliyun-cdn-guard/internal/model"
	"aliyun-cdn-guard/internal/normalization"
	"aliyun-cdn-guard/internal/storage"
)

type counters struct{ received, processed int64 }
type Detector struct {
	cfg      *config.Config
	storage  *storage.Storage
	blockLog *audit.BlockLog
	domains  map[string]struct{}
	mu       sync.Mutex
	counts   map[string]counters
}

func New(cfg *config.Config, s *storage.Storage, b *audit.BlockLog) *Detector {
	domains := map[string]struct{}{}
	counts := map[string]counters{}
	for _, d := range cfg.CDN.Domains {
		domains[d] = struct{}{}
		counts[d] = counters{}
	}
	return &Detector{cfg: cfg, storage: s, blockLog: b, domains: domains, counts: counts}
}
func (d *Detector) RecordReceived(domain string) {
	if _, ok := d.domains[domain]; !ok {
		return
	}
	d.mu.Lock()
	c := d.counts[domain]
	c.received++
	d.counts[domain] = c
	d.mu.Unlock()
}
func (d *Detector) Snapshot(reset bool) map[string][2]int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string][2]int64{}
	for _, domain := range d.cfg.CDN.Domains {
		c := d.counts[domain]
		out[domain] = [2]int64{c.received, c.processed}
	}
	if reset {
		for k := range d.counts {
			d.counts[k] = counters{}
		}
	}
	return out
}

// BatchSize bounds transaction size and the delay before decisions become visible.
const BatchSize = 256

func (d *Detector) Process(ctx context.Context, event model.AccessEvent, now int64) (*model.BlockDecision, error) {
	decisions, err := d.ProcessBatch(ctx, []model.AccessEvent{event}, now)
	if err != nil || len(decisions) == 0 {
		return nil, err
	}
	return decisions[0], nil
}

// ProcessBatch filters events, commits in bounded chunks, then publishes audit records.
func (d *Detector) ProcessBatch(ctx context.Context, events []model.AccessEvent, now int64) ([]*model.BlockDecision, error) {
	var out []*model.BlockDecision
	for start := 0; start < len(events); start += BatchSize {
		end := min(start+BatchSize, len(events))
		records := make([]storage.Record, 0, end-start)
		for _, event := range events[start:end] {
			if record, ok := d.prepare(event); ok {
				records = append(records, record)
			}
		}
		decisions, err := d.storage.RecordBatch(ctx, records, storage.DetectionOptions{Threshold: d.cfg.Detection.Threshold, WindowSeconds: d.cfg.Detection.WindowSeconds, BaseDuration: d.cfg.Penalty.BaseDurationSeconds, Multiplier: d.cfg.Penalty.Multiplier, MaxDuration: d.cfg.Penalty.MaxDurationSeconds, UseUA: d.cfg.Detection.UA.Enabled, UseURI: d.cfg.Detection.URI.Enabled, Now: now})
		if err != nil {
			return nil, err
		}
		for i, decision := range decisions {
			if decision != nil {
				d.publish(records[i].Event, decision)
				out = append(out, decision)
			}
		}
	}
	return out, nil
}

func (d *Detector) prepare(event model.AccessEvent) (storage.Record, bool) {
	if _, ok := d.domains[event.Domain]; !ok {
		slog.Debug("ignoring log", "reason", "unmanaged domain", "domain", event.Domain)
		return storage.Record{}, false
	}
	addr, err := netip.ParseAddr(event.ClientIP)
	if err != nil {
		slog.Warn("ignoring log", "reason", "invalid client_ip", "client_ip", event.ClientIP)
		return storage.Record{}, false
	}
	if addr.Is6() {
		event.ClientIP = addr.StringExpanded()
	} else {
		event.ClientIP = addr.String()
	}
	if _, ok := d.cfg.Whitelist.Domains[event.Domain]; ok {
		return storage.Record{}, false
	}
	for _, network := range d.cfg.Whitelist.IPNetworks {
		if network.Contains(addr) {
			return storage.Record{}, false
		}
	}
	for _, r := range d.cfg.Whitelist.UARegexes {
		if r.MatchString(event.UserAgent) {
			return storage.Record{}, false
		}
	}
	uriKey := ""
	if d.cfg.Detection.URI.Enabled || len(d.cfg.Whitelist.URIRegexes) > 0 {
		uriKey = normalization.URI(event.URI, event.URIParam, d.cfg.Detection.URI)
	}
	for _, r := range d.cfg.Whitelist.URIRegexes {
		if r.MatchString(uriKey) {
			return storage.Record{}, false
		}
	}
	d.mu.Lock()
	c := d.counts[event.Domain]
	c.processed++
	d.counts[event.Domain] = c
	d.mu.Unlock()
	uaKey := ""
	if d.cfg.Detection.UA.Enabled {
		uaKey = event.UserAgent
	}
	if !d.cfg.Detection.URI.Enabled {
		uriKey = ""
	}
	return storage.Record{Event: event, UAKey: uaKey, URIKey: uriKey}, true
}

func (d *Detector) publish(event model.AccessEvent, decision *model.BlockDecision) {
	if decision != nil {
		if err := d.blockLog.Append(event, *decision); err != nil {
			slog.Error("failed to append block audit log", "path", d.blockLog.Path, "error", err)
		}
		slog.Warn("abuse threshold reached", "domain", decision.Domain, "ip", decision.ClientIP, "count", decision.Count, "offense", decision.OffenseCount, "blocked_at", decision.BlockedAt, "blocked_until", decision.BlockedUntil)
	}
}
func (d *Detector) Prune(ctx context.Context, now int64) (int64, error) {
	if now == 0 {
		now = time.Now().Unix()
	}
	return d.storage.PruneEvents(ctx, now-int64(d.cfg.Detection.RetentionSeconds))
}
