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

func (d *Detector) Process(ctx context.Context, event model.AccessEvent, now int64) (*model.BlockDecision, error) {
	if _, ok := d.domains[event.Domain]; !ok {
		slog.Debug("ignoring log", "reason", "unmanaged domain", "domain", event.Domain)
		return nil, nil
	}
	addr, err := netip.ParseAddr(event.ClientIP)
	if err != nil {
		slog.Warn("ignoring log", "reason", "invalid client_ip", "client_ip", event.ClientIP)
		return nil, nil
	}
	if addr.Is6() {
		event.ClientIP = addr.StringExpanded()
	} else {
		event.ClientIP = addr.String()
	}
	uriKey := normalization.URI(event.URI, event.URIParam, d.cfg.Detection.URI)
	if _, ok := d.cfg.Whitelist.Domains[event.Domain]; ok {
		return nil, nil
	}
	for _, network := range d.cfg.Whitelist.IPNetworks {
		if network.Contains(addr) {
			return nil, nil
		}
	}
	for _, r := range d.cfg.Whitelist.UARegexes {
		if r.FindStringIndex(event.UserAgent) != nil {
			return nil, nil
		}
	}
	for _, r := range d.cfg.Whitelist.URIRegexes {
		if r.FindStringIndex(uriKey) != nil {
			return nil, nil
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
	decision, err := d.storage.RecordAndMaybeBlock(ctx, event, uaKey, uriKey, storage.DetectionOptions{Threshold: d.cfg.Detection.Threshold, WindowSeconds: d.cfg.Detection.WindowSeconds, BaseDuration: d.cfg.Penalty.BaseDurationSeconds, Multiplier: d.cfg.Penalty.Multiplier, MaxDuration: d.cfg.Penalty.MaxDurationSeconds, UseUA: d.cfg.Detection.UA.Enabled, UseURI: d.cfg.Detection.URI.Enabled, Now: now})
	if err != nil {
		return nil, err
	}
	if decision != nil {
		if err := d.blockLog.Append(event, *decision); err != nil {
			slog.Error("failed to append block audit log", "path", d.blockLog.Path, "error", err)
		}
		slog.Warn("abuse threshold reached", "domain", decision.Domain, "ip", decision.ClientIP, "count", decision.Count, "offense", decision.OffenseCount, "blocked_at", decision.BlockedAt, "blocked_until", decision.BlockedUntil)
	}
	return decision, nil
}
func (d *Detector) Prune(ctx context.Context, now int64) (int64, error) {
	if now == 0 {
		now = time.Now().Unix()
	}
	return d.storage.PruneEvents(ctx, now-int64(d.cfg.Detection.RetentionSeconds))
}
