// Package benchmark measures the local detection/storage pipeline without cloud calls.
package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"time"

	"aliyun-cdn-guard/internal/audit"
	"aliyun-cdn-guard/internal/config"
	"aliyun-cdn-guard/internal/detector"
	"aliyun-cdn-guard/internal/model"
	"aliyun-cdn-guard/internal/storage"
)

type Options struct {
	Duration                        time.Duration
	Scenario, Directory, CPUProfile string
	BatchSize, IPs                  int
}

type Result struct {
	Scenario       string  `json:"scenario"`
	GoVersion      string  `json:"go_version"`
	CPUs           int     `json:"logical_cpus"`
	GOMAXPROCS     int     `json:"gomaxprocs"`
	BatchSize      int     `json:"batch_size"`
	IPs            int     `json:"ips"`
	Threshold      int     `json:"threshold"`
	WindowSeconds  int     `json:"window_seconds"`
	UseUA          bool    `json:"use_ua"`
	UseURI         bool    `json:"use_uri"`
	Events         int64   `json:"events"`
	Processed      int64   `json:"processed"`
	Decisions      int64   `json:"decisions"`
	Seconds        float64 `json:"seconds"`
	QPS            float64 `json:"qps"`
	MeanBatchMS    float64 `json:"mean_batch_ms"`
	MaxBatchMS     float64 `json:"max_batch_ms"`
	BytesPerEvent  float64 `json:"allocated_bytes_per_event"`
	AllocsPerEvent float64 `json:"allocations_per_event"`
}

// DefaultConfig is independent of production credentials and configuration files.
func DefaultConfig() *config.Config {
	return &config.Config{
		CDN:       config.CDNConfig{Domains: []string{"benchmark.example"}, DryRun: true},
		Detection: config.DetectionConfig{Threshold: 1000, WindowSeconds: 60, RetentionSeconds: 3600, URI: config.URIConfig{QueryMode: "keep"}},
		Penalty:   config.PenaltyConfig{BaseDurationSeconds: 600, Multiplier: 2, MaxDurationSeconds: 86400},
	}
}

func Run(ctx context.Context, cfg *config.Config, opts Options, out io.Writer) error {
	if opts.Duration <= 0 || opts.BatchSize < 1 || opts.BatchSize > detector.BatchSize || opts.IPs < 1 || opts.IPs > 1<<24 {
		return fmt.Errorf("benchmark requires duration > 0, batch-size 1..%d, ips 1..16777216", detector.BatchSize)
	}
	scenarios := []string{opts.Scenario}
	if opts.Scenario == "all" {
		scenarios = []string{"hot", "distributed", "unique"}
	}
	for _, scenario := range scenarios {
		if scenario != "hot" && scenario != "distributed" && scenario != "unique" {
			return fmt.Errorf("unknown benchmark scenario %q", scenario)
		}
	}
	if opts.CPUProfile != "" {
		f, err := os.OpenFile(opts.CPUProfile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			f.Close()
			return err
		}
		defer func() { pprof.StopCPUProfile(); f.Close() }()
	}
	for _, scenario := range scenarios {
		result, err := runScenario(ctx, cfg, opts, scenario)
		if err != nil {
			return err
		}
		if err := json.NewEncoder(out).Encode(result); err != nil {
			return err
		}
	}
	return nil
}

func runScenario(ctx context.Context, source *config.Config, opts Options, scenario string) (Result, error) {
	r := Result{Scenario: scenario, GoVersion: runtime.Version(), CPUs: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0), BatchSize: opts.BatchSize, IPs: opts.IPs, Threshold: source.Detection.Threshold, WindowSeconds: source.Detection.WindowSeconds, UseUA: source.Detection.UA.Enabled, UseURI: source.Detection.URI.Enabled}
	if scenario == "hot" {
		r.IPs = 1
	}
	if scenario == "unique" {
		r.IPs = 0
	} // One new IPv6 address per event.
	dir, err := os.MkdirTemp(opts.Directory, "cdn-guard-benchmark-")
	if err != nil {
		return r, err
	}
	defer os.RemoveAll(dir)
	cfg := *source
	cfg.StoragePath = filepath.Join(dir, "guard.db")
	cfg.BlockLogPath = filepath.Join(dir, "blocks.jsonl")
	cfg.CDN.DryRun = true
	s, err := storage.Open(cfg.StoragePath)
	if err != nil {
		return r, err
	}
	defer s.Close()
	b, err := audit.New(cfg.BlockLogPath, true)
	if err != nil {
		return r, err
	}
	d := detector.New(&cfg, s, b)
	events := make([]model.AccessEvent, opts.BatchSize)
	var sequence uint64
	nextPrune := time.Now().Add(30 * time.Second)
	// Warm the same database for one second; do not time setup or initial allocations.
	run := func(duration time.Duration, measure bool) error {
		start := time.Now()
		deadline := start.Add(duration)
		var batches int64
		for time.Now().Before(deadline) {
			if err := ctx.Err(); err != nil {
				return err
			}
			batchStart := time.Now()
			for i := range events {
				sequence++
				ipID := sequence
				if scenario == "hot" {
					ipID = 1
				} else if scenario == "distributed" {
					ipID = sequence%uint64(opts.IPs) + 1
				}
				ip := fmt.Sprintf("2001:db8::%x:%x:%x:%x", uint16(ipID>>48), uint16(ipID>>32), uint16(ipID>>16), uint16(ipID))
				events[i] = model.AccessEvent{EventID: strconv.FormatUint(sequence, 10), Timestamp: batchStart.Unix(), Domain: cfg.CDN.Domains[0], ClientIP: ip, UserAgent: "cdn-guard-benchmark/1", URI: "/asset.js", URIParam: "v=1"}
				d.RecordReceived(events[i].Domain)
			}
			decisions, err := d.ProcessBatch(ctx, events, 0)
			if err != nil {
				return err
			}
			if time.Now().After(nextPrune) {
				if _, err := d.Prune(ctx, 0); err != nil {
					return err
				}
				nextPrune = time.Now().Add(30 * time.Second)
			}
			if measure {
				r.Events += int64(len(events))
				r.Decisions += int64(len(decisions))
				batches++
				r.MaxBatchMS = max(r.MaxBatchMS, float64(time.Since(batchStart))/float64(time.Millisecond))
			}
		}
		if measure {
			r.Seconds = time.Since(start).Seconds()
			r.QPS = float64(r.Events) / r.Seconds
			r.MeanBatchMS = r.Seconds * 1000 / float64(batches)
		}
		return nil
	}
	if err := run(time.Second, false); err != nil {
		return r, err
	}
	d.Snapshot(true)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := run(opts.Duration, true); err != nil {
		return r, err
	}
	runtime.ReadMemStats(&after)
	r.Processed = d.Snapshot(false)[cfg.CDN.Domains[0]][1]
	if r.Events == 0 || r.Processed != r.Events {
		return r, fmt.Errorf("benchmark events were filtered by configuration: received=%d processed=%d; use default benchmark configuration or adjust whitelist", r.Events, r.Processed)
	}
	r.BytesPerEvent = float64(after.TotalAlloc-before.TotalAlloc) / float64(r.Events)
	r.AllocsPerEvent = float64(after.Mallocs-before.Mallocs) / float64(r.Events)
	return r, nil
}
