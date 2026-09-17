package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/aliyun/credentials-go/credentials"

	"aliyun-cdn-guard/internal/audit"
	"aliyun-cdn-guard/internal/cdn"
	"aliyun-cdn-guard/internal/config"
	"aliyun-cdn-guard/internal/detector"
	"aliyun-cdn-guard/internal/slsconsumer"
	"aliyun-cdn-guard/internal/storage"
)

func Run(ctx context.Context, cfg *config.Config) error {
	s, err := storage.Open(cfg.StoragePath)
	if err != nil {
		return err
	}
	defer s.Close()
	blockLog, err := audit.New(cfg.BlockLogPath, cfg.CDN.DryRun)
	if err != nil {
		return err
	}
	d := detector.New(cfg, s, blockLog)
	credential, err := credentials.NewCredential(nil)
	if err != nil {
		return fmt.Errorf("initialize credentials: %w", err)
	}
	gateway, err := cdn.NewAliyunGateway(cfg, credential)
	if err != nil {
		return fmt.Errorf("initialize CDN client: %w", err)
	}
	hostname, _ := os.Hostname()
	consumerName := cfg.SLS.ConsumerName
	if consumerName == "" {
		consumerName = fmt.Sprintf("%s-%d", hostname, os.Getpid())
	}
	worker, err := slsconsumer.New(cfg, credential, d, consumerName)
	if err != nil {
		return err
	}
	reconcileCtx, cancelReconcile := context.WithCancel(context.Background())
	reconcileDone := make(chan struct{})
	go func() {
		defer close(reconcileDone)
		cdn.NewReconciler(cfg, s, gateway).Run(reconcileCtx)
	}()
	worker.Start()
	slog.Info("guard started", "consumer", consumerName, "dry_run", cfg.CDN.DryRun)
	pruneTicker := time.NewTicker(30 * time.Second)
	defer pruneTicker.Stop()
	reportTicker := time.NewTicker(time.Duration(cfg.ReportIntervalSeconds) * time.Second)
	defer reportTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			cancelReconcile()
			worker.Stop()
			<-reconcileDone
			slog.Info("guard stopped")
			return nil
		case <-pruneTicker.C:
			deleted, err := d.Prune(context.Background(), 0)
			if err != nil {
				slog.Error("failed to prune old events", "error", err)
			} else if deleted > 0 {
				slog.Debug("pruned old events", "count", deleted)
			}
		case now := <-reportTicker.C:
			counts := d.Snapshot(true)
			for _, domain := range cfg.CDN.Domains {
				active, err := s.ActiveBlockEntries(context.Background(), domain, now.Unix())
				if err != nil {
					slog.Error("failed to read active blocks", "domain", domain, "error", err)
					continue
				}
				for _, entry := range cfg.PermanentBlocklist[domain] {
					active[entry] = struct{}{}
				}
				c := counts[domain]
				slog.Info("periodic report", "domain", domain, "received", c[0], "processed", c[1], "blocked_ips", len(active))
			}
		}
	}
}
