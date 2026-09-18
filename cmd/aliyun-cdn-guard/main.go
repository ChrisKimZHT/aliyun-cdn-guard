package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"aliyun-cdn-guard/internal/app"
	"aliyun-cdn-guard/internal/benchmark"
	"aliyun-cdn-guard/internal/config"
)

var version = "dev"

func main() {
	configureLogging("INFO")
	configPath := flag.String("config", "config.yml", "YAML configuration path")
	envFile := flag.String("env-file", ".env", "dotenv file for local development")
	checkConfig := flag.Bool("check-config", false, "validate configuration and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	bench := flag.Bool("benchmark", false, "benchmark local detection and SQLite; no cloud calls or production writes")
	benchDuration := flag.Duration("benchmark-duration", 10*time.Second, "measurement duration per scenario, plus 1s warmup")
	benchScenario := flag.String("benchmark-scenario", "all", "hot, distributed, unique, or all")
	benchDir := flag.String("benchmark-dir", ".", "existing directory on the disk to benchmark; temporary databases are removed")
	benchBatch := flag.Int("benchmark-batch-size", 256, "events per transaction (1..256)")
	benchIPs := flag.Int("benchmark-ips", 1024, "number of source IPs in the distributed scenario")
	benchProfile := flag.String("benchmark-cpu-profile", "", "write CPU profile to a new file")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *bench {
		cfg := benchmark.DefaultConfig()
		var err error
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "config" {
				cfg, err = config.Load(*configPath)
			}
		})
		if err == nil {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			err = benchmark.Run(ctx, cfg, benchmark.Options{Duration: *benchDuration, Scenario: *benchScenario, Directory: *benchDir, BatchSize: *benchBatch, IPs: *benchIPs, CPUProfile: *benchProfile}, os.Stdout)
		}
		if err != nil {
			slog.Error("benchmark failed", "error", err)
			os.Exit(1)
		}
		return
	}
	if err := godotenv.Load(*envFile); err != nil && !os.IsNotExist(err) {
		slog.Error("cannot load env file", "error", err)
		os.Exit(2)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(2)
	}
	configureLogging(cfg.LogLevel)
	if *checkConfig {
		fmt.Println("configuration is valid")
		return
	}
	slog.Info("aliyun-cdn-guard", "version", version)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, cfg); err != nil {
		slog.Error("guard terminated unexpectedly", "error", err)
		os.Exit(1)
	}
}

func configureLogging(level string) {
	var l slog.Level
	switch strings.ToUpper(level) {
	case "TRACE", "DEBUG":
		l = slog.LevelDebug
	case "WARNING":
		l = slog.LevelWarn
	case "ERROR", "CRITICAL":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}
