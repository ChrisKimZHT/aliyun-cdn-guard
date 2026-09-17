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

	"github.com/joho/godotenv"

	"aliyun-cdn-guard/internal/app"
	"aliyun-cdn-guard/internal/config"
)

const version = "1.1.0-go"

func main() {
	configPath := flag.String("config", "config.yml", "YAML configuration path")
	envFile := flag.String("env-file", ".env", "dotenv file for local development")
	checkConfig := flag.Bool("check-config", false, "validate configuration and exit")
	flag.Parse()
	if err := godotenv.Load(*envFile); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "cannot load env file: %v\n", err)
		os.Exit(2)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
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
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}
