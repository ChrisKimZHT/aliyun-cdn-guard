package slsconsumer

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/go-kit/kit/log/level"
)

func TestToEventFallbackIDIsStable(t *testing.T) {
	fields := map[string]string{"domain": " Example.COM ", "client_ip": " 192.0.2.1 ", "user_agent": "ua", "uri": "/x", "uri_param": "a=1"}
	a, ok := toEvent(fields, 123)
	if !ok {
		t.Fatal("event rejected")
	}
	b, _ := toEvent(fields, 123)
	if a.EventID == "" || a.EventID != b.EventID {
		t.Fatalf("ids %q %q", a.EventID, b.EventID)
	}
	if a.Domain != "example.com" || a.ClientIP != "192.0.2.1" {
		t.Fatalf("event=%+v", a)
	}
}

func TestSDKLoggerProducesUnifiedJSON(t *testing.T) {
	var output bytes.Buffer
	logger := sdkLogger{logger: slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	if err := level.Warn(logger).Log("msg", "heartbeat", "shard", 2); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("invalid JSONL record %q: %v", output.String(), err)
	}
	if record["level"] != "WARN" || record["msg"] != "heartbeat" || record["component"] != "sls_sdk" || record["shard"] != float64(2) {
		t.Fatalf("record=%v", record)
	}
}
