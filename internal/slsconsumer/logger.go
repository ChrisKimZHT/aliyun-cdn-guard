package slsconsumer

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// sdkLogger adapts the go-kit logger used by the SLS SDK to the application's
// slog logger, keeping every runtime log entry in the same JSONL format.
type sdkLogger struct {
	logger *slog.Logger
}

func (l sdkLogger) Log(keyvals ...any) error {
	level := slog.LevelInfo
	message := "SLS SDK"
	attrs := make([]any, 0, len(keyvals)+2)
	attrs = append(attrs, "component", "sls_sdk")

	for i := 0; i < len(keyvals); i += 2 {
		key := fmt.Sprint(keyvals[i])
		if i+1 >= len(keyvals) {
			attrs = append(attrs, "unpaired", key)
			break
		}
		value := keyvals[i+1]
		switch key {
		case "level":
			level = sdkLogLevel(value)
		case "msg":
			message = fmt.Sprint(value)
		case "time":
			// slog supplies the canonical timestamp for the unified record.
		default:
			if err, ok := value.(error); ok {
				value = err.Error()
			}
			attrs = append(attrs, key, value)
		}
	}

	l.logger.Log(context.Background(), level, message, attrs...)
	return nil
}

func sdkLogLevel(value any) slog.Level {
	switch strings.ToLower(fmt.Sprint(value)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
