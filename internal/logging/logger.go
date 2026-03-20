package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

const defaultLevel = "info"

func New(level string) (*slog.Logger, error) {
	return NewWithWriter(level, os.Stdout)
}

func NewWithWriter(level string, writer io.Writer) (*slog.Logger, error) {
	parsedLevel, err := ParseLevel(level)
	if err != nil {
		return nil, err
	}

	return slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{
		Level: parsedLevel,
	})), nil
}

func ParseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", defaultLevel, "information":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unsupported log level %q", level)
	}
}
