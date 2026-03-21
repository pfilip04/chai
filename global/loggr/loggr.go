package loggr

import (
	"log/slog"
	"os"
)

//
// Global Logger

var Log = NewLogger(slog.LevelInfo)

func NewLogger(level slog.Leveler) *slog.Logger {

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})

	return slog.New(handler)
}

//
// Helper functions (Cleaner syntax + readability)

func Info(msg string, args ...any) {
	Log.Info(msg, args...)
}

func Error(msg string, args ...any) {
	Log.Error(msg, args...)
}
