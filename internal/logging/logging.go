package logging

import (
	"log/slog"
	"os"
)

// NewLogger returns a structured logger.
// If verbose == true, level = Debug, else Info.
func NewLogger(verbose bool) *slog.Logger {
	level := new(slog.LevelVar)
	if verbose {
		level.Set(slog.LevelDebug)
	} else {
		level.Set(slog.LevelInfo)
	}

	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})
	return slog.New(handler)
}

