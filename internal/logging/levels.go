// Package logging provides log level helpers and a syslog-backed slog handler.
package logging

import (
	"log/slog"
	"strings"
)

// LevelVerbose sits between Info (0) and Debug (-4). At LevelVerbose the
// daemon emits per-request decisions (pass/fail/defer) in addition to the
// tolerant-override events emitted at Info. Debug adds cache traces and
// upstream library debug strings.
const LevelVerbose slog.Level = -2

// ParseLevel converts a config string into a slog.Level.
// Accepts: debug, verbose, info, notice, warn/warning, error/err.
// Returns ok=false on unrecognised input so the caller can decide whether to
// keep the current level or fall back to a default.
func ParseLevel(s string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, true
	case "verbose":
		return LevelVerbose, true
	case "info", "notice":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error", "err":
		return slog.LevelError, true
	default:
		return slog.LevelInfo, false
	}
}

// LevelString gives a stable short name for a level, including the custom
// LevelVerbose. slog.Level.String() returns "DEBUG+2" for -2 by default; this
// returns "VERBOSE" instead.
func LevelString(l slog.Level) string {
	switch l {
	case LevelVerbose:
		return "VERBOSE"
	default:
		return l.String()
	}
}
