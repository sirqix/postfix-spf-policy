package logging

import (
	"log/slog"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		in     string
		want   slog.Level
		wantOk bool
	}{
		{"debug", slog.LevelDebug, true},
		{"DEBUG", slog.LevelDebug, true},
		{"verbose", LevelVerbose, true},
		{"  Verbose  ", LevelVerbose, true},
		{"info", slog.LevelInfo, true},
		{"notice", slog.LevelInfo, true},
		{"warn", slog.LevelWarn, true},
		{"warning", slog.LevelWarn, true},
		{"error", slog.LevelError, true},
		{"err", slog.LevelError, true},
		{"", slog.LevelInfo, false},
		{"bogus", slog.LevelInfo, false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := ParseLevel(tc.in)
			if ok != tc.wantOk || got != tc.want {
				t.Errorf("ParseLevel(%q) = (%v, %v), want (%v, %v)", tc.in, got, ok, tc.want, tc.wantOk)
			}
		})
	}
}

func TestLevelString(t *testing.T) {
	tests := []struct {
		in   slog.Level
		want string
	}{
		{slog.LevelDebug, "DEBUG"},
		{LevelVerbose, "VERBOSE"},
		{slog.LevelInfo, "INFO"},
		{slog.LevelWarn, "WARN"},
		{slog.LevelError, "ERROR"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := LevelString(tc.in)
			if got != tc.want {
				t.Errorf("LevelString(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestLevelOrdering(t *testing.T) {
	// Verbose must sit strictly between Info and Debug so the level filter
	// behaves as documented.
	if !(slog.LevelDebug < LevelVerbose) {
		t.Errorf("LevelVerbose (%d) should be > LevelDebug (%d)", LevelVerbose, slog.LevelDebug)
	}
	if !(LevelVerbose < slog.LevelInfo) {
		t.Errorf("LevelVerbose (%d) should be < LevelInfo (%d)", LevelVerbose, slog.LevelInfo)
	}
}
