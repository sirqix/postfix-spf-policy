package evaluator

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

// TestFindBrokenIncludes_Live runs against live DNS. Guarded by env var so
// CI without internet can skip. Validates the canonical case from the
// 2026-06-15 incident: lsnc.net's SPF references spf-us.ppe-hosted.com
// (no underscore) which is NXDOMAIN; the corrected name is
// _spf-us.ppe-hosted.com (with underscore prefix).
func TestFindBrokenIncludes_Live(t *testing.T) {
	if os.Getenv("EVALUATOR_LIVE_DNS") == "" {
		t.Skip("set EVALUATOR_LIVE_DNS=1 to run live-network test")
	}
	e := New(10*time.Second, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	broken := e.findBrokenIncludes(ctx, "lsnc.net")
	if len(broken) == 0 {
		t.Fatalf("expected at least one broken include for lsnc.net, got none")
	}
	for _, bi := range broken {
		t.Logf("  broken: %s (%s)", bi.target, bi.cause)
	}
	// Specifically verify spf-us.ppe-hosted.com is among the broken set
	found := false
	for _, bi := range broken {
		if bi.target == "spf-us.ppe-hosted.com" {
			found = true
			if bi.cause != "NXDOMAIN" {
				t.Errorf("expected NXDOMAIN cause for spf-us.ppe-hosted.com, got %q", bi.cause)
			}
		}
	}
	if !found {
		t.Errorf("expected spf-us.ppe-hosted.com in broken list, not found")
	}
}
