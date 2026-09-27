package evaluator

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

// TestTolerantWalkFollowsRedirect_Live guards against a regression where the
// tolerant PermError bypass (checkIPInSPFRecord) failed to follow the
// redirect= modifier. cisco.com's apex record is a bare
// "v=spf1 redirect=spfa._spf.cisco.com"; every authorized ip4: lives in the
// redirect target chain (spfa -> spfb -> spfc). Before the fix,
// ipMatchesSPFRecord only handled ip4:/ip6:/include:/exists:, so the walk
// stopped at the apex and the bypass silently no-oped for the whole class of
// redirect-based senders — even for IPs explicitly listed in the chain.
//
// Live-DNS; guarded by env var so offline CI skips. cisco could re-number its
// SPF chain, so a failure here means "re-check cisco's record", not
// necessarily a code regression.
func TestTolerantWalkFollowsRedirect_Live(t *testing.T) {
	if os.Getenv("EVALUATOR_LIVE_DNS") == "" {
		t.Skip("set EVALUATOR_LIVE_DNS=1 to run live-network test")
	}
	e := New(10*time.Second, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 68.232.135.80 is published as ip4:68.232.135.80 in spfb._spf.cisco.com,
	// reachable from the cisco.com apex only by following redirect=.
	found, recs := e.checkIPInSPFRecord(ctx, "68.232.135.80", "noreply@cisco.com", "helo.example", "cisco.com")
	if !found {
		t.Errorf("expected IP authorized via redirect chain to be found; apex record(s)=%v", recs)
	}

	// A relay IP that is NOT in cisco's chain must still not match: the
	// redirect follow must not turn the bypass into a blanket pass.
	if found, _ := e.checkIPInSPFRecord(ctx, "68.232.143.85", "noreply@cisco.com", "helo.example", "cisco.com"); found {
		t.Errorf("unauthorized relay IP must not match through redirect chain")
	}
}
