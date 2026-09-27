package evaluator

import (
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"blitiri.com.ar/go/spf"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"user@domain", "user@example.com", "example.com"},
		{"with subdomain", "user@mail.example.com", "mail.example.com"},
		{"uppercase", "User@EXAMPLE.COM", "example.com"},
		{"empty", "", ""},
		{"no at sign bare domain", "example.com", "example.com"},
		{"no at sign single word", "localhost", ""},
		{"bare domain with dots", "sub.example.com", "sub.example.com"},
		{"multiple at signs", "user@bad@example.com", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractDomain(tc.input)
			if got != tc.want {
				t.Errorf("extractDomain(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestGetDomainRoot(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"two parts", "example.com", "example.com"},
		{"three parts", "sub.example.com", "example.com"},
		{"four parts", "a.b.example.com", "example.com"},
		{"single part", "localhost", "localhost"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := getDomainRoot(tc.input)
			if got != tc.want {
				t.Errorf("getDomainRoot(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestMatchesIPSpec(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		spec string
		want bool
	}{
		{"exact IPv4 match", "192.168.1.1", "192.168.1.1", true},
		{"exact IPv4 no match", "192.168.1.1", "192.168.1.2", false},
		{"CIDR match /24", "192.168.1.100", "192.168.1.0/24", true},
		{"CIDR no match /24", "192.168.2.1", "192.168.1.0/24", false},
		{"CIDR match /16", "10.0.5.1", "10.0.0.0/16", true},
		{"IPv6 exact match", "::1", "::1", true},
		{"IPv6 CIDR match", "2001:db8::1", "2001:db8::/32", true},
		{"IPv6 CIDR no match", "2001:db9::1", "2001:db8::/32", false},
		{"invalid spec", "192.168.1.1", "not-an-ip", false},
		{"invalid CIDR", "192.168.1.1", "192.168.1.0/99", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("invalid test IP: %s", tc.ip)
			}
			got := matchesIPSpec(ip, tc.spec)
			if got != tc.want {
				t.Errorf("matchesIPSpec(%s, %q) = %v, want %v", tc.ip, tc.spec, got, tc.want)
			}
		})
	}
}

func TestPermErrorReason(t *testing.T) {
	tests := []struct {
		name        string
		domain      string
		records     []string
		wantSubstrs []string // substrings that must appear in the message
	}{
		{
			name:    "multiple records (the discoverownliberty case)",
			domain:  "daily.discoverownliberty.com",
			records: []string{"v=spf1 a ~all", "v=spf1 mx ~all", "v=spf1 ip4:1.2.3.4 ~all"},
			wantSubstrs: []string{
				"daily.discoverownliberty.com",
				"3 v=spf1 records",
				"§4.5",
				"merge",
			},
		},
		{
			name:        "no records found",
			domain:      "broken.example.com",
			records:     nil,
			wantSubstrs: []string{"broken.example.com", "no usable v=spf1 record"},
		},
		{
			name:        "single record (genuine syntax/lookup error)",
			domain:      "syntax-broken.example.com",
			records:     []string{"v=spf1 ip4:not-an-ip ~all"},
			wantSubstrs: []string{"syntax-broken.example.com", "invalid mechanism syntax", "10 lookups"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := permErrorReason(tc.domain, tc.records)
			for _, want := range tc.wantSubstrs {
				if !strings.Contains(got, want) {
					t.Errorf("permErrorReason() = %q; missing substring %q", got, want)
				}
			}
		})
	}
}

func TestExpandSPFMacros(t *testing.T) {
	walk := &spfWalk{
		clientIP:     net.ParseIP("192.0.2.5"),
		senderEmail:  "alice@example.com",
		senderDomain: "example.com",
		heloName:     "mta1.example.com",
	}
	v6Walk := &spfWalk{
		clientIP: net.ParseIP("2001:db8::1"),
	}

	tests := []struct {
		name   string
		spec   string
		walk   *spfWalk
		curDom string
		want   string
		wantOk bool
	}{
		{"no macros", "_spf.example.com", walk, "example.com", "_spf.example.com", true},
		{"%{i} v4 (sparkpost pattern)", "%{i}._spf.sparkpostmail.com", walk, "example.com",
			"192.0.2.5._spf.sparkpostmail.com", true},
		{"%{s}", "verp.%{s}", walk, "example.com", "verp.alice@example.com", true},
		{"%{o}", "%{o}.example.net", walk, "example.com", "example.com.example.net", true},
		{"%{d} reflects current SPF domain", "_check.%{d}", walk, "sub.example.com",
			"_check.sub.example.com", true},
		{"%{l}", "%{l}.bounce", walk, "example.com", "alice.bounce", true},
		{"%{h}", "%{h}.helo-check", walk, "example.com", "mta1.example.com.helo-check", true},
		{"%% literal", "100%%off", walk, "example.com", "100%off", true},
		{"%_ space", "a%_b", walk, "example.com", "a b", true},
		{"%- escaped", "a%-b", walk, "example.com", "a%20b", true},
		{"%{i} IPv6 nibble form", "%{i}.example.com", v6Walk, "example.com",
			"2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.example.com", true},
		// Failure modes — caller will skip the mechanism.
		{"transformer rejected", "%{ir}.example.com", walk, "example.com", "", false},
		{"digit transformer rejected", "%{i1}.example.com", walk, "example.com", "", false},
		{"unknown letter rejected", "%{x}.example.com", walk, "example.com", "", false},
		{"unterminated brace rejected", "%{i.example.com", walk, "example.com", "", false},
		{"trailing percent rejected", "abc%", walk, "example.com", "", false},
		{"empty macro rejected", "%{}", walk, "example.com", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := expandSPFMacros(tc.spec, tc.walk, tc.curDom)
			if ok != tc.wantOk {
				t.Fatalf("ok = %v, want %v (got=%q)", ok, tc.wantOk, got)
			}
			if ok && got != tc.want {
				t.Errorf("expandSPFMacros(%q) = %q, want %q", tc.spec, got, tc.want)
			}
		})
	}
}

func TestStripMechPrefix(t *testing.T) {
	tests := []struct {
		part, partLower, mech string
		wantVal               string
		wantOk                bool
	}{
		{"ip4:1.2.3.4", "ip4:1.2.3.4", "ip4:", "1.2.3.4", true},
		{"+ip4:1.2.3.4", "+ip4:1.2.3.4", "ip4:", "1.2.3.4", true},
		{"IP4:1.2.3.4", "ip4:1.2.3.4", "ip4:", "1.2.3.4", true},
		{"+EXISTS:%{i}.x.com", "+exists:%{i}.x.com", "exists:", "%{i}.x.com", true},
		{"include:foo.com", "include:foo.com", "ip4:", "", false},
		{"-ip4:1.2.3.4", "-ip4:1.2.3.4", "ip4:", "", false}, // we don't support '-' qualifier
	}
	for _, tc := range tests {
		t.Run(tc.part, func(t *testing.T) {
			gotVal, gotOk := stripMechPrefix(tc.part, tc.partLower, tc.mech)
			if gotOk != tc.wantOk || gotVal != tc.wantVal {
				t.Errorf("stripMechPrefix(%q, %q, %q) = (%q, %v), want (%q, %v)",
					tc.part, tc.partLower, tc.mech, gotVal, gotOk, tc.wantVal, tc.wantOk)
			}
		})
	}
}

func TestSplitSPFTokens(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "well-formed record unchanged",
			in:   "v=spf1 +mx +a +ip4:199.192.21.88 ~all",
			want: []string{"v=spf1", "+mx", "+a", "+ip4:199.192.21.88", "~all"},
		},
		{
			name: "missing space before ~all (the detroittraders case)",
			in:   "v=spf1 +mx +a +ip4:199.192.21.88~all",
			want: []string{"v=spf1", "+mx", "+a", "+ip4:199.192.21.88", "~all"},
		},
		{
			name: "missing space before -all",
			in:   "v=spf1 ip4:1.2.3.4-all",
			want: []string{"v=spf1", "ip4:1.2.3.4", "-all"},
		},
		{
			name: "missing space before ?all",
			in:   "v=spf1 ip4:1.2.3.4?all",
			want: []string{"v=spf1", "ip4:1.2.3.4", "?all"},
		},
		{
			name: "missing space before +all",
			in:   "v=spf1 ip4:1.2.3.4+all",
			want: []string{"v=spf1", "ip4:1.2.3.4", "+all"},
		},
		{
			name: "bare all (no qualifier) mashed onto IP",
			in:   "v=spf1 ip4:1.2.3.4all",
			want: []string{"v=spf1", "ip4:1.2.3.4", "all"},
		},
		{
			name: "case insensitive ~ALL",
			in:   "v=spf1 ip4:1.2.3.4~ALL",
			want: []string{"v=spf1", "ip4:1.2.3.4", "~ALL"},
		},
		{
			name: "standalone ~all not split",
			in:   "~all",
			want: []string{"~all"},
		},
		{
			name: "include with all suffix",
			in:   "include:_spf.example.com~all",
			want: []string{"include:_spf.example.com", "~all"},
		},
		{
			name: "empty record",
			in:   "",
			want: []string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := splitSPFTokens(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("splitSPFTokens(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("splitSPFTokens(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestSameSubnet(t *testing.T) {
	tests := []struct {
		name      string
		ip1       string
		ip2       string
		prefixLen int
		want      bool
	}{
		{"same /24", "192.168.1.1", "192.168.1.200", 24, true},
		{"different /24", "192.168.1.1", "192.168.2.1", 24, false},
		{"same /16", "10.0.1.1", "10.0.2.1", 16, true},
		{"different /16", "10.0.1.1", "10.1.1.1", 16, false},
		{"same /32", "1.2.3.4", "1.2.3.4", 32, true},
		{"different /32", "1.2.3.4", "1.2.3.5", 32, false},
		{"IPv6 returns false", "::1", "::2", 64, false},
		{"mixed v4/v6 returns false", "192.168.1.1", "::1", 24, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip1 := net.ParseIP(tc.ip1)
			ip2 := net.ParseIP(tc.ip2)
			got := sameSubnet(ip1, ip2, tc.prefixLen)
			if got != tc.want {
				t.Errorf("sameSubnet(%s, %s, %d) = %v, want %v", tc.ip1, tc.ip2, tc.prefixLen, got, tc.want)
			}
		})
	}
}

func TestSpfResultString(t *testing.T) {
	tests := []struct {
		input spf.Result
		want  string
	}{
		{spf.Pass, "pass"},
		{spf.Fail, "fail"},
		{spf.SoftFail, "softfail"},
		{spf.Neutral, "neutral"},
		{spf.None, "none"},
		{spf.TempError, "temperror"},
		{spf.PermError, "permerror"},
		{spf.Result("bogus"), "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := spfResultString(tc.input)
			if got != tc.want {
				t.Errorf("spfResultString(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestResultToAction(t *testing.T) {
	logger := newTestLogger()
	e := New(10*time.Second, logger)

	tests := []struct {
		result     spf.Result
		wantAction string
	}{
		{spf.Pass, "DUNNO"},
		{spf.Fail, "REJECT"},
		{spf.SoftFail, "DEFER"},
		{spf.Neutral, "DUNNO"},
		{spf.None, "DUNNO"},
		{spf.TempError, "DEFER"},
		{spf.PermError, "DEFER"},
	}

	for _, tc := range tests {
		t.Run(string(tc.result), func(t *testing.T) {
			action, _ := e.resultToAction(tc.result, "user@example.com", "example.com")
			if action != tc.wantAction {
				t.Errorf("resultToAction(%v) action = %q, want %q", tc.result, action, tc.wantAction)
			}
		})
	}
}

func TestNew(t *testing.T) {
	logger := newTestLogger()
	e := New(10*time.Second, logger)

	if !e.TolerantMode() {
		t.Error("TolerantMode should be true by default")
	}
}

func TestSetTolerantMode(t *testing.T) {
	logger := newTestLogger()
	e := New(10*time.Second, logger)

	e.SetTolerantMode(false)
	if e.TolerantMode() {
		t.Error("TolerantMode should be false after SetTolerantMode(false)")
	}

	e.SetTolerantMode(true)
	if !e.TolerantMode() {
		t.Error("TolerantMode should be true after SetTolerantMode(true)")
	}
}

func TestStats(t *testing.T) {
	logger := newTestLogger()
	e := New(10*time.Second, logger)

	stats := e.Stats()
	if stats.Checks != 0 || stats.Passes != 0 || stats.Fails != 0 {
		t.Errorf("initial stats should all be zero, got %+v", stats)
	}
}

func TestResetStats(t *testing.T) {
	logger := newTestLogger()
	e := New(10*time.Second, logger)

	// Increment counters directly via resultToAction
	e.resultToAction(spf.Pass, "user@example.com", "example.com")
	e.resultToAction(spf.Fail, "user@example.com", "example.com")

	stats := e.Stats()
	if stats.Passes != 1 || stats.Fails != 1 {
		t.Errorf("pre-reset: Passes=%d Fails=%d, want 1,1", stats.Passes, stats.Fails)
	}

	e.ResetStats()
	stats = e.Stats()
	if stats.Passes != 0 || stats.Fails != 0 {
		t.Errorf("post-reset: Passes=%d Fails=%d, want 0,0", stats.Passes, stats.Fails)
	}
}

func BenchmarkExtractDomain(b *testing.B) {
	for i := 0; i < b.N; i++ {
		extractDomain("user@example.com")
	}
}

func BenchmarkMatchesIPSpec(b *testing.B) {
	ip := net.ParseIP("192.168.1.100")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matchesIPSpec(ip, "192.168.1.0/24")
	}
}

func BenchmarkSameSubnet(b *testing.B) {
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.200")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sameSubnet(ip1, ip2, 24)
	}
}
