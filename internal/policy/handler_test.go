package policy

import (
	"bufio"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blitiri.com.ar/go/spf"
	"postfix-spf-policy/internal/cache"
	"postfix-spf-policy/internal/domains"
	"postfix-spf-policy/internal/evaluator"
	"postfix-spf-policy/internal/whitelist"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	logger := newTestLogger()
	eval := evaluator.New(5*time.Second, logger)
	c, err := cache.New(1000, 5*time.Minute)
	if err != nil {
		t.Fatalf("cache.New() error: %v", err)
	}
	d := domains.New(logger)
	wl := whitelist.New(logger)
	return NewHandler(eval, c, d, wl, 30*time.Second, logger)
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"user@domain", "user@example.com", "example.com"},
		{"uppercase", "User@EXAMPLE.COM", "example.com"},
		{"empty", "", ""},
		{"no at sign", "example.com", ""},
		{"bare user", "user", ""},
		{"multiple at signs", "a@b@c.com", ""},
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

func TestIsInternalIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"loopback v4", "127.0.0.1", true},
		{"loopback v6", "::1", true},
		{"RFC1918 10.x", "10.0.0.1", true},
		{"RFC1918 172.16.x", "172.16.0.1", true},
		{"RFC1918 192.168.x", "192.168.1.1", true},
		{"link-local v4", "169.254.1.1", true},
		{"link-local v6", "fe80::1", true},
		{"public IP", "8.8.8.8", false},
		{"public IP 2", "1.2.3.4", false},
		{"invalid", "not-an-ip", false},
		{"empty", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isInternalIP(tc.ip)
			if got != tc.want {
				t.Errorf("isInternalIP(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestReadRequest(t *testing.T) {
	input := "request=smtpd_access_policy\n" +
		"protocol_state=RCPT\n" +
		"protocol_name=SMTP\n" +
		"client_address=192.168.1.1\n" +
		"client_name=mail.example.com\n" +
		"helo_name=mail.example.com\n" +
		"sender=user@example.com\n" +
		"recipient=admin@test.com\n" +
		"queue_id=ABC123\n" +
		"instance=1234.5\n" +
		"\n"

	h := newTestHandler(t)
	reader := bufio.NewReader(strings.NewReader(input))
	req, err := h.readRequest(reader)
	if err != nil {
		t.Fatalf("readRequest() error: %v", err)
	}

	if req.Request != "smtpd_access_policy" {
		t.Errorf("Request = %q, want %q", req.Request, "smtpd_access_policy")
	}
	if req.ProtocolState != "RCPT" {
		t.Errorf("ProtocolState = %q, want %q", req.ProtocolState, "RCPT")
	}
	if req.ClientAddress != "192.168.1.1" {
		t.Errorf("ClientAddress = %q, want %q", req.ClientAddress, "192.168.1.1")
	}
	if req.HeloName != "mail.example.com" {
		t.Errorf("HeloName = %q, want %q", req.HeloName, "mail.example.com")
	}
	if req.Sender != "user@example.com" {
		t.Errorf("Sender = %q, want %q", req.Sender, "user@example.com")
	}
	if req.Recipient != "admin@test.com" {
		t.Errorf("Recipient = %q, want %q", req.Recipient, "admin@test.com")
	}
}

func TestReadRequest_UnknownKeys(t *testing.T) {
	input := "request=smtpd_access_policy\n" +
		"unknown_key=some_value\n" +
		"client_address=1.2.3.4\n" +
		"another_unknown=42\n" +
		"\n"

	h := newTestHandler(t)
	reader := bufio.NewReader(strings.NewReader(input))
	req, err := h.readRequest(reader)
	if err != nil {
		t.Fatalf("readRequest() error: %v", err)
	}

	if req.Request != "smtpd_access_policy" {
		t.Errorf("Request = %q, want %q", req.Request, "smtpd_access_policy")
	}
	if req.ClientAddress != "1.2.3.4" {
		t.Errorf("ClientAddress = %q, want %q", req.ClientAddress, "1.2.3.4")
	}
}

func TestProcessRequest_NonPolicyRequest(t *testing.T) {
	h := newTestHandler(t)
	req := &Request{
		Request:       "not_a_policy_request",
		ClientAddress: "1.2.3.4",
		Sender:        "user@example.com",
	}

	action, _ := h.ProcessRequest(req)
	if action != "DUNNO" {
		t.Errorf("action = %q, want %q for non-policy request", action, "DUNNO")
	}
}

func TestProcessRequest_NoClientAddress(t *testing.T) {
	h := newTestHandler(t)
	req := &Request{
		Request:       "smtpd_access_policy",
		ClientAddress: "",
		Sender:        "user@example.com",
	}

	action, _ := h.ProcessRequest(req)
	if action != "DUNNO" {
		t.Errorf("action = %q, want %q for empty client address", action, "DUNNO")
	}
}

func TestProcessRequest_LocalDomain_InternalIP(t *testing.T) {
	logger := newTestLogger()

	dir := t.TempDir()
	domainFile := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(domainFile, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	d := domains.New(logger)
	if err := d.LoadFromFile(domainFile); err != nil {
		t.Fatal(err)
	}

	eval := evaluator.New(5*time.Second, logger)
	c, _ := cache.New(1000, 5*time.Minute)
	wl := whitelist.New(logger)
	h := NewHandler(eval, c, d, wl, 30*time.Second, logger)

	req := &Request{
		Request:       "smtpd_access_policy",
		ClientAddress: "10.0.0.1",
		Sender:        "user@example.com",
	}

	action, reason := h.ProcessRequest(req)
	if action != "DUNNO" {
		t.Errorf("action = %q, want %q for local domain from internal IP", action, "DUNNO")
	}
	if !strings.Contains(reason, "local sender") {
		t.Errorf("reason = %q, should mention local sender", reason)
	}
}

func TestProcessRequest_LocalDomain_ExternalIP(t *testing.T) {
	logger := newTestLogger()

	dir := t.TempDir()
	domainFile := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(domainFile, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	d := domains.New(logger)
	if err := d.LoadFromFile(domainFile); err != nil {
		t.Fatal(err)
	}

	eval := evaluator.New(5*time.Second, logger)
	c, _ := cache.New(1000, 5*time.Minute)
	wl := whitelist.New(logger)
	h := NewHandler(eval, c, d, wl, 30*time.Second, logger)

	req := &Request{
		Request:       "smtpd_access_policy",
		ClientAddress: "8.8.8.8", // public IP
		Sender:        "user@example.com",
	}

	action, _ := h.ProcessRequest(req)
	if action != "REJECT" {
		t.Errorf("action = %q, want %q for local domain from external IP", action, "REJECT")
	}
}

func TestProcessRequest_Whitelisted(t *testing.T) {
	logger := newTestLogger()

	dir := t.TempDir()
	wlFile := filepath.Join(dir, "whitelist.txt")
	if err := os.WriteFile(wlFile, []byte("trusted.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	wl := whitelist.New(logger)
	if err := wl.LoadFromFile(wlFile); err != nil {
		t.Fatal(err)
	}

	eval := evaluator.New(5*time.Second, logger)
	c, _ := cache.New(1000, 5*time.Minute)
	d := domains.New(logger)
	h := NewHandler(eval, c, d, wl, 30*time.Second, logger)

	req := &Request{
		Request:       "smtpd_access_policy",
		ClientAddress: "1.2.3.4",
		Sender:        "user@trusted.com",
	}

	action, reason := h.ProcessRequest(req)
	if action != "DUNNO" {
		t.Errorf("action = %q, want %q for whitelisted domain", action, "DUNNO")
	}
	if !strings.Contains(reason, "whitelisted") {
		t.Errorf("reason = %q, should mention whitelisted", reason)
	}
}

func TestProcessRequest_CacheHit(t *testing.T) {
	h := newTestHandler(t)

	// Pre-populate cache
	cacheKey := "1.2.3.4|user@cached.com|mail.cached.com"
	h.cache.Set(cacheKey, &cache.Result{
		Action:    "REJECT",
		Reason:    "cached SPF fail",
		SPFResult: "fail",
	})

	req := &Request{
		Request:       "smtpd_access_policy",
		ClientAddress: "1.2.3.4",
		Sender:        "user@cached.com",
		HeloName:      "mail.cached.com",
	}

	action, reason := h.ProcessRequest(req)
	if action != "REJECT" {
		t.Errorf("action = %q, want %q for cache hit", action, "REJECT")
	}
	if reason != "cached SPF fail" {
		t.Errorf("reason = %q, want %q", reason, "cached SPF fail")
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

func TestStats(t *testing.T) {
	h := newTestHandler(t)

	stats := h.Stats()
	if stats.Connections != 0 || stats.Requests != 0 || stats.Errors != 0 {
		t.Errorf("initial stats should all be zero, got %+v", stats)
	}
}

func TestResetStats(t *testing.T) {
	h := newTestHandler(t)

	// Process a request to increment counters
	h.ProcessRequest(&Request{
		Request:       "smtpd_access_policy",
		ClientAddress: "",
	})

	h.ResetStats()
	stats := h.Stats()
	if stats.Connections != 0 || stats.Requests != 0 || stats.Errors != 0 {
		t.Errorf("after ResetStats: %+v, want all zeros", stats)
	}
}

func BenchmarkProcessRequest_CacheHit(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	eval := evaluator.New(5*time.Second, logger)
	c, _ := cache.New(10000, 5*time.Minute)
	d := domains.New(logger)
	wl := whitelist.New(logger)
	h := NewHandler(eval, c, d, wl, 30*time.Second, logger)

	cacheKey := "1.2.3.4|user@bench.com|mail.bench.com"
	c.Set(cacheKey, &cache.Result{
		Action:    "DUNNO",
		Reason:    "SPF pass",
		SPFResult: "pass",
	})

	req := &Request{
		Request:       "smtpd_access_policy",
		ClientAddress: "1.2.3.4",
		Sender:        "user@bench.com",
		HeloName:      "mail.bench.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.ProcessRequest(req)
	}
}

func BenchmarkProcessRequest_LocalDomain(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	dir := b.TempDir()
	domainFile := filepath.Join(dir, "domains.txt")
	os.WriteFile(domainFile, []byte("bench.com\n"), 0644)

	d := domains.New(logger)
	d.LoadFromFile(domainFile)

	eval := evaluator.New(5*time.Second, logger)
	c, _ := cache.New(10000, 5*time.Minute)
	wl := whitelist.New(logger)
	h := NewHandler(eval, c, d, wl, 30*time.Second, logger)

	req := &Request{
		Request:       "smtpd_access_policy",
		ClientAddress: "10.0.0.1", // internal IP
		Sender:        "user@bench.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.ProcessRequest(req)
	}
}

func TestHandle_Integration(t *testing.T) {
	h := newTestHandler(t)

	// Create a pipe to simulate a connection
	server, client := net.Pipe()

	type result struct {
		response string
		err      error
	}
	ch := make(chan result, 1)

	// Client goroutine: write request then read response
	// Must be in goroutine because net.Pipe is synchronous (unbuffered)
	go func() {
		defer client.Close()
		request := "request=smtpd_access_policy\n" +
			"client_address=\n" +
			"sender=user@example.com\n" +
			"\n"
		if _, err := client.Write([]byte(request)); err != nil {
			ch <- result{err: err}
			return
		}
		buf := make([]byte, 1024)
		n, err := client.Read(buf)
		if err != nil {
			ch <- result{err: err}
			return
		}
		ch <- result{response: string(buf[:n])}
	}()

	// Handle on the server side (blocks until done)
	h.Handle(server)

	r := <-ch
	if r.err != nil {
		t.Fatalf("client error: %v", r.err)
	}

	if !strings.HasPrefix(r.response, "action=dunno") {
		t.Errorf("response = %q, want prefix %q", r.response, "action=dunno")
	}
}
