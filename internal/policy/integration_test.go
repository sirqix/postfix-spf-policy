//go:build integration

package policy

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"postfix-spf-policy/internal/cache"
	"postfix-spf-policy/internal/domains"
	"postfix-spf-policy/internal/evaluator"
	"postfix-spf-policy/internal/whitelist"
)

func newIntegrationHandler(t *testing.T) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	eval := evaluator.New(5*time.Second, logger)
	c, err := cache.New(1000, 5*time.Minute)
	if err != nil {
		t.Fatalf("cache.New() error: %v", err)
	}
	d := domains.New(logger)
	wl := whitelist.New(logger)
	return NewHandler(eval, c, d, wl, 30*time.Second, logger)
}

func startTestServer(t *testing.T, h *Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go h.Handle(conn)
		}
	}()

	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func sendPolicyRequest(t *testing.T, addr string, fields map[string]string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send request
	var req strings.Builder
	for k, v := range fields {
		fmt.Fprintf(&req, "%s=%s\n", k, v)
	}
	req.WriteString("\n")

	if _, err := conn.Write([]byte(req.String())); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error: %v", err)
	}

	return strings.TrimSpace(line)
}

func TestIntegration_PolicyProtocol(t *testing.T) {
	h := newIntegrationHandler(t)
	addr := startTestServer(t, h)

	response := sendPolicyRequest(t, addr, map[string]string{
		"request":        "smtpd_access_policy",
		"client_address": "",
		"sender":         "user@example.com",
	})

	if !strings.HasPrefix(response, "action=") {
		t.Errorf("response should start with 'action=', got: %q", response)
	}
}

func TestIntegration_ConcurrentConnections(t *testing.T) {
	h := newIntegrationHandler(t)
	addr := startTestServer(t, h)

	var wg sync.WaitGroup
	errors := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			response := sendPolicyRequest(t, addr, map[string]string{
				"request":        "smtpd_access_policy",
				"client_address": "",
				"sender":         fmt.Sprintf("user%d@example.com", n),
			})
			if !strings.HasPrefix(response, "action=") {
				errors <- fmt.Errorf("connection %d: unexpected response: %q", n, response)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

func TestIntegration_MalformedRequest(t *testing.T) {
	h := newIntegrationHandler(t)
	addr := startTestServer(t, h)

	// Send garbage data - the server should handle it gracefully
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send malformed data followed by empty line (end of request)
	conn.Write([]byte("this is not a valid request line\n\n"))

	// Read response - server should respond with action=dunno for invalid request type
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error: %v", err)
	}

	response := strings.TrimSpace(line)
	if !strings.HasPrefix(response, "action=") {
		t.Errorf("response should start with 'action=', got: %q", response)
	}
}
