// Package policy implements the Postfix policy delegation protocol.
package policy

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"blitiri.com.ar/go/spf"
	"postfix-spf-policy/internal/cache"
	"postfix-spf-policy/internal/domains"
	"postfix-spf-policy/internal/evaluator"
	"postfix-spf-policy/internal/whitelist"
)

// Request represents a Postfix policy request.
type Request struct {
	Request           string
	ProtocolState     string
	ProtocolName      string
	ClientAddress     string
	ClientName        string
	ClientPort        string
	ReverseClientName string
	HeloName          string
	Sender            string
	Recipient         string
	RecipientCount    string
	QueueID           string
	Instance          string
	Size              string
	SaslMethod        string
	SaslUsername      string
	SaslSender        string
	EncryptionProtocol string
	EncryptionCipher   string
	EncryptionKeysize  string
}

// Handler handles Postfix policy connections.
type Handler struct {
	evaluator *evaluator.Evaluator
	cache     *cache.Cache
	domains   *domains.Loader
	whitelist *whitelist.Whitelist
	logger    *slog.Logger
	timeout   time.Duration

	// Statistics
	connections      atomic.Int64
	requests         atomic.Int64
	errors           atomic.Int64
	localSkipped     atomic.Int64 // Requests skipped because sender is local from internal IP
	localSpoofed     atomic.Int64 // Requests rejected because external IP spoofed local domain
	whitelistSkipped atomic.Int64 // Requests skipped because sender domain is whitelisted
}

// Stats holds handler statistics.
type Stats struct {
	Connections      int64
	Requests         int64
	Errors           int64
	LocalSkipped     int64
	LocalSpoofed     int64
	WhitelistSkipped int64
}

// NewHandler creates a new policy handler.
func NewHandler(eval *evaluator.Evaluator, c *cache.Cache, d *domains.Loader, wl *whitelist.Whitelist, timeout time.Duration, logger *slog.Logger) *Handler {
	return &Handler{
		evaluator: eval,
		cache:     c,
		domains:   d,
		whitelist: wl,
		logger:    logger,
		timeout:   timeout,
	}
}

// Handle processes a single connection.
func (h *Handler) Handle(conn net.Conn) {
	h.connections.Add(1)
	defer conn.Close()

	// Set connection timeout
	conn.SetDeadline(time.Now().Add(h.timeout))

	reader := bufio.NewReader(conn)

	// Read the request
	req, err := h.readRequest(reader)
	if err != nil {
		if err != io.EOF {
			h.errors.Add(1)
			h.logger.Debug("error reading request", "error", err)
		}
		return
	}

	h.requests.Add(1)

	// Process the request
	action, reason := h.ProcessRequest(req)

	// Send response
	response := fmt.Sprintf("action=%s %s\n\n", strings.ToLower(action), reason)
	conn.Write([]byte(response))
}

func (h *Handler) readRequest(reader *bufio.Reader) (*Request, error) {
	req := &Request{}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		line = strings.TrimSpace(line)

		// Empty line signals end of request
		if line == "" {
			break
		}

		// Parse key=value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := parts[1]

		switch key {
		case "request":
			req.Request = value
		case "protocol_state":
			req.ProtocolState = value
		case "protocol_name":
			req.ProtocolName = value
		case "client_address":
			req.ClientAddress = value
		case "client_name":
			req.ClientName = value
		case "client_port":
			req.ClientPort = value
		case "reverse_client_name":
			req.ReverseClientName = value
		case "helo_name":
			req.HeloName = value
		case "sender":
			req.Sender = value
		case "recipient":
			req.Recipient = value
		case "recipient_count":
			req.RecipientCount = value
		case "queue_id":
			req.QueueID = value
		case "instance":
			req.Instance = value
		case "size":
			req.Size = value
		case "sasl_method":
			req.SaslMethod = value
		case "sasl_username":
			req.SaslUsername = value
		case "sasl_sender":
			req.SaslSender = value
		case "encryption_protocol":
			req.EncryptionProtocol = value
		case "encryption_cipher":
			req.EncryptionCipher = value
		case "encryption_keysize":
			req.EncryptionKeysize = value
		}
	}

	return req, nil
}

// ProcessRequest processes a policy request and returns action and reason.
// This is the core logic used by both daemon mode and CLI diagnostic mode.
func (h *Handler) ProcessRequest(req *Request) (string, string) {
	// Validate request
	if req.Request != "smtpd_access_policy" {
		return "DUNNO", ""
	}

	if req.ClientAddress == "" {
		return "DUNNO", ""
	}

	senderDomain := extractDomain(req.Sender)

	// Check if sender domain is local (our own domain)
	// If so, only allow from internal IPs - reject external attempts to spoof our domains
	if h.domains != nil && senderDomain != "" {
		if h.domains.IsLocal(senderDomain) {
			if isInternalIP(req.ClientAddress) {
				h.localSkipped.Add(1)
				h.logger.Debug("allowing local sender from internal IP", "sender", req.Sender, "domain", senderDomain, "ip", req.ClientAddress)
				return "DUNNO", "local sender from internal IP"
			}
			// External IP trying to send as our domain - reject!
			h.localSpoofed.Add(1)
			h.logger.Warn("rejecting external sender spoofing local domain",
				"sender", req.Sender,
				"domain", senderDomain,
				"ip", req.ClientAddress,
			)
			return "REJECT", fmt.Sprintf("Sender %s not authorized to send for local domain %s from external IP", req.Sender, senderDomain)
		}
	}

	// Check if sender domain is whitelisted (bypass SPF entirely)
	if h.whitelist != nil && senderDomain != "" {
		if h.whitelist.IsWhitelisted(senderDomain) {
			h.whitelistSkipped.Add(1)
			h.logger.Debug("bypassing SPF for whitelisted domain", "sender", req.Sender, "domain", senderDomain, "ip", req.ClientAddress)
			return "DUNNO", "whitelisted domain"
		}
	}

	// Check cache first
	cacheKey := fmt.Sprintf("%s|%s|%s", req.ClientAddress, req.Sender, req.HeloName)
	if cached := h.cache.Get(cacheKey); cached != nil {
		h.logger.Debug("cache hit", "key", cacheKey, "action", cached.Action)
		return cached.Action, cached.Reason
	}

	// Evaluate SPF
	result, err := h.evaluator.Evaluate(req.ClientAddress, req.Sender, req.HeloName)
	if err != nil {
		h.errors.Add(1)
		h.logger.Error("evaluation error", "error", err)
		return "DEFER", "temporary evaluation error"
	}

	// Cache the result
	h.cache.Set(cacheKey, &cache.Result{
		Action:    result.Action,
		Reason:    result.Reason,
		SPFResult: spfResultString(result.SPFResult),
	})

	h.logger.Debug("evaluated",
		"ip", req.ClientAddress,
		"sender", req.Sender,
		"action", result.Action,
		"spf", spfResultString(result.SPFResult),
		"tolerant", result.Tolerant,
	)

	return result.Action, result.Reason
}

// Stats returns handler statistics.
func (h *Handler) Stats() Stats {
	return Stats{
		Connections:      h.connections.Load(),
		Requests:         h.requests.Load(),
		Errors:           h.errors.Load(),
		LocalSkipped:     h.localSkipped.Load(),
		LocalSpoofed:     h.localSpoofed.Load(),
		WhitelistSkipped: h.whitelistSkipped.Load(),
	}
}

// ResetStats resets all statistics.
func (h *Handler) ResetStats() {
	h.connections.Store(0)
	h.requests.Store(0)
	h.errors.Store(0)
	h.localSkipped.Store(0)
	h.localSpoofed.Store(0)
	h.whitelistSkipped.Store(0)
}

// extractDomain extracts the domain from an email address.
func extractDomain(email string) string {
	if email == "" {
		return ""
	}
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return strings.ToLower(parts[1])
	}
	return ""
}

// spfResultString converts an SPF result to a string.
func spfResultString(r spf.Result) string {
	switch r {
	case spf.Pass:
		return "pass"
	case spf.Fail:
		return "fail"
	case spf.SoftFail:
		return "softfail"
	case spf.Neutral:
		return "neutral"
	case spf.None:
		return "none"
	case spf.TempError:
		return "temperror"
	case spf.PermError:
		return "permerror"
	default:
		return "unknown"
	}
}

// isInternalIP checks if an IP address is from a private/internal network.
// This includes RFC1918 private ranges, localhost, and link-local addresses.
func isInternalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check for loopback (127.0.0.0/8 or ::1)
	if ip.IsLoopback() {
		return true
	}

	// Check for private networks (RFC1918)
	if ip.IsPrivate() {
		return true
	}

	// Check for link-local (169.254.0.0/16 or fe80::/10)
	if ip.IsLinkLocalUnicast() {
		return true
	}

	return false
}
