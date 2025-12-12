// Package evaluator performs SPF checks with tolerant heuristics.
package evaluator

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"blitiri.com.ar/go/spf"
)

// Result represents the outcome of an SPF evaluation.
type Result struct {
	Action    string // DUNNO, DEFER, REJECT
	Reason    string
	SPFResult spf.Result
	Tolerant  bool     // Was tolerant override applied?
	Evidence  []string // Evidence for tolerant decision
}

// Stats holds evaluation statistics.
type Stats struct {
	Checks            int64
	Passes            int64
	Fails             int64
	SoftFails         int64
	Neutrals          int64
	Nones             int64
	PermErrors        int64
	TempErrors        int64
	TolerantOverrides int64
}

// Evaluator performs SPF checks with tolerant heuristics.
type Evaluator struct {
	dnsTimeout   time.Duration
	resolver     *net.Resolver
	logger       *slog.Logger
	tolerantMode atomic.Bool // Whether tolerant heuristics are enabled

	// Statistics (atomic for thread safety)
	checks            atomic.Int64
	passes            atomic.Int64
	fails             atomic.Int64
	softFails         atomic.Int64
	neutrals          atomic.Int64
	nones             atomic.Int64
	permErrors        atomic.Int64
	tempErrors        atomic.Int64
	tolerantOverrides atomic.Int64
}

// New creates a new Evaluator with tolerant mode enabled by default.
func New(dnsTimeout time.Duration, logger *slog.Logger) *Evaluator {
	e := &Evaluator{
		dnsTimeout: dnsTimeout,
		resolver:   net.DefaultResolver,
		logger:     logger,
	}
	e.tolerantMode.Store(true) // Enabled by default
	return e
}

// SetTolerantMode enables or disables tolerant heuristics.
func (e *Evaluator) SetTolerantMode(enabled bool) {
	e.tolerantMode.Store(enabled)
	e.logger.Info("tolerant mode updated", "enabled", enabled)
}

// TolerantMode returns whether tolerant heuristics are enabled.
func (e *Evaluator) TolerantMode() bool {
	return e.tolerantMode.Load()
}

// Evaluate performs an SPF check with tolerant heuristics.
func (e *Evaluator) Evaluate(clientIP, sender, heloName string) (*Result, error) {
	e.checks.Add(1)

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid client IP: %s", clientIP)
	}

	// Extract sender domain
	senderDomain := extractDomain(sender)
	if senderDomain == "" {
		senderDomain = heloName
	}
	if senderDomain == "" {
		// No identity to check
		return &Result{
			Action: "DUNNO",
			Reason: "no sender identity",
		}, nil
	}

	// Perform SPF check
	ctx, cancel := context.WithTimeout(context.Background(), e.dnsTimeout)
	defer cancel()

	// Use sender if available, otherwise HELO
	identity := sender
	if identity == "" {
		identity = heloName
	}

	result, debugInfo := spf.CheckHostWithSender(ip, heloName, identity, spf.WithContext(ctx))
	// Note: The SPF library returns an error for debugging purposes even on successful checks.
	// The error indicates which mechanism matched (e.g., "matched ip", "matched mx").
	// We should only treat it as a real error if the result is TempError or PermError.
	if result == spf.TempError {
		e.tempErrors.Add(1)
		errMsg := "unknown"
		if debugInfo != nil {
			errMsg = debugInfo.Error()
		}
		e.logger.Warn("SPF temporary error", "debug", errMsg, "ip", clientIP, "sender", sender)
		return &Result{
			Action:    "DEFER",
			Reason:    fmt.Sprintf("SPF temporary error for %s: %s", senderDomain, errMsg),
			SPFResult: spf.TempError,
		}, nil
	}

	// Log debug info for all checks
	if debugInfo != nil {
		e.logger.Debug("SPF check", "result", result, "debug", debugInfo.Error(), "ip", clientIP, "sender", sender)
	}

	// Update stats and determine action
	action, reason := e.resultToAction(result, sender, senderDomain)

	res := &Result{
		Action:    action,
		Reason:    reason,
		SPFResult: result,
	}

	// Apply tolerant heuristics for softfail/fail/permerror (if enabled)
	if e.tolerantMode.Load() && (result == spf.Fail || result == spf.SoftFail || result == spf.PermError) {
		// For PermError, first check if IP is directly listed in SPF record
		// This handles cases where the SPF record has too many DNS lookups
		// but the IP is explicitly authorized
		if result == spf.PermError {
			if ipInSPF, spfRecord := e.checkIPInSPFRecord(ctx, clientIP, senderDomain); ipInSPF {
				e.tolerantOverrides.Add(1)
				res.Tolerant = true
				originalAction := res.Action
				res.Action = "DUNNO"
				res.Evidence = []string{fmt.Sprintf("IP %s found in SPF record chain (PermError bypassed due to DNS lookup limit)", clientIP)}
				res.Reason = fmt.Sprintf("tolerant override: %s", strings.Join(res.Evidence, ", "))

				e.logger.Info("tolerant override applied for PermError",
					"ip", clientIP,
					"sender", sender,
					"domain", senderDomain,
					"helo", heloName,
					"spf_result", "permerror",
					"original_action", originalAction,
					"problem", "SPF record exceeded DNS lookup limit but IP is authorized in SPF chain",
					"spf_record", spfRecord,
					"evidence", strings.Join(res.Evidence, "; "),
				)
				return res, nil
			}
		}

		// Apply standard tolerant heuristics
		if e.shouldOverride(ctx, clientIP, senderDomain, heloName, res) {
			e.tolerantOverrides.Add(1)
			res.Tolerant = true
			originalAction := res.Action
			res.Action = "DUNNO"
			res.Reason = fmt.Sprintf("tolerant override: %s", strings.Join(res.Evidence, ", "))

			// Determine problem being compensated
			problem := "SPF policy too strict for legitimate sender"
			switch result {
			case spf.Fail:
				problem = "SPF hard fail (-all) but sender shows signs of legitimacy"
			case spf.SoftFail:
				problem = "SPF soft fail (~all) but sender shows signs of legitimacy"
			case spf.PermError:
				problem = "SPF record has syntax error or too many DNS lookups"
			}

			// Log tolerant override at INFO level
			e.logger.Info("tolerant override applied",
				"ip", clientIP,
				"sender", sender,
				"domain", senderDomain,
				"helo", heloName,
				"spf_result", spfResultString(result),
				"original_action", originalAction,
				"problem", problem,
				"evidence", strings.Join(res.Evidence, "; "),
			)
		}
	}

	return res, nil
}

func (e *Evaluator) resultToAction(result spf.Result, sender, domain string) (string, string) {
	switch result {
	case spf.Pass:
		e.passes.Add(1)
		return "DUNNO", fmt.Sprintf("SPF pass for %s", domain)

	case spf.Fail:
		e.fails.Add(1)
		return "REJECT", fmt.Sprintf("SPF fail: sender %s not authorized for domain %s. Check SPF record.", sender, domain)

	case spf.SoftFail:
		e.softFails.Add(1)
		return "DEFER", fmt.Sprintf("SPF softfail for %s. Sender IP not in SPF record.", domain)

	case spf.Neutral:
		e.neutrals.Add(1)
		return "DUNNO", fmt.Sprintf("SPF neutral for %s", domain)

	case spf.None:
		e.nones.Add(1)
		return "DUNNO", fmt.Sprintf("no SPF record for %s", domain)

	case spf.TempError:
		e.tempErrors.Add(1)
		return "DEFER", fmt.Sprintf("SPF temporary error for %s", domain)

	case spf.PermError:
		e.permErrors.Add(1)
		return "DEFER", fmt.Sprintf("SPF permanent error for %s. Invalid SPF record syntax.", domain)

	default:
		return "DUNNO", "unknown SPF result"
	}
}

// shouldOverride applies tolerant heuristics to determine if we should
// override an SPF fail/softfail.
func (e *Evaluator) shouldOverride(ctx context.Context, clientIP, senderDomain, heloName string, res *Result) bool {
	var evidence []string
	score := 0

	// Heuristic 1: rDNS alignment
	// If the client's reverse DNS matches or is a subdomain of the sender domain
	if names, err := e.resolver.LookupAddr(ctx, clientIP); err == nil && len(names) > 0 {
		for _, name := range names {
			name = strings.TrimSuffix(strings.ToLower(name), ".")
			if strings.HasSuffix(name, "."+senderDomain) || name == senderDomain {
				score += 30
				evidence = append(evidence, fmt.Sprintf("rDNS aligned: %s", name))
				break
			}
			// Check if sender domain is subdomain of rDNS
			if strings.HasSuffix(senderDomain, "."+getDomainRoot(name)) {
				score += 20
				evidence = append(evidence, fmt.Sprintf("rDNS parent: %s", name))
				break
			}
		}
	}

	// Heuristic 2: HELO alignment
	// If HELO name matches or is related to sender domain
	if heloName != "" {
		heloLower := strings.ToLower(heloName)
		if heloLower == senderDomain || strings.HasSuffix(heloLower, "."+senderDomain) {
			score += 25
			evidence = append(evidence, fmt.Sprintf("HELO aligned: %s", heloName))
		} else if strings.HasSuffix(senderDomain, "."+getDomainRoot(heloLower)) {
			score += 15
			evidence = append(evidence, fmt.Sprintf("HELO related: %s", heloName))
		}
	}

	// Heuristic 3: MX alignment (hostname match)
	// Check if sender domain's MX records point to something related to client
	if mxs, err := e.resolver.LookupMX(ctx, senderDomain); err == nil {
		for _, mx := range mxs {
			mxHost := strings.TrimSuffix(strings.ToLower(mx.Host), ".")
			// Check if client IP resolves to an MX host
			if names, err := e.resolver.LookupAddr(ctx, clientIP); err == nil {
				for _, name := range names {
					name = strings.TrimSuffix(strings.ToLower(name), ".")
					if name == mxHost || strings.HasSuffix(name, "."+getDomainRoot(mxHost)) {
						score += 25
						evidence = append(evidence, fmt.Sprintf("MX hostname aligned: %s", mxHost))
						break
					}
				}
			}
		}
	}

	// Heuristic 4: MX subnet proximity
	// Check if client IP is in the same /24 subnet as the domain's MX servers
	// This catches misconfigured mail servers that are in the same network as legitimate MX
	clientNetIP := net.ParseIP(clientIP)
	if clientNetIP != nil {
		if mxs, err := e.resolver.LookupMX(ctx, senderDomain); err == nil {
			for _, mx := range mxs {
				mxHost := strings.TrimSuffix(mx.Host, ".")
				if mxIPs, err := e.resolver.LookupIP(ctx, "ip4", mxHost); err == nil {
					for _, mxIP := range mxIPs {
						if sameSubnet(clientNetIP, mxIP, 24) {
							score += 40
							evidence = append(evidence, fmt.Sprintf("same /24 subnet as MX %s (%s)", mxHost, mxIP))
							break
						}
					}
				}
			}
		}
	}

	res.Evidence = evidence

	// Threshold for override
	// For softfail/permerror: lower threshold (40) - these indicate config issues, not spoofing
	// For fail: higher threshold (60) - explicit rejection by SPF policy
	threshold := 60
	if res.SPFResult == spf.SoftFail || res.SPFResult == spf.PermError {
		threshold = 40
	}

	return score >= threshold
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
	// Might be a bare domain (bounce address)
	if strings.Contains(email, ".") && !strings.Contains(email, "@") {
		return strings.ToLower(email)
	}
	return ""
}

// getDomainRoot returns the registrable domain (last two parts).
func getDomainRoot(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}

// checkIPInSPFRecord checks if an IP is listed in the domain's SPF record or its includes.
// This is used to bypass PermError when the IP is explicitly authorized but the
// SPF record has too many DNS lookups.
func (e *Evaluator) checkIPInSPFRecord(ctx context.Context, clientIP, domain string) (bool, string) {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false, ""
	}

	// Track visited domains to prevent loops
	visited := make(map[string]bool)

	// Get main SPF record for logging
	mainRecord := e.getSPFRecord(ctx, domain)

	// Check with depth limit (RFC 7208 allows 10 lookups, we use 5 for includes to be safe)
	found := e.checkIPInSPFRecordRecursive(ctx, ip, domain, visited, 5)
	return found, mainRecord
}

// getSPFRecord retrieves the SPF record for a domain.
func (e *Evaluator) getSPFRecord(ctx context.Context, domain string) string {
	txts, err := e.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return ""
	}

	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1 ") {
			return txt
		}
	}
	return ""
}

// checkIPInSPFRecordRecursive checks if an IP is in an SPF record, following includes.
func (e *Evaluator) checkIPInSPFRecordRecursive(ctx context.Context, ip net.IP, domain string, visited map[string]bool, depth int) bool {
	// Prevent infinite loops and excessive depth
	if depth <= 0 {
		return false
	}
	domain = strings.ToLower(domain)
	if visited[domain] {
		return false
	}
	visited[domain] = true

	// Look up TXT records for the domain
	txts, err := e.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return false
	}

	// Find the SPF record
	var spfRecord string
	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1 ") {
			spfRecord = txt
			break
		}
	}

	if spfRecord == "" {
		return false
	}

	// Parse the SPF record
	parts := strings.Fields(spfRecord)
	for _, part := range parts {
		partLower := strings.ToLower(part)

		// Handle ip4: mechanism (with optional + prefix)
		if strings.HasPrefix(partLower, "ip4:") || strings.HasPrefix(partLower, "+ip4:") {
			ipSpec := strings.TrimPrefix(partLower, "+")
			ipSpec = strings.TrimPrefix(ipSpec, "ip4:")
			if matchesIPSpec(ip, ipSpec) {
				return true
			}
		}

		// Handle ip6: mechanism (with optional + prefix)
		if strings.HasPrefix(partLower, "ip6:") || strings.HasPrefix(partLower, "+ip6:") {
			ipSpec := strings.TrimPrefix(partLower, "+")
			ipSpec = strings.TrimPrefix(ipSpec, "ip6:")
			if matchesIPSpec(ip, ipSpec) {
				return true
			}
		}

		// Handle include: mechanism (with optional + prefix)
		if strings.HasPrefix(partLower, "include:") || strings.HasPrefix(partLower, "+include:") {
			includeDomain := strings.TrimPrefix(partLower, "+")
			includeDomain = strings.TrimPrefix(includeDomain, "include:")
			if e.checkIPInSPFRecordRecursive(ctx, ip, includeDomain, visited, depth-1) {
				return true
			}
		}
	}

	return false
}

// matchesIPSpec checks if an IP matches an SPF IP specification (IP or CIDR).
func matchesIPSpec(ip net.IP, spec string) bool {
	// Check if it's a CIDR range
	if strings.Contains(spec, "/") {
		_, network, err := net.ParseCIDR(spec)
		if err != nil {
			return false
		}
		return network.Contains(ip)
	}

	// It's a single IP
	specIP := net.ParseIP(spec)
	if specIP == nil {
		return false
	}
	return ip.Equal(specIP)
}

// Stats returns current statistics.
func (e *Evaluator) Stats() Stats {
	return Stats{
		Checks:            e.checks.Load(),
		Passes:            e.passes.Load(),
		Fails:             e.fails.Load(),
		SoftFails:         e.softFails.Load(),
		Neutrals:          e.neutrals.Load(),
		Nones:             e.nones.Load(),
		PermErrors:        e.permErrors.Load(),
		TempErrors:        e.tempErrors.Load(),
		TolerantOverrides: e.tolerantOverrides.Load(),
	}
}

// ResetStats resets all statistics.
func (e *Evaluator) ResetStats() {
	e.checks.Store(0)
	e.passes.Store(0)
	e.fails.Store(0)
	e.softFails.Store(0)
	e.neutrals.Store(0)
	e.nones.Store(0)
	e.permErrors.Store(0)
	e.tempErrors.Store(0)
	e.tolerantOverrides.Store(0)
}

// sameSubnet checks if two IPs are in the same subnet given a prefix length.
func sameSubnet(ip1, ip2 net.IP, prefixLen int) bool {
	// Normalize to IPv4 if possible
	ip1 = ip1.To4()
	ip2 = ip2.To4()

	if ip1 == nil || ip2 == nil {
		// One or both are IPv6, skip for now
		return false
	}

	// Create mask and compare
	mask := net.CIDRMask(prefixLen, 32)
	net1 := ip1.Mask(mask)
	net2 := ip2.Mask(mask)

	return net1.Equal(net2)
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
