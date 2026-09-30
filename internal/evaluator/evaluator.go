// Package evaluator performs SPF checks with tolerant heuristics.
package evaluator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"blitiri.com.ar/go/spf"
	"golang.org/x/net/publicsuffix"
)

// spfRaisedLookupLimit is the DNS-lookup cap used when re-evaluating a sender
// that hit ErrLookupLimitReached under the default limit of 10. The upstream
// library over-counts (mechanism + each resolved host + the initial lookup),
// so legitimate large senders need headroom above 10 without removing the
// bound entirely (the limit still exists to cap DNS load per evaluation).
// 20 comfortably covers observed real-world chains (cisco.com counts ~12)
// while still rejecting genuinely runaway records.
const spfRaisedLookupLimit = 20

// Result represents the outcome of an SPF evaluation.
type Result struct {
	Action    string // DUNNO, DEFER, REJECT
	Reason    string
	SPFResult spf.Result
	Tolerant  bool     // Was tolerant override applied?
	Evidence  []string // Evidence for tolerant decision
	// IgnoredTerms lists the unusable SPF terms that were excluded from the
	// sender's record chain to reach SPFResult (tolerant mode only).
	IgnoredTerms []string
}

// dnsResolver is the DNS surface the evaluator needs: everything the SPF
// library uses plus LookupIP for the tolerant heuristics. *net.Resolver
// satisfies it; tests substitute a fake.
type dnsResolver interface {
	spf.DNSResolver
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
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
	TermErrorsIgnored int64 // Evaluations decided after excluding unusable SPF terms
}

// Evaluator performs SPF checks with tolerant heuristics.
type Evaluator struct {
	dnsTimeout   time.Duration
	resolver     dnsResolver
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
	termErrorsIgnored atomic.Int64
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

	result, debugInfo := spf.CheckHostWithSender(ip, heloName, identity,
		spf.WithContext(ctx), spf.WithResolver(e.resolver))
	// Note: The SPF library returns an error for debugging purposes even on successful checks.
	// The error indicates which mechanism matched (e.g., "matched ip", "matched mx").
	// We should only treat it as a real error if the result is TempError or PermError.

	// The upstream library counts DNS lookups more strictly than real-world
	// consensus: it charges the RFC 7208 §4.6.4 10-lookup budget once per
	// mx/a mechanism AND once per resolved MX/A host (spf.go:703 + :721),
	// plus the initial domain lookup. So a large-but-legitimate sender whose
	// chain uses ~6 term-lookups can be counted at ~12 and trip
	// ErrLookupLimitReached — returning a spurious PermError before its
	// terminal `all` is ever evaluated. cisco.com is the canonical case
	// (v=spf1 redirect=spfa._spf.cisco.com ... mx:res.cisco.com mx:sco.cisco.com ~all);
	// Gmail/Outlook/pyspf all deliver it. When we see a lookup-limit
	// PermError, re-run once with a raised limit so the sender's actual
	// policy (their `all`, or a genuine ip match) decides instead of a
	// fabricated "invalid syntax / too many lookups" rejection. A real
	// syntax error, or a chain that genuinely exceeds the raised limit, still
	// surfaces as PermError and is handled below unchanged.
	if result == spf.PermError && errors.Is(debugInfo, spf.ErrLookupLimitReached) {
		r2, d2 := spf.CheckHostWithSender(ip, heloName, identity,
			spf.WithContext(ctx), spf.WithResolver(e.resolver), spf.OverrideLookupLimit(spfRaisedLookupLimit))
		if r2 == spf.PermError {
			// Still a PermError with headroom: keep the raised-limit error
			// for diagnosis. It is either a genuine overrun (limit reached
			// again) or a different defect that sat behind the 10th lookup.
			debugInfo = d2
		} else if r2 != spf.TempError {
			e.logger.Info("SPF lookup-limit permerror re-evaluated with raised limit",
				"domain", senderDomain,
				"ip", clientIP,
				"sender", sender,
				"helo", heloName,
				"raised_limit", spfRaisedLookupLimit,
				"original", "permerror (lookup limit reached)",
				"resolved", spfResultString(r2),
				"note", "upstream lib over-counts mx/a host lookups; real MTAs deliver this sender",
			)
			result, debugInfo = r2, d2
		}
	}

	// A PermError that survives the raised limit is usually a defect in the
	// published record itself: a misspelled mechanism ("ip:" for "ip4:"), a
	// stray token, an unknown modifier (which RFC 7208 §6 says to ignore but
	// the library rejects). In tolerant mode such terms are excluded from
	// consideration and the rest of the record decides, exactly as if the
	// sender had not published them. Re-run once through a resolver that
	// strips them from every record in the chain. The raised lookup limit is
	// used because the strict pass stopped at the bad term and never counted
	// what follows it.
	var ignored []termIssue
	if result == spf.PermError && e.tolerantMode.Load() {
		san := &sanitizingResolver{DNSResolver: e.resolver}
		r3, d3 := spf.CheckHostWithSender(ip, heloName, identity,
			spf.WithContext(ctx), spf.WithResolver(san), spf.OverrideLookupLimit(spfRaisedLookupLimit))
		switch {
		case len(san.issues) == 0 || r3 == spf.TempError:
			// Nothing to exclude, or DNS failed past the bad term: keep the
			// strict PermError and let the handling below decide.
		case r3 == spf.PermError:
			// Terms were excluded but another defect remains (too many
			// lookups, void include, ...). Report that one as the cause.
			ignored, debugInfo = san.issues, d3
		default:
			e.termErrorsIgnored.Add(1)
			ignored = san.issues
			e.logger.Info("SPF record errors ignored",
				"ip", clientIP,
				"sender", sender,
				"domain", senderDomain,
				"helo", heloName,
				"original", "permerror",
				"original_cause", permErrorCause(debugInfo),
				"resolved", spfResultString(r3),
				"ignored_terms", formatIssues(ignored, 0),
			)
			result, debugInfo = r3, d3
		}
	}

	if result == spf.TempError {
		e.tempErrors.Add(1)
		errMsg := "unknown"
		if debugInfo != nil {
			errMsg = debugInfo.Error()
		}

		// Walk the SPF chain to identify broken include targets so the
		// operator (and the sender's postmaster, via the bounce DSN) sees
		// exactly which referenced record is the cause. The upstream library
		// classifies an NXDOMAIN-during-include as TempError even though it's
		// functionally a sender-side permanent config error (e.g. lsnc.net
		// references spf-us.ppe-hosted.com which is NXDOMAIN; the working
		// name is _spf-us.ppe-hosted.com with the underscore prefix).
		// We deliberately KEEP the DEFER behavior — RFC 7208 says TempError
		// → 4xx so the sender keeps retrying, and if they fix the SPF the
		// next attempt succeeds. We only enrich the diagnostic.
		brokenIncludes := e.findBrokenIncludes(ctx, senderDomain)

		if len(brokenIncludes) > 0 {
			parts := make([]string, 0, len(brokenIncludes))
			for _, bi := range brokenIncludes {
				parts = append(parts, fmt.Sprintf("%s (%s)", bi.target, bi.cause))
			}
			joined := strings.Join(parts, ", ")
			e.logger.Warn("SPF temporary error: broken include(s) detected",
				"domain", senderDomain,
				"ip", clientIP,
				"sender", sender,
				"broken_includes", joined,
				"explanation", "SPF chain references an include target that does not resolve; sender must fix their SPF record",
			)
			// Surface the first broken include in the 4xx reason so the
			// sender's bounce DSN tells the postmaster what to fix.
			reason := fmt.Sprintf("SPF temporary error for %s: broken include %s (%s) — sender DNS must be fixed",
				senderDomain, brokenIncludes[0].target, brokenIncludes[0].cause)
			return &Result{Action: "DEFER", Reason: reason, SPFResult: spf.TempError}, nil
		}

		// No broken include in the sender's chain: the failure is at the DNS
		// resolver layer (SERVFAIL / timeout / unreachable authoritative). This
		// can be EITHER a receiver-side/network condition (local resolver can't
		// handle the response, authoritative unreachable from this host) OR a
		// genuinely broken sender domain that fails everywhere. We can't tell
		// which from a single failed lookup, so the log points the operator at
		// the discriminating test (compare against a public resolver) rather
		// than asserting a side. Classify the error so the log carries an
		// actionable diagnosis instead of a bare "server misbehaving".
		diag := classifyResolverError(debugInfo)
		e.logger.Warn("SPF temporary error: DNS resolution failure",
			"domain", senderDomain,
			"ip", clientIP,
			"sender", sender,
			"helo", heloName,
			"resolver", diag.server,
			"error_kind", diag.kind,
			"raw_error", errMsg,
			"likely_cause", diag.cause,
			"operator_action", diag.action,
			"disposition", "deferred 4xx; sender will retry. Discriminate: if 'dig @1.1.1.1 TXT "+senderDomain+"' also fails, the sender's DNS is broken; if only the local resolver fails, it's receiver-side",
		)
		// Keep the SMTP 4xx text generic and non-accusatory: this is our DNS
		// problem, so we neither blame the sender nor leak our resolver's
		// address to the outside world via the bounce DSN.
		reason := fmt.Sprintf("temporary DNS error while validating SPF for %s; please retry", senderDomain)
		return &Result{Action: "DEFER", Reason: reason, SPFResult: spf.TempError}, nil
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
	ignoredTerms := formatIssues(ignored, 3)
	if len(ignored) > 0 {
		for _, i := range ignored {
			res.IgnoredTerms = append(res.IgnoredTerms, i.String())
		}
		if result != spf.PermError && res.Action != "DUNNO" {
			// Tell the sender's postmaster which terms were discounted, so a
			// fail caused by their own typo is diagnosable from the bounce.
			res.Reason += " Ignored invalid SPF terms: " + ignoredTerms
		}
	}

	// Apply tolerant heuristics for softfail/fail/permerror (if enabled)
	var permCause string // what is wrong with the record, for a PermError that is not IP-matched
	if e.tolerantMode.Load() && (result == spf.Fail || result == spf.SoftFail || result == spf.PermError) {
		// A PermError reaching this point is one that excluding bad terms
		// could not resolve: too many DNS lookups even at the raised limit,
		// more than 10 MX records behind an mx mechanism, a void include or
		// redirect target, or multiple v=spf1 records (RFC 7208 §4.5 — we
		// treat those as a union: any record authorizing the IP passes).
		// If the IP is nonetheless listed in the chain, let the mail through.
		if result == spf.PermError {
			cause := permErrorCause(debugInfo)
			if isVoidTargetErr(debugInfo) {
				if broken := e.findBrokenIncludes(ctx, senderDomain); len(broken) > 0 {
					parts := make([]string, 0, len(broken))
					for _, bi := range broken {
						parts = append(parts, fmt.Sprintf("%s (%s)", bi.target, bi.cause))
					}
					cause = "SPF chain references a target with no SPF record: " + strings.Join(parts, ", ")
				}
			}
			spfError := "none"
			if debugInfo != nil {
				spfError = debugInfo.Error()
			}

			ipInSPF, spfRecords := e.checkIPInSPFRecord(ctx, clientIP, sender, heloName, senderDomain)
			if ipInSPF {
				e.tolerantOverrides.Add(1)
				res.Tolerant = true
				originalAction := res.Action
				res.Action = "DUNNO"

				evidence := fmt.Sprintf("IP %s found in SPF record chain (PermError bypassed)", clientIP)
				problem := cause + "; IP is authorized in SPF chain"
				if len(spfRecords) > 1 {
					evidence = fmt.Sprintf("IP %s found in SPF record chain (PermError bypassed; %d v=spf1 records present, treated as union)", clientIP, len(spfRecords))
					problem = fmt.Sprintf("Multiple v=spf1 records (%d) cause PermError; IP is authorized in at least one record", len(spfRecords))
				}
				res.Evidence = []string{evidence}
				res.Reason = fmt.Sprintf("tolerant override: %s", strings.Join(res.Evidence, ", "))

				e.logger.Info("tolerant override applied for PermError",
					"ip", clientIP,
					"sender", sender,
					"domain", senderDomain,
					"helo", heloName,
					"spf_result", "permerror",
					"original_action", originalAction,
					"problem", problem,
					"spf_error", spfError,
					"ignored_terms", ignoredTerms,
					"spf_record", strings.Join(spfRecords, " || "),
					"spf_record_count", len(spfRecords),
					"evidence", strings.Join(res.Evidence, "; "),
				)
				return res, nil
			}
			// No IP-in-record match — refine the user-visible reason so the
			// operator sees the actual cause (e.g. multi-record) instead of a
			// generic "invalid SPF record syntax" string. Heuristics below may
			// still override this reason with a tolerant pass.
			res.Reason = permErrorReason(senderDomain, spfRecords, cause)
			if ignoredTerms != "" {
				res.Reason += " Ignored invalid SPF terms: " + ignoredTerms
			}
			permCause = cause
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
				problem = permCause
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
				"ignored_terms", ignoredTerms,
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

// Heuristic weights. A tolerant override needs overrideThresholdLenient
// points for softfail/permerror and overrideThresholdStrict for fail. Each
// heuristic contributes at most once, however many PTR names or MX hosts
// match.
const (
	scoreRDNSAligned         = 30 // client's confirmed rDNS is (under) the sender domain
	scoreRDNSParent          = 20 // sender domain is under the client's registrable domain
	scoreHELOAligned         = 25
	scoreHELORelated         = 15
	scoreMXAligned           = 40 // match and go for softfail/permerror; fail (-all) needs more
	scoreMXSubnet            = 40 // client shares an MX's /24 (IPv4) or /64 (IPv6)
	overrideThresholdLenient = 40
	overrideThresholdStrict  = 60
)

// shouldOverride applies tolerant heuristics to determine if we should
// override an SPF fail/softfail/permerror.
func (e *Evaluator) shouldOverride(ctx context.Context, clientIP, senderDomain, heloName string, res *Result) bool {
	var evidence []string
	score := 0
	clientNetIP := net.ParseIP(clientIP)

	// Every rDNS-based heuristic uses only forward-confirmed names: whoever
	// controls an IP's reverse zone can publish any PTR (e.g. "x.google.com"),
	// so an unconfirmed name proves nothing.
	names := e.confirmedPTRNames(ctx, clientNetIP)

	// Heuristic 1: rDNS alignment
	// If the client's reverse DNS matches or is a subdomain of the sender domain
	for _, name := range names {
		if strings.HasSuffix(name, "."+senderDomain) || name == senderDomain {
			score += scoreRDNSAligned
			evidence = append(evidence, fmt.Sprintf("rDNS aligned: %s", name))
			break
		}
		// Check if sender domain is subdomain of rDNS
		if strings.HasSuffix(senderDomain, "."+getDomainRoot(name)) {
			score += scoreRDNSParent
			evidence = append(evidence, fmt.Sprintf("rDNS parent: %s", name))
			break
		}
	}

	// Heuristic 2: HELO alignment
	// If HELO name matches or is related to sender domain
	if heloName != "" {
		heloLower := strings.ToLower(heloName)
		if heloLower == senderDomain || strings.HasSuffix(heloLower, "."+senderDomain) {
			score += scoreHELOAligned
			evidence = append(evidence, fmt.Sprintf("HELO aligned: %s", heloName))
		} else if strings.HasSuffix(senderDomain, "."+getDomainRoot(heloLower)) {
			score += scoreHELORelated
			evidence = append(evidence, fmt.Sprintf("HELO related: %s", heloName))
		}
	}

	var mxHosts []string
	if mxs, err := e.resolver.LookupMX(ctx, senderDomain); err == nil {
		for _, mx := range mxs {
			if h := strings.TrimSuffix(strings.ToLower(mx.Host), "."); h != "" {
				mxHosts = append(mxHosts, h)
			}
		}
	}

	// Heuristic 3: MX alignment (match and go)
	// The client's confirmed rDNS is in the same registrable domain as one of
	// the sender domain's MX hosts, i.e. the mail comes from the organisation
	// (or provider, e.g. Google/Microsoft) that receives the domain's mail.
	// This alone overrides softfail/permerror, independent of how many MX
	// records the domain has. It is a provider-level match (any Google,
	// Microsoft or Proofpoint customer shares it), so it deliberately does
	// not override a hard fail on its own: -all is the sender's explicit
	// decision, and tolerance is only meant to absorb typos and human error.
mxAlign:
	for _, mxHost := range mxHosts {
		mxRoot := getDomainRoot(mxHost)
		for _, name := range names {
			if name == mxHost || getDomainRoot(name) == mxRoot {
				score += scoreMXAligned
				evidence = append(evidence, fmt.Sprintf("MX hostname aligned: %s ~ %s", name, mxHost))
				break mxAlign
			}
		}
	}

	// Heuristic 4: MX subnet proximity
	// Client in the same /24 (IPv4) or /64 (IPv6) as one of the domain's MX
	// servers. Catches misconfigured mail servers on the same network as the
	// legitimate MX.
mxSubnet:
	for _, mxHost := range mxHosts {
		if clientNetIP == nil {
			break
		}
		mxIPs, err := e.resolver.LookupIP(ctx, "ip", mxHost)
		if err != nil {
			continue
		}
		for _, mxIP := range mxIPs {
			if prefix, ok := sameMXNetwork(clientNetIP, mxIP); ok {
				score += scoreMXSubnet
				evidence = append(evidence, fmt.Sprintf("same /%d subnet as MX %s (%s)", prefix, mxHost, mxIP))
				break mxSubnet
			}
		}
	}

	res.Evidence = evidence

	// Threshold for override
	// For softfail/permerror: lower threshold - these indicate config issues, not spoofing
	// For fail: higher threshold - explicit rejection by SPF policy
	threshold := overrideThresholdStrict
	if res.SPFResult == spf.SoftFail || res.SPFResult == spf.PermError {
		threshold = overrideThresholdLenient
	}

	return score >= threshold
}

// confirmedPTRNames returns the client's PTR names (lowercased, no trailing
// dot) that resolve forward to the client IP again (FCrDNS).
func (e *Evaluator) confirmedPTRNames(ctx context.Context, ip net.IP) []string {
	if ip == nil {
		return nil
	}
	ptrs, err := e.resolver.LookupAddr(ctx, ip.String())
	if err != nil {
		return nil
	}
	var names []string
	for _, ptr := range ptrs {
		name := strings.TrimSuffix(strings.ToLower(ptr), ".")
		if name == "" {
			continue
		}
		addrs, err := e.resolver.LookupIP(ctx, "ip", name)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a.Equal(ip) {
				names = append(names, name)
				break
			}
		}
	}
	return names
}

// sameMXNetwork reports whether a and b share a /24 (both IPv4) or a /64
// (both IPv6), returning the prefix length that matched.
func sameMXNetwork(a, b net.IP) (int, bool) {
	if a.To4() != nil || b.To4() != nil {
		return 24, sameSubnet(a, b, 24)
	}
	a16, b16 := a.To16(), b.To16()
	if a16 == nil || b16 == nil {
		return 64, false
	}
	mask := net.CIDRMask(64, 128)
	return 64, a16.Mask(mask).Equal(b16.Mask(mask))
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

// getDomainRoot returns the registrable domain (public suffix + 1 label),
// e.g. "mail.example.co.uk" -> "example.co.uk", not "co.uk". A name that is
// itself a public suffix (or unparseable) is returned unchanged.
func getDomainRoot(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if root, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil {
		return root
	}
	return domain
}

// permErrorReason builds a human-readable reason for a PermError that wasn't
// overridden, using the count of v=spf1 records found at the apex to
// distinguish the most common causes. The upstream library returns a single
// PermError constant for all causes; we narrow it for operator clarity.
//
// `cause` is the specific defect derived from the library's error (see
// permErrorCause); it is used when the record count alone doesn't explain it.
func permErrorReason(domain string, records []string, cause string) string {
	switch {
	case len(records) > 1:
		return fmt.Sprintf("SPF permanent error for %s: %d v=spf1 records found at apex (RFC 7208 §4.5 requires exactly one — merge them into a single record).", domain, len(records))
	case len(records) == 0:
		return fmt.Sprintf("SPF permanent error for %s: no usable v=spf1 record found (referenced include/redirect target may be missing, or DNS may be misconfigured).", domain)
	default:
		return fmt.Sprintf("SPF permanent error for %s: %s.", domain, cause)
	}
}

// isSPFRecord returns true if the TXT record is a v=spf1 record (case-insensitive).
// Accepts both bare "v=spf1" (no mechanisms) and "v=spf1 ..." with mechanisms.
func isSPFRecord(txt string) bool {
	lower := strings.ToLower(strings.TrimSpace(txt))
	return lower == "v=spf1" || strings.HasPrefix(lower, "v=spf1 ")
}

// spfWalk carries identities needed during a tolerant SPF walk so that
// macro-bearing mechanisms (currently exists:) can be expanded.
type spfWalk struct {
	clientIP     net.IP
	senderEmail  string // full MAIL FROM, may be empty
	senderDomain string // domain portion of senderEmail (for %{o})
	heloName     string
	visited      map[string]bool
}

// checkIPInSPFRecord checks if an IP is listed in the domain's SPF record(s) or includes.
// Used to bypass PermError when the IP is explicitly authorized but the SPF chain
// has too many DNS lookups, or when the domain has multiple v=spf1 records.
// Returns the match result and all v=spf1 TXT records found at the apex (for logging).
func (e *Evaluator) checkIPInSPFRecord(ctx context.Context, clientIP, sender, helo, domain string) (bool, []string) {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false, nil
	}

	walk := &spfWalk{
		clientIP:     ip,
		senderEmail:  sender,
		senderDomain: extractDomain(sender),
		heloName:     helo,
		visited:      make(map[string]bool),
	}
	records := e.getSPFRecords(ctx, domain)

	// Depth limit (RFC 7208 allows 10 lookups; we cap include depth at 5 to be safe).
	found := e.checkIPInSPFRecordRecursive(ctx, walk, domain, 5)
	return found, records
}

// voidTargetCause labels an include/redirect target with no TXT record.
const voidTargetCause = "NXDOMAIN or no TXT record"

// brokenInclude describes an SPF include target that fails to resolve.
type brokenInclude struct {
	target string // the include target as written (e.g. "spf-us.ppe-hosted.com")
	cause  string // short cause: voidTargetCause, "no v=spf1 record" or "lookup failed"
}

// findBrokenIncludes walks the SPF chain of `domain` and returns every
// include target whose TXT lookup yields NXDOMAIN, or whose response is
// NOERROR but contains no v=spf1 record. Both are functionally permanent
// sender-side errors that the upstream library classifies as TempError.
//
// Walks include depth up to 5 (same cap as checkIPInSPFRecord). Visited
// targets are tracked to break cycles. The walk does NOT abort on the
// first failure — we collect all broken nodes so the operator/postmaster
// sees the full picture.
//
// The walk only inspects include: mechanisms; redirect= is followed too,
// since RFC 7208 §6.1 treats it equivalently for the "doesn't resolve"
// failure mode.
func (e *Evaluator) findBrokenIncludes(ctx context.Context, domain string) []brokenInclude {
	if domain == "" {
		return nil
	}
	visited := make(map[string]bool)
	var broken []brokenInclude
	e.walkBrokenIncludes(ctx, domain, visited, &broken, 5)
	return broken
}

func (e *Evaluator) walkBrokenIncludes(ctx context.Context, domain string, visited map[string]bool, broken *[]brokenInclude, depth int) {
	if depth <= 0 {
		return
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if visited[domain] {
		return
	}
	visited[domain] = true

	txts, err := e.resolver.LookupTXT(ctx, domain)
	if err != nil {
		// Caller responsible for top-level — but for recursion this would
		// only be reached via an include that was already added to broken
		// at the parent level; don't double-record.
		return
	}

	// Walk every v=spf1 record at this domain (typically 1)
	for _, txt := range txts {
		if !isSPFRecord(txt) {
			continue
		}
		for _, tok := range splitSPFTokens(txt) {
			low := strings.ToLower(tok)
			var target string
			if v, ok := stripMechPrefix(tok, low, "include:"); ok {
				target = strings.ToLower(strings.TrimSuffix(v, "."))
			} else if v, ok := stripMechPrefix(tok, low, "redirect="); ok {
				target = strings.ToLower(strings.TrimSuffix(v, "."))
			} else {
				continue
			}
			if target == "" || visited[target] {
				continue
			}
			// Probe the include target. We treat both "no TXT at all"
			// (NXDOMAIN-like) and "TXT present but no v=spf1" as broken
			// for include semantics — both produce TempError upstream
			// and both are sender config errors.
			childTxts, lookupErr := e.resolver.LookupTXT(ctx, target)
			if lookupErr != nil {
				// Distinguish "not there" from other errors when possible.
				// Go's resolver reports NXDOMAIN and NODATA (name exists,
				// no TXT) identically, so the label must cover both.
				cause := "lookup failed"
				if isNXDomainErr(lookupErr) {
					cause = voidTargetCause
				}
				*broken = append(*broken, brokenInclude{target: target, cause: cause})
				continue
			}
			hasSPF := false
			for _, ct := range childTxts {
				if isSPFRecord(ct) {
					hasSPF = true
					break
				}
			}
			if !hasSPF {
				*broken = append(*broken, brokenInclude{target: target, cause: "no v=spf1 record"})
				continue
			}
			// Healthy include — recurse to surface deeper breaks too.
			e.walkBrokenIncludes(ctx, target, visited, broken, depth-1)
		}
	}
}

// isNXDomainErr returns true if the resolver error indicates the queried
// name does not exist. Go's net package surfaces this via DNSError.IsNotFound
// (Go 1.13+) or, on older platforms, by the error text. We check both.
func isNXDomainErr(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return true
		}
	}
	// Fallback for resolver paths that don't fill IsNotFound (e.g. some
	// custom resolvers). The "server misbehaving" string is SERVFAIL, not
	// NXDOMAIN, and is deliberately NOT matched here.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such host") || strings.Contains(msg, "nxdomain")
}

// resolverDiag is a human-actionable classification of a DNS resolver error
// encountered during SPF evaluation. It turns an opaque error string (e.g.
// "server misbehaving") into an operator-facing cause and a concrete next step.
type resolverDiag struct {
	server string // resolver/server that reported the failure, if the error carried it
	kind   string // short category: SERVFAIL, timeout, refused, unreachable, NXDOMAIN, other
	cause  string // plain-language likely cause
	action string // concrete next step for the operator
}

// classifyResolverError inspects a DNS lookup error (as surfaced by the SPF
// library, which passes through the underlying *net.DNSError) and produces an
// actionable diagnosis for the operator log. It is deliberately conservative:
// when it cannot recognise the error it still returns a useful generic
// classification rather than nothing.
//
// The two field-observed causes it calls out explicitly:
//   - SERVFAIL ("server misbehaving"): a local resolver that cannot handle a
//     large or DNSSEC-signed response (e.g. stanford.edu via a dnsmasq that
//     SERVFAILs large signed RRsets), a DNSSEC validation failure, or an
//     authoritative server that refuses this host's IP.
//   - unreachable: the domain's authoritative servers drop traffic from this
//     host (some operators firewall cloud-hosted IP ranges), so full recursion
//     fails while public resolvers succeed.
func classifyResolverError(err error) resolverDiag {
	d := resolverDiag{
		kind:   "other",
		cause:  "DNS lookup failed for a reason the resolver did not detail",
		action: "compare 'dig TXT <domain>' via the local resolver against 'dig @1.1.1.1 TXT <domain>' to localise the failure",
	}
	if err == nil {
		return d
	}
	msg := strings.ToLower(err.Error())

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		d.server = dnsErr.Server
		switch {
		case dnsErr.IsNotFound:
			d.kind = "NXDOMAIN"
			d.cause = "the name does not exist (authoritative NXDOMAIN)"
			d.action = "usually a sender-side DNS issue; confirm the domain publishes the expected records"
			return d
		case dnsErr.IsTimeout:
			d.kind = "timeout"
			d.cause = "the resolver did not answer in time — it may be overloaded, or the authoritative servers are slow/unreachable from this host"
			d.action = "check local resolver health/load, and verify the domain's authoritative NS respond from this host"
			return d
		}
	}

	switch {
	case strings.Contains(msg, "server misbehaving"):
		d.kind = "SERVFAIL"
		d.cause = "resolver returned SERVFAIL — commonly a local resolver that cannot handle a large or DNSSEC-signed response, a DNSSEC validation failure, or an authoritative server that does not answer this host's IP"
		d.action = "compare local 'dig TXT <domain>' vs 'dig @1.1.1.1'; if only the local resolver fails on a large/signed record, fix or replace it; if the authoritative servers are unreachable from this host, forward that zone to a public resolver"
	case strings.Contains(msg, "connection refused"):
		d.kind = "refused"
		d.cause = "resolver refused the connection — it may be down or not listening on the configured address"
		d.action = "verify the local DNS service is running and reachable on the address in /etc/resolv.conf"
	case strings.Contains(msg, "no route to host"),
		strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "no servers could be reached"),
		strings.Contains(msg, "i/o timeout"):
		d.kind = "unreachable"
		d.cause = "resolver or the domain's authoritative servers could not be reached from this host (network/firewall); some DNS operators firewall cloud-hosted IP ranges"
		d.action = "check egress on udp/tcp 53; if the domain's authoritative NS block this host, forward that zone to a public resolver"
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "nxdomain"):
		d.kind = "NXDOMAIN"
		d.cause = "the name does not exist (authoritative NXDOMAIN)"
		d.action = "usually a sender-side DNS issue; confirm the domain publishes the expected records"
	}
	return d
}

// getSPFRecords retrieves all v=spf1 TXT records for a domain.
// A domain SHOULD have at most one (RFC 7208 §4.5); multiple is a misconfiguration
// that yields PermError, but in tolerant mode we expose all of them.
func (e *Evaluator) getSPFRecords(ctx context.Context, domain string) []string {
	txts, err := e.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil
	}

	var records []string
	for _, txt := range txts {
		if isSPFRecord(txt) {
			records = append(records, txt)
		}
	}
	return records
}

// checkIPInSPFRecordRecursive checks if an IP is in any v=spf1 record at the domain
// or its includes. When a domain has multiple v=spf1 records, all are checked and
// any match passes (union semantics).
func (e *Evaluator) checkIPInSPFRecordRecursive(ctx context.Context, walk *spfWalk, domain string, depth int) bool {
	if depth <= 0 {
		return false
	}
	domain = strings.ToLower(domain)
	if walk.visited[domain] {
		return false
	}
	walk.visited[domain] = true

	txts, err := e.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return false
	}

	for _, txt := range txts {
		if !isSPFRecord(txt) {
			continue
		}
		if e.ipMatchesSPFRecord(ctx, walk, domain, txt, depth) {
			return true
		}
	}
	return false
}

// ipMatchesSPFRecord parses a single SPF record string and reports whether the
// IP matches via ip4:, ip6:, include:, exists:, or redirect= terms. Recurses
// into include: and redirect= targets.
// `currentDomain` is the domain whose record we are currently parsing (used as %{d}).
// Note: qualifiers other than '+' are not interpreted — a '-ip4:' still counts
// as a match. This is consistent with the rest of the tolerant-mode behavior.
func (e *Evaluator) ipMatchesSPFRecord(ctx context.Context, walk *spfWalk, currentDomain, spfRecord string, depth int) bool {
	parts := splitSPFTokens(spfRecord)
	for _, part := range parts {
		partLower := strings.ToLower(part)

		if val, ok := stripMechPrefix(part, partLower, "ip4:"); ok {
			if matchesIPSpec(walk.clientIP, strings.ToLower(val)) {
				return true
			}
			continue
		}

		if val, ok := stripMechPrefix(part, partLower, "ip6:"); ok {
			if matchesIPSpec(walk.clientIP, strings.ToLower(val)) {
				return true
			}
			continue
		}

		if val, ok := stripMechPrefix(part, partLower, "include:"); ok {
			// include: targets are domain names — lowercase is fine.
			if e.checkIPInSPFRecordRecursive(ctx, walk, strings.ToLower(val), depth-1) {
				return true
			}
			continue
		}

		if val, ok := stripMechPrefix(part, partLower, "redirect="); ok {
			// redirect= points evaluation at another domain's record
			// (RFC 7208 §6.1). Records that use a bare apex redirect —
			// e.g. cisco.com is "v=spf1 redirect=spfa._spf.cisco.com" —
			// keep all their ip4:/include: terms in the target, so without
			// following the redirect the walk never reaches any authorized
			// IP and the PermError bypass silently no-ops for the whole
			// (large) class of redirect-based senders. Treat it like an
			// include for the "is this IP authorized anywhere in the chain"
			// question: recurse, and match if the target authorizes the IP.
			target := strings.TrimSuffix(strings.ToLower(val), ".")
			if target != "" && e.checkIPInSPFRecordRecursive(ctx, walk, target, depth-1) {
				return true
			}
			continue
		}

		if val, ok := stripMechPrefix(part, partLower, "exists:"); ok {
			expanded, exOk := expandSPFMacros(val, walk, currentDomain)
			if !exOk {
				// Unsupported macro syntax — skip silently in tolerant mode.
				continue
			}
			ips, err := e.resolver.LookupIP(ctx, "ip4", expanded)
			if err == nil && len(ips) > 0 {
				return true
			}
			continue
		}
	}
	return false
}

// stripMechPrefix returns the value portion of a mechanism token if the token
// starts with `mech:` (optionally preceded by a `+` qualifier), case-insensitive
// on the prefix. The original-case suffix is preserved for callers that need
// case-sensitive value handling (e.g. macro expansion).
func stripMechPrefix(part, partLower, mech string) (string, bool) {
	if strings.HasPrefix(partLower, mech) {
		return part[len(mech):], true
	}
	if strings.HasPrefix(partLower, "+"+mech) {
		return part[len(mech)+1:], true
	}
	return "", false
}

// expandSPFMacros performs minimal SPF macro expansion (RFC 7208 §7.2) sufficient
// for the most common exists: patterns. Supports:
//   - %% (literal %), %_ (space), %- (literal "%20")
//   - %{i} %{s} %{o} %{d} %{l} %{h}
//
// Macros with transformers (digits or 'r'), or unknown letters, cause the whole
// expansion to fail with ok=false; callers should skip the mechanism.
func expandSPFMacros(spec string, walk *spfWalk, currentDomain string) (string, bool) {
	if !strings.Contains(spec, "%") {
		return spec, true
	}

	var b strings.Builder
	b.Grow(len(spec) * 2)
	i := 0
	for i < len(spec) {
		c := spec[i]
		if c != '%' {
			b.WriteByte(c)
			i++
			continue
		}
		if i+1 >= len(spec) {
			return "", false
		}
		switch spec[i+1] {
		case '%':
			b.WriteByte('%')
			i += 2
		case '_':
			b.WriteByte(' ')
			i += 2
		case '-':
			b.WriteString("%20")
			i += 2
		case '{':
			end := strings.IndexByte(spec[i+2:], '}')
			if end < 0 {
				return "", false
			}
			macro := spec[i+2 : i+2+end]
			// Only single-letter macros, no transformers (digits/'r').
			if len(macro) != 1 {
				return "", false
			}
			val, ok := lookupMacroLetter(macro[0], walk, currentDomain)
			if !ok {
				return "", false
			}
			b.WriteString(val)
			i += 3 + end // %, {, ..., }
		default:
			return "", false
		}
	}
	return b.String(), true
}

func lookupMacroLetter(letter byte, walk *spfWalk, currentDomain string) (string, bool) {
	switch letter {
	case 'i', 'I':
		return macroIP(walk.clientIP), true
	case 's', 'S':
		return walk.senderEmail, walk.senderEmail != ""
	case 'o', 'O':
		return walk.senderDomain, walk.senderDomain != ""
	case 'd', 'D':
		return currentDomain, currentDomain != ""
	case 'l', 'L':
		if at := strings.IndexByte(walk.senderEmail, '@'); at > 0 {
			return walk.senderEmail[:at], true
		}
		return "", false
	case 'h', 'H':
		return walk.heloName, walk.heloName != ""
	default:
		return "", false
	}
}

// macroIP returns the %{i} expansion: dotted-quad for IPv4, dot-separated nibble
// form (most-significant-first) for IPv6, per RFC 7208 §7.4.
func macroIP(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	if ip6 := ip.To16(); ip6 != nil {
		nibbles := make([]string, 0, 32)
		for _, b := range ip6 {
			nibbles = append(nibbles, fmt.Sprintf("%x", b>>4), fmt.Sprintf("%x", b&0x0f))
		}
		return strings.Join(nibbles, ".")
	}
	return ""
}

// splitSPFTokens splits an SPF record into mechanism tokens, recovering from
// a common admin typo: a missing space before the terminating "all" mechanism.
// E.g. "v=spf1 +ip4:1.2.3.4~all" -> ["v=spf1", "+ip4:1.2.3.4", "~all"].
//
// The "all" mechanism is always terminal (RFC 7208 §5.1), so any [+-~?]all
// suffix preceded by a non-space character is unambiguously a missing-space
// typo. Only the trailing all-token is split off; other concatenation typos
// (e.g. "+mx+a") are left alone because they are genuinely ambiguous.
func splitSPFTokens(record string) []string {
	allSuffixes := []string{"~all", "-all", "?all", "+all"}
	fields := strings.Fields(record)
	out := make([]string, 0, len(fields)+1)
	for _, f := range fields {
		split := false
		// Case-insensitive suffix check; the bare "all" mechanism is also valid.
		lower := strings.ToLower(f)
		for _, s := range allSuffixes {
			if len(lower) > len(s) && strings.HasSuffix(lower, s) {
				out = append(out, f[:len(f)-len(s)], f[len(f)-len(s):])
				split = true
				break
			}
		}
		// Also handle bare "all" mashed onto a previous token (no qualifier).
		if !split && len(lower) > 3 && strings.HasSuffix(lower, "all") {
			// Only split if the character before "all" looks like the end of a
			// value (digit, letter, dot, colon) — avoids splitting tokens that
			// legitimately end in "all" like "include:foo.callall.example".
			// In practice the common case is an IP or domain followed by "all".
			prev := lower[len(lower)-4]
			if prev >= '0' && prev <= '9' || prev == '.' {
				out = append(out, f[:len(f)-3], f[len(f)-3:])
				split = true
			}
		}
		if !split {
			out = append(out, f)
		}
	}
	return out
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
		TermErrorsIgnored: e.termErrorsIgnored.Load(),
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
	e.termErrorsIgnored.Store(0)
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
