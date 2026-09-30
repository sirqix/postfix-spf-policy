package evaluator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"blitiri.com.ar/go/spf"
)

// termIssue describes one defect found in a published SPF record while
// sanitizing it for tolerant re-evaluation.
type termIssue struct {
	domain string // name whose TXT record carried the term
	term   string // the offending term exactly as published
	reason string // short classification, e.g. "unknown mechanism"
}

// maxIssueTermLen bounds how much of an offending term is echoed back.
const maxIssueTermLen = 64

func (i termIssue) String() string {
	if i.term == "" {
		return fmt.Sprintf("%s: %s", i.domain, i.reason)
	}
	// %+q keeps the term single-line ASCII: it comes straight from DNS and
	// ends up in log lines and in the SMTP reply text.
	term := i.term
	if len(term) > maxIssueTermLen {
		term = term[:maxIssueTermLen] + "..."
	}
	return fmt.Sprintf("%s: %+q (%s)", i.domain, term, i.reason)
}

// formatIssues renders issues for log lines and SMTP reasons, capped at max
// entries so a badly mangled record cannot produce an unbounded reply.
func formatIssues(issues []termIssue, max int) string {
	parts := make([]string, 0, len(issues))
	for n, i := range issues {
		if max > 0 && n == max {
			parts = append(parts, fmt.Sprintf("+%d more", len(issues)-max))
			break
		}
		parts = append(parts, i.String())
	}
	return strings.Join(parts, ", ")
}

var (
	// RFC 7208 §6: modifier = name "=" macro-string, name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
	modifierRe = regexp.MustCompile(`^[a-z][a-z0-9._-]*=`)
	// a / mx with optional domain-spec and dual-cidr-length (RFC 7208 §5.3, §5.4).
	aMxRe = regexp.MustCompile(`^(?:a|mx)(?::([^/]+))?(?:/(\d+))?(?://(\d+))?$`)
	// Macro expressions and escapes allowed inside a domain-spec (RFC 7208 §7.1).
	macroExprRe = regexp.MustCompile(`%\{[^}]*\}|%[%_-]`)
	// What may remain of a domain-spec once macros are removed.
	domainCharsRe = regexp.MustCompile(`^[A-Za-z0-9._-]*$`)
)

// domainSpecProblem validates the domain-spec of a mechanism or redirect=.
// It returns "" when the spec is usable. The point is to catch values that can
// never name a DNS record (e.g. "include:include:spf.example.com") so the term
// is reported as a syntax error instead of surfacing later as a void lookup.
func domainSpecProblem(spec string) string {
	if spec == "" {
		return "missing domain"
	}
	if !domainCharsRe.MatchString(macroExprRe.ReplaceAllString(spec, "")) {
		return "invalid domain"
	}
	return ""
}

// spfTermProblem classifies a single SPF term. It returns "" for a term the
// SPF library can evaluate, otherwise a short reason. The accepted grammar
// deliberately mirrors the vendored library's parser so that a record with
// every flagged term removed can no longer yield a syntax PermError.
func spfTermProblem(term string) string {
	body := term
	if body != "" && strings.ContainsRune("+-~?", rune(body[0])) {
		body = body[1:]
	}
	lower := strings.ToLower(body)

	switch {
	case lower == "all", lower == "ptr":
		return ""
	case strings.HasPrefix(lower, "include:"):
		return domainSpecProblem(body[len("include:"):])
	case strings.HasPrefix(lower, "exists:"):
		return domainSpecProblem(body[len("exists:"):])
	case strings.HasPrefix(lower, "ptr:"):
		return domainSpecProblem(body[len("ptr:"):])
	case strings.HasPrefix(lower, "redirect="):
		return domainSpecProblem(body[len("redirect="):])
	case strings.HasPrefix(lower, "exp="):
		return ""
	case strings.HasPrefix(lower, "ip4:"), strings.HasPrefix(lower, "ip6:"):
		val := body[4:]
		if strings.Contains(val, "/") {
			if _, _, err := net.ParseCIDR(val); err != nil {
				return "invalid CIDR"
			}
		} else if net.ParseIP(val) == nil {
			return "invalid IP address"
		}
		return ""
	case lower == "a", lower == "mx",
		strings.HasPrefix(lower, "a:"), strings.HasPrefix(lower, "a/"),
		strings.HasPrefix(lower, "mx:"), strings.HasPrefix(lower, "mx/"):
		groups := aMxRe.FindStringSubmatch(lower)
		if groups == nil {
			return "invalid domain or CIDR length"
		}
		if strings.Contains(lower, ":") {
			if p := domainSpecProblem(groups[1]); p != "" {
				return p
			}
		}
		if groups[2] != "" {
			if n, err := strconv.Atoi(groups[2]); err != nil || n > 32 {
				return "invalid CIDR length"
			}
		}
		if groups[3] != "" {
			if n, err := strconv.Atoi(groups[3]); err != nil || n > 128 {
				return "invalid CIDR length"
			}
		}
		return ""
	case modifierRe.MatchString(lower):
		// RFC 7208 §6 says unrecognized modifiers MUST be ignored; the
		// vendored library instead fails the whole record with PermError.
		return "unknown modifier"
	default:
		return "unknown mechanism"
	}
}

// sanitizeSPFRecord returns the record with every unusable term removed, plus
// a description of each removal. Terms are excluded from consideration, never
// reinterpreted: "ip:192.0.2.1" is dropped, not treated as ip4. Two layout
// defects are repaired rather than dropped because the intent is unambiguous:
// non-space whitespace between terms, and a missing space before the final
// "all" (see splitSPFTokens).
func sanitizeSPFRecord(record string) (string, []termIssue) {
	var issues []termIssue
	fields := strings.Fields(record)
	kept := make([]string, 0, len(fields))

	if strings.ContainsAny(record, "\t\n\r\v\f") {
		issues = append(issues, termIssue{reason: "terms separated by non-space whitespace, repaired"})
	}

	for n, field := range fields {
		if n == 0 {
			// The version tag; isSPFRecord already vetted it.
			kept = append(kept, field)
			continue
		}
		tokens := []string{field}
		if spfTermProblem(field) != "" {
			// Only consult the missing-space heuristic for a term that is
			// broken as written, so a valid term is never split.
			if split := splitSPFTokens(field); len(split) > 1 {
				issues = append(issues, termIssue{term: field, reason: "missing space before all, repaired"})
				tokens = split
			}
		}
		for _, tok := range tokens {
			if reason := spfTermProblem(tok); reason != "" {
				issues = append(issues, termIssue{term: tok, reason: reason})
				continue
			}
			kept = append(kept, tok)
		}
	}
	return strings.Join(kept, " "), issues
}

// sanitizingResolver is a DNS resolver for the SPF library that strips
// unusable terms from every v=spf1 record in the evaluated chain and remembers
// what it removed. It is built per evaluation and used from a single
// goroutine, so it needs no locking.
type sanitizingResolver struct {
	spf.DNSResolver
	issues []termIssue
}

func (s *sanitizingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	txts, err := s.DNSResolver.LookupTXT(ctx, name)
	if err != nil {
		return txts, err
	}
	out := make([]string, len(txts))
	for n, txt := range txts {
		if !isSPFRecord(txt) {
			out[n] = txt
			continue
		}
		clean, issues := sanitizeSPFRecord(txt)
		for _, i := range issues {
			i.domain = strings.ToLower(strings.TrimSuffix(name, "."))
			s.issues = append(s.issues, i)
		}
		out[n] = clean
	}
	return out, nil
}

// permErrorCause turns the SPF library's PermError debug error into an
// operator-facing statement of what is actually wrong with the sender's
// record. The library reports every cause as the same PermError result; the
// distinction only survives in the accompanying error value.
func permErrorCause(err error) string {
	switch {
	case err == nil:
		return "SPF record could not be interpreted"
	case errors.Is(err, spf.ErrLookupLimitReached):
		return fmt.Sprintf("SPF chain exceeds the DNS lookup limit (RFC 7208 §4.6.4 allows 10; still over at our raised limit of %d)", spfRaisedLookupLimit)
	case errors.Is(err, spf.ErrTooManyMXRecords):
		return "an mx mechanism resolves to more than 10 MX records (RFC 7208 §4.6.4)"
	case errors.Is(err, spf.ErrMultipleRecords):
		return "multiple v=spf1 records published at one name in the SPF chain (RFC 7208 §4.5)"
	case errors.Is(err, spf.ErrUnknownField):
		return "SPF record syntax error: unknown mechanism or modifier"
	case errors.Is(err, spf.ErrInvalidIP):
		return "SPF record syntax error: invalid ip4/ip6 address"
	case errors.Is(err, spf.ErrInvalidMask):
		return "SPF record syntax error: invalid CIDR prefix length"
	case errors.Is(err, spf.ErrInvalidMacro):
		return "SPF record syntax error: invalid macro"
	case errors.Is(err, spf.ErrInvalidDomain):
		return "SPF record syntax error: invalid domain-spec or more than one redirect="
	case errors.Is(err, spf.ErrNoResult):
		return "an include/redirect target publishes no SPF record"
	case isNXDomainErr(err):
		return fmt.Sprintf("an include/redirect target has no TXT record in DNS (%v)", err)
	default:
		return fmt.Sprintf("SPF permanent error (%v)", err)
	}
}

// isVoidTargetErr reports whether a PermError was caused by an include: or
// redirect= target that has no SPF record (missing name or no v=spf1 TXT).
func isVoidTargetErr(err error) bool {
	return err != nil && (errors.Is(err, spf.ErrNoResult) || isNXDomainErr(err))
}
