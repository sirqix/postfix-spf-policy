package evaluator

import (
	"errors"
	"net"
	"testing"
)

// TestClassifyResolverError verifies that opaque DNS errors are mapped to the
// operator-facing categories used in the "SPF temporary error: DNS resolver
// failure" warning. These are the real strings the Go resolver / SPF library
// surface for the field-observed failure modes.
func TestClassifyResolverError(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantKind string
		wantSrv  string
	}{
		{
			name:     "servfail server misbehaving (stanford large signed RRset)",
			err:      &net.DNSError{Err: "server misbehaving", Name: "stanford.edu", Server: "127.0.0.1:53", IsTemporary: true},
			wantKind: "SERVFAIL",
			wantSrv:  "127.0.0.1:53",
		},
		{
			name:     "authoritative unreachable (coned IP-fenced)",
			err:      &net.DNSError{Err: "no servers could be reached", Name: "example.email.coned.com", Server: "127.0.0.1:53"},
			wantKind: "unreachable",
			wantSrv:  "127.0.0.1:53",
		},
		{
			name:     "timeout",
			err:      &net.DNSError{Err: "i/o timeout", Name: "slow.example", Server: "10.0.0.1:53", IsTimeout: true},
			wantKind: "timeout",
			wantSrv:  "10.0.0.1:53",
		},
		{
			name:     "nxdomain via IsNotFound",
			err:      &net.DNSError{Err: "no such host", Name: "nope.example", IsNotFound: true},
			wantKind: "NXDOMAIN",
		},
		{
			name:     "connection refused (resolver down)",
			err:      &net.DNSError{Err: "connection refused", Server: "127.0.0.1:53"},
			wantKind: "refused",
			wantSrv:  "127.0.0.1:53",
		},
		{
			name:     "wrapped error still classified",
			err:      errors.New("lookup x.example: server misbehaving"),
			wantKind: "SERVFAIL",
		},
		{
			name:     "nil error yields generic",
			err:      nil,
			wantKind: "other",
		},
		{
			name:     "unrecognised error yields generic",
			err:      errors.New("something totally new"),
			wantKind: "other",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := classifyResolverError(tc.err)
			if d.kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", d.kind, tc.wantKind)
			}
			if tc.wantSrv != "" && d.server != tc.wantSrv {
				t.Errorf("server = %q, want %q", d.server, tc.wantSrv)
			}
			if tc.err != nil {
				if d.cause == "" || d.action == "" {
					t.Errorf("cause/action must be non-empty for a real error: cause=%q action=%q", d.cause, d.action)
				}
			}
		})
	}
}
