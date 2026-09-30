package evaluator

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"blitiri.com.ar/go/spf"
)

// fakeResolver is an in-memory DNS for driving Evaluate without the network.
type fakeResolver struct {
	txt  map[string][]string
	mx   map[string][]*net.MX
	addr map[string][]string // host -> IPs
	ptr  map[string][]string // IP -> names
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f.txt[strings.TrimSuffix(name, ".")]; ok {
		return v, nil
	}
	return nil, notFound(name)
}

func (f *fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if v, ok := f.mx[strings.TrimSuffix(name, ".")]; ok {
		return v, nil
	}
	return nil, notFound(name)
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	v, ok := f.addr[strings.TrimSuffix(host, ".")]
	if !ok {
		return nil, notFound(host)
	}
	out := make([]net.IPAddr, 0, len(v))
	for _, s := range v {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

func (f *fakeResolver) LookupIP(ctx context.Context, _, host string) ([]net.IP, error) {
	addrs, err := f.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if v, ok := f.ptr[addr]; ok {
		return v, nil
	}
	return nil, notFound(addr)
}

// newFakeEvaluator returns an evaluator wired to res, plus the buffer its
// log lines are written to.
func newFakeEvaluator(res *fakeResolver) (*Evaluator, *bytes.Buffer) {
	var buf bytes.Buffer
	e := New(10*time.Second, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	e.resolver = res
	return e, &buf
}

func TestSpfTermProblem(t *testing.T) {
	tests := []struct {
		term string
		want string // "" = usable
	}{
		{"all", ""}, {"-all", ""}, {"~ALL", ""},
		{"a", ""}, {"+mx", ""}, {"ptr", ""}, {"ptr:example.com", ""},
		{"a:mail.example.com", ""}, {"a/24", ""}, {"mx:example.com/24//64", ""}, {"a//64", ""},
		{"ip4:192.0.2.1", ""}, {"ip4:192.0.2.0/24", ""}, {"ip6:2001:db8::/32", ""}, {"IP4:192.0.2.1", ""},
		{"include:_spf.example.com", ""}, {"exists:%{i}._spf.example.com", ""},
		{"redirect=_spf.example.com", ""}, {"exp=explain.example.com", ""},

		// The reported production cases.
		{"ip:192.0.2.12", "unknown mechanism"},
		{"include.zcsend.net", "unknown mechanism"},
		{"include:include:spf.protection.outlook.com", "invalid domain"},
		{"include:", "missing domain"},
		{"spf.mxhichina.com", "unknown mechanism"},
		{"google-site-verification=qv-1lWAnNGZuA1Ll8P4vcAzOnkmcvyYgI_qFDlmjGvk", "unknown modifier"},
		{"~allyahoo-verification-key=hhcsp9wk/k=", "unknown modifier"},

		{"ipv4:192.0.2.1", "unknown mechanism"},
		{"192.0.2.1", "unknown mechanism"},
		{"ip4:192.0.2.300", "invalid IP address"},
		{"ip4:192.0.2.0/33", "invalid CIDR"},
		{"ip4:", "invalid IP address"},
		{"a/33", "invalid CIDR length"},
		{"mx//129", "invalid CIDR length"},
		{"a:", "invalid domain or CIDR length"},
		{"mx/abc", "invalid domain or CIDR length"},
		{"redirect=", "missing domain"},
	}
	for _, tc := range tests {
		if got := spfTermProblem(tc.term); got != tc.want {
			t.Errorf("spfTermProblem(%q) = %q, want %q", tc.term, got, tc.want)
		}
	}
}

func TestSanitizeSPFRecord(t *testing.T) {
	tests := []struct {
		name        string
		record      string
		want        string
		wantReasons []string
	}{
		{
			name:   "valid record is untouched",
			record: "v=spf1 mx ip4:203.0.113.240/29 include:_spf.google.com -all",
			want:   "v=spf1 mx ip4:203.0.113.240/29 include:_spf.google.com -all",
		},
		{
			name:        "ip: instead of ip4: (winery.example)",
			record:      "v=spf1 ip:192.0.2.12 include:spf.protection.outlook.com include:emailus.freshservice.com -all",
			want:        "v=spf1 include:spf.protection.outlook.com include:emailus.freshservice.com -all",
			wantReasons: []string{"unknown mechanism"},
		},
		{
			name:        "dot instead of colon (ipv4shop.example)",
			record:      "v=spf1 include.zcsend.net ip4:198.51.100.57 include:_spf.google.com -all",
			want:        "v=spf1 ip4:198.51.100.57 include:_spf.google.com -all",
			wantReasons: []string{"unknown mechanism"},
		},
		{
			name:        "space after include: plus trailing verification token (lifestyle.example)",
			record:      "v=spf1 include: spf.mxhichina.com include:mailgun.org ~all google-site-verification=abc",
			want:        "v=spf1 include:mailgun.org ~all",
			wantReasons: []string{"missing domain", "unknown mechanism", "unknown modifier"},
		},
		{
			name:        "newline between terms (parts.example)",
			record:      "v=spf1 mx a ip4:192.0.2.153 \na:relays.hosting.example  include:spf.protection.outlook.com ~all",
			want:        "v=spf1 mx a ip4:192.0.2.153 a:relays.hosting.example include:spf.protection.outlook.com ~all",
			wantReasons: []string{"terms separated by non-space whitespace, repaired"},
		},
		{
			name:        "missing space before all",
			record:      "v=spf1 ip4:192.0.2.1~all",
			want:        "v=spf1 ip4:192.0.2.1 ~all",
			wantReasons: []string{"missing space before all, repaired"},
		},
		{
			name:   "valid include ending in all is not split",
			record: "v=spf1 include:spf.firewall -all",
			want:   "v=spf1 include:spf.firewall -all",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, issues := sanitizeSPFRecord(tc.record)
			if got != tc.want {
				t.Errorf("record = %q, want %q", got, tc.want)
			}
			var reasons []string
			for _, i := range issues {
				reasons = append(reasons, i.reason)
			}
			if strings.Join(reasons, "|") != strings.Join(tc.wantReasons, "|") {
				t.Errorf("reasons = %q, want %q", reasons, tc.wantReasons)
			}
		})
	}
}

// A term echoed into the SMTP reply must never be able to break the
// single-line policy protocol, whatever bytes the sender puts in DNS.
func TestTermIssueStringIsSingleLineASCII(t *testing.T) {
	s := termIssue{domain: "example.com", term: "evil\n\naction=oké" + strings.Repeat("x", 200), reason: "unknown mechanism"}.String()
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			t.Fatalf("String() contains non-printable/non-ASCII rune %q: %q", r, s)
		}
	}
	if len(s) > 200 {
		t.Errorf("String() not truncated: %d bytes", len(s))
	}
}

const outlookSPF = "v=spf1 ip6:2a01:111:f403::/48 ip4:40.92.0.0/15 -all"

func TestEvaluateIgnoresInvalidTerms(t *testing.T) {
	res := &fakeResolver{txt: map[string][]string{
		"winery.example":             {"v=spf1 ip:192.0.2.12 include:spf.protection.outlook.com -all"},
		"ipv4shop.example":           {"v=spf1 include.zcsend.net ip4:198.51.100.57 include:spf.protection.outlook.com -all"},
		"modifier.example":           {"some-other-txt", "v=spf1 google-site-verification=abc ip4:192.0.2.1 -all"},
		"spf.protection.outlook.com": {outlookSPF},
	}}

	tests := []struct {
		name        string
		ip, sender  string
		wantResult  spf.Result
		wantAction  string
		wantIgnored string
	}{
		{"ip: typo, sender in a later include", "2a01:111:f403:c105::7", "a@winery.example", spf.Pass, "DUNNO", `"ip:192.0.2.12" (unknown mechanism)`},
		{"ip: typo, the mistyped IP itself is not authorized", "192.0.2.12", "a@winery.example", spf.Fail, "REJECT", `"ip:192.0.2.12" (unknown mechanism)`},
		{"dot for colon, sender in a later ip4", "198.51.100.57", "a@ipv4shop.example", spf.Pass, "DUNNO", `"include.zcsend.net" (unknown mechanism)`},
		{"dot for colon, unauthorized sender fails on -all", "198.51.100.9", "a@ipv4shop.example", spf.Fail, "REJECT", `"include.zcsend.net" (unknown mechanism)`},
		{"unknown modifier is ignored per RFC 7208 §6", "192.0.2.1", "a@modifier.example", spf.Pass, "DUNNO", `(unknown modifier)`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, logs := newFakeEvaluator(res)
			got, err := e.Evaluate(tc.ip, tc.sender, "helo.example")
			if err != nil {
				t.Fatal(err)
			}
			if got.SPFResult != tc.wantResult || got.Action != tc.wantAction {
				t.Fatalf("got %s/%s (%s), want %s/%s\nlogs: %s", got.SPFResult, got.Action, got.Reason, tc.wantResult, tc.wantAction, logs)
			}
			if !strings.Contains(strings.Join(got.IgnoredTerms, ", "), tc.wantIgnored) {
				t.Errorf("IgnoredTerms = %q, want it to contain %q", got.IgnoredTerms, tc.wantIgnored)
			}
			if !strings.Contains(logs.String(), "SPF record errors ignored") {
				t.Errorf("missing 'SPF record errors ignored' log line:\n%s", logs)
			}
			if strings.Contains(logs.String(), "lookup limit") {
				t.Errorf("syntax error must not be reported as a lookup-limit problem:\n%s", logs)
			}
			if tc.wantAction != "DUNNO" && !strings.Contains(got.Reason, "Ignored invalid SPF terms") {
				t.Errorf("rejection reason should name the ignored terms: %q", got.Reason)
			}
			if s := e.Stats(); s.TermErrorsIgnored != 1 || s.PermErrors != 0 {
				t.Errorf("stats = %+v, want TermErrorsIgnored=1 PermErrors=0", s)
			}
		})
	}
}

func TestEvaluateStrictModeKeepsSyntaxPermError(t *testing.T) {
	res := &fakeResolver{txt: map[string][]string{
		"winery.example":             {"v=spf1 ip:192.0.2.12 include:spf.protection.outlook.com -all"},
		"spf.protection.outlook.com": {outlookSPF},
	}}
	e, _ := newFakeEvaluator(res)
	e.SetTolerantMode(false)
	got, err := e.Evaluate("2a01:111:f403:c105::7", "a@winery.example", "helo.example")
	if err != nil {
		t.Fatal(err)
	}
	if got.SPFResult != spf.PermError || got.Action != "DEFER" || len(got.IgnoredTerms) != 0 {
		t.Errorf("got %s/%s ignored=%q, want permerror/DEFER with nothing ignored", got.SPFResult, got.Action, got.IgnoredTerms)
	}
}

// bulkmail.example: the record is syntactically fine; the PermError is the
// RFC 7208 §4.6.4 cap of 10 MX records per mx mechanism (the domain has 16).
func TestEvaluateTooManyMXReportedAccurately(t *testing.T) {
	res := &fakeResolver{
		txt: map[string][]string{"bulkmail.example": {"v=spf1 mx ip4:203.0.113.240/29 -all"}},
		mx:  map[string][]*net.MX{},
	}
	for n := 1; n <= 16; n++ {
		res.mx["bulkmail.example"] = append(res.mx["bulkmail.example"], &net.MX{Host: fmt.Sprintf("mail%d.bulkmail.example.", n), Pref: 10})
	}
	e, logs := newFakeEvaluator(res)
	got, err := e.Evaluate("203.0.113.245", "bounce@bulkmail.example", "mail6.bulkmail.example")
	if err != nil {
		t.Fatal(err)
	}
	if got.SPFResult != spf.PermError || got.Action != "DUNNO" || !got.Tolerant {
		t.Fatalf("got %s/%s tolerant=%v, want permerror overridden to DUNNO\nlogs: %s", got.SPFResult, got.Action, got.Tolerant, logs)
	}
	if !strings.Contains(logs.String(), "more than 10 MX records") {
		t.Errorf("override should name the MX-count cause:\n%s", logs)
	}
	if strings.Contains(logs.String(), "lookup limit") {
		t.Errorf("MX-count PermError must not be reported as a lookup-limit problem:\n%s", logs)
	}
}

// A chain that really does blow the lookup budget (even at the raised limit)
// must still be reported as exactly that.
func TestEvaluateGenuineLookupLimitStillReported(t *testing.T) {
	res := &fakeResolver{txt: map[string][]string{}}
	var terms []string
	for n := 0; n < spfRaisedLookupLimit+5; n++ {
		name := fmt.Sprintf("s%d.big.example", n)
		res.txt[name] = []string{"v=spf1 ip4:203.0.113.1 -all"}
		terms = append(terms, "include:"+name)
	}
	res.txt["big.example"] = []string{"v=spf1 " + strings.Join(terms, " ") + " ip4:192.0.2.77 -all"}

	e, logs := newFakeEvaluator(res)
	got, err := e.Evaluate("192.0.2.77", "a@big.example", "helo.example")
	if err != nil {
		t.Fatal(err)
	}
	if got.SPFResult != spf.PermError || got.Action != "DUNNO" || !got.Tolerant {
		t.Fatalf("got %s/%s tolerant=%v, want permerror overridden to DUNNO\nlogs: %s", got.SPFResult, got.Action, got.Tolerant, logs)
	}
	if !strings.Contains(logs.String(), "exceeds the DNS lookup limit") {
		t.Errorf("override should report the lookup limit:\n%s", logs)
	}
}

// A void include is not a term error: it stays a PermError, but the reason
// names the broken target rather than claiming a lookup-limit problem.
func TestEvaluateVoidIncludeNamesTarget(t *testing.T) {
	res := &fakeResolver{txt: map[string][]string{
		"drinks.example": {"v=spf1 include:spf.google.com ~all"},
	}}
	e, _ := newFakeEvaluator(res)
	got, err := e.Evaluate("198.51.100.9", "steve@drinks.example", "helo.example")
	if err != nil {
		t.Fatal(err)
	}
	if got.SPFResult != spf.PermError || got.Action != "DEFER" {
		t.Fatalf("got %s/%s, want permerror/DEFER", got.SPFResult, got.Action)
	}
	if !strings.Contains(got.Reason, "spf.google.com ("+voidTargetCause+")") || strings.Contains(got.Reason, "lookups") {
		t.Errorf("reason should name the void include target: %q", got.Reason)
	}
}

func TestPermErrorCause(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{spf.ErrLookupLimitReached, "DNS lookup limit"},
		{spf.ErrTooManyMXRecords, "more than 10 MX records"},
		{spf.ErrMultipleRecords, "multiple v=spf1 records"},
		{spf.ErrUnknownField, "unknown mechanism or modifier"},
		{spf.ErrInvalidIP, "invalid ip4/ip6 address"},
		{spf.ErrInvalidMask, "invalid CIDR prefix length"},
		{spf.ErrNoResult, "publishes no SPF record"},
		{notFound("spf.example.com"), "has no TXT record in DNS"},
		{nil, "could not be interpreted"},
	}
	for _, tc := range tests {
		if got := permErrorCause(tc.err); !strings.Contains(got, tc.want) {
			t.Errorf("permErrorCause(%v) = %q, want it to contain %q", tc.err, got, tc.want)
		}
	}
}

// heuristicFixture: a domain with -all that does not authorize the client,
// so only the tolerant heuristics can let the mail through.
func heuristicFixture() *fakeResolver {
	return &fakeResolver{
		txt: map[string][]string{
			"gws.example":     {"v=spf1 ip4:192.0.2.1 -all"},
			"gwssoft.example": {"v=spf1 ip4:192.0.2.1 ~all"},
			"m365.example":    {"v=spf1 ip4:192.0.2.1 ~all"},
			"example.co.uk":   {"v=spf1 ip4:192.0.2.1 -all"},
			"v6.example":      {"v=spf1 ip4:192.0.2.1 ~all"},
			"v6hard.example":  {"v=spf1 ip4:192.0.2.1 -all"},
		},
		mx: map[string][]*net.MX{
			"gwssoft.example": {{Host: "aspmx.l.google.com.", Pref: 1}},
			"gws.example": {
				{Host: "aspmx.l.google.com.", Pref: 1}, {Host: "alt1.aspmx.l.google.com.", Pref: 5},
				{Host: "alt2.aspmx.l.google.com.", Pref: 5}, {Host: "alt3.aspmx.l.google.com.", Pref: 10},
				{Host: "alt4.aspmx.l.google.com.", Pref: 10},
			},
			"m365.example":   {{Host: "m365-example.mail.protection.outlook.com.", Pref: 0}},
			"example.co.uk":  {{Host: "mail.example.co.uk.", Pref: 10}},
			"v6.example":     {{Host: "mx.v6.example.", Pref: 10}},
			"v6hard.example": {{Host: "mx.v6hard.example.", Pref: 10}},
		},
		addr: map[string][]string{
			"mail-ej1-x10.google.com":                  {"2a00:1450:4864:34::10"},
			"mail-sn1.outbound.protection.outlook.com": {"2a01:111:f403:c10d::3"},
			"mail.other.co.uk":                         {"198.51.100.20"},
			"mx.v6.example":                            {"2001:db8:5:1::25"},
			"mx.v6hard.example":                        {"2001:db8:5:1::25"},
			// PTR claims google.com but forward DNS does not point back.
			"forged.google.com": {"203.0.113.99"},
		},
		ptr: map[string][]string{
			"2a00:1450:4864:34::10": {"mail-ej1-x10.google.com."},
			"2a01:111:f403:c10d::3": {"mail-sn1.outbound.protection.outlook.com."},
			"198.51.100.20":         {"mail.other.co.uk."},
			"198.51.100.66":         {"forged.google.com."},
		},
	}
}

func TestHeuristicsMXAlignmentMatchAndGo(t *testing.T) {
	tests := []struct {
		name         string
		ip, sender   string
		wantAction   string
		wantTolerant bool
		wantEvidence string
	}{
		{"Google-hosted domain, confirmed Google rDNS, overrides softfail", "2a00:1450:4864:34::10", "a@gwssoft.example", "DUNNO", true, "MX hostname aligned: mail-ej1-x10.google.com ~ aspmx.l.google.com"},
		{"MX alignment alone does not override -all", "2a00:1450:4864:34::10", "a@gws.example", "REJECT", false, ""},
		{"MX alignment plus HELO alignment does override -all", "2a00:1450:4864:34::10", "a@gws.example", "DUNNO", true, "HELO aligned"},
		{"M365 domain with a single MX overrides too", "2a01:111:f403:c10d::3", "a@m365.example", "DUNNO", true, "MX hostname aligned"},
		{"co.uk is a public suffix, not a shared organisation", "198.51.100.20", "a@example.co.uk", "REJECT", false, ""},
		{"unconfirmed PTR is ignored", "198.51.100.66", "a@gws.example", "REJECT", false, ""},
		{"IPv6 same /64 as MX overrides softfail", "2001:db8:5:1::99", "a@v6.example", "DUNNO", true, "same /64 subnet as MX mx.v6.example"},
		{"IPv6 subnet alone is not enough for -all", "2001:db8:5:1::99", "a@v6hard.example", "REJECT", false, ""},
		{"IPv6 different /64 does not match", "2001:db8:5:2::99", "a@v6.example", "DEFER", false, ""},
	}
	// HELO that aligns with the sender domain, for the cases that need it.
	heloFor := map[string]string{"MX alignment plus HELO alignment does override -all": "mail.gws.example"}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			helo := "unrelated.helo.test"
			if h, ok := heloFor[tc.name]; ok {
				helo = h
			}
			e, logs := newFakeEvaluator(heuristicFixture())
			got, err := e.Evaluate(tc.ip, tc.sender, helo)
			if err != nil {
				t.Fatal(err)
			}
			if got.Action != tc.wantAction || got.Tolerant != tc.wantTolerant {
				t.Fatalf("got %s tolerant=%v evidence=%q, want %s tolerant=%v\nlogs: %s", got.Action, got.Tolerant, got.Evidence, tc.wantAction, tc.wantTolerant, logs)
			}
			ev := strings.Join(got.Evidence, "; ")
			if tc.wantEvidence != "" && !strings.Contains(ev, tc.wantEvidence) {
				t.Errorf("evidence %q, want it to contain %q", ev, tc.wantEvidence)
			}
			if strings.Count(ev, "MX hostname aligned") > 1 || strings.Count(ev, "subnet as MX") > 1 {
				t.Errorf("a heuristic was counted more than once: %q", ev)
			}
		})
	}
}

func TestSameMXNetwork(t *testing.T) {
	tests := []struct {
		a, b   string
		prefix int
		want   bool
	}{
		{"192.0.2.10", "192.0.2.200", 24, true},
		{"192.0.2.10", "192.0.3.10", 24, false},
		{"2001:db8:5:1::1", "2001:db8:5:1:ffff::1", 64, true},
		{"2001:db8:5:1::1", "2001:db8:5:2::1", 64, false},
		{"192.0.2.10", "2001:db8::1", 24, false},
	}
	for _, tc := range tests {
		prefix, ok := sameMXNetwork(net.ParseIP(tc.a), net.ParseIP(tc.b))
		if ok != tc.want || prefix != tc.prefix {
			t.Errorf("sameMXNetwork(%s, %s) = /%d %v, want /%d %v", tc.a, tc.b, prefix, ok, tc.prefix, tc.want)
		}
	}
}
