package domains

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")

	content := `example.com
example.org
test.net
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := New(newTestLogger())
	if err := loader.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile() error: %v", err)
	}

	if !loader.IsLocal("example.com") {
		t.Error("example.com should be local")
	}
	if !loader.IsLocal("example.org") {
		t.Error("example.org should be local")
	}
	if !loader.IsLocal("test.net") {
		t.Error("test.net should be local")
	}
	if loader.IsLocal("unknown.com") {
		t.Error("unknown.com should not be local")
	}
}

func TestLoadFromFile_CommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")

	content := `# This is a comment
example.com

# Another comment


test.net
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := New(newTestLogger())
	if err := loader.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile() error: %v", err)
	}

	if loader.Count() != 2 {
		t.Errorf("Count() = %d, want 2", loader.Count())
	}
	if !loader.IsLocal("example.com") {
		t.Error("example.com should be local")
	}
	if !loader.IsLocal("test.net") {
		t.Error("test.net should be local")
	}
}

func TestLoadFromFile_CaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")

	content := `Example.COM
TEST.Net
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := New(newTestLogger())
	if err := loader.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile() error: %v", err)
	}

	if !loader.IsLocal("example.com") {
		t.Error("example.com should match Example.COM")
	}
	if !loader.IsLocal("EXAMPLE.COM") {
		t.Error("EXAMPLE.COM should match Example.COM")
	}
	if !loader.IsLocal("test.net") {
		t.Error("test.net should match TEST.Net")
	}
}

func TestLoadFromFile_Missing(t *testing.T) {
	loader := New(newTestLogger())
	err := loader.LoadFromFile("/nonexistent/path/domains.txt")
	if err == nil {
		t.Fatal("LoadFromFile() should return error for missing file")
	}
}

func TestIsLocal(t *testing.T) {
	loader := New(newTestLogger())

	// Empty loader
	if loader.IsLocal("example.com") {
		t.Error("empty loader should not match anything")
	}
	if loader.IsLocal("") {
		t.Error("empty domain should not match")
	}
}

// A subdomain of a hosted domain must count as local. SPF does not inherit to
// subdomains, so if these fall through to a normal SPF evaluation they find no
// record, return "no SPF record", and an external client gets to spoof
// anything@<label>.hostedbyexample.net.
func TestIsLocal_Subdomains(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")
	content := "hostedbyexample.net\nexample.net\nexample.co.uk\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	loader := New(newTestLogger())
	if err := loader.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	local := []string{
		"hostedbyexample.net",      // exact
		"HostedByExample.NET",      // exact, mixed case
		"example.net.",             // trailing dot
		"mx-1.hostedbyexample.net", // one label deep
		"mail.example.net",
		"x.y.hostedbyexample.net", // multi-label
		"a.b.c.d.example.net",
		"bounce.example.co.uk", // multi-label registrable suffix
	}
	for _, d := range local {
		if !loader.IsLocal(d) {
			t.Errorf("IsLocal(%q) = false, want true", d)
		}
	}

	// Must not over-match: a domain that merely ends with the same *text*, or a
	// parent of a hosted domain, is not local.
	notLocal := []string{
		"notexample.net",          // suffix text match without a label boundary
		"evilhostedbyexample.net", //
		"example.net.evil.com",    // hosted domain as a left-hand label
		"net",                     // parent of a hosted domain
		"co.uk",                   // parent, multi-label
		"example.com",             //
		"",                        //
		".",                       //
	}
	for _, d := range notLocal {
		if loader.IsLocal(d) {
			t.Errorf("IsLocal(%q) = true, want false", d)
		}
	}
}

func TestReload_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")

	// Initial content
	if err := os.WriteFile(path, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	loader := New(newTestLogger())
	if err := loader.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile() error: %v", err)
	}

	if !loader.IsLocal("example.com") {
		t.Error("example.com should be local initially")
	}
	if loader.IsLocal("example.org") {
		t.Error("example.org should not be local initially")
	}

	// Update file
	if err := os.WriteFile(path, []byte("example.com\nexample.org\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := loader.Reload(); err != nil {
		t.Fatalf("Reload() error: %v", err)
	}

	if !loader.IsLocal("example.org") {
		t.Error("example.org should be local after reload")
	}
}

func TestConvertToGetAllQuery(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			"simple WHERE removal",
			"SELECT domain FROM domain WHERE domain='%s'",
			"SELECT domain FROM domain",
		},
		{
			"WHERE with spaces",
			"SELECT domain FROM domain WHERE domain = '%s'",
			"SELECT domain FROM domain",
		},
		{
			"UNION query",
			"SELECT domain FROM domain WHERE domain='%s' UNION SELECT alias FROM aliases WHERE domain='%s'",
			"SELECT domain FROM domain UNION SELECT alias FROM aliases",
		},
		{
			"WHERE with additional condition",
			"SELECT domain FROM domain WHERE domain='%s' AND active=1",
			"SELECT domain FROM domain WHERE active=1",
		},
		{
			"no WHERE clause",
			"SELECT domain FROM domain",
			"SELECT domain FROM domain",
		},
		{
			// Regression: the real production query ends each parenthesized
			// UNION branch in "LIMIT 1". The trailing LIMIT must be stripped
			// or the get-all preload returns a single row and IsLocal() only
			// recognises one hosted domain.
			"parenthesized UNION with trailing LIMIT 1",
			`(SELECT domain FROM domain WHERE domain='%s' AND backupmx=0 AND active=1 LIMIT 1) UNION (SELECT alias_domain.alias_domain FROM alias_domain,domain WHERE alias_domain.alias_domain='%s' AND alias_domain.active=1 AND alias_domain.target_domain=domain.domain AND domain.active=1 AND domain.backupmx=0 LIMIT 1)`,
			`(SELECT domain FROM domain WHERE backupmx=0 AND active=1) UNION (SELECT alias_domain.alias_domain FROM alias_domain,domain WHERE alias_domain.active=1 AND alias_domain.target_domain=domain.domain AND domain.active=1 AND domain.backupmx=0)`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := convertToGetAllQuery(tc.input)
			if got != tc.want {
				t.Errorf("convertToGetAllQuery(%q)\n  got:  %q\n  want: %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestStripTrailingLimit(t *testing.T) {
	tests := []struct{ in, want string }{
		{"SELECT domain FROM domain WHERE active=1 LIMIT 1", "SELECT domain FROM domain WHERE active=1"},
		{"(SELECT domain FROM domain WHERE active=1 LIMIT 1)", "(SELECT domain FROM domain WHERE active=1)"},
		{"SELECT x FROM t LIMIT 5,10", "SELECT x FROM t"},
		{"SELECT x FROM t LIMIT 10 OFFSET 20", "SELECT x FROM t"},
		{"SELECT x FROM t WHERE active=1", "SELECT x FROM t WHERE active=1"}, // no LIMIT: unchanged
		{"SELECT limit_col FROM t", "SELECT limit_col FROM t"},               // not a LIMIT clause
	}
	for _, tc := range tests {
		if got := stripTrailingLimit(tc.in); got != tc.want {
			t.Errorf("stripTrailingLimit(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSplitByUnion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int // number of parts
	}{
		{"single query", "SELECT domain FROM domain", 1},
		{"two parts", "SELECT a FROM b UNION SELECT c FROM d", 2},
		{"three parts", "SELECT a FROM b UNION SELECT c FROM d UNION SELECT e FROM f", 3},
		{"case insensitive", "SELECT a FROM b union SELECT c FROM d", 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parts := splitByUnion(tc.input)
			if len(parts) != tc.want {
				t.Errorf("splitByUnion(%q) = %d parts, want %d", tc.input, len(parts), tc.want)
			}
		})
	}
}

func TestRemoveWhereClause(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			"with WHERE",
			"SELECT domain FROM domain WHERE domain='%s'",
			"SELECT domain FROM domain",
		},
		{
			"without WHERE",
			"SELECT domain FROM domain",
			"SELECT domain FROM domain",
		},
		{
			"WHERE with extra condition",
			"SELECT domain FROM domain WHERE domain='%s' AND active=1",
			"SELECT domain FROM domain WHERE active=1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := removeWhereClause(tc.input)
			if got != tc.want {
				t.Errorf("removeWhereClause(%q)\n  got:  %q\n  want: %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestRemoveDomainLookup(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "domain='%s'", ""},
		{"with spaces", "domain = '%s'", ""},
		{"with AND after", "domain='%s' AND active=1", "active=1"},
		{"with AND before", "active=1 AND domain='%s'", "active=1"},
		{"alias_domain pattern", "alias_domain.alias_domain='%s'", ""},
		{"double quoted", `domain="%s"`, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := removeDomainLookup(tc.input)
			if got != tc.want {
				t.Errorf("removeDomainLookup(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")

	content := `example.com
example.org
test.net
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := New(newTestLogger())
	if err := loader.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile() error: %v", err)
	}

	if loader.Count() != 3 {
		t.Errorf("Count() = %d, want 3", loader.Count())
	}
}

func TestList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")

	content := `example.com
test.net
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := New(newTestLogger())
	if err := loader.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile() error: %v", err)
	}

	list := loader.List()
	if len(list) != 2 {
		t.Errorf("List() returned %d items, want 2", len(list))
	}

	found := make(map[string]bool)
	for _, d := range list {
		found[d] = true
	}
	if !found["example.com"] {
		t.Error("List() should contain example.com")
	}
	if !found["test.net"] {
		t.Error("List() should contain test.net")
	}
}

func TestLastLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")

	if err := os.WriteFile(path, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	loader := New(newTestLogger())

	if !loader.LastLoad().IsZero() {
		t.Error("LastLoad() should be zero before loading")
	}

	if err := loader.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile() error: %v", err)
	}

	if loader.LastLoad().IsZero() {
		t.Error("LastLoad() should not be zero after loading")
	}
}

func TestConcurrency(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")

	if err := os.WriteFile(path, []byte("example.com\nexample.org\n"), 0644); err != nil {
		t.Fatal(err)
	}

	loader := New(newTestLogger())
	if err := loader.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile() error: %v", err)
	}

	// Test concurrent reads while a single goroutine reloads.
	// Note: concurrent Reload calls race on l.filePath (unprotected write
	// in LoadFromFile), so we test the realistic single-writer pattern.
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Single reloader
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = loader.Reload()
			}
		}
	}()

	// Many concurrent readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					loader.IsLocal("example.com")
					loader.IsLocal("unknown.com")
					loader.Count()
					loader.List()
				}
			}
		}()
	}

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	if !loader.IsLocal("example.com") {
		t.Error("example.com should still be local after concurrent access")
	}
}
