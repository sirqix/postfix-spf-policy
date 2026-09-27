package whitelist

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")

	content := `example.com
trusted.org
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	wl := New(newTestLogger())
	if err := wl.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile() error: %v", err)
	}

	if !wl.IsWhitelisted("example.com") {
		t.Error("example.com should be whitelisted")
	}
	if !wl.IsWhitelisted("trusted.org") {
		t.Error("trusted.org should be whitelisted")
	}
	if wl.IsWhitelisted("unknown.com") {
		t.Error("unknown.com should not be whitelisted")
	}
}

func TestLoadFromFile_CommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")

	content := `# SPF bypass whitelist
example.com

# Trusted partner
trusted.org

`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	wl := New(newTestLogger())
	if err := wl.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile() error: %v", err)
	}

	if wl.Count() != 2 {
		t.Errorf("Count() = %d, want 2", wl.Count())
	}
}

func TestLoadFromFile_Missing(t *testing.T) {
	wl := New(newTestLogger())
	err := wl.LoadFromFile("/nonexistent/path/whitelist.txt")
	// Missing file is silently ignored (returns nil)
	if err != nil {
		t.Fatalf("LoadFromFile() for missing file should return nil, got: %v", err)
	}
}

func TestIsWhitelisted_ExactMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")

	if err := os.WriteFile(path, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	wl := New(newTestLogger())
	if err := wl.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	if !wl.IsWhitelisted("example.com") {
		t.Error("exact match should be whitelisted")
	}
}

func TestIsWhitelisted_ParentDomain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")

	if err := os.WriteFile(path, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	wl := New(newTestLogger())
	if err := wl.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	if !wl.IsWhitelisted("mail.example.com") {
		t.Error("mail.example.com should match parent example.com")
	}
	if !wl.IsWhitelisted("sub.mail.example.com") {
		t.Error("sub.mail.example.com should match parent example.com")
	}
}

func TestIsWhitelisted_CaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")

	if err := os.WriteFile(path, []byte("Example.COM\n"), 0644); err != nil {
		t.Fatal(err)
	}

	wl := New(newTestLogger())
	if err := wl.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	if !wl.IsWhitelisted("example.com") {
		t.Error("example.com should match Example.COM (case insensitive)")
	}
	if !wl.IsWhitelisted("EXAMPLE.COM") {
		t.Error("EXAMPLE.COM should match Example.COM (case insensitive)")
	}
}

func TestIsWhitelisted_NotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")

	if err := os.WriteFile(path, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	wl := New(newTestLogger())
	if err := wl.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	if wl.IsWhitelisted("other.com") {
		t.Error("other.com should not be whitelisted")
	}
	if wl.IsWhitelisted("notexample.com") {
		t.Error("notexample.com should not match example.com")
	}
}

func TestReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")

	// Initial content
	if err := os.WriteFile(path, []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	wl := New(newTestLogger())
	if err := wl.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	if !wl.IsWhitelisted("example.com") {
		t.Error("example.com should be whitelisted initially")
	}
	if wl.IsWhitelisted("new.com") {
		t.Error("new.com should not be whitelisted initially")
	}

	// Update file
	if err := os.WriteFile(path, []byte("example.com\nnew.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := wl.Reload(); err != nil {
		t.Fatalf("Reload() error: %v", err)
	}

	if !wl.IsWhitelisted("new.com") {
		t.Error("new.com should be whitelisted after reload")
	}
}

func TestCount(t *testing.T) {
	wl := New(newTestLogger())

	if wl.Count() != 0 {
		t.Errorf("Count() = %d for empty whitelist, want 0", wl.Count())
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")
	if err := os.WriteFile(path, []byte("a.com\nb.com\nc.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := wl.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	if wl.Count() != 3 {
		t.Errorf("Count() = %d, want 3", wl.Count())
	}
}

func TestReload_NoPath(t *testing.T) {
	wl := New(newTestLogger())
	// Reload with no path set should be a no-op
	if err := wl.Reload(); err != nil {
		t.Errorf("Reload() with no path should return nil, got: %v", err)
	}
}
