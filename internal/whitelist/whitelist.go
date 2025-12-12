// Package whitelist manages a list of domains that bypass SPF checks.
package whitelist

import (
	"bufio"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Whitelist holds domains that should bypass SPF checking.
type Whitelist struct {
	domains map[string]bool
	path    string
	mu      sync.RWMutex
	logger  *slog.Logger
}

// New creates a new Whitelist.
func New(logger *slog.Logger) *Whitelist {
	return &Whitelist{
		domains: make(map[string]bool),
		logger:  logger,
	}
}

// LoadFromFile loads whitelisted domains from a file.
// If the file doesn't exist, it's silently ignored (not an error).
// File format: one domain per line, # for comments, blank lines ignored.
func (w *Whitelist) LoadFromFile(path string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.path = path

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist - silently ignore
			w.logger.Debug("whitelist file not found, continuing without it", "path", path)
			return nil
		}
		return err
	}
	defer file.Close()

	domains := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Normalize to lowercase
		domain := strings.ToLower(line)
		domains[domain] = true
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	w.domains = domains
	w.logger.Info("loaded SPF whitelist", "path", path, "domains", len(domains))

	return nil
}

// Reload reloads the whitelist from the original file.
func (w *Whitelist) Reload() error {
	if w.path == "" {
		return nil
	}
	return w.LoadFromFile(w.path)
}

// IsWhitelisted checks if a domain is in the whitelist.
// Also checks parent domains (e.g., mail.example.com matches example.com).
func (w *Whitelist) IsWhitelisted(domain string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()

	domain = strings.ToLower(domain)

	// Check exact match
	if w.domains[domain] {
		return true
	}

	// Check parent domains
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if w.domains[parent] {
			return true
		}
	}

	return false
}

// Count returns the number of whitelisted domains.
func (w *Whitelist) Count() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.domains)
}
