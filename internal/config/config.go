// Package config handles configuration file parsing.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration settings.
type Config struct {
	// Network settings
	ListenAddress string
	ListenPort    int

	// Cache settings
	CacheMaxSize int
	CacheTTL     time.Duration

	// DNS settings
	DNSTimeout time.Duration
	DNSRetries int

	// Domain sources
	DomainsDatabaseConfig string // Path to Postfix-style MySQL config file
	DomainsFile           string // Path to flat file with domains

	// SPF bypass whitelist
	SPFWhitelistFile string // Path to file with domains that bypass SPF checks

	// Reload settings
	ReloadInterval time.Duration

	// Tolerant mode - apply heuristics to reduce false positives
	TolerantMode bool

	// Logging
	LogLevel string

	// PID file
	PidFile string

	// Connection handling
	ConnectionTimeout time.Duration
}

// Default returns a Config with default values.
func Default() *Config {
	return &Config{
		ListenAddress:     "127.0.0.1",
		ListenPort:        10033,
		CacheMaxSize:      10000,
		CacheTTL:          5 * time.Minute,
		DNSTimeout:        10 * time.Second,
		DNSRetries:        2,
		DomainsDatabaseConfig: "",
		DomainsFile:           "",
		ReloadInterval:    5 * time.Minute,
		TolerantMode:      true, // Enabled by default
		LogLevel:          "info",
		PidFile:           "/var/run/spf-policy.pid",
		ConnectionTimeout: 30 * time.Second,
	}
}

// Load reads configuration from a file.
// Format is simple key=value pairs, one per line.
// Lines starting with # are comments.
// If the file doesn't exist, returns default config with no error.
func Load(path string) (*Config, error) {
	cfg := Default()

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // Use defaults if config file doesn't exist
		}
		return nil, fmt.Errorf("cannot open config file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key=value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid config line %d: %s", lineNum, line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if err := cfg.set(key, value); err != nil {
			return nil, fmt.Errorf("config line %d: %w", lineNum, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config: %w", err)
	}

	return cfg, nil
}

func (c *Config) set(key, value string) error {
	switch key {
	case "listen_address":
		c.ListenAddress = value
	case "listen_port":
		port, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid listen_port: %w", err)
		}
		c.ListenPort = port
	case "cache_max_size":
		size, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid cache_max_size: %w", err)
		}
		c.CacheMaxSize = size
	case "cache_ttl":
		ttl, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid cache_ttl: %w", err)
		}
		c.CacheTTL = time.Duration(ttl) * time.Second
	case "dns_timeout":
		timeout, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid dns_timeout: %w", err)
		}
		c.DNSTimeout = time.Duration(timeout) * time.Second
	case "dns_retries":
		retries, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid dns_retries: %w", err)
		}
		c.DNSRetries = retries
	case "domains_database_config":
		c.DomainsDatabaseConfig = value
	case "domains_file":
		c.DomainsFile = value
	case "spf_whitelist_file":
		c.SPFWhitelistFile = value
	case "reload_interval":
		interval, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid reload_interval: %w", err)
		}
		c.ReloadInterval = time.Duration(interval) * time.Second
	case "tolerant_mode":
		c.TolerantMode = parseBool(value)
	case "log_level":
		c.LogLevel = value
	case "pidfile":
		c.PidFile = value
	case "connection_timeout":
		timeout, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid connection_timeout: %w", err)
		}
		c.ConnectionTimeout = time.Duration(timeout) * time.Second
	default:
		// Unknown keys are silently ignored for forward compatibility
	}

	return nil
}

// parseBool parses a boolean config value.
// Accepts: yes, no, true, false, 1, 0 (case-insensitive)
func parseBool(value string) bool {
	switch strings.ToLower(value) {
	case "yes", "true", "1", "on":
		return true
	default:
		return false
	}
}
