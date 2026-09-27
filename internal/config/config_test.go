package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	cfg := Default()

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"ListenAddress", cfg.ListenAddress, "127.0.0.1"},
		{"ListenPort", cfg.ListenPort, 10033},
		{"CacheMaxSize", cfg.CacheMaxSize, 10000},
		{"CacheTTL", cfg.CacheTTL, 5 * time.Minute},
		{"DNSTimeout", cfg.DNSTimeout, 10 * time.Second},
		{"DNSRetries", cfg.DNSRetries, 2},
		{"DomainsDatabaseConfig", cfg.DomainsDatabaseConfig, ""},
		{"DomainsFile", cfg.DomainsFile, ""},
		{"SPFWhitelistFile", cfg.SPFWhitelistFile, ""},
		{"ReloadInterval", cfg.ReloadInterval, 5 * time.Minute},
		{"TolerantMode", cfg.TolerantMode, true},
		{"LogLevel", cfg.LogLevel, "info"},
		{"PidFile", cfg.PidFile, "/var/run/spf-policy.pid"},
		{"ConnectionTimeout", cfg.ConnectionTimeout, 30 * time.Second},
	}

	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("got %v, want %v", tc.got, tc.want)
			}
		})
	}
}

func TestParseBool(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"yes", true},
		{"Yes", true},
		{"YES", true},
		{"true", true},
		{"True", true},
		{"TRUE", true},
		{"1", true},
		{"on", true},
		{"On", true},
		{"ON", true},
		{"no", false},
		{"No", false},
		{"false", false},
		{"False", false},
		{"0", false},
		{"off", false},
		{"Off", false},
		{"", false},
		{"maybe", false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := parseBool(tc.input)
			if got != tc.want {
				t.Errorf("parseBool(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestLoad_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	content := `listen_address = 0.0.0.0
listen_port = 9999
cache_max_size = 5000
cache_ttl = 120
dns_timeout = 5
dns_retries = 3
domains_database_config = /etc/postfix/mysql.cf
domains_file = /etc/postfix/domains.txt
spf_whitelist_file = /etc/postfix/whitelist.txt
reload_interval = 600
tolerant_mode = no
log_level = debug
pidfile = /tmp/test.pid
connection_timeout = 60
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.ListenAddress != "0.0.0.0" {
		t.Errorf("ListenAddress = %q, want %q", cfg.ListenAddress, "0.0.0.0")
	}
	if cfg.ListenPort != 9999 {
		t.Errorf("ListenPort = %d, want %d", cfg.ListenPort, 9999)
	}
	if cfg.CacheMaxSize != 5000 {
		t.Errorf("CacheMaxSize = %d, want %d", cfg.CacheMaxSize, 5000)
	}
	if cfg.CacheTTL != 120*time.Second {
		t.Errorf("CacheTTL = %v, want %v", cfg.CacheTTL, 120*time.Second)
	}
	if cfg.DNSTimeout != 5*time.Second {
		t.Errorf("DNSTimeout = %v, want %v", cfg.DNSTimeout, 5*time.Second)
	}
	if cfg.DNSRetries != 3 {
		t.Errorf("DNSRetries = %d, want %d", cfg.DNSRetries, 3)
	}
	if cfg.DomainsDatabaseConfig != "/etc/postfix/mysql.cf" {
		t.Errorf("DomainsDatabaseConfig = %q, want %q", cfg.DomainsDatabaseConfig, "/etc/postfix/mysql.cf")
	}
	if cfg.DomainsFile != "/etc/postfix/domains.txt" {
		t.Errorf("DomainsFile = %q, want %q", cfg.DomainsFile, "/etc/postfix/domains.txt")
	}
	if cfg.SPFWhitelistFile != "/etc/postfix/whitelist.txt" {
		t.Errorf("SPFWhitelistFile = %q, want %q", cfg.SPFWhitelistFile, "/etc/postfix/whitelist.txt")
	}
	if cfg.ReloadInterval != 600*time.Second {
		t.Errorf("ReloadInterval = %v, want %v", cfg.ReloadInterval, 600*time.Second)
	}
	if cfg.TolerantMode != false {
		t.Errorf("TolerantMode = %v, want false", cfg.TolerantMode)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
	if cfg.PidFile != "/tmp/test.pid" {
		t.Errorf("PidFile = %q, want %q", cfg.PidFile, "/tmp/test.pid")
	}
	if cfg.ConnectionTimeout != 60*time.Second {
		t.Errorf("ConnectionTimeout = %v, want %v", cfg.ConnectionTimeout, 60*time.Second)
	}
}

func TestLoad_CommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	content := `# This is a comment
listen_port = 8080

# Another comment

   # Indented comment
cache_max_size = 2000
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.ListenPort != 8080 {
		t.Errorf("ListenPort = %d, want %d", cfg.ListenPort, 8080)
	}
	if cfg.CacheMaxSize != 2000 {
		t.Errorf("CacheMaxSize = %d, want %d", cfg.CacheMaxSize, 2000)
	}
	// Other values should be defaults
	if cfg.ListenAddress != "127.0.0.1" {
		t.Errorf("ListenAddress = %q, want default %q", cfg.ListenAddress, "127.0.0.1")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.conf")
	if err != nil {
		t.Fatalf("Load() should return defaults for missing file, got error: %v", err)
	}
	// Should return defaults
	def := Default()
	if cfg.ListenPort != def.ListenPort {
		t.Errorf("ListenPort = %d, want default %d", cfg.ListenPort, def.ListenPort)
	}
}

func TestLoad_PartialConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	content := `listen_port = 5555
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.ListenPort != 5555 {
		t.Errorf("ListenPort = %d, want %d", cfg.ListenPort, 5555)
	}
	// All others should be defaults
	def := Default()
	if cfg.ListenAddress != def.ListenAddress {
		t.Errorf("ListenAddress = %q, want default %q", cfg.ListenAddress, def.ListenAddress)
	}
	if cfg.CacheMaxSize != def.CacheMaxSize {
		t.Errorf("CacheMaxSize = %d, want default %d", cfg.CacheMaxSize, def.CacheMaxSize)
	}
	if cfg.TolerantMode != def.TolerantMode {
		t.Errorf("TolerantMode = %v, want default %v", cfg.TolerantMode, def.TolerantMode)
	}
}

func TestLoad_DurationParsing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	// All duration fields are specified in seconds
	content := `cache_ttl = 300
dns_timeout = 15
reload_interval = 3600
connection_timeout = 45
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	tests := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"CacheTTL", cfg.CacheTTL, 300 * time.Second},
		{"DNSTimeout", cfg.DNSTimeout, 15 * time.Second},
		{"ReloadInterval", cfg.ReloadInterval, 3600 * time.Second},
		{"ConnectionTimeout", cfg.ConnectionTimeout, 45 * time.Second},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("got %v, want %v", tc.got, tc.want)
			}
		})
	}
}

func TestLoad_InvalidLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	content := `listen_port = 8080
this is not valid
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() should return error for invalid line")
	}
}

func TestLoad_InvalidIntValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	content := `listen_port = notanumber
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() should return error for invalid integer value")
	}
}

func TestLoad_UnknownKeysIgnored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	content := `listen_port = 7777
unknown_key = some_value
another_unknown = 42
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() should ignore unknown keys, got error: %v", err)
	}
	if cfg.ListenPort != 7777 {
		t.Errorf("ListenPort = %d, want %d", cfg.ListenPort, 7777)
	}
}
