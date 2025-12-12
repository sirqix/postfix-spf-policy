// Package domains provides local domain lookup for skipping SPF checks.
// Supports loading domains from MySQL (Postfix config format) and flat files.
package domains

import (
	"bufio"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// Loader manages local domain lookups.
type Loader struct {
	domains   map[string]bool
	mu        sync.RWMutex
	logger    *slog.Logger
	mysqlCfg  *MySQLConfig
	filePath  string
	lastLoad  time.Time
	loadCount int64
}

// MySQLConfig holds Postfix-style MySQL configuration.
type MySQLConfig struct {
	Hosts    string // Comma-separated list of hosts
	User     string
	Password string
	DBName   string
	Query    string // Query with %s placeholder for domain
}

// New creates a new domain loader.
func New(logger *slog.Logger) *Loader {
	return &Loader{
		domains: make(map[string]bool),
		logger:  logger,
	}
}

// LoadFromPostfixConfig loads MySQL configuration from a Postfix-style config file.
// Format:
//
//	hosts = localhost
//	user = postfix
//	password = secret
//	dbname = mail
//	query = SELECT domain FROM virtual_domains WHERE domain='%s'
func (l *Loader) LoadFromPostfixConfig(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot open postfix config: %w", err)
	}
	defer file.Close()

	cfg := &MySQLConfig{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key = value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "hosts", "host":
			cfg.Hosts = value
		case "user":
			cfg.User = value
		case "password":
			cfg.Password = value
		case "dbname":
			cfg.DBName = value
		case "query":
			cfg.Query = value
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading config: %w", err)
	}

	// Validate required fields
	if cfg.Hosts == "" || cfg.User == "" || cfg.DBName == "" || cfg.Query == "" {
		return fmt.Errorf("incomplete MySQL config: hosts, user, dbname, and query are required")
	}

	l.mysqlCfg = cfg
	return l.loadFromMySQL()
}

// loadFromMySQL loads all domains from MySQL.
func (l *Loader) loadFromMySQL() error {
	if l.mysqlCfg == nil {
		return fmt.Errorf("MySQL not configured")
	}

	// Build DSN: user:password@tcp(host)/dbname
	host := strings.Split(l.mysqlCfg.Hosts, ",")[0] // Use first host
	host = strings.TrimSpace(host)
	if !strings.Contains(host, ":") {
		host = host + ":3306"
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?timeout=10s",
		l.mysqlCfg.User,
		l.mysqlCfg.Password,
		host,
		l.mysqlCfg.DBName,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("cannot connect to MySQL: %w", err)
	}
	defer db.Close()

	// Set connection limits
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Minute)

	// Test connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("MySQL ping failed: %w", err)
	}

	// Convert Postfix lookup query to a "get all" query
	// Original Postfix queries use %s for single domain lookup
	// We need to remove WHERE clauses to get all domains
	//
	// Examples:
	// - Simple: SELECT domain FROM domain WHERE domain='%s'
	//   -> SELECT domain FROM domain
	// - UNION: SELECT domain FROM domain WHERE domain='%s' UNION SELECT alias FROM aliases WHERE alias='%s'
	//   -> SELECT domain FROM domain UNION SELECT alias FROM aliases
	query := convertToGetAllQuery(l.mysqlCfg.Query)

	l.logger.Debug("loading domains from MySQL", "query", query)

	rows, err := db.Query(query)
	if err != nil {
		return fmt.Errorf("MySQL query failed: %w", err)
	}
	defer rows.Close()

	domains := make(map[string]bool)
	count := 0
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			l.logger.Warn("error scanning domain row", "error", err)
			continue
		}
		domains[strings.ToLower(domain)] = true
		count++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("MySQL rows error: %w", err)
	}

	l.mu.Lock()
	l.domains = domains
	l.lastLoad = time.Now()
	l.loadCount++
	l.mu.Unlock()

	l.logger.Info("loaded domains from MySQL", "count", count)
	return nil
}

// LoadFromFile loads domains from a flat file (one domain per line).
func (l *Loader) LoadFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot open domains file: %w", err)
	}
	defer file.Close()

	l.filePath = path

	domains := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	count := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		domains[strings.ToLower(line)] = true
		count++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading domains file: %w", err)
	}

	l.mu.Lock()
	l.domains = domains
	l.lastLoad = time.Now()
	l.loadCount++
	l.mu.Unlock()

	l.logger.Info("loaded domains from file", "path", path, "count", count)
	return nil
}

// IsLocal checks if a domain is in the local domains list.
func (l *Loader) IsLocal(domain string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.domains[strings.ToLower(domain)]
}

// Reload reloads domains from the configured source.
func (l *Loader) Reload() error {
	if l.mysqlCfg != nil {
		return l.loadFromMySQL()
	}
	if l.filePath != "" {
		return l.LoadFromFile(l.filePath)
	}
	return nil
}

// Count returns the number of loaded domains.
func (l *Loader) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.domains)
}

// LastLoad returns when domains were last loaded.
func (l *Loader) LastLoad() time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.lastLoad
}

// List returns all loaded domains (for debugging).
func (l *Loader) List() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]string, 0, len(l.domains))
	for domain := range l.domains {
		result = append(result, domain)
	}
	return result
}

// convertToGetAllQuery converts a Postfix lookup query (with %s placeholder)
// to a query that returns all domains.
// It handles UNION queries by processing each SELECT separately.
func convertToGetAllQuery(originalQuery string) string {
	// Normalize whitespace
	query := strings.TrimSpace(originalQuery)

	// Split by UNION (case-insensitive)
	parts := splitByUnion(query)
	var resultParts []string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Remove WHERE clause and everything after it
		// But preserve the basic SELECT ... FROM ... structure
		processed := removeWhereClause(part)
		if processed != "" {
			resultParts = append(resultParts, processed)
		}
	}

	return strings.Join(resultParts, " UNION ")
}

// splitByUnion splits a query by UNION keyword (case-insensitive).
func splitByUnion(query string) []string {
	// Use case-insensitive split
	upper := strings.ToUpper(query)
	var parts []string
	lastIdx := 0

	for {
		idx := strings.Index(upper[lastIdx:], " UNION ")
		if idx == -1 {
			parts = append(parts, query[lastIdx:])
			break
		}
		parts = append(parts, query[lastIdx:lastIdx+idx])
		lastIdx = lastIdx + idx + 7 // len(" UNION ")
	}

	return parts
}

// removeWhereClause removes the domain='%s' lookup from a SELECT statement
// while preserving other WHERE conditions like active=1.
func removeWhereClause(query string) string {
	upper := strings.ToUpper(query)

	// Find WHERE position
	whereIdx := strings.Index(upper, " WHERE ")
	if whereIdx == -1 {
		return strings.TrimSpace(query)
	}

	// Extract the part before WHERE and the WHERE clause
	beforeWhere := query[:whereIdx]
	whereClause := query[whereIdx+7:] // Skip " WHERE "

	// Remove the domain='%s' or domain = '%s' pattern from the WHERE clause
	// This handles various patterns:
	// - domain='%s'
	// - domain = '%s'
	// - domain='%s' AND active=1
	// - active=1 AND domain='%s'
	cleanedWhere := removeDomainLookup(whereClause)

	if cleanedWhere == "" {
		// Nothing left in WHERE clause
		return strings.TrimSpace(beforeWhere)
	}

	return strings.TrimSpace(beforeWhere) + " WHERE " + cleanedWhere
}

// removeDomainLookup removes domain='%s' patterns from a WHERE clause
// while preserving other conditions.
func removeDomainLookup(whereClause string) string {
	// Patterns to remove (case-insensitive matching)
	// We need to handle: domain='%s', domain = '%s', domain='%s' AND, AND domain='%s'

	result := whereClause

	// Remove patterns like: domain='%s' or domain = '%s'
	// Using simple string replacement for common patterns
	// Also handle alias_domain lookups
	patterns := []string{
		"alias_domain.alias_domain='%s'",
		"alias_domain.alias_domain = '%s'",
		"domain='%s'",
		"domain = '%s'",
		"domain= '%s'",
		"domain ='%s'",
		`domain="%s"`,
		`domain = "%s"`,
	}

	for _, pattern := range patterns {
		// Try case-insensitive removal
		result = removePatternCaseInsensitive(result, pattern)
	}

	// Clean up leftover AND/OR connectors
	result = cleanupConnectors(result)

	return strings.TrimSpace(result)
}

// removePatternCaseInsensitive removes a pattern from a string case-insensitively.
func removePatternCaseInsensitive(s, pattern string) string {
	upper := strings.ToUpper(s)
	patternUpper := strings.ToUpper(pattern)

	idx := strings.Index(upper, patternUpper)
	if idx == -1 {
		return s
	}

	return s[:idx] + s[idx+len(pattern):]
}

// cleanupConnectors removes orphaned AND/OR at the start/end of a clause.
func cleanupConnectors(s string) string {
	s = strings.TrimSpace(s)

	// Remove leading AND/OR
	upper := strings.ToUpper(s)
	if strings.HasPrefix(upper, "AND ") {
		s = strings.TrimSpace(s[4:])
	} else if strings.HasPrefix(upper, "OR ") {
		s = strings.TrimSpace(s[3:])
	}

	// Remove trailing AND/OR
	upper = strings.ToUpper(s)
	if strings.HasSuffix(upper, " AND") {
		s = strings.TrimSpace(s[:len(s)-4])
	} else if strings.HasSuffix(upper, " OR") {
		s = strings.TrimSpace(s[:len(s)-3])
	}

	return s
}
