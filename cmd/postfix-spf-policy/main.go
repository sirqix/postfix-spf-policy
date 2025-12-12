// SPF Policy Server - Postfix policy delegation server for SPF checking
// with tolerant heuristics for handling misconfigured but legitimate senders.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"postfix-spf-policy/internal/cache"
	"postfix-spf-policy/internal/config"
	"postfix-spf-policy/internal/domains"
	"postfix-spf-policy/internal/evaluator"
	"postfix-spf-policy/internal/policy"
	"postfix-spf-policy/internal/whitelist"
)

var (
	buildDate     = "unknown"                              // Set by -ldflags at build time
	defaultConfig = "/etc/postfix/postfix-spf-policy.conf" // Set by -ldflags at build time
	startTime     time.Time
)

func main() {
	// Check if invoked as a diagnostic tool (busybox-style)
	binName := filepath.Base(os.Args[0])
	if binName == "spf-check" || strings.HasPrefix(binName, "spf-check.") {
		runSPFCheck()
		return
	}
	if binName == "domain-check" || strings.HasPrefix(binName, "domain-check.") {
		runDomainCheck()
		return
	}

	// Command line flags
	configFile := flag.String("config", defaultConfig, "Configuration file")
	foreground := flag.Bool("foreground", false, "Run in foreground")
	verbose := flag.Bool("verbose", false, "Verbose logging")
	showVersion := flag.Bool("version", false, "Show version")
	showHelp := flag.Bool("help", false, "Show help")
	flag.Parse()

	if *showHelp {
		printUsage()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("postfix-spf-policy version %s (built %s)\n", Version, buildDate)
		os.Exit(0)
	}

	// Set up logging
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}

	var logger *slog.Logger
	if *foreground {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: logLevel,
		}))
	} else {
		// For daemon mode, log to syslog would be better, but for now use stderr
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: logLevel,
		}))
	}

	// Load configuration
	cfg, err := config.Load(*configFile)
	if err != nil {
		// Try defaults if config file doesn't exist
		if os.IsNotExist(err) {
			logger.Warn("config file not found, using defaults", "path", *configFile)
			cfg = config.Default()
		} else {
			logger.Error("failed to load config", "error", err)
			os.Exit(1)
		}
	}

	// Override log level from config
	if cfg.LogLevel == "debug" {
		logLevel = slog.LevelDebug
	}

	// Initialize cache
	spfCache, err := cache.New(cfg.CacheMaxSize, cfg.CacheTTL)
	if err != nil {
		logger.Error("failed to create cache", "error", err)
		os.Exit(1)
	}

	// Initialize evaluator
	eval := evaluator.New(cfg.DNSTimeout, logger)
	eval.SetTolerantMode(cfg.TolerantMode)

	// Initialize domains loader
	domainLoader := domains.New(logger)
	if cfg.DomainsDatabaseConfig != "" {
		if err := domainLoader.LoadFromPostfixConfig(cfg.DomainsDatabaseConfig); err != nil {
			logger.Error("failed to load domains from MySQL config", "path", cfg.DomainsDatabaseConfig, "error", err)
			os.Exit(1)
		}
	} else if cfg.DomainsFile != "" {
		if err := domainLoader.LoadFromFile(cfg.DomainsFile); err != nil {
			logger.Error("failed to load domains from file", "path", cfg.DomainsFile, "error", err)
			os.Exit(1)
		}
	}

	// Initialize SPF whitelist (domains that bypass SPF checks)
	spfWhitelist := whitelist.New(logger)
	if cfg.SPFWhitelistFile != "" {
		if err := spfWhitelist.LoadFromFile(cfg.SPFWhitelistFile); err != nil {
			logger.Error("failed to load SPF whitelist", "path", cfg.SPFWhitelistFile, "error", err)
			os.Exit(1)
		}
	}

	// Initialize policy handler
	handler := policy.NewHandler(eval, spfCache, domainLoader, spfWhitelist, cfg.ConnectionTimeout, logger)

	// Start listener
	addr := fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.ListenPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("failed to listen", "address", addr, "error", err)
		os.Exit(1)
	}
	defer listener.Close()

	logger.Info("server starting",
		"version", Version,
		"built", buildDate,
		"address", addr,
		"cache_size", cfg.CacheMaxSize,
		"cache_ttl", cfg.CacheTTL,
		"tolerant_mode", cfg.TolerantMode,
		"local_domains", domainLoader.Count(),
		"whitelist_domains", spfWhitelist.Count(),
	)

	startTime = time.Now()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1)

	// Channel to coordinate shutdown
	done := make(chan struct{})
	var wg sync.WaitGroup

	// Semaphore to limit concurrent connections (prevent goroutine explosion)
	maxConcurrent := 1000
	sem := make(chan struct{}, maxConcurrent)

	// Signal handler goroutine
	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				logger.Info("shutdown signal received", "signal", sig)
				close(done)
				listener.Close()
				return
			case syscall.SIGHUP:
				logger.Info("SIGHUP received, reloading configuration")
				// Reload config file
				newCfg, cfgErr := config.Load(*configFile)
				if cfgErr != nil {
					logger.Warn("failed to reload config, keeping current settings", "error", cfgErr)
				} else {
					// Update tolerant mode from config
					eval.SetTolerantMode(newCfg.TolerantMode)
				}
				// Reload domains
				if err := domainLoader.Reload(); err != nil {
					logger.Warn("failed to reload domains", "error", err)
				} else {
					logger.Info("reloaded domains", "count", domainLoader.Count())
				}
				// Reload whitelist
				if err := spfWhitelist.Reload(); err != nil {
					logger.Warn("failed to reload whitelist", "error", err)
				} else {
					logger.Info("reloaded whitelist", "count", spfWhitelist.Count())
				}
			case syscall.SIGUSR1:
				printStats(logger, handler, eval, spfCache)
			}
		}
	}()

	// Periodic cache cleanup goroutine
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				expired := spfCache.ExpireOld()
				if expired > 0 {
					logger.Debug("expired cache entries", "count", expired)
				}
			}
		}
	}()

	// Periodic domain reload goroutine
	if cfg.ReloadInterval > 0 && (cfg.DomainsDatabaseConfig != "" || cfg.DomainsFile != "") {
		go func() {
			ticker := time.NewTicker(cfg.ReloadInterval)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					if err := domainLoader.Reload(); err != nil {
						logger.Warn("failed to reload domains", "error", err)
					} else {
						logger.Debug("reloaded domains", "count", domainLoader.Count())
					}
				}
			}
		}()
	}

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-done:
				// Shutdown requested - wait for in-flight requests with timeout
				logger.Info("waiting for in-flight requests to complete")
				waitDone := make(chan struct{})
				go func() {
					wg.Wait()
					close(waitDone)
				}()

				select {
				case <-waitDone:
					logger.Info("all requests completed")
				case <-time.After(10 * time.Second):
					logger.Warn("shutdown timeout, forcing exit")
				}

				printStats(logger, handler, eval, spfCache)
				logger.Info("server stopped")
				return
			default:
				logger.Error("accept error", "error", err)
				continue
			}
		}

		// Acquire semaphore slot (with non-blocking check for shutdown)
		select {
		case <-done:
			conn.Close()
			continue
		case sem <- struct{}{}:
			// Got a slot
		}

		wg.Add(1)
		go func(c net.Conn) {
			defer func() {
				<-sem // Release semaphore slot
				wg.Done()
			}()
			handler.Handle(c)
		}(conn)
	}
}

func printStats(logger *slog.Logger, handler *policy.Handler, eval *evaluator.Evaluator, c *cache.Cache) {
	uptime := time.Since(startTime)
	hStats := handler.Stats()
	eStats := eval.Stats()
	cStats := c.Stats()

	logger.Info("statistics",
		"uptime", uptime.Round(time.Second),
		"connections", hStats.Connections,
		"requests", hStats.Requests,
		"errors", hStats.Errors,
		"local_skipped", hStats.LocalSkipped,
		"local_spoofed", hStats.LocalSpoofed,
		"whitelist_skipped", hStats.WhitelistSkipped,
	)

	logger.Info("spf results",
		"checks", eStats.Checks,
		"passes", eStats.Passes,
		"fails", eStats.Fails,
		"softfails", eStats.SoftFails,
		"neutrals", eStats.Neutrals,
		"nones", eStats.Nones,
		"permerrors", eStats.PermErrors,
		"temperrors", eStats.TempErrors,
		"tolerant_overrides", eStats.TolerantOverrides,
	)

	logger.Info("cache",
		"size", cStats.Size,
		"hits", cStats.Hits,
		"misses", cStats.Misses,
		"hit_rate", fmt.Sprintf("%.1f%%", cStats.HitRate),
		"expired", cStats.Expired,
		"evicted", cStats.Evicted,
	)
}

func printUsage() {
	fmt.Println(`postfix-spf-policy - Postfix SPF checking with tolerant heuristics

Usage: postfix-spf-policy [options]

Options:
  --config FILE     Configuration file (default: /etc/postfix/postfix-spf-policy.conf)
  --foreground      Run in foreground (don't daemonize)
  --verbose         Enable verbose/debug logging
  --version         Show version
  --help            Show this help

Signals:
  SIGINT/SIGTERM    Graceful shutdown
  SIGHUP            Reload config, domains, and whitelist
  SIGUSR1           Print statistics

Configuration file format (key=value):
  listen_address           Address to listen on (default: 127.0.0.1)
  listen_port              Port to listen on (default: 10033)
  cache_max_size           Maximum cache entries (default: 10000)
  cache_ttl                Cache TTL in seconds (default: 300)
  dns_timeout              DNS lookup timeout in seconds (default: 10)
  domains_database_config  Path to Postfix-style MySQL config file for local domains
  domains_file             Path to flat file with local domains (one per line)
  spf_whitelist_file       Path to file with domains that bypass SPF checks
  reload_interval          Interval to reload domains in seconds (default: 300)
  tolerant_mode            Enable tolerant heuristics: yes/no (default: yes)
  log_level                Log level: debug, info, warn, error (default: info)

Example:
  postfix-spf-policy --foreground --verbose --config /etc/postfix/postfix-spf-policy.conf`)
}

// runSPFCheck runs in CLI diagnostic mode (when invoked as spf-check)
func runSPFCheck() {
	// Separate flag set for diagnostic mode
	fs := flag.NewFlagSet("spf-check", flag.ExitOnError)
	ip := fs.String("ip", "", "Client IP address (required)")
	sender := fs.String("sender", "", "Sender email address (required)")
	helo := fs.String("helo", "", "HELO/EHLO hostname (optional, defaults to sender domain)")
	configFile := fs.String("config", defaultConfig, "Configuration file")
	showVersion := fs.Bool("version", false, "Show version")
	showHelp := fs.Bool("help", false, "Show help")

	fs.Usage = func() {
		fmt.Println(`spf-check - SPF diagnostic tool

Usage: spf-check --ip IP --sender EMAIL [--helo HOSTNAME] [--config FILE]

This tool checks SPF for a given IP/sender combination and shows what
action postfix-spf-policy would take, using the exact same code path
as the daemon mode (including whitelist, local domains, tolerant heuristics).

Options:
  --ip IP           Client IP address (required)
  --sender EMAIL    Sender email address (required)
  --helo HOSTNAME   HELO/EHLO hostname (optional)
  --config FILE     Configuration file (default: /etc/postfix/postfix-spf-policy.conf)
  --version         Show version
  --help            Show this help

Examples:
  spf-check --ip 192.0.2.1 --sender user@example.com
  spf-check --ip 192.0.2.1 --sender user@example.com --helo mail.example.com

Exit codes:
  0  DUNNO (pass through to next check)
  1  REJECT (hard reject)
  2  DEFER (temporary failure)`)
	}

	fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("spf-check version %s (built %s)\n", Version, buildDate)
		os.Exit(0)
	}

	if *showHelp {
		fs.Usage()
		os.Exit(0)
	}

	if *ip == "" || *sender == "" {
		fmt.Fprintln(os.Stderr, "Error: --ip and --sender are required")
		fmt.Fprintln(os.Stderr, "")
		fs.Usage()
		os.Exit(1)
	}

	// Validate IP
	if net.ParseIP(*ip) == nil {
		fmt.Fprintf(os.Stderr, "Error: invalid IP address: %s\n", *ip)
		os.Exit(1)
	}

	// Extract domain from sender
	senderDomain := ""
	if parts := strings.Split(*sender, "@"); len(parts) == 2 {
		senderDomain = parts[1]
	}
	if senderDomain == "" {
		fmt.Fprintf(os.Stderr, "Error: invalid sender email: %s\n", *sender)
		os.Exit(1)
	}

	// Default HELO to sender domain if not specified
	heloName := *helo
	if heloName == "" {
		heloName = senderDomain
	}

	// Create a silent logger (discard output)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Load configuration (silently use defaults if not found)
	cfg, err := config.Load(*configFile)
	if err != nil {
		cfg = config.Default()
	}

	// Initialize cache (small, just for this request)
	spfCache, _ := cache.New(100, cfg.CacheTTL)

	// Initialize evaluator
	eval := evaluator.New(cfg.DNSTimeout, logger)
	eval.SetTolerantMode(cfg.TolerantMode)

	// Initialize domains loader
	domainLoader := domains.New(logger)
	if cfg.DomainsDatabaseConfig != "" {
		domainLoader.LoadFromPostfixConfig(cfg.DomainsDatabaseConfig)
	} else if cfg.DomainsFile != "" {
		domainLoader.LoadFromFile(cfg.DomainsFile)
	}

	// Initialize SPF whitelist
	spfWhitelist := whitelist.New(logger)
	if cfg.SPFWhitelistFile != "" {
		spfWhitelist.LoadFromFile(cfg.SPFWhitelistFile)
	}

	// Initialize policy handler - uses exact same code path as daemon mode
	handler := policy.NewHandler(eval, spfCache, domainLoader, spfWhitelist, cfg.ConnectionTimeout, logger)

	// Create a policy request exactly as it would come from Postfix
	req := &policy.Request{
		Request:       "smtpd_access_policy",
		ClientAddress: *ip,
		Sender:        *sender,
		HeloName:      heloName,
	}

	// Process using the exact same method as daemon mode
	action, reason := handler.ProcessRequest(req)

	// Print results
	fmt.Println("SPF Check Results")
	fmt.Println("=================")
	fmt.Printf("IP:      %s\n", *ip)
	fmt.Printf("Sender:  %s\n", *sender)
	fmt.Printf("HELO:    %s\n", heloName)
	fmt.Println()
	fmt.Printf("Action:  %s\n", action)
	if reason != "" {
		fmt.Printf("Reason:  %s\n", reason)
	}

	// Show config info if relevant
	if domainLoader.Count() > 0 {
		fmt.Printf("\nLocal domains loaded: %d\n", domainLoader.Count())
	}
	if spfWhitelist.Count() > 0 {
		fmt.Printf("Whitelist domains loaded: %d\n", spfWhitelist.Count())
	}

	// Exit with appropriate code
	switch action {
	case "REJECT":
		os.Exit(1)
	case "DEFER":
		os.Exit(2)
	default:
		os.Exit(0)
	}
}

// stringSliceFlag is a flag that can be specified multiple times
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// runDomainCheck validates local domains have MX records pointing to expected IPs/hosts
func runDomainCheck() {
	fs := flag.NewFlagSet("domain-check", flag.ExitOnError)

	var expectedIPs stringSliceFlag
	var expectedMXs stringSliceFlag
	var domainFiles stringSliceFlag

	fs.Var(&expectedIPs, "ip", "Expected MX IP address (can be specified multiple times)")
	fs.Var(&expectedMXs, "mx", "Expected MX hostname (can be specified multiple times)")
	fs.Var(&domainFiles, "domains-file", "File with domains to check, one per line (use '-' for stdin, can be repeated)")
	sqlConfig := fs.String("sql-config", "", "Postfix-style MySQL config file for loading domains")
	showVersion := fs.Bool("version", false, "Show version")
	showHelp := fs.Bool("help", false, "Show help")

	fs.Usage = func() {
		fmt.Println(`domain-check - Verify domains have correct MX records

Usage: domain-check --ip IP [options] [domain ...]

This tool checks domains and verifies that their MX records resolve to one
of the expected IP addresses or hostnames. At least one --ip or --mx must
be specified.

Domain sources (can be combined):
  domain ...              Domains listed on command line
  --domains-file FILE     File with domains (one per line, use '-' for stdin)
  --sql-config FILE       Postfix-style MySQL config file

Options:
  --ip IP             Expected MX IP address (can be repeated)
  --mx HOSTNAME       Expected MX hostname (can be repeated)
  --domains-file FILE Domain file (can be repeated, use '-' for stdin)
  --sql-config FILE   MySQL config file for domain lookup
  --version           Show version
  --help              Show this help

Examples:
  domain-check --ip 192.0.2.1 example.com example.org
  domain-check --ip 192.0.2.1 --domains-file /etc/postfix/local-domains.txt
  domain-check --ip 192.0.2.1 --sql-config /etc/postfix/mysql-virtual-domains.cf
  domain-check --mx mail.example.com --domains-file - < domains.txt
  cat domains.txt | domain-check --ip 192.0.2.1 --domains-file -

Output format:
  OK   domain.com - MX: mail.example.com (192.0.2.1)
  FAIL domain.org - MX: other.host.com (10.0.0.1) - no match

Exit codes:
  0  All domains OK
  1  One or more domains failed`)
	}

	fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("domain-check version %s (built %s)\n", Version, buildDate)
		os.Exit(0)
	}

	if *showHelp {
		fs.Usage()
		os.Exit(0)
	}

	if len(expectedIPs) == 0 && len(expectedMXs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: at least one --ip or --mx is required")
		fmt.Fprintln(os.Stderr, "")
		fs.Usage()
		os.Exit(1)
	}

	// Validate IP addresses
	for _, ip := range expectedIPs {
		if net.ParseIP(ip) == nil {
			fmt.Fprintf(os.Stderr, "Error: invalid IP address: %s\n", ip)
			os.Exit(1)
		}
	}

	// Collect domains from all sources
	domainSet := make(map[string]bool)

	// 1. Command line arguments (remaining args after flags)
	for _, domain := range fs.Args() {
		domain = strings.TrimSpace(strings.ToLower(domain))
		if domain != "" {
			domainSet[domain] = true
		}
	}

	// 2. Domain files (including stdin if "-")
	for _, file := range domainFiles {
		if err := loadDomainsFromFile(file, domainSet); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading domains from %s: %v\n", file, err)
			os.Exit(1)
		}
	}

	// 3. SQL config
	if *sqlConfig != "" {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		domainLoader := domains.New(logger)
		if err := domainLoader.LoadFromPostfixConfig(*sqlConfig); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading domains from SQL config: %v\n", err)
			os.Exit(1)
		}
		for _, d := range domainLoader.List() {
			domainSet[strings.ToLower(d)] = true
		}
	}

	if len(domainSet) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no domains specified")
		fmt.Fprintln(os.Stderr, "Provide domains via command line, --domains-file, or --sql-config")
		os.Exit(1)
	}

	// Convert to sorted list
	domainList := make([]string, 0, len(domainSet))
	for d := range domainSet {
		domainList = append(domainList, d)
	}
	sort.Strings(domainList)

	// Build lookup maps for faster matching
	expectedIPMap := make(map[string]bool)
	for _, ip := range expectedIPs {
		expectedIPMap[ip] = true
	}
	expectedMXMap := make(map[string]bool)
	for _, mx := range expectedMXs {
		expectedMXMap[strings.ToLower(mx)] = true
	}

	// Check each domain
	var failCount int
	for _, domain := range domainList {
		status, detail := checkDomainMX(domain, expectedIPMap, expectedMXMap)
		if status == "OK" {
			fmt.Printf("OK   %s - %s\n", domain, detail)
		} else {
			fmt.Printf("FAIL %s - %s\n", domain, detail)
			failCount++
		}
	}

	// Summary
	fmt.Printf("\nChecked %d domains: %d OK, %d FAIL\n", len(domainList), len(domainList)-failCount, failCount)

	if failCount > 0 {
		os.Exit(1)
	}
}

// loadDomainsFromFile loads domains from a file into the provided map.
// If filename is "-", reads from stdin.
func loadDomainsFromFile(filename string, domainSet map[string]bool) error {
	var reader io.Reader
	if filename == "-" {
		reader = os.Stdin
	} else {
		file, err := os.Open(filename)
		if err != nil {
			return err
		}
		defer file.Close()
		reader = file
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domainSet[strings.ToLower(line)] = true
	}
	return scanner.Err()
}

// checkDomainMX checks if a domain's MX records match expected IPs or hostnames
func checkDomainMX(domain string, expectedIPs map[string]bool, expectedMXs map[string]bool) (status, detail string) {
	// Use a custom resolver with short timeout to avoid hanging on broken DNS
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, network, address)
		},
	}

	// Context with overall timeout for this domain check
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Look up MX records
	mxRecords, err := resolver.LookupMX(ctx, domain)
	if err != nil {
		return "FAIL", fmt.Sprintf("MX lookup error: %v", err)
	}

	if len(mxRecords) == 0 {
		return "FAIL", "no MX records found"
	}

	// Check each MX record
	var matchedMX string
	var matchedIP string
	var allMXInfo []string

	for _, mx := range mxRecords {
		mxHost := strings.TrimSuffix(mx.Host, ".")
		mxHostLower := strings.ToLower(mxHost)

		// Check if MX hostname matches
		if expectedMXs[mxHostLower] {
			// Get an IP for display (with short timeout)
			ipCtx, ipCancel := context.WithTimeout(ctx, 2*time.Second)
			ips, _ := resolver.LookupHost(ipCtx, mxHost)
			ipCancel()
			ipStr := ""
			if len(ips) > 0 {
				ipStr = ips[0]
			}
			return "OK", fmt.Sprintf("MX: %s (%s) - hostname match", mxHost, ipStr)
		}

		// Look up MX IPs with short timeout
		ipCtx, ipCancel := context.WithTimeout(ctx, 2*time.Second)
		ips, err := resolver.LookupHost(ipCtx, mxHost)
		ipCancel()

		if err != nil {
			allMXInfo = append(allMXInfo, fmt.Sprintf("%s (lookup failed)", mxHost))
			continue
		}

		for _, ip := range ips {
			if expectedIPs[ip] {
				matchedMX = mxHost
				matchedIP = ip
				break
			}
		}

		if matchedMX != "" {
			break
		}

		// Record for error message
		if len(ips) > 0 {
			allMXInfo = append(allMXInfo, fmt.Sprintf("%s (%s)", mxHost, ips[0]))
		} else {
			allMXInfo = append(allMXInfo, mxHost)
		}
	}

	if matchedMX != "" {
		return "OK", fmt.Sprintf("MX: %s (%s)", matchedMX, matchedIP)
	}

	return "FAIL", fmt.Sprintf("MX: %s - no match", strings.Join(allMXInfo, ", "))
}
