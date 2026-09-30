# postfix-spf-policy

A high-performance SPF (Sender Policy Framework) policy server for Postfix with tolerant heuristics to reduce false positives from misconfigured but legitimate senders.

## Features

- **SPF Checking**: Full SPF validation using the [blitiri.com.ar/go/spf](https://blitiri.com.ar/go/spf) library
- **Tolerant Mode**: Intelligent heuristics to handle common SPF misconfigurations
- **Local Domain Awareness**: Skip SPF checks for your own domains, detect spoofing attempts
- **SPF Whitelist**: Bypass SPF checks for trusted sender domains
- **Result Caching**: LRU cache with configurable TTL for improved performance
- **MySQL Integration**: Load domains from Postfix-style MySQL configuration
- **Live Reload**: SIGHUP signal reloads configuration, domains, and whitelist without restart
- **Diagnostic Tools**: Built-in CLI tools for testing SPF and validating domain MX records
- **Static Binary**: Single statically-linked binary with vendored dependencies

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/sirqix/postfix-spf-policy.git
cd postfix-spf-policy

# Build
make build

# The binary is created as ./postfix-spf-policy
```

### Using the Installer

```bash
# Build the self-extracting installer
make installer

# Run the installer on target system
sudo ./postfix-spf-policy-installer.run
```

## Quick Start

1. Copy the example configuration:
   ```bash
   sudo cp examples/postfix-spf-policy.conf /etc/postfix/postfix-spf-policy.conf
   ```

2. Edit the configuration as needed:
   ```bash
   sudo editor /etc/postfix/postfix-spf-policy.conf
   ```

3. Start the server:
   ```bash
   ./postfix-spf-policy --config /etc/postfix/postfix-spf-policy.conf
   ```

4. Configure Postfix to use the policy server (in `main.cf`):
   ```
   smtpd_recipient_restrictions =
       ...
       check_policy_service inet:127.0.0.1:10033
       ...
   ```

5. Reload Postfix:
   ```bash
   sudo postfix reload
   ```

## Configuration

Configuration uses simple `key = value` format. Lines starting with `#` are comments.

### Network Settings

| Option | Default | Description |
|--------|---------|-------------|
| `listen_address` | `127.0.0.1` | IP address to listen on |
| `listen_port` | `10033` | TCP port to listen on |
| `connection_timeout` | `30` | Connection timeout in seconds |

### Cache Settings

| Option | Default | Description |
|--------|---------|-------------|
| `cache_max_size` | `10000` | Maximum number of cached SPF results |
| `cache_ttl` | `300` | Cache TTL in seconds (5 minutes) |

### DNS Settings

| Option | Default | Description |
|--------|---------|-------------|
| `dns_timeout` | `10` | DNS lookup timeout in seconds |

### Domain Sources

Configure local domains to skip SPF checks for legitimate local senders and detect spoofing:

| Option | Default | Description |
|--------|---------|-------------|
| `domains_database_config` | - | Path to Postfix-style MySQL config file |
| `domains_file` | - | Path to flat file with domains (one per line) |
| `reload_interval` | `300` | Auto-reload interval in seconds |

Use **one** of `domains_database_config` or `domains_file`, not both.

### SPF Whitelist

| Option | Default | Description |
|--------|---------|-------------|
| `spf_whitelist_file` | - | Path to file with domains that bypass SPF checks |

The whitelist file contains one domain per line. Emails from these sender domains will pass through without SPF checking.

### Tolerant Mode

| Option | Default | Description |
|--------|---------|-------------|
| `tolerant_mode` | `yes` | Enable heuristics to reduce false positives |

When enabled, tolerant mode scores these heuristics for SPF fail/softfail/permerror. An override needs 40 points for softfail/permerror and 60 for fail. Each heuristic counts at most once, and reverse DNS is only used when it is forward-confirmed (the PTR name resolves back to the client IP). "Registrable domain" uses the public suffix list, so `co.uk` never counts as a shared organisation.

| Heuristic | Points |
|-----------|--------|
| **MX alignment** — client rDNS is in the same registrable domain as one of the sender domain's MX hosts (e.g. `*.google.com` client for a Google Workspace domain, `*.outbound.protection.outlook.com` for Microsoft 365). Decisive on its own for softfail/permerror ("match and go"). A hard fail (`-all`) needs further evidence: `-all` is the sender's explicit decision, and tolerance is only meant to absorb typos and human error. | 40 |
| **MX subnet** — client is in the same /24 (IPv4) or /64 (IPv6) as one of the domain's MX hosts | 40 |
| **rDNS aligned** — client rDNS is the sender domain or under it (20 if the sender domain is merely under the client's registrable domain) | 30 / 20 |
| **HELO aligned** — HELO is the sender domain or under it (15 if only related) | 25 / 15 |

For PermError, an IP explicitly listed anywhere in the record chain (ip4/ip6/include/redirect/exists) is accepted first.

Accepts: `yes`, `no`, `true`, `false`, `1`, `0`, `on`, `off`

#### Broken SPF records (PermError)

In tolerant mode a defect in the sender's published record does not by itself fail the message:

- **Unusable terms are excluded from consideration.** A misspelled mechanism (`ip:` for `ip4:`, `include.example.net` for `include:example.net`), an invalid address or CIDR, a stray token, or an unknown modifier is dropped and the rest of the record is evaluated as if the term had never been published. Nothing is guessed: `ip:192.0.2.1` is ignored, not treated as `ip4:`. The outcome is whatever the remaining terms say, so a sender that was only authorized by the broken term gets the record's `all` result. Each case is logged as `SPF record errors ignored` with the terms listed in `ignored_terms`, and a resulting reject/defer reply names them.
- **Structural PermErrors stay PermErrors**: more than 10 MX records behind an `mx` mechanism, an `include:`/`redirect=` target with no SPF record, multiple `v=spf1` records, or a chain that exceeds the DNS lookup limit even at the raised limit of 20. These are deferred unless the client IP is listed in the record chain or the heuristics above apply.
- **The log states the real cause.** `problem=` on the `tolerant override applied` lines, and the reply text for a deferred PermError, are derived from the SPF library's error (`spf_error=`), so a lookup-limit problem is only reported when the lookup limit was actually hit.

With `tolerant_mode = no` every PermError is deferred, per RFC 7208.

*Possible future feature — typo repair:* reinterpreting unambiguous typos instead of excluding them (`ip:`/`ipv4:` followed by a valid address → `ip4:`/`ip6:`, `include:include:X` → `include:X`). Not implemented by design: it means guessing the sender's intent. Seen in production: `include:include:spf.protection.outlook.com`, `ip:` and `ipv4:` in place of `ip4:`.

### Logging

| Option | Default | Description |
|--------|---------|-------------|
| `log_level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `pidfile` | `/var/run/postfix-spf-policy.pid` | PID file location |

## Command Line Options

```
postfix-spf-policy [options]

Options:
  --config FILE     Configuration file (default: /etc/postfix/postfix-spf-policy.conf)
  --foreground      Run in foreground (don't daemonize)
  --verbose         Enable verbose/debug logging
  --version         Show version
  --help            Show help
```

## Signals

| Signal | Action |
|--------|--------|
| `SIGTERM`, `SIGINT` | Graceful shutdown |
| `SIGHUP` | Reload configuration, domains, and whitelist |
| `SIGUSR1` | Print statistics to log |

Example:
```bash
# Reload configuration after editing
kill -HUP $(cat /var/run/postfix-spf-policy.pid)

# Print statistics
kill -USR1 $(cat /var/run/postfix-spf-policy.pid)
```

## Diagnostic Tools

The binary includes built-in diagnostic tools accessed via symlinks:

### spf-check

Test SPF evaluation for a specific IP/sender combination:

```bash
# Create symlink
ln -s postfix-spf-policy spf-check

# Check SPF
./spf-check --ip 192.0.2.1 --sender user@example.com

# With custom HELO
./spf-check --ip 192.0.2.1 --sender user@example.com --helo mail.example.com

# Show why: the daemon's log lines (PermError cause, ignored SPF terms, overrides)
./spf-check --ip 192.0.2.1 --sender user@example.com --verbose
```

### domain-check

Verify that domains have MX records pointing to expected servers:

```bash
# Create symlink
ln -s postfix-spf-policy domain-check

# Check domains against expected MX IPs
./domain-check --ip 192.0.2.1 example.com example.org

# Check domains from file
./domain-check --ip 192.0.2.1 --domains-file /etc/postfix/local-domains.txt

# Check domains from MySQL config
./domain-check --ip 192.0.2.1 --sql-config /etc/postfix/mysql-virtual-domains.cf

# Check against expected MX hostname
./domain-check --mx mail.example.com --domains-file domains.txt
```

## Postfix MySQL Configuration

The `domains_database_config` option accepts Postfix-style MySQL configuration files:

```
# /etc/postfix/mysql-virtual-domains.cf
user = postfix
password = secret
hosts = localhost
dbname = mail
query = SELECT domain FROM virtual_domains WHERE active = 1
```

## Example Configuration

```ini
# Network
listen_address = 127.0.0.1
listen_port = 10033

# Cache
cache_max_size = 10000
cache_ttl = 300

# DNS
dns_timeout = 10

# Local domains (choose one)
# domains_database_config = /etc/postfix/mysql-virtual-domains.cf
domains_file = /etc/postfix/local-domains.txt

# Whitelist
spf_whitelist_file = /etc/postfix/spf-whitelist.txt

# Reload domains every 5 minutes
reload_interval = 300

# Enable tolerant heuristics
tolerant_mode = yes

# Logging
log_level = info
pidfile = /var/run/postfix-spf-policy.pid
```

## systemd Service

An example systemd service file is included in the installer. Manual setup:

```ini
# /etc/systemd/system/postfix-spf-policy.service
[Unit]
Description=Postfix SPF Policy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/postfix-spf-policy --config /etc/postfix/postfix-spf-policy.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable postfix-spf-policy
sudo systemctl start postfix-spf-policy
```

## Building

```bash
# Build binary
make build

# Build installer package
make installer

# Run tests
make test

# Check for dependency updates
make check-updates

# Clean build artifacts
make clean
```

## Project Structure

```
postfix-spf-policy/
├── cmd/postfix-spf-policy/    # Main application
│   ├── main.go                # Entry point and CLI tools
│   └── version.go             # Version constant
├── internal/
│   ├── cache/                 # SPF result caching
│   ├── config/                # Configuration parsing
│   ├── domains/               # Local domain loading
│   ├── evaluator/             # SPF evaluation with heuristics
│   ├── policy/                # Postfix policy protocol handler
│   └── whitelist/             # SPF whitelist management
├── examples/
│   └── postfix-spf-policy.conf  # Example configuration
├── installer-pkg/             # Installer resources
├── vendor/                    # Vendored dependencies
├── go.mod                     # Go module definition
├── go.sum                     # Dependency checksums
└── Makefile                   # Build automation
```

## License

MIT License

## Acknowledgments

- [blitiri.com.ar/go/spf](https://blitiri.com.ar/go/spf) - SPF implementation
- [hashicorp/golang-lru](https://github.com/hashicorp/golang-lru) - LRU cache
- [go-sql-driver/mysql](https://github.com/go-sql-driver/mysql) - MySQL driver
