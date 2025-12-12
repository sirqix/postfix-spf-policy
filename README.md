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
git clone https://github.com/youruser/postfix-spf-policy.git
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

When enabled, tolerant mode applies these heuristics for SPF failures:

1. **PTR Validation**: If the sending IP has a PTR record, and that PTR domain passes SPF, allow the message
2. **ESP Detection**: Recognize shared infrastructure from known Email Service Providers
3. **Include Chain**: Check if SPF records reference other domains that might authorize the sender

Accepts: `yes`, `no`, `true`, `false`, `1`, `0`, `on`, `off`

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
