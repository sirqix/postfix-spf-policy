#!/bin/bash
# postfix-spf-policy installer script
# This script is executed by the makeself archive

set -e

BINARY="postfix-spf-policy"
CONFIG="postfix-spf-policy.conf"
SERVICE="postfix-spf-policy.service"

INSTALL_BIN="/usr/local/bin"
INSTALL_CONF="/etc/postfix"
INSTALL_SERVICE="/etc/systemd/system"

echo "========================================"
echo "  postfix-spf-policy Installer"
echo "========================================"
echo ""

# Check if running as root
if [ "$(id -u)" != "0" ]; then
    echo "ERROR: This installer must be run as root"
    echo "Usage: sudo $0"
    exit 1
fi

# Stop service if running (to avoid "Text file busy" error)
if systemctl is-active --quiet postfix-spf-policy 2>/dev/null; then
    echo "[0/3] Stopping running service..."
    systemctl stop postfix-spf-policy
    RESTART_SERVICE=1
fi

# Install binary
echo "[1/3] Installing binary..."
cp -v "$BINARY" "$INSTALL_BIN/$BINARY"
chmod 755 "$INSTALL_BIN/$BINARY"
echo "      Installed: $INSTALL_BIN/$BINARY"

# Create diagnostic tool symlinks
ln -sf "$BINARY" "$INSTALL_BIN/spf-check"
echo "      Created symlink: $INSTALL_BIN/spf-check -> $BINARY"
ln -sf "$BINARY" "$INSTALL_BIN/domain-check"
echo "      Created symlink: $INSTALL_BIN/domain-check -> $BINARY"

# Install config (only if not exists)
echo ""
echo "[2/3] Installing configuration..."
if [ -f "$INSTALL_CONF/$CONFIG" ]; then
    echo "      SKIPPED: $INSTALL_CONF/$CONFIG already exists"
    echo "      New config saved as: $INSTALL_CONF/${CONFIG}.new"
    cp -v "$CONFIG" "$INSTALL_CONF/${CONFIG}.new"
else
    cp -v "$CONFIG" "$INSTALL_CONF/$CONFIG"
    chmod 644 "$INSTALL_CONF/$CONFIG"
    echo "      Installed: $INSTALL_CONF/$CONFIG"
    echo ""
    echo "      IMPORTANT: Edit the config file to set your domain source:"
    echo "        sudo vim $INSTALL_CONF/$CONFIG"
    echo "        # Uncomment ONE of:"
    echo "        # domains_database_config = /etc/postfix/mysql-virtual-domains.cf"
    echo "        # domains_file = /etc/postfix/local-domains.txt"
fi

# Install systemd service (only if not exists)
echo ""
echo "[3/3] Installing systemd service..."
if [ -f "$INSTALL_SERVICE/$SERVICE" ]; then
    echo "      SKIPPED: $INSTALL_SERVICE/$SERVICE already exists"
    echo "      New service saved as: $INSTALL_SERVICE/${SERVICE}.new"
    cp -v "$SERVICE" "$INSTALL_SERVICE/${SERVICE}.new"
else
    cp -v "$SERVICE" "$INSTALL_SERVICE/$SERVICE"
    chmod 644 "$INSTALL_SERVICE/$SERVICE"
    echo "      Installed: $INSTALL_SERVICE/$SERVICE"

    # Reload systemd
    systemctl daemon-reload
    echo "      Systemd reloaded"
fi

# Restart service if it was running before
if [ "$RESTART_SERVICE" = "1" ]; then
    echo ""
    echo "[4/3] Restarting service..."
    systemctl start postfix-spf-policy
    echo "      Service restarted"
fi

echo ""
echo "========================================"
echo "  Installation Complete!"
echo "========================================"
echo ""
echo "To start/restart the service:"
echo ""
echo "  systemctl restart postfix-spf-policy"
echo ""
echo "To enable on boot:"
echo ""
echo "  systemctl enable postfix-spf-policy"
echo ""
echo "To check status:"
echo ""
echo "  systemctl status postfix-spf-policy"
echo ""
echo "To view logs:"
echo ""
echo "  journalctl -u postfix-spf-policy -f"
echo ""
echo "Don't forget to add to Postfix main.cf:"
echo ""
echo "  smtpd_recipient_restrictions ="
echo "      ..."
echo "      check_policy_service inet:127.0.0.1:10033"
echo "      ..."
echo ""
echo "To test SPF checks from command line:"
echo ""
echo "  spf-check --ip 192.0.2.1 --sender user@example.com"
echo ""
echo "To verify local domains have correct MX records:"
echo ""
echo "  domain-check --ip YOUR_SERVER_IP"
echo ""
