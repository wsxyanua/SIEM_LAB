# Mini SIEM + SOAR for SSH Brute Force

This project tails SSH auth logs, stores events in SQLite, and auto-blocks brute-force IPs using ipset + iptables (nft-compatible). Includes a CLI to inspect, unblock, and a systemd service.

## Features
- Detects sshd failed logins and invalid users from `/var/log/auth.log` (Debian/Ubuntu/Kali) and `/var/log/secure` (RHEL/CentOS)
- Threshold-based blocking (e.g., 5 failures in 3 minutes => block for 24h)
- ipset blacklist with iptables DROP rule
- Whitelist with defaults for local/private networks (configurable via YAML)
- SQLite storage of events and actions for auditing
- **NEW**: Comprehensive logging system with file rotation
- **NEW**: Web dashboard with authentication and real-time updates
- **NEW**: REST API endpoints for external integration
- **NEW**: Email and Slack notifications for security events
- **NEW**: GeoIP lookup for IP addresses with threat assessment
- **NEW**: Rate-limited notifications to prevent spam
- **NEW**: User authentication and session management
- **NEW**: Real-time WebSocket updates for dashboard
- **NEW**: Mobile-responsive web interface
- CLI to view events/actions, list blocked IPs, unblock
- systemd service to run detector at boot and ensure firewall setup

## Quick Start

```bash
# 1) Install requirements
sudo apt-get update -y
sudo apt-get install -y ipset iptables python3 python3-venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2) Configure (optional): edit /etc/mini_siem/config.yaml
# Copy template: cp mini_siem/config_template.yaml /etc/mini_siem/config.yaml
# If not present, sensible defaults are used.

# 3) Setup notifications (optional)
export SIEM_SMTP_SERVER="smtp.gmail.com"
export SIEM_SMTP_USER="your-email@gmail.com"
export SIEM_SMTP_PASSWORD="your-app-password"
export SIEM_NOTIFICATION_EMAILS="admin@yourdomain.com"
export SIEM_SLACK_WEBHOOK="https://hooks.slack.com/services/..."

# 4) One-time firewall setup (also handled on service start)
sudo ./scripts/setup.sh --ensure-firewall

# 5) Test notifications (optional)
python3 scripts/test_notifications.py

# 6) Run detector in foreground
python -m mini_siem

# 7) Use CLI (examples)
python -m mini_siem.cli events --limit 20
python -m mini_siem.cli actions --limit 20
python -m mini_siem.cli blocked
python -m mini_siem.cli unblock 1.2.3.4

# 8) Start web dashboard (optional)
python -m mini_siem.dashboard_cli --host 0.0.0.0 --port 5000
# Then open http://localhost:5000 in your browser
# Default login: admin / admin123 (CHANGE IMMEDIATELY!)

# 9) Install systemd service (optional)
sudo ./scripts/setup.sh --install-service
sudo systemctl enable --now mini-siem.service
```

## Config
Default location: `/etc/mini_siem/config.yaml`. Example:

```yaml
# thresholds
failures_threshold: 5          # number of failed attempts
window_seconds: 180            # within this many seconds
block_seconds: 86400           # block duration (24h)

# paths
auth_logs:
  - /var/log/auth.log
  - /var/log/secure

# whitelist (CIDRs or IPs)
whitelist:
  - 127.0.0.1/32
  - ::1/128
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
```

## API Endpoints
- `GET /api/stats` - System statistics
- `GET /api/events?limit=50` - Recent security events
- `GET /api/actions?limit=50` - Recent actions taken
- `GET /api/blocked` - List of currently blocked IPs
- `POST /api/unblock/<ip>` - Unblock a specific IP

## Log Files
- `~/.local/share/mini_siem/logs/siem.log` - Main system logs
- `~/.local/share/mini_siem/logs/security.log` - Security events only
- `~/.local/share/mini_siem/logs/performance.log` - Performance metrics

## Environment Variables for Notifications

```bash
# Email notifications
export SIEM_SMTP_SERVER="smtp.gmail.com"
export SIEM_SMTP_PORT="587"
export SIEM_SMTP_USER="your-email@gmail.com"
export SIEM_SMTP_PASSWORD="your-app-password"
export SIEM_FROM_EMAIL="siem@yourdomain.com"
export SIEM_NOTIFICATION_EMAILS="admin@yourdomain.com,security@yourdomain.com"

# Slack notifications
export SIEM_SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
export SIEM_SLACK_CHANNEL="#security"

# GeoIP (optional, for more accurate location data)
export IPSTACK_API_KEY="your-ipstack-api-key"

# Web dashboard security
export SIEM_SECRET_KEY="your-secret-key-for-sessions"
export SIEM_DEFAULT_PASSWORD="your-secure-default-password"
```

## Notes
- Requires root privileges to manage ipset/iptables; run detector under systemd which runs ensure-setup with sudo/root.
- Uses iptables (nft backend on modern systems) for broad compatibility.
- SQLite DB file is stored at `~/.local/share/mini_siem/mini_siem.db` by default.
- Log format assumptions are based on OpenSSH `sshd` standard messages.
- Web dashboard auto-refreshes every 30 seconds with real-time WebSocket updates.
- Notifications are rate-limited (5 minutes between same type notifications).
- GeoIP lookups are cached for 1 hour to reduce API calls.
- **SECURITY**: Change default admin password immediately after first login.
- User accounts are stored in `~/.local/share/mini_siem/users.json`.
- Web dashboard requires authentication for all endpoints.
