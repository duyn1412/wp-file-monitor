# WP File Monitor

🔒 **Lightweight WordPress file integrity monitoring** — detects modified, new, and deleted PHP files. Sends email & Telegram alerts.

## Features

- **Core Verification** — Verifies WordPress core files against official checksums from WordPress.org API
- **wp-content Monitoring** — Snapshot-based change detection for themes, plugins, and mu-plugins
- **Malware Pattern Detection** — Scans new/modified files for suspicious code patterns (eval, base64_decode, shell_exec, etc.)
- **Email & Telegram Alerts** — Instant notifications when changes are detected
- **Admin Dashboard** — Status cards, scan history, and detailed file change reports
- **REST API** — Remote monitoring via `GET /wpfm/v1/status` and `POST /wpfm/v1/scan`
- **WP-Cron Scheduling** — Automated scans every hour, 6h, 12h, or daily
- **Lightweight** — No bloat, no firewall, just file monitoring. Runs in < 3 seconds on shared hosting.

## Installation

1. Download or clone this repository
2. Upload the `wp-file-monitor` folder to `wp-content/plugins/`
3. Activate the plugin in **Plugins → Installed Plugins**
4. Go to **Tools → File Monitor** to configure and run your first scan

## Quick Start

1. **Activate** → default settings monitor themes + plugins + mu-plugins (PHP files only)
2. **Click "Scan Now"** → creates baseline snapshot + verifies core files
3. **Configure alerts** → set your email and (optionally) Telegram bot token
4. **Done** — the plugin scans automatically every 6 hours

## How It Works

### Layer 1: Core Verification (Checksum API)
Fetches official MD5 checksums from `api.wordpress.org` and compares every core PHP file against the known-good hash. Detects:
- **Modified core files** — hash mismatch (possible injection)
- **Unknown files** — PHP files in `wp-admin/` or `wp-includes/` not in official checksums (possible backdoor)
- **Missing core files** — files that should exist but don't

### Layer 2: wp-content Snapshot
Takes an MD5 snapshot of all PHP files in themes, plugins, and mu-plugins. On each scan, compares with the previous snapshot to detect:
- **New files** added since last scan
- **Modified files** with changed content
- **Deleted files** removed since last scan

### Layer 3: Malware Pattern Detection
Scans only **new and modified** files (not the entire codebase) for suspicious patterns:
- `eval()`, `base64_decode()`, `preg_replace /e`
- `shell_exec()`, `exec()`, `system()`, `passthru()`
- `file_put_contents()` writing PHP files
- User input + eval combinations

## Screenshots

### Admin Dashboard
- **Status Cards**: Files monitored, Core integrity, Last scan, Changes detected
- **Scan Now**: One-click manual scan with terminal-style output
- **Detailed Reports**: Tables showing exactly which files changed and how
- **Scan History**: Log of all past scans with change counts

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Alert Email | admin email | Where to send alerts |
| Scan Interval | Every 6 Hours | Hourly / 6h / 12h / Daily |
| Core Verification | Enabled | Verify against WordPress.org checksums |
| Monitored Dirs | themes, plugins, mu-plugins | Toggle each directory |
| File Extensions | php | Comma-separated (add js,css if needed) |
| Max Scan Depth | 6 | Recursive depth for wp-content |
| Excluded Patterns | uploads, cache, wflogs | One pattern per line |
| Telegram Bot Token | empty | Leave empty to disable |
| Telegram Chat ID | empty | Your Telegram chat ID |

## REST API

Requires `manage_options` capability (admin authentication).

```bash
# Get monitor status
curl -u "admin:APP_PASSWORD" https://yoursite.com/wp-json/wpfm/v1/status

# Trigger manual scan
curl -X POST -u "admin:APP_PASSWORD" https://yoursite.com/wp-json/wpfm/v1/scan
```

## Requirements

- WordPress 5.8+
- PHP 7.4+

## License

GPLv2 or later

## Author

**Duy Nguyen** — [wptopd3v.com](https://wptopd3v.com)
