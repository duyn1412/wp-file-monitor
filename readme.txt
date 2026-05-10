=== WP File Monitor ===
Contributors: duynguyen
Tags: security, file monitor, malware, integrity, file changes
Requires at least: 5.8
Tested up to: 6.7
Stable tag: 1.2.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

File integrity monitoring for WordPress — detects modified, new, and deleted files with email & Telegram alerts.

== Description ==

WP File Monitor continuously monitors your WordPress installation for unauthorized file changes. It detects new, modified, and deleted files in your themes, plugins, and mu-plugins directories, and alerts you immediately via email or Telegram.

**Key Features:**

* **Core File Verification** — Compares your WordPress core files against official checksums from WordPress.org API
* **wp-content Monitoring** — Tracks changes in themes, plugins, and mu-plugins directories
* **Malware Pattern Detection** — Scans new/modified files for suspicious code patterns (eval, base64_decode, shell_exec, etc.)
* **Real-time Sentinel** — Detects changes on plugin/theme install, update, or delete events
* **Critical File Quick-Check** — Monitors wp-login.php, wp-config.php, and other high-risk files on every admin page load
* **Email Alerts** — Send notifications to one or multiple email addresses
* **Telegram Alerts** — Optional Telegram bot notifications for instant mobile alerts
* **Scan History** — View detailed logs of all scan results with expandable file details
* **Scheduled Scans** — Automatic scanning every 1, 6, 12, or 24 hours via WP-Cron
* **Manual Scan** — One-click scan from the admin dashboard
* **REST API** — Programmatic access to scan status and trigger scans

**Hub Connection (Optional):**

Connect to a central monitoring hub to track multiple WordPress sites from a single dashboard. Hub connection is completely optional and disabled by default.

== Third-Party Services ==

This plugin connects to the following external services:

= WordPress.org Checksums API =
* **Purpose:** Verify the integrity of WordPress core files by comparing local file hashes against official checksums.
* **When:** During scheduled or manual scans when "Core Verification" is enabled in settings.
* **Data sent:** WordPress version and locale.
* **Endpoint:** `https://api.wordpress.org/core/checksums/1.0/`
* **Privacy Policy:** [WordPress.org Privacy Policy](https://wordpress.org/about/privacy/)

= Telegram Bot API (Optional) =
* **Purpose:** Send file change alert notifications via Telegram.
* **When:** Only when Telegram Bot Token and Chat ID are configured in settings.
* **Data sent:** Alert message containing site name, changed file paths, and timestamps.
* **Endpoint:** `https://api.telegram.org/bot{token}/sendMessage`
* **Privacy Policy:** [Telegram Privacy Policy](https://telegram.org/privacy)

= Central Monitoring Hub (Optional) =
* **Purpose:** Send scan results to a central dashboard for multi-site monitoring.
* **When:** Only when Hub URL is configured in settings. Disabled by default.
* **Data sent:** Scan results including file counts, change details, WordPress version, and PHP version.
* **Endpoint:** User-configured Hub URL.
* **Privacy Policy:** Determined by the Hub operator.

== Installation ==

1. Upload the `wp-file-monitor` directory to `/wp-content/plugins/`
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to **Tools → File Monitor** to configure settings
4. Click **Scan Now** to run your first baseline scan
5. Configure email and/or Telegram alerts
6. Set your preferred scan interval

== Frequently Asked Questions ==

= Does this plugin slow down my site? =

No. File scans run in the background via WP-Cron and do not affect front-end performance. The Sentinel quick-check on admin pages takes less than 10ms.

= What file types does it monitor? =

By default, it monitors PHP files only. You can add additional extensions (js, css, etc.) in the settings.

= Can I monitor multiple sites? =

Yes. Use the optional Hub Connection feature to send scan results to a central monitoring dashboard.

= Does it work with caching plugins? =

Yes. The plugin uses WP-Cron for scheduling and does not interfere with page caching.

= What happens on the first scan? =

The first scan creates a baseline snapshot of all monitored files. Subsequent scans compare against this baseline to detect changes.

== Screenshots ==

1. Dashboard showing file monitor status cards and last scan details
2. Settings page with email, Telegram, and scan configuration
3. Scan history log with expandable file change details

== Changelog ==

= 1.2.0 =
* Added: REST API integrity endpoint for external verification
* Added: Self-integrity check class
* Added: Third-party services disclosure (WordPress.org compliance)
* Added: readme.txt for WordPress.org submission
* Improved: Security hardening and output escaping

= 1.1.0 =
* Added: Sentinel real-time file change detection
* Added: Critical file quick-check on admin page load
* Added: Multi-email support (comma-separated)
* Added: Send Test Email button
* Added: Scan history with expandable file details
* Added: Hub Connection for central monitoring

= 1.0.0 =
* Initial release
* File integrity monitoring for wp-content
* Core file verification against WordPress.org checksums
* Email and Telegram alerts
* Malware pattern detection
* Scheduled and manual scans

== Upgrade Notice ==

= 1.2.0 =
Adds WordPress.org compliance improvements and REST API integrity endpoint. Recommended update for all users.
