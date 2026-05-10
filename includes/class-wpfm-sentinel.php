<?php
/**
 * WPFM Sentinel — real-time detection of file changes.
 *
 * Two mechanisms:
 * 1. WordPress event hooks — triggers scan on plugin/theme install/update/delete
 * 2. Quick integrity check — on every admin page load, checks critical files only
 *
 * This ensures changes are detected within minutes, not hours.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPFM_Sentinel {

    /**
     * List of critical files to quick-check on every admin load.
     * These are the files most likely to be targeted by hackers.
     */
    private static $critical_files = [
        'wp-login.php',
        'wp-config.php',
        'index.php',
        'wp-settings.php',
        'wp-blog-header.php',
        'wp-load.php',
    ];

    /**
     * Option key for storing quick-check hashes.
     */
    const HASH_KEY = 'wpfm_sentinel_hashes';

    /**
     * Throttle key — don't send multiple alerts within this window.
     */
    const THROTTLE_KEY = 'wpfm_sentinel_throttle';
    const THROTTLE_TTL = 300; // 5 minutes

    /**
     * Transient key to mark legitimate WordPress-initiated changes.
     * When this transient exists, the Scanner knows changes are expected
     * and should auto-baseline instead of sending critical alerts.
     */
    const LEGITIMATE_KEY = 'wpfm_legitimate_change';
    const LEGITIMATE_TTL = 600; // 10 minutes window

    /**
     * Initialize hooks.
     */
    public static function init() {
        // WordPress events — trigger immediate scan
        add_action( 'upgrader_process_complete', [ __CLASS__, 'on_upgrade' ], 10, 2 );
        add_action( 'activated_plugin', [ __CLASS__, 'on_plugin_change' ] );
        add_action( 'deactivated_plugin', [ __CLASS__, 'on_plugin_change' ] );
        add_action( 'deleted_plugin', [ __CLASS__, 'on_plugin_change' ] );
        add_action( 'switch_theme', [ __CLASS__, 'on_theme_change' ] );

        // Track plugin/theme installs via WordPress admin
        add_action( 'upgrader_process_complete', [ __CLASS__, 'on_install' ], 5, 2 );

        // Quick integrity check on admin page load (lightweight)
        if ( is_admin() ) {
            add_action( 'admin_init', [ __CLASS__, 'quick_check' ] );
        }
    }

    /**
     * Mark a change as legitimate (initiated through WordPress admin).
     *
     * @param string $reason Human-readable reason for the change.
     */
    private static function mark_legitimate( $reason ) {
        $current = get_transient( self::LEGITIMATE_KEY );
        if ( ! is_array( $current ) ) {
            $current = [];
        }

        $current[] = [
            'reason' => $reason,
            'time'   => current_time( 'mysql' ),
            'user'   => wp_get_current_user()->user_login ?? 'system',
        ];

        set_transient( self::LEGITIMATE_KEY, $current, self::LEGITIMATE_TTL );
    }

    /**
     * Check if current changes are marked as legitimate.
     *
     * @return array|false Array of reasons if legitimate, false otherwise.
     */
    public static function get_legitimate_context() {
        $context = get_transient( self::LEGITIMATE_KEY );
        return is_array( $context ) && ! empty( $context ) ? $context : false;
    }

    /**
     * Clear the legitimate change marker.
     */
    public static function clear_legitimate() {
        delete_transient( self::LEGITIMATE_KEY );
    }

    /**
     * On plugin/theme upgrade — mark legitimate + trigger scan.
     */
    public static function on_upgrade( $upgrader, $options ) {
        $type = $options['type'] ?? '';
        if ( in_array( $type, [ 'plugin', 'theme', 'core' ], true ) ) {
            self::mark_legitimate( 'WordPress ' . $type . ' upgrade via admin' );
            self::trigger_scan( 'WordPress ' . $type . ' upgrade detected' );
        }
    }

    /**
     * On plugin/theme install — mark legitimate.
     */
    public static function on_install( $upgrader, $options ) {
        $action = $options['action'] ?? '';
        $type   = $options['type'] ?? '';
        if ( 'install' === $action ) {
            self::mark_legitimate( 'WordPress ' . $type . ' installed via admin' );
        }
    }

    /**
     * On plugin activate/deactivate/delete — mark legitimate + trigger scan.
     */
    public static function on_plugin_change( $plugin = '' ) {
        // Don't trigger for our own plugin
        if ( strpos( $plugin, 'wp-file-monitor' ) !== false ) {
            return;
        }
        self::mark_legitimate( 'Plugin change: ' . basename( dirname( $plugin ) ) );
        self::trigger_scan( 'Plugin change: ' . $plugin );
    }

    /**
     * On theme switch — mark legitimate + trigger scan.
     */
    public static function on_theme_change() {
        self::mark_legitimate( 'Theme switch via admin' );
        self::trigger_scan( 'Theme switch detected' );
    }

    /**
     * Quick integrity check — runs on every admin page load.
     * Only checks a few critical root files. Very fast (< 10ms).
     */
    public static function quick_check() {
        $abspath = untrailingslashit( ABSPATH );
        $saved   = get_option( self::HASH_KEY, [] );

        // First run — save hashes, don't alert
        if ( empty( $saved ) ) {
            self::save_hashes();
            return;
        }

        $changed = [];

        foreach ( self::$critical_files as $file ) {
            $full = $abspath . '/' . $file;
            if ( ! file_exists( $full ) ) {
                continue;
            }

            $current_hash = md5_file( $full );
            $saved_hash   = $saved[ $file ] ?? null;

            if ( $saved_hash !== null && $saved_hash !== $current_hash ) {
                $changed[] = [
                    'file'     => $file,
                    'old_hash' => $saved_hash,
                    'new_hash' => $current_hash,
                    'mtime'    => date( 'Y-m-d H:i:s', filemtime( $full ) ),
                    'size'     => filesize( $full ),
                ];
            }
        }

        if ( ! empty( $changed ) ) {
            // Throttle — don't send duplicate alerts
            if ( get_transient( self::THROTTLE_KEY ) ) {
                return;
            }

            set_transient( self::THROTTLE_KEY, true, self::THROTTLE_TTL );
            self::send_immediate_alert( $changed );
            self::save_hashes(); // Update hashes after alert
        }
    }

    /**
     * Send immediate email + Telegram alert for critical file changes.
     */
    private static function send_immediate_alert( $changed ) {
        $settings  = get_option( 'wpfm_settings', [] );
        $site_name = get_bloginfo( 'name' );
        $site_url  = home_url();

        $subject = "[WPFM] 🚨 CRITICAL: " . count( $changed ) . " core file(s) modified on {$site_name}!";

        $body  = "⚠ IMMEDIATE ALERT — Critical file change detected!\n\n";
        $body .= "Site: {$site_name} ({$site_url})\n";
        $body .= "Time: " . current_time( 'mysql' ) . "\n\n";
        $body .= "Changed files:\n";

        foreach ( $changed as $c ) {
            $body .= "  🔴 {$c['file']}\n";
            $body .= "     Modified: {$c['mtime']}\n";
            $body .= "     Size: {$c['size']} bytes\n";
            $body .= "     Old hash: " . substr( $c['old_hash'], 0, 12 ) . "…\n";
            $body .= "     New hash: " . substr( $c['new_hash'], 0, 12 ) . "…\n\n";
        }

        $body .= "Action: Check your site immediately.\n";
        $body .= "Dashboard: {$site_url}/wp-admin/tools.php?page=wp-file-monitor\n";

        // Email
        $email = $settings['email'] ?? get_option( 'admin_email' );
        if ( ! empty( $email ) ) {
            wp_mail( $email, $subject, $body );
        }

        // Telegram
        $token   = $settings['telegram_token'] ?? '';
        $chat_id = $settings['telegram_chat_id'] ?? '';
        if ( ! empty( $token ) && ! empty( $chat_id ) ) {
            wp_remote_post( "https://api.telegram.org/bot{$token}/sendMessage", [
                'timeout' => 10,
                'body'    => [
                    'chat_id' => $chat_id,
                    'text'    => mb_substr( $subject . "\n\n" . $body, 0, 3500 ),
                ],
            ] );
        }

        // Log
        error_log( '[WPFM Sentinel] Critical file change: ' . implode( ', ', array_column( $changed, 'file' ) ) );
    }

    /**
     * Trigger a full scan (deferred to avoid blocking the current request).
     */
    private static function trigger_scan( $reason ) {
        // Schedule a single event to run the scan in the background
        if ( ! wp_next_scheduled( 'wpfm_sentinel_scan' ) ) {
            wp_schedule_single_event( time() + 30, 'wpfm_sentinel_scan' );
        }

        error_log( '[WPFM Sentinel] Scan triggered: ' . $reason );
    }

    /**
     * Save current hashes of critical files.
     */
    private static function save_hashes() {
        $abspath = untrailingslashit( ABSPATH );
        $hashes  = [];

        foreach ( self::$critical_files as $file ) {
            $full = $abspath . '/' . $file;
            if ( file_exists( $full ) ) {
                $hashes[ $file ] = md5_file( $full );
            }
        }

        update_option( self::HASH_KEY, $hashes, false );
    }
}
