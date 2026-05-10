<?php
/**
 * Plugin Name: WP File Monitor
 * Plugin URI:  https://wptopd3v.com/vibe-plugins/
 * Description: File integrity monitoring for WordPress — detects modified, new, and deleted files. Sends email & Telegram alerts.
 * Version:     1.2.0
 * Author:      Duy Nguyen
 * Author URI:  https://wptopd3v.com
 * License:     GPLv2 or later
 * Text Domain: wp-file-monitor
 * Requires PHP: 7.4
 * Requires at least: 5.8
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// Plugin constants
define( 'WPFM_VERSION', '1.2.0' );
define( 'WPFM_FILE', __FILE__ );
define( 'WPFM_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPFM_URL', plugin_dir_url( __FILE__ ) );
define( 'WPFM_BASENAME', plugin_basename( __FILE__ ) );

// Autoload classes
require_once WPFM_DIR . 'includes/class-wpfm-scanner.php';
require_once WPFM_DIR . 'includes/class-wpfm-core-verify.php';
require_once WPFM_DIR . 'includes/class-wpfm-notifier.php';
require_once WPFM_DIR . 'includes/class-wpfm-heartbeat.php';
require_once WPFM_DIR . 'includes/class-wpfm-sentinel.php';
require_once WPFM_DIR . 'includes/class-wpfm-self-check.php';
require_once WPFM_DIR . 'includes/class-wpfm-cron.php';

if ( is_admin() ) {
    require_once WPFM_DIR . 'admin/class-wpfm-admin.php';
}

/**
 * Main plugin class — singleton.
 */
final class WP_File_Monitor {

    private static $instance = null;

    public static function instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        // Initialize cron
        WPFM_Cron::init();

        // Real-time file change detection
        WPFM_Sentinel::init();

        // Handle sentinel-triggered scan
        add_action( 'wpfm_sentinel_scan', [ $this, 'run_scan' ] );

        // Admin UI
        if ( is_admin() ) {
            WPFM_Admin::init();
        }

        // REST API for remote status
        add_action( 'rest_api_init', [ $this, 'register_rest_routes' ] );
    }

    /**
     * Run a full scan — used by sentinel triggers and cron.
     */
    public function run_scan() {
        $scanner = new WPFM_Scanner();
        $scanner->run();
    }

    /**
     * Plugin activation — schedule cron & create baseline.
     */
    public static function activate() {
        // Set default options
        $defaults = [
            'email'            => get_option( 'admin_email' ),
            'telegram_token'   => '',
            'telegram_chat_id' => '',
            'scan_interval'    => 'wpfm_six_hours',
            'verify_core'      => true,
            'monitored_dirs'   => [
                'themes'     => true,
                'plugins'    => true,
                'mu-plugins' => true,
            ],
            'excluded_patterns' => implode( "\n", [
                '/wp-content/uploads/',
                '/wp-content/cache/',
                '/wp-content/wflogs/',
                '/wp-content/upgrade/',
                '/wp-content/languages/',
                '/wp-content/debug.log',
                '.DS_Store',
                'Thumbs.db',
            ] ),
            'file_extensions'  => 'php',
            'max_depth'        => 6,
        ];

        if ( ! get_option( 'wpfm_settings' ) ) {
            update_option( 'wpfm_settings', $defaults );
        }

        // Schedule cron
        WPFM_Cron::schedule();
    }

    /**
     * Plugin deactivation — clear cron.
     */
    public static function deactivate() {
        WPFM_Cron::unschedule();
    }

    /**
     * Register REST API routes.
     */
    public function register_rest_routes() {
        register_rest_route( 'wpfm/v1', '/status', [
            'methods'             => 'GET',
            'callback'            => [ $this, 'rest_status' ],
            'permission_callback' => function () {
                return current_user_can( 'manage_options' );
            },
        ] );

        register_rest_route( 'wpfm/v1', '/scan', [
            'methods'             => 'POST',
            'callback'            => [ $this, 'rest_trigger_scan' ],
            'permission_callback' => function () {
                return current_user_can( 'manage_options' );
            },
        ] );

        register_rest_route( 'wpfm/v1', '/integrity', [
            'methods'             => 'GET',
            'callback'            => [ $this, 'rest_integrity' ],
            'permission_callback' => [ $this, 'verify_integrity_request' ],
        ] );
    }

    /**
     * REST: Get monitor status.
     */
    public function rest_status() {
        $last_scan = get_option( 'wpfm_last_scan', [] );
        $log       = get_option( 'wpfm_scan_log', [] );

        return rest_ensure_response( [
            'last_scan'      => $last_scan,
            'recent_log'     => array_slice( $log, -20 ),
            'files_monitored'=> $last_scan['file_count'] ?? 0,
            'next_scheduled' => wp_next_scheduled( 'wpfm_scheduled_scan' ),
        ] );
    }

    /**
     * REST: Trigger manual scan.
     */
    public function rest_trigger_scan() {
        $scanner = new WPFM_Scanner();
        $result  = $scanner->run();

        return rest_ensure_response( $result );
    }

    /**
     * REST: Get plugin integrity hashes.
     * Used by the Hub to verify plugin files haven't been tampered with.
     */
    public function rest_integrity() {
        return rest_ensure_response( WPFM_Self_Check::get_integrity() );
    }

    /**
     * Verify integrity request — either admin or valid site_key.
     */
    public function verify_integrity_request( $request ) {
        // Admin can always access
        if ( current_user_can( 'manage_options' ) ) {
            return true;
        }

        // Hub can access with site_key
        $site_key = $request->get_param( 'site_key' );
        if ( empty( $site_key ) ) {
            return false;
        }

        $settings       = get_option( 'wpfm_settings', [] );
        $stored_key     = $settings['hub_site_key'] ?? '';

        return ! empty( $stored_key ) && hash_equals( $stored_key, $site_key );
    }
}

// Hooks
register_activation_hook( WPFM_FILE, [ 'WP_File_Monitor', 'activate' ] );
register_deactivation_hook( WPFM_FILE, [ 'WP_File_Monitor', 'deactivate' ] );

// Boot
add_action( 'plugins_loaded', [ 'WP_File_Monitor', 'instance' ] );
