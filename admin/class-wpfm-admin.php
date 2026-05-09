<?php
/**
 * WPFM Admin — settings page, dashboard widget, and scan-now button.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPFM_Admin {

    /**
     * Initialize admin hooks.
     */
    public static function init() {
        add_action( 'admin_menu', [ __CLASS__, 'add_menu' ] );
        add_action( 'admin_init', [ __CLASS__, 'register_settings' ] );
        add_action( 'admin_enqueue_scripts', [ __CLASS__, 'enqueue_assets' ] );
        add_action( 'wp_ajax_wpfm_run_scan', [ __CLASS__, 'ajax_run_scan' ] );
        add_action( 'wp_ajax_wpfm_reset_snapshot', [ __CLASS__, 'ajax_reset_snapshot' ] );

        // Add action link on Plugins page
        add_filter( 'plugin_action_links_' . WPFM_BASENAME, [ __CLASS__, 'action_links' ] );
    }

    /**
     * Add admin menu page.
     */
    public static function add_menu() {
        add_management_page(
            __( 'File Monitor', 'wp-file-monitor' ),
            __( 'File Monitor', 'wp-file-monitor' ),
            'manage_options',
            'wp-file-monitor',
            [ __CLASS__, 'render_page' ]
        );
    }

    /**
     * Plugin action links.
     */
    public static function action_links( $links ) {
        $settings_link = '<a href="' . admin_url( 'tools.php?page=wp-file-monitor' ) . '">'
                       . __( 'Dashboard', 'wp-file-monitor' ) . '</a>';
        array_unshift( $links, $settings_link );
        return $links;
    }

    /**
     * Register settings.
     */
    public static function register_settings() {
        register_setting( 'wpfm_settings_group', 'wpfm_settings', [
            'sanitize_callback' => [ __CLASS__, 'sanitize_settings' ],
        ] );
    }

    /**
     * Sanitize settings.
     */
    public static function sanitize_settings( $input ) {
        $clean = [];

        $clean['email']            = sanitize_email( $input['email'] ?? '' );
        $clean['telegram_token']   = sanitize_text_field( $input['telegram_token'] ?? '' );
        $clean['telegram_chat_id'] = sanitize_text_field( $input['telegram_chat_id'] ?? '' );
        $clean['scan_interval']    = sanitize_text_field( $input['scan_interval'] ?? 'wpfm_six_hours' );
        $clean['file_extensions']  = sanitize_text_field( $input['file_extensions'] ?? 'php' );
        $clean['max_depth']        = absint( $input['max_depth'] ?? 6 );
        $clean['verify_core']      = ! empty( $input['verify_core'] );

        $clean['excluded_patterns'] = sanitize_textarea_field( $input['excluded_patterns'] ?? '' );

        $clean['monitored_dirs'] = [
            'themes'      => ! empty( $input['monitored_dirs']['themes'] ),
            'plugins'     => ! empty( $input['monitored_dirs']['plugins'] ),
            'mu-plugins'  => ! empty( $input['monitored_dirs']['mu-plugins'] ),
        ];

        // Reschedule cron if interval changed
        $old = get_option( 'wpfm_settings', [] );
        if ( ( $old['scan_interval'] ?? '' ) !== $clean['scan_interval'] ) {
            WPFM_Cron::reschedule( $clean['scan_interval'] );
        }

        // Clear core checksum cache if verify_core toggled
        if ( ( $old['verify_core'] ?? true ) !== $clean['verify_core'] ) {
            WPFM_Core_Verify::clear_cache();
        }

        // Hub connection
        $clean['hub_url']         = esc_url_raw( $input['hub_url'] ?? '' );
        $clean['hub_license_key'] = sanitize_text_field( $input['hub_license_key'] ?? '' );
        $clean['hub_site_key']    = sanitize_text_field( $input['hub_site_key'] ?? '' );

        // Auto-register with Hub if URL provided and no site_key yet (or license key changed)
        $old_license = $old['hub_license_key'] ?? '';
        if ( ! empty( $clean['hub_url'] ) &&
             ( empty( $clean['hub_site_key'] ) || $clean['hub_license_key'] !== $old_license )
        ) {
            $registered_key = WPFM_Heartbeat::register( $clean['hub_url'], $clean['hub_license_key'] );
            if ( $registered_key ) {
                $clean['hub_site_key'] = $registered_key;
            }
        }

        return $clean;
    }

    /**
     * Enqueue admin assets.
     */
    public static function enqueue_assets( $hook ) {
        if ( $hook !== 'tools_page_wp-file-monitor' ) {
            return;
        }
        wp_enqueue_style( 'wpfm-admin', WPFM_URL . 'assets/css/admin.css', [], WPFM_VERSION );
        wp_enqueue_script( 'wpfm-admin', WPFM_URL . 'assets/js/admin.js', [ 'jquery' ], WPFM_VERSION, true );
        wp_localize_script( 'wpfm-admin', 'wpfm', [
            'ajax_url' => admin_url( 'admin-ajax.php' ),
            'nonce'    => wp_create_nonce( 'wpfm_nonce' ),
        ] );
    }

    /**
     * AJAX: Run scan now.
     */
    public static function ajax_run_scan() {
        check_ajax_referer( 'wpfm_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Unauthorized' );
        }

        $scanner = new WPFM_Scanner();
        $result  = $scanner->run();

        wp_send_json_success( $result );
    }

    /**
     * AJAX: Reset snapshot (re-baseline).
     */
    public static function ajax_reset_snapshot() {
        check_ajax_referer( 'wpfm_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Unauthorized' );
        }

        delete_option( 'wpfm_snapshot' );
        delete_option( 'wpfm_last_scan' );
        delete_option( 'wpfm_last_details' );
        WPFM_Core_Verify::clear_cache();

        wp_send_json_success( [ 'message' => 'Snapshot & core cache reset. Next scan will create a new baseline.' ] );
    }

    /**
     * Render admin page.
     */
    public static function render_page() {
        $settings     = get_option( 'wpfm_settings', [] );
        $last_scan    = get_option( 'wpfm_last_scan', [] );
        $last_details = get_option( 'wpfm_last_details', [] );
        $scan_log     = get_option( 'wpfm_scan_log', [] );
        $next_scan    = wp_next_scheduled( 'wpfm_scheduled_scan' );

        $intervals = [
            'wpfm_hourly'       => __( 'Every Hour', 'wp-file-monitor' ),
            'wpfm_six_hours'    => __( 'Every 6 Hours', 'wp-file-monitor' ),
            'wpfm_twelve_hours' => __( 'Every 12 Hours', 'wp-file-monitor' ),
            'wpfm_daily'        => __( 'Once Daily', 'wp-file-monitor' ),
        ];

        $dirs = [
            'themes'      => __( 'wp-content/themes/', 'wp-file-monitor' ),
            'plugins'     => __( 'wp-content/plugins/', 'wp-file-monitor' ),
            'mu-plugins'  => __( 'wp-content/mu-plugins/', 'wp-file-monitor' ),
        ];

        // Determine core status
        $core_changes = $last_scan['core_changes'] ?? 0;
        $core_class   = $core_changes > 0 ? 'wpfm-card--alert' : 'wpfm-card--ok';
        $core_value   = $core_changes > 0
            ? "⚠ {$core_changes} issue(s)"
            : '✅ Intact';

        // Determine changes status
        $total_changes = $last_scan['total_changes'] ?? 0;
        $changes_class = $total_changes > 0 ? 'wpfm-card--alert' : 'wpfm-card--ok';
        ?>
        <div class="wrap wpfm-wrap">
            <h1>
                <span class="dashicons dashicons-shield-alt" style="font-size:1.3em;margin-right:8px;vertical-align:middle"></span>
                <?php _e( 'WP File Monitor', 'wp-file-monitor' ); ?>
            </h1>

            <!-- Status Cards -->
            <div class="wpfm-status-grid">
                <div class="wpfm-card">
                    <div class="wpfm-card__label"><?php _e( 'Files Monitored', 'wp-file-monitor' ); ?></div>
                    <div class="wpfm-card__value"><?php echo esc_html( $last_scan['file_count'] ?? '—' ); ?></div>
                </div>
                <div class="wpfm-card <?php echo esc_attr( $core_class ); ?>">
                    <div class="wpfm-card__label"><?php _e( 'Core Integrity', 'wp-file-monitor' ); ?></div>
                    <div class="wpfm-card__value wpfm-card__value--sm"><?php echo $core_value; ?></div>
                </div>
                <div class="wpfm-card">
                    <div class="wpfm-card__label"><?php _e( 'Last Scan', 'wp-file-monitor' ); ?></div>
                    <div class="wpfm-card__value wpfm-card__value--sm">
                        <?php
                        if ( $last_scan ) {
                            echo esc_html( $last_scan['time'] );
                            if ( ! empty( $last_scan['elapsed'] ) ) {
                                echo ' <small>(' . esc_html( $last_scan['elapsed'] ) . 's)</small>';
                            }
                        } else {
                            echo '—';
                        }
                        ?>
                    </div>
                </div>
                <div class="wpfm-card <?php echo esc_attr( $changes_class ); ?>">
                    <div class="wpfm-card__label"><?php _e( 'Last Changes', 'wp-file-monitor' ); ?></div>
                    <div class="wpfm-card__value">
                        <?php echo esc_html( $total_changes ); ?>
                        <?php if ( ( $last_scan['suspicious'] ?? 0 ) > 0 ) : ?>
                            <span style="color:#d63638;font-size:14px">
                                (🚨 <?php echo esc_html( $last_scan['suspicious'] ); ?> suspicious)
                            </span>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Next scan info -->
            <?php if ( $next_scan ) : ?>
                <p class="description" style="margin-bottom:16px">
                    <?php printf(
                        __( 'Next scheduled scan: %s', 'wp-file-monitor' ),
                        '<strong>' . esc_html( date_i18n( 'Y-m-d H:i:s', $next_scan ) ) . '</strong>'
                    ); ?>
                </p>
            <?php endif; ?>

            <!-- Actions -->
            <div class="wpfm-actions">
                <button id="wpfm-scan-now" class="button button-primary button-hero">
                    <span class="dashicons dashicons-search" style="margin-top:4px"></span>
                    <?php _e( 'Scan Now', 'wp-file-monitor' ); ?>
                </button>
                <button id="wpfm-reset" class="button button-secondary">
                    <span class="dashicons dashicons-image-rotate" style="margin-top:4px"></span>
                    <?php _e( 'Reset Baseline', 'wp-file-monitor' ); ?>
                </button>
                <span id="wpfm-status-msg" class="wpfm-msg"></span>
            </div>

            <div id="wpfm-scan-result" class="wpfm-result" style="display:none"></div>

            <?php
            // ── Last Scan Details (persistent) ──
            $core_detail = $last_details['core'] ?? [];
            $changes_detail = $last_details['changes'] ?? [];
            $suspicious_detail = $last_details['suspicious'] ?? [];
            $has_details = ! empty( $core_detail ) || ! empty( $changes_detail ) || ! empty( $suspicious_detail );

            if ( $has_details && ! empty( $last_scan ) && ! ( $last_scan['is_first_run'] ?? false ) ) :
                $core_modified = $core_detail['modified'] ?? [];
                $core_unknown  = $core_detail['unknown'] ?? [];
                $core_missing  = $core_detail['missing'] ?? [];
                $core_verified = $core_detail['verified'] ?? 0;
                $core_has_issues = ! empty( $core_modified ) || ! empty( $core_unknown ) || ! empty( $core_missing );

                $new_files     = $changes_detail['new_files'] ?? [];
                $mod_files     = $changes_detail['modified_files'] ?? [];
                $del_files     = $changes_detail['deleted_files'] ?? [];
                $content_has   = ! empty( $new_files ) || ! empty( $mod_files ) || ! empty( $del_files );
            ?>

            <div class="wpfm-details">
                <h3><?php _e( 'Last Scan Details', 'wp-file-monitor' ); ?> <small>(<?php echo esc_html( $last_scan['time'] ?? '' ); ?>)</small></h3>

                <?php // ── Core Integrity ── ?>
                <?php if ( ! ( $core_detail['api_error'] ?? false ) ) : ?>
                    <?php if ( $core_has_issues ) : ?>
                        <div class="wpfm-detail-section wpfm-detail-section--alert">
                            <h4>🔒 <?php _e( 'Core Integrity Issues', 'wp-file-monitor' ); ?></h4>

                            <?php if ( ! empty( $core_modified ) ) : ?>
                                <h5>⚠ <?php printf( __( 'Modified Core Files (%d)', 'wp-file-monitor' ), count( $core_modified ) ); ?></h5>
                                <table class="widefat striped">
                                    <thead><tr><th><?php _e( 'File', 'wp-file-monitor' ); ?></th><th><?php _e( 'Expected Hash', 'wp-file-monitor' ); ?></th><th><?php _e( 'Actual Hash', 'wp-file-monitor' ); ?></th></tr></thead>
                                    <tbody>
                                    <?php foreach ( $core_modified as $f ) : ?>
                                        <tr>
                                            <td><code><?php echo esc_html( $f['path'] ); ?></code></td>
                                            <td><small><?php echo esc_html( substr( $f['expected_hash'], 0, 12 ) . '…' ); ?></small></td>
                                            <td><small style="color:#d63638"><?php echo esc_html( substr( $f['actual_hash'], 0, 12 ) . '…' ); ?></small></td>
                                        </tr>
                                    <?php endforeach; ?>
                                    </tbody>
                                </table>
                            <?php endif; ?>

                            <?php if ( ! empty( $core_unknown ) ) : ?>
                                <h5>🆕 <?php printf( __( 'Unknown Files in Core Directories (%d)', 'wp-file-monitor' ), count( $core_unknown ) ); ?></h5>
                                <table class="widefat striped">
                                    <thead><tr><th><?php _e( 'File', 'wp-file-monitor' ); ?></th><th><?php _e( 'Size', 'wp-file-monitor' ); ?></th><th><?php _e( 'Modified', 'wp-file-monitor' ); ?></th></tr></thead>
                                    <tbody>
                                    <?php foreach ( $core_unknown as $f ) : ?>
                                        <tr>
                                            <td><code><?php echo esc_html( $f['path'] ); ?></code></td>
                                            <td><?php echo esc_html( size_format( $f['size'] ) ); ?></td>
                                            <td><?php echo esc_html( $f['mtime'] ); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                    </tbody>
                                </table>
                            <?php endif; ?>

                            <?php if ( ! empty( $core_missing ) ) : ?>
                                <h5>🗑 <?php printf( __( 'Missing Core Files (%d)', 'wp-file-monitor' ), count( $core_missing ) ); ?></h5>
                                <ul>
                                    <?php foreach ( $core_missing as $f ) : ?>
                                        <li><code><?php echo esc_html( $f['path'] ); ?></code></li>
                                    <?php endforeach; ?>
                                </ul>
                            <?php endif; ?>
                        </div>
                    <?php else : ?>
                        <p class="wpfm-detail-ok">🔒 <?php printf( __( 'Core: ✅ %d PHP files verified — all intact', 'wp-file-monitor' ), $core_verified ); ?></p>
                    <?php endif; ?>
                <?php elseif ( $core_detail['api_error'] ?? false ) : ?>
                    <p class="wpfm-detail-warn">🔒 <?php _e( 'Core: ⚠ Checksum API was unavailable during last scan', 'wp-file-monitor' ); ?></p>
                <?php endif; ?>

                <?php // ── wp-content Changes ── ?>
                <?php if ( $content_has ) : ?>
                    <div class="wpfm-detail-section">
                        <h4>📁 <?php _e( 'wp-content Changes', 'wp-file-monitor' ); ?></h4>

                        <?php if ( ! empty( $new_files ) ) : ?>
                            <h5>🆕 <?php printf( __( 'New Files (%d)', 'wp-file-monitor' ), count( $new_files ) ); ?></h5>
                            <table class="widefat striped">
                                <thead><tr><th><?php _e( 'File', 'wp-file-monitor' ); ?></th><th><?php _e( 'Size', 'wp-file-monitor' ); ?></th></tr></thead>
                                <tbody>
                                <?php foreach ( $new_files as $f ) : ?>
                                    <tr>
                                        <td><code><?php echo esc_html( $f['path'] ); ?></code></td>
                                        <td><?php echo esc_html( size_format( $f['size'] ) ); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                                </tbody>
                            </table>
                        <?php endif; ?>

                        <?php if ( ! empty( $mod_files ) ) : ?>
                            <h5>✏️ <?php printf( __( 'Modified Files (%d)', 'wp-file-monitor' ), count( $mod_files ) ); ?></h5>
                            <table class="widefat striped">
                                <thead><tr><th><?php _e( 'File', 'wp-file-monitor' ); ?></th><th><?php _e( 'Before', 'wp-file-monitor' ); ?></th><th><?php _e( 'After', 'wp-file-monitor' ); ?></th></tr></thead>
                                <tbody>
                                <?php foreach ( $mod_files as $f ) : ?>
                                    <tr>
                                        <td><code><?php echo esc_html( $f['path'] ); ?></code></td>
                                        <td><small><?php echo esc_html( $f['old_time'] . ' (' . size_format( $f['old_size'] ) . ')' ); ?></small></td>
                                        <td><small><?php echo esc_html( $f['new_time'] . ' (' . size_format( $f['new_size'] ) . ')' ); ?></small></td>
                                    </tr>
                                <?php endforeach; ?>
                                </tbody>
                            </table>
                        <?php endif; ?>

                        <?php if ( ! empty( $del_files ) ) : ?>
                            <h5>🗑 <?php printf( __( 'Deleted Files (%d)', 'wp-file-monitor' ), count( $del_files ) ); ?></h5>
                            <ul>
                                <?php foreach ( $del_files as $f ) : ?>
                                    <li><code><?php echo esc_html( $f['path'] ); ?></code></li>
                                <?php endforeach; ?>
                            </ul>
                        <?php endif; ?>
                    </div>
                <?php elseif ( ! empty( $last_scan ) ) : ?>
                    <p class="wpfm-detail-ok">📁 <?php _e( 'wp-content: ✅ No changes detected', 'wp-file-monitor' ); ?></p>
                <?php endif; ?>

                <?php // ── Suspicious Patterns ── ?>
                <?php if ( ! empty( $suspicious_detail ) ) : ?>
                    <div class="wpfm-detail-section wpfm-detail-section--danger">
                        <h4>🚨 <?php printf( __( 'Suspicious Patterns (%d files)', 'wp-file-monitor' ), count( $suspicious_detail ) ); ?></h4>
                        <table class="widefat striped">
                            <thead><tr><th><?php _e( 'File', 'wp-file-monitor' ); ?></th><th><?php _e( 'Patterns Found', 'wp-file-monitor' ); ?></th></tr></thead>
                            <tbody>
                            <?php foreach ( $suspicious_detail as $f ) : ?>
                                <tr>
                                    <td><code><?php echo esc_html( $f['path'] ); ?></code></td>
                                    <td>
                                        <?php foreach ( $f['patterns'] as $p ) : ?>
                                            <span class="wpfm-pattern-tag">→ <?php echo esc_html( $p ); ?></span><br>
                                        <?php endforeach; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>

            <?php endif; ?>

            <hr>

            <!-- Settings Form -->
            <form method="post" action="options.php">
                <?php settings_fields( 'wpfm_settings_group' ); ?>

                <h2><?php _e( 'Settings', 'wp-file-monitor' ); ?></h2>

                <table class="form-table">
                    <tr>
                        <th><?php _e( 'Alert Email', 'wp-file-monitor' ); ?></th>
                        <td>
                            <input type="email" name="wpfm_settings[email]"
                                   value="<?php echo esc_attr( $settings['email'] ?? '' ); ?>"
                                   class="regular-text" />
                        </td>
                    </tr>
                    <tr>
                        <th><?php _e( 'Scan Interval', 'wp-file-monitor' ); ?></th>
                        <td>
                            <select name="wpfm_settings[scan_interval]">
                                <?php foreach ( $intervals as $val => $label ) : ?>
                                    <option value="<?php echo esc_attr( $val ); ?>"
                                        <?php selected( $settings['scan_interval'] ?? '', $val ); ?>>
                                        <?php echo esc_html( $label ); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th><?php _e( 'Core Verification', 'wp-file-monitor' ); ?></th>
                        <td>
                            <label>
                                <input type="checkbox"
                                       name="wpfm_settings[verify_core]"
                                       value="1"
                                    <?php checked( $settings['verify_core'] ?? true ); ?> />
                                <?php _e( 'Verify core files against WordPress.org checksums (cached 24h)', 'wp-file-monitor' ); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th><?php _e( 'wp-content Directories', 'wp-file-monitor' ); ?></th>
                        <td>
                            <?php foreach ( $dirs as $key => $label ) : ?>
                                <label style="display:block;margin-bottom:6px">
                                    <input type="checkbox"
                                           name="wpfm_settings[monitored_dirs][<?php echo esc_attr( $key ); ?>]"
                                           value="1"
                                        <?php checked( $settings['monitored_dirs'][ $key ] ?? false ); ?> />
                                    <?php echo esc_html( $label ); ?>
                                </label>
                            <?php endforeach; ?>
                        </td>
                    </tr>
                    <tr>
                        <th><?php _e( 'File Extensions', 'wp-file-monitor' ); ?></th>
                        <td>
                            <input type="text" name="wpfm_settings[file_extensions]"
                                   value="<?php echo esc_attr( $settings['file_extensions'] ?? 'php' ); ?>"
                                   class="regular-text" />
                            <p class="description"><?php _e( 'Comma-separated. Default: php', 'wp-file-monitor' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th><?php _e( 'Max Scan Depth', 'wp-file-monitor' ); ?></th>
                        <td>
                            <input type="number" name="wpfm_settings[max_depth]"
                                   value="<?php echo esc_attr( $settings['max_depth'] ?? 6 ); ?>"
                                   min="1" max="20" style="width:80px" />
                        </td>
                    </tr>
                    <tr>
                        <th><?php _e( 'Excluded Patterns', 'wp-file-monitor' ); ?></th>
                        <td>
                            <textarea name="wpfm_settings[excluded_patterns]" rows="8"
                                      class="large-text code"><?php echo esc_textarea( $settings['excluded_patterns'] ?? '' ); ?></textarea>
                            <p class="description"><?php _e( 'One pattern per line. Paths matching any pattern will be ignored.', 'wp-file-monitor' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th><?php _e( 'Telegram Bot Token', 'wp-file-monitor' ); ?></th>
                        <td>
                            <input type="text" name="wpfm_settings[telegram_token]"
                                   value="<?php echo esc_attr( $settings['telegram_token'] ?? '' ); ?>"
                                   class="regular-text" placeholder="<?php _e( 'Leave empty to disable', 'wp-file-monitor' ); ?>" />
                        </td>
                    </tr>
                    <tr>
                        <th><?php _e( 'Telegram Chat ID', 'wp-file-monitor' ); ?></th>
                        <td>
                            <input type="text" name="wpfm_settings[telegram_chat_id]"
                                   value="<?php echo esc_attr( $settings['telegram_chat_id'] ?? '' ); ?>"
                                   class="regular-text" />
                        </td>
                    </tr>
                    <tr>
                        <th colspan="2"><hr><h3 style="margin:0"><?php _e( '🔗 Hub Connection (Pro)', 'wp-file-monitor' ); ?></h3></th>
                    </tr>
                    <tr>
                        <th><?php _e( 'Hub URL', 'wp-file-monitor' ); ?></th>
                        <td>
                            <input type="url" name="wpfm_settings[hub_url]"
                                   value="<?php echo esc_attr( $settings['hub_url'] ?? '' ); ?>"
                                   class="regular-text"
                                   placeholder="https://wptopd3v.com" />
                            <p class="description"><?php _e( 'URL of the central monitoring hub. Leave empty to disable.', 'wp-file-monitor' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th><?php _e( 'License Key', 'wp-file-monitor' ); ?></th>
                        <td>
                            <input type="text" name="wpfm_settings[hub_license_key]"
                                   value="<?php echo esc_attr( $settings['hub_license_key'] ?? '' ); ?>"
                                   class="regular-text"
                                   placeholder="WPFM-XXXX-XXXX-XXXX" />
                            <p class="description"><?php _e( 'Enter your Pro license key. Free users can leave this empty.', 'wp-file-monitor' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th><?php _e( 'Site Key', 'wp-file-monitor' ); ?></th>
                        <td>
                            <?php $site_key = $settings['hub_site_key'] ?? ''; ?>
                            <?php if ( $site_key ) : ?>
                                <code style="padding:6px 12px;background:#edfaef;border-radius:4px">
                                    ✅ <?php echo esc_html( substr( $site_key, 0, 8 ) . '…' . substr( $site_key, -4 ) ); ?>
                                </code>
                                <p class="description"><?php _e( 'Connected. Heartbeats are sent after each scan.', 'wp-file-monitor' ); ?></p>
                            <?php else : ?>
                                <span style="color:#888"><?php _e( 'Not registered. Enter Hub URL and save to auto-register.', 'wp-file-monitor' ); ?></span>
                            <?php endif; ?>
                            <input type="hidden" name="wpfm_settings[hub_site_key]"
                                   value="<?php echo esc_attr( $site_key ); ?>" />
                        </td>
                    </tr>
                </table>

                <?php submit_button( __( 'Save Settings', 'wp-file-monitor' ) ); ?>
            </form>

            <hr>

            <!-- Scan Log -->
            <h2><?php _e( 'Recent Scan History', 'wp-file-monitor' ); ?></h2>
            <?php if ( ! empty( $scan_log ) ) : ?>
                <table class="widefat striped wpfm-log-table">
                    <thead>
                        <tr>
                            <th><?php _e( 'Time', 'wp-file-monitor' ); ?></th>
                            <th><?php _e( 'Files', 'wp-file-monitor' ); ?></th>
                            <th><?php _e( 'Core', 'wp-file-monitor' ); ?></th>
                            <th><?php _e( 'New', 'wp-file-monitor' ); ?></th>
                            <th><?php _e( 'Modified', 'wp-file-monitor' ); ?></th>
                            <th><?php _e( 'Deleted', 'wp-file-monitor' ); ?></th>
                            <th><?php _e( 'Suspicious', 'wp-file-monitor' ); ?></th>
                            <th><?php _e( 'Total', 'wp-file-monitor' ); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ( array_reverse( $scan_log ) as $entry ) : ?>
                            <?php
                            $row_class = '';
                            if ( ( $entry['suspicious'] ?? 0 ) > 0 ) {
                                $row_class = 'wpfm-row--danger';
                            } elseif ( ( $entry['changes'] ?? 0 ) > 0 ) {
                                $row_class = 'wpfm-row--alert';
                            }
                            ?>
                            <tr class="<?php echo esc_attr( $row_class ); ?>">
                                <td><?php echo esc_html( $entry['time'] ); ?></td>
                                <td><?php echo esc_html( $entry['files'] ); ?></td>
                                <td><?php echo esc_html( $entry['core'] ?? 0 ); ?></td>
                                <td><?php echo esc_html( $entry['new'] ?? 0 ); ?></td>
                                <td><?php echo esc_html( $entry['modified'] ?? 0 ); ?></td>
                                <td><?php echo esc_html( $entry['deleted'] ?? 0 ); ?></td>
                                <td>
                                    <?php if ( ( $entry['suspicious'] ?? 0 ) > 0 ) : ?>
                                        <strong style="color:#d63638">🚨 <?php echo esc_html( $entry['suspicious'] ); ?></strong>
                                    <?php else : ?>
                                        0
                                    <?php endif; ?>
                                </td>
                                <td><strong><?php echo esc_html( $entry['changes'] ); ?></strong></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else : ?>
                <p class="description"><?php _e( 'No scans recorded yet. Click "Scan Now" to run the first scan.', 'wp-file-monitor' ); ?></p>
            <?php endif; ?>
        </div>
        <?php
    }
}
