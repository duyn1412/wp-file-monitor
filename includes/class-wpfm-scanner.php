<?php
/**
 * WPFM Scanner — scans wp-content files, integrates core verify, detects malware patterns.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPFM_Scanner {

    private $settings;
    private $wp_root;
    private $excluded_patterns;
    private $allowed_extensions;

    /**
     * Suspicious code patterns — regex for malware detection.
     * Only checked against NEW or MODIFIED PHP files.
     */
    private $malware_patterns = [
        'eval\s*\('                                      => 'eval() — arbitrary code execution',
        'base64_decode\s*\('                              => 'base64_decode() — obfuscated code',
        'preg_replace\s*\(\s*["\'].*\/e["\']'            => 'preg_replace /e modifier — code execution',
        'shell_exec\s*\('                                 => 'shell_exec() — OS command',
        '\bexec\s*\('                                     => 'exec() — OS command',
        '\bsystem\s*\('                                   => 'system() — OS command',
        'passthru\s*\('                                   => 'passthru() — OS command',
        'file_put_contents\s*\(.*(\.php|backdoor|shell)' => 'file_put_contents() — writing PHP files',
        '\$_(GET|POST|REQUEST)\s*\[.*\]\s*\).*eval'      => 'User input + eval — remote code execution',
        'assert\s*\(\s*\$'                                => 'assert() with variable — code injection',
    ];

    public function __construct() {
        $this->settings           = get_option( 'wpfm_settings', [] );
        $this->wp_root            = untrailingslashit( ABSPATH );
        $this->excluded_patterns  = $this->parse_excluded();
        $this->allowed_extensions = $this->parse_extensions();
    }

    /**
     * Run a full scan — core verify + wp-content snapshot + malware check.
     *
     * @return array Complete scan results.
     */
    public function run() {
        $start_time = microtime( true );

        // ── Step 1: Core verification ──
        $core_result = [ 'modified' => [], 'unknown' => [], 'missing' => [], 'verified' => 0, 'total' => 0, 'api_error' => false ];
        $verify_core = $this->settings['verify_core'] ?? true;

        if ( $verify_core ) {
            $core_verifier = new WPFM_Core_Verify();
            $core_result   = $core_verifier->verify();
        }

        // ── Step 2: wp-content snapshot comparison ──
        $old_snapshot = get_option( 'wpfm_snapshot', [] );
        $is_first_run = empty( $old_snapshot );
        $new_snapshot = $this->build_snapshot();

        $content_changes = [
            'new_files'      => [],
            'modified_files' => [],
            'deleted_files'  => [],
        ];

        if ( ! $is_first_run ) {
            $content_changes = $this->compare( $old_snapshot, $new_snapshot );
        }

        // Save new snapshot
        update_option( 'wpfm_snapshot', $new_snapshot, false );

        // ── Step 3: Malware pattern check (new/modified files only) ──
        $suspicious = [];

        // Check wp-content new/modified files
        $files_to_check = [];
        foreach ( $content_changes['new_files'] as $f ) {
            $files_to_check[] = $f['path'];
        }
        foreach ( $content_changes['modified_files'] as $f ) {
            $files_to_check[] = $f['path'];
        }

        // Check core modified/unknown files
        foreach ( $core_result['modified'] as $f ) {
            $files_to_check[] = $f['path'];
        }
        foreach ( $core_result['unknown'] as $f ) {
            $files_to_check[] = $f['path'];
        }

        // Plugin's own directory — exclude from malware scan (contains regex patterns that trigger false positives)
        $self_dir = '/wp-content/plugins/wp-file-monitor/';

        foreach ( $files_to_check as $rel_path ) {
            // Skip plugin's own files
            if ( strpos( $rel_path, $self_dir ) === 0 ) {
                continue;
            }

            $full_path = $this->wp_root . $rel_path;
            if ( is_file( $full_path ) && is_readable( $full_path ) ) {
                $matches = $this->check_malware( $full_path );
                if ( ! empty( $matches ) ) {
                    $suspicious[] = [
                        'path'     => $rel_path,
                        'patterns' => $matches,
                    ];
                }
            }
        }

        // ── Step 4: Build result ──
        $core_changes = count( $core_result['modified'] )
                       + count( $core_result['unknown'] )
                       + count( $core_result['missing'] );

        $content_total = count( $content_changes['new_files'] )
                       + count( $content_changes['modified_files'] )
                       + count( $content_changes['deleted_files'] );

        $total_changes = $core_changes + $content_total;
        $elapsed       = round( microtime( true ) - $start_time, 2 );

        $result = [
            'is_first_run'    => $is_first_run,
            'file_count'      => count( $new_snapshot ),
            'total_changes'   => $total_changes,
            'scan_time'       => current_time( 'mysql' ),
            'elapsed_seconds' => $elapsed,
            'core'            => $core_result,
            'changes'         => $content_changes,
            'suspicious'      => $suspicious,
        ];

        // Update last scan info
        update_option( 'wpfm_last_scan', [
            'time'           => current_time( 'mysql' ),
            'timestamp'      => time(),
            'file_count'     => count( $new_snapshot ),
            'total_changes'  => $total_changes,
            'core_changes'   => $core_changes,
            'content_changes'=> $content_total,
            'suspicious'     => count( $suspicious ),
            'is_first_run'   => $is_first_run,
            'elapsed'        => $elapsed,
        ] );

        // Save full details for admin dashboard display
        update_option( 'wpfm_last_details', [
            'core'       => $core_result,
            'changes'    => $content_changes,
            'suspicious' => $suspicious,
        ], false );

        // ── Step 5: Determine change context ──
        $legitimate_context = WPFM_Sentinel::get_legitimate_context();
        $is_legitimate      = ! empty( $legitimate_context );

        // Append to scan log (keep last 100)
        $log   = get_option( 'wpfm_scan_log', [] );
        $entry = [
            'time'       => current_time( 'mysql' ),
            'files'      => count( $new_snapshot ),
            'changes'    => $total_changes,
            'core'       => $core_changes,
            'new'        => count( $content_changes['new_files'] ),
            'modified'   => count( $content_changes['modified_files'] ),
            'deleted'    => count( $content_changes['deleted_files'] ),
            'suspicious' => count( $suspicious ),
            'context'    => $is_legitimate ? 'admin' : 'external',
        ];

        // Add context reason to log
        if ( $is_legitimate ) {
            $entry['context_reason'] = implode( ', ', array_column( $legitimate_context, 'reason' ) );
        }

        // Store file paths for "View Details" (limit 20 per category to keep size small)
        if ( $total_changes > 0 || count( $suspicious ) > 0 ) {
            $entry['detail_files'] = [
                'new'        => array_slice( array_column( $content_changes['new_files'], 'path' ), 0, 20 ),
                'modified'   => array_slice( array_column( $content_changes['modified_files'], 'path' ), 0, 20 ),
                'deleted'    => array_slice( array_column( $content_changes['deleted_files'], 'path' ), 0, 20 ),
                'core'       => array_slice( array_merge(
                    array_column( $core_result['modified'] ?? [], 'path' ),
                    array_column( $core_result['unknown'] ?? [], 'path' ),
                    array_column( $core_result['missing'] ?? [], 'path' )
                ), 0, 20 ),
                'suspicious' => array_slice( array_column( $suspicious, 'path' ), 0, 20 ),
            ];
        }

        $log[] = $entry;
        if ( count( $log ) > 100 ) {
            $log = array_slice( $log, -100 );
        }
        update_option( 'wpfm_scan_log', $log, false );

        // ── Step 6: Context-aware alerting ──
        // Add context to result
        $result['is_legitimate'] = $is_legitimate;
        $result['context']       = $legitimate_context ?: [];

        if ( $is_legitimate ) {
            // Changes came from WordPress admin (plugin install/update/delete, theme switch)
            // → Log as INFO, auto-baseline, do NOT send critical alert
            WPFM_Sentinel::clear_legitimate();

            // Still log for audit trail
            $context_reasons = array_column( $legitimate_context, 'reason' );
            error_log( '[WPFM] Legitimate change detected: ' . implode( ', ', $context_reasons ) );

            // Send heartbeat to Hub (mark as legitimate)
            $result['alert_level'] = 'info';
            WPFM_Heartbeat::send( $result );
        } else {
            // No WordPress hook fired → changes are SUSPICIOUS
            $result['alert_level'] = 'critical';

            // Send alerts if changes detected or first run
            if ( $total_changes > 0 || count( $suspicious ) > 0 || $is_first_run ) {
                $notifier = new WPFM_Notifier();
                $notifier->send( $result );
            }

            // Send heartbeat to Hub API (if configured)
            WPFM_Heartbeat::send( $result );
        }

        return $result;
    }

    /**
     * Build snapshot of all monitored wp-content files.
     */
    private function build_snapshot() {
        $snapshot = [];
        $dirs     = $this->get_monitored_dirs();

        foreach ( $dirs as $dir_config ) {
            $snapshot = $this->scan_directory(
                $dir_config['path'],
                $snapshot,
                0,
                $dir_config['max_depth']
            );
        }

        return $snapshot;
    }

    /**
     * Recursively scan a directory.
     */
    private function scan_directory( $dir, $snapshot, $depth, $max_depth ) {
        if ( $depth > $max_depth || ! is_dir( $dir ) || ! is_readable( $dir ) ) {
            return $snapshot;
        }

        $files = @scandir( $dir );
        if ( ! $files ) {
            return $snapshot;
        }

        foreach ( $files as $file ) {
            if ( $file === '.' || $file === '..' ) {
                continue;
            }

            $full_path = $dir . '/' . $file;
            $rel_path  = str_replace( $this->wp_root, '', $full_path );

            if ( $this->is_excluded( $rel_path, $file ) ) {
                continue;
            }

            if ( is_dir( $full_path ) ) {
                $snapshot = $this->scan_directory( $full_path, $snapshot, $depth + 1, $max_depth );
            } elseif ( is_file( $full_path ) && is_readable( $full_path ) ) {
                if ( ! $this->is_monitored_file( $file ) ) {
                    continue;
                }

                $snapshot[ $rel_path ] = [
                    'hash'  => md5_file( $full_path ),
                    'mtime' => filemtime( $full_path ),
                    'size'  => filesize( $full_path ),
                ];
            }
        }

        return $snapshot;
    }

    /**
     * Compare old and new snapshots.
     */
    private function compare( $old, $new ) {
        $changes = [
            'new_files'      => [],
            'modified_files' => [],
            'deleted_files'  => [],
        ];

        foreach ( $new as $path => $info ) {
            if ( ! isset( $old[ $path ] ) ) {
                $changes['new_files'][] = [
                    'path' => $path,
                    'size' => $info['size'],
                    'time' => date( 'Y-m-d H:i:s', $info['mtime'] ),
                ];
            } elseif ( $old[ $path ]['hash'] !== $info['hash'] ) {
                $changes['modified_files'][] = [
                    'path'     => $path,
                    'old_time' => date( 'Y-m-d H:i:s', $old[ $path ]['mtime'] ),
                    'new_time' => date( 'Y-m-d H:i:s', $info['mtime'] ),
                    'old_size' => $old[ $path ]['size'],
                    'new_size' => $info['size'],
                ];
            }
        }

        foreach ( $old as $path => $info ) {
            if ( ! isset( $new[ $path ] ) ) {
                $changes['deleted_files'][] = [
                    'path' => $path,
                    'size' => $info['size'],
                    'time' => date( 'Y-m-d H:i:s', $info['mtime'] ),
                ];
            }
        }

        return $changes;
    }

    /**
     * Check a file for malware patterns.
     *
     * @param string $full_path Absolute file path.
     * @return array Matched pattern descriptions.
     */
    private function check_malware( $full_path ) {
        // Skip files larger than 1MB to avoid memory issues
        if ( filesize( $full_path ) > 1048576 ) {
            return [];
        }

        $content = @file_get_contents( $full_path );
        if ( false === $content ) {
            return [];
        }

        $matches = [];
        foreach ( $this->malware_patterns as $regex => $description ) {
            if ( preg_match( '/' . $regex . '/i', $content ) ) {
                $matches[] = $description;
            }
        }

        return $matches;
    }

    /**
     * Get monitored wp-content directories.
     */
    private function get_monitored_dirs() {
        $dirs     = [];
        $settings = $this->settings['monitored_dirs'] ?? [];
        $max_d    = intval( $this->settings['max_depth'] ?? 6 );

        if ( ! empty( $settings['themes'] ) ) {
            $dirs[] = [ 'path' => WP_CONTENT_DIR . '/themes', 'max_depth' => $max_d ];
        }
        if ( ! empty( $settings['plugins'] ) ) {
            $dirs[] = [ 'path' => WP_CONTENT_DIR . '/plugins', 'max_depth' => $max_d ];
        }
        if ( ! empty( $settings['mu-plugins'] ) ) {
            $dirs[] = [ 'path' => WPMU_PLUGIN_DIR, 'max_depth' => $max_d ];
        }

        return $dirs;
    }

    /**
     * Check if a path should be excluded.
     */
    private function is_excluded( $rel_path, $filename ) {
        foreach ( $this->excluded_patterns as $pattern ) {
            if ( strpos( $rel_path, $pattern ) !== false || $filename === $pattern ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a file is a monitored type.
     */
    private function is_monitored_file( $filename ) {
        if ( $filename === '.htaccess' || $filename === 'wp-config.php' ) {
            return true;
        }
        $ext = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );
        return in_array( $ext, $this->allowed_extensions, true );
    }

    /**
     * Parse excluded patterns.
     */
    private function parse_excluded() {
        $raw = $this->settings['excluded_patterns'] ?? '';
        if ( empty( $raw ) ) {
            return [];
        }
        return array_filter( array_map( 'trim', explode( "\n", $raw ) ) );
    }

    /**
     * Parse file extensions (default: php only).
     */
    private function parse_extensions() {
        $raw = $this->settings['file_extensions'] ?? 'php';
        return array_filter( array_map( 'trim', explode( ',', $raw ) ) );
    }
}
