<?php
/**
 * WPFM Core Verify — verifies WordPress core files against official checksums.
 *
 * Uses the WordPress.org Checksums API:
 *   https://api.wordpress.org/core/checksums/1.0/?version=X.X&locale=XX
 *
 * Results cached for 24 hours via transient.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPFM_Core_Verify {

    /**
     * Transient key for caching checksums.
     */
    const CACHE_KEY = 'wpfm_core_checksums';

    /**
     * Cache duration: 24 hours.
     */
    const CACHE_TTL = DAY_IN_SECONDS;

    /**
     * Run core verification.
     *
     * @return array {
     *     @type array $modified  Core files with hash mismatch.
     *     @type array $unknown   Files in core dirs not in official checksums.
     *     @type array $missing   Files in checksums but not on disk.
     *     @type int   $verified  Number of files that matched.
     *     @type int   $total     Total files checked.
     *     @type bool  $api_error Whether the API call failed.
     * }
     */
    public function verify() {
        $result = [
            'modified'  => [],
            'unknown'   => [],
            'missing'   => [],
            'verified'  => 0,
            'total'     => 0,
            'api_error' => false,
        ];

        // Get official checksums
        $checksums = $this->get_checksums();

        if ( false === $checksums ) {
            $result['api_error'] = true;
            return $result;
        }

        $result['total'] = count( $checksums );
        $abspath         = untrailingslashit( ABSPATH );

        // 1. Compare each official file against disk
        foreach ( $checksums as $rel_path => $official_hash ) {
            // Only check PHP files (per user requirement)
            $ext = strtolower( pathinfo( $rel_path, PATHINFO_EXTENSION ) );
            if ( $ext !== 'php' ) {
                continue;
            }

            $full_path = $abspath . '/' . $rel_path;

            if ( ! file_exists( $full_path ) ) {
                $result['missing'][] = [
                    'path' => '/' . $rel_path,
                ];
                continue;
            }

            $actual_hash = md5_file( $full_path );

            if ( $actual_hash !== $official_hash ) {
                $result['modified'][] = [
                    'path'          => '/' . $rel_path,
                    'expected_hash' => $official_hash,
                    'actual_hash'   => $actual_hash,
                    'size'          => filesize( $full_path ),
                    'mtime'         => date( 'Y-m-d H:i:s', filemtime( $full_path ) ),
                ];
            } else {
                $result['verified']++;
            }
        }

        // 2. Scan for unknown PHP files in core directories
        $unknown = $this->find_unknown_files( $checksums );
        $result['unknown'] = $unknown;

        return $result;
    }

    /**
     * Get official checksums from WordPress.org API (cached 24h).
     *
     * @return array|false  Associative array { relative_path => md5_hash } or false on failure.
     */
    private function get_checksums() {
        // Check cache
        $cached = get_transient( self::CACHE_KEY );
        if ( false !== $cached ) {
            return $cached;
        }

        // Build API URL
        $version = get_bloginfo( 'version' );
        $locale  = get_locale();
        $url     = sprintf(
            'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s',
            $version,
            $locale
        );

        $response = wp_remote_get( $url, [ 'timeout' => 15 ] );

        if ( is_wp_error( $response ) ) {
            return false;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( empty( $body['checksums'] ) ) {
            // Try with en_US locale as fallback
            if ( $locale !== 'en_US' ) {
                $url_fallback = sprintf(
                    'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=en_US',
                    $version
                );
                $response = wp_remote_get( $url_fallback, [ 'timeout' => 15 ] );
                if ( is_wp_error( $response ) ) {
                    return false;
                }
                $body = json_decode( wp_remote_retrieve_body( $response ), true );
            }

            if ( empty( $body['checksums'] ) ) {
                return false;
            }
        }

        $checksums = $body['checksums'];

        // Cache for 24 hours
        set_transient( self::CACHE_KEY, $checksums, self::CACHE_TTL );

        return $checksums;
    }

    /**
     * Find PHP files in wp-admin/ and wp-includes/ that are NOT in the official checksums.
     * These could be backdoors injected by hackers.
     *
     * @param array $checksums Official checksums.
     * @return array List of unknown files.
     */
    private function find_unknown_files( $checksums ) {
        $unknown = [];
        $abspath = untrailingslashit( ABSPATH );

        $core_dirs = [
            $abspath . '/wp-admin',
            $abspath . '/wp-includes',
        ];

        foreach ( $core_dirs as $dir ) {
            $this->scan_for_unknown( $dir, $abspath, $checksums, $unknown, 0, 3 );
        }

        // Also check root PHP files
        $root_files = glob( $abspath . '/*.php' );
        if ( $root_files ) {
            foreach ( $root_files as $file ) {
                $rel = ltrim( str_replace( $abspath, '', $file ), '/' );
                if ( ! isset( $checksums[ $rel ] ) ) {
                    // Exclude wp-config.php (user-created) and this plugin
                    if ( $rel === 'wp-config.php' ) {
                        continue;
                    }
                    $unknown[] = [
                        'path'  => '/' . $rel,
                        'size'  => filesize( $file ),
                        'mtime' => date( 'Y-m-d H:i:s', filemtime( $file ) ),
                    ];
                }
            }
        }

        return $unknown;
    }

    /**
     * Recursively scan a core directory for unknown PHP files.
     */
    private function scan_for_unknown( $dir, $abspath, $checksums, &$unknown, $depth, $max_depth ) {
        if ( $depth > $max_depth || ! is_dir( $dir ) || ! is_readable( $dir ) ) {
            return;
        }

        $files = @scandir( $dir );
        if ( ! $files ) {
            return;
        }

        foreach ( $files as $file ) {
            if ( $file === '.' || $file === '..' ) {
                continue;
            }

            $full_path = $dir . '/' . $file;
            $rel_path  = ltrim( str_replace( $abspath, '', $full_path ), '/' );

            if ( is_dir( $full_path ) ) {
                $this->scan_for_unknown( $full_path, $abspath, $checksums, $unknown, $depth + 1, $max_depth );
            } elseif ( is_file( $full_path ) ) {
                $ext = strtolower( pathinfo( $file, PATHINFO_EXTENSION ) );
                if ( $ext !== 'php' ) {
                    continue;
                }

                // If this file is NOT in official checksums → unknown/suspicious
                if ( ! isset( $checksums[ $rel_path ] ) ) {
                    $unknown[] = [
                        'path'  => '/' . $rel_path,
                        'size'  => filesize( $full_path ),
                        'mtime' => date( 'Y-m-d H:i:s', filemtime( $full_path ) ),
                    ];
                }
            }
        }
    }

    /**
     * Clear the cached checksums (e.g. after WP update).
     */
    public static function clear_cache() {
        delete_transient( self::CACHE_KEY );
    }
}
