<?php
/**
 * WPFM Self Check — Generates integrity hashes for the plugin's own files.
 *
 * Used by the Hub to verify that wp-file-monitor has not been tampered with.
 * Returns SHA-256 hashes of all plugin PHP files for remote comparison.
 *
 * @since 1.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPFM_Self_Check {

    /**
     * Get integrity data for all plugin files.
     *
     * @return array {
     *     @type string $plugin_version Plugin version.
     *     @type string $wp_version     WordPress version.
     *     @type string $php_version    PHP version.
     *     @type array  $files          Associative array of relative_path => sha256 hash.
     *     @type int    $timestamp      Unix timestamp of when the check ran.
     *     @type int    $file_count     Total number of files checked.
     * }
     */
    public static function get_integrity() {
        $plugin_dir = WPFM_DIR;
        $files      = self::hash_directory( $plugin_dir );

        return [
            'plugin_version' => WPFM_VERSION,
            'wp_version'     => get_bloginfo( 'version' ),
            'php_version'    => phpversion(),
            'files'          => $files,
            'timestamp'      => time(),
            'file_count'     => count( $files ),
        ];
    }

    /**
     * Compute a single combined hash of all plugin files.
     * Useful for quick integrity comparison.
     *
     * @return string SHA-256 hash of concatenated file hashes.
     */
    public static function get_combined_hash() {
        $files = self::hash_directory( WPFM_DIR );

        // Sort by key for deterministic ordering
        ksort( $files );

        // Concatenate all hashes
        $combined = implode( '', $files );

        return hash( 'sha256', $combined );
    }

    /**
     * Recursively hash all PHP, JS, and CSS files in a directory.
     *
     * @param string $dir       Absolute directory path.
     * @param string $base_dir  Base directory for relative path calculation.
     * @return array Associative array of relative_path => sha256 hash.
     */
    private static function hash_directory( $dir, $base_dir = '' ) {
        if ( empty( $base_dir ) ) {
            $base_dir = $dir;
        }

        $hashes = [];
        $items  = @scandir( $dir );

        if ( ! $items ) {
            return $hashes;
        }

        // Extensions to hash
        $extensions = [ 'php', 'js', 'css' ];

        // Directories to skip
        $skip_dirs = [ '.', '..', '.git', '.github', 'node_modules', 'vendor' ];

        foreach ( $items as $item ) {
            if ( in_array( $item, $skip_dirs, true ) ) {
                continue;
            }

            $full_path = $dir . '/' . $item;
            $rel_path  = ltrim( str_replace( $base_dir, '', $full_path ), '/' );

            // Skip the check script itself
            if ( $item === 'check-plugin.sh' ) {
                continue;
            }

            if ( is_dir( $full_path ) ) {
                $hashes = array_merge( $hashes, self::hash_directory( $full_path, $base_dir ) );
            } elseif ( is_file( $full_path ) && is_readable( $full_path ) ) {
                $ext = strtolower( pathinfo( $item, PATHINFO_EXTENSION ) );
                if ( in_array( $ext, $extensions, true ) ) {
                    $hashes[ $rel_path ] = hash_file( 'sha256', $full_path );
                }
            }
        }

        return $hashes;
    }
}
