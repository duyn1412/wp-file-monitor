<?php
/**
 * WPFM Heartbeat — sends scan results to the central Hub API.
 *
 * After each scan, sends a POST request to the hub with:
 *   - site_key, file_count, total_changes, core_changes, suspicious
 *   - scan details (core, changes, suspicious files)
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPFM_Heartbeat {

    /**
     * Send heartbeat to the Hub API after a scan completes.
     *
     * @param array $result Scan result from WPFM_Scanner::run().
     */
    public static function send( $result ) {
        $settings = get_option( 'wpfm_settings', [] );

        $hub_url  = $settings['hub_url'] ?? '';
        $site_key = $settings['hub_site_key'] ?? '';

        // Hub not configured → skip
        if ( empty( $hub_url ) || empty( $site_key ) ) {
            return false;
        }

        $endpoint = trailingslashit( $hub_url ) . 'wp-json/wpfm-hub/v1/heartbeat';

        $payload = [
            'site_key'      => $site_key,
            'file_count'    => $result['file_count'] ?? 0,
            'total_changes' => $result['total_changes'] ?? 0,
            'core_changes'  => count( $result['core']['modified'] ?? [] )
                             + count( $result['core']['unknown'] ?? [] )
                             + count( $result['core']['missing'] ?? [] ),
            'suspicious'    => count( $result['suspicious'] ?? [] ),
            'scan_time'     => $result['scan_time'] ?? current_time( 'mysql' ),
            'elapsed'       => $result['elapsed_seconds'] ?? 0,
            'wp_version'    => get_bloginfo( 'version' ),
            'php_version'   => phpversion(),
            'details'       => [
                'core'       => $result['core'] ?? [],
                'changes'    => $result['changes'] ?? [],
                'suspicious' => $result['suspicious'] ?? [],
            ],
        ];

        $response = wp_remote_post( $endpoint, [
            'timeout' => 15,
            'headers' => [ 'Content-Type' => 'application/json' ],
            'body'    => wp_json_encode( $payload ),
        ] );

        if ( is_wp_error( $response ) ) {
            // Log error but don't block scan
            error_log( '[WPFM] Heartbeat failed: ' . $response->get_error_message() );
            return false;
        }

        $code = wp_remote_retrieve_response_code( $response );
        return $code === 200;
    }

    /**
     * Register this site with the Hub API.
     *
     * @param string $hub_url Hub site URL.
     * @param string $license_key Optional license key.
     * @return string|false Site key on success, false on failure.
     */
    public static function register( $hub_url, $license_key = '' ) {
        $endpoint = trailingslashit( $hub_url ) . 'wp-json/wpfm-hub/v1/register';

        $response = wp_remote_post( $endpoint, [
            'timeout' => 15,
            'headers' => [ 'Content-Type' => 'application/json' ],
            'body'    => wp_json_encode( [
                'site_url'    => home_url(),
                'site_name'   => get_bloginfo( 'name' ),
                'license_key' => $license_key,
                'wp_version'  => get_bloginfo( 'version' ),
                'php_version' => phpversion(),
            ] ),
        ] );

        if ( is_wp_error( $response ) ) {
            return false;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( ! empty( $body['site_key'] ) ) {
            // Save site key to settings
            $settings = get_option( 'wpfm_settings', [] );
            $settings['hub_site_key'] = $body['site_key'];
            $settings['hub_url']      = $hub_url;
            update_option( 'wpfm_settings', $settings );

            return $body['site_key'];
        }

        return false;
    }
}
