<?php
/**
 * WPFM Cron — manages WP-Cron scheduling for automated scans.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPFM_Cron {

    const HOOK = 'wpfm_scheduled_scan';

    /**
     * Initialize cron hooks.
     */
    public static function init() {
        add_filter( 'cron_schedules', [ __CLASS__, 'add_schedules' ] );
        add_action( self::HOOK, [ __CLASS__, 'run_scan' ] );
    }

    /**
     * Add custom cron intervals.
     */
    public static function add_schedules( $schedules ) {
        $schedules['wpfm_hourly'] = [
            'interval' => HOUR_IN_SECONDS,
            'display'  => __( 'Every Hour', 'wp-file-monitor' ),
        ];
        $schedules['wpfm_six_hours'] = [
            'interval' => 6 * HOUR_IN_SECONDS,
            'display'  => __( 'Every 6 Hours', 'wp-file-monitor' ),
        ];
        $schedules['wpfm_twelve_hours'] = [
            'interval' => 12 * HOUR_IN_SECONDS,
            'display'  => __( 'Every 12 Hours', 'wp-file-monitor' ),
        ];
        $schedules['wpfm_daily'] = [
            'interval' => DAY_IN_SECONDS,
            'display'  => __( 'Once Daily', 'wp-file-monitor' ),
        ];

        return $schedules;
    }

    /**
     * Schedule the cron event.
     */
    public static function schedule() {
        if ( ! wp_next_scheduled( self::HOOK ) ) {
            $settings = get_option( 'wpfm_settings', [] );
            $interval = $settings['scan_interval'] ?? 'wpfm_six_hours';
            wp_schedule_event( time(), $interval, self::HOOK );
        }
    }

    /**
     * Unschedule (clear) cron event.
     */
    public static function unschedule() {
        $timestamp = wp_next_scheduled( self::HOOK );
        if ( $timestamp ) {
            wp_unschedule_event( $timestamp, self::HOOK );
        }
    }

    /**
     * Reschedule with a new interval.
     */
    public static function reschedule( $interval ) {
        self::unschedule();
        wp_schedule_event( time(), $interval, self::HOOK );
    }

    /**
     * Cron callback — run the scan.
     */
    public static function run_scan() {
        $scanner = new WPFM_Scanner();
        $scanner->run();
    }
}
