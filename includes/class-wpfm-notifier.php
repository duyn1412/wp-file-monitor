<?php
/**
 * WPFM Notifier — sends email and Telegram alerts with core verify + wp-content changes.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPFM_Notifier {

    private $settings;

    public function __construct() {
        $this->settings = get_option( 'wpfm_settings', [] );
    }

    /**
     * Send notifications for scan results.
     *
     * @param array $result Scan result from WPFM_Scanner::run().
     */
    public function send( $result ) {
        $subject = $this->build_subject( $result );
        $body    = $this->build_body( $result );

        $this->send_email( $subject, $body );
        $this->send_telegram( $subject, $body );
    }

    /**
     * Build email subject.
     */
    private function build_subject( $result ) {
        $site_name = get_bloginfo( 'name' );

        if ( $result['is_first_run'] ) {
            return "[{$site_name}] File Monitor initialized — {$result['file_count']} files indexed";
        }

        $total      = $result['total_changes'];
        $suspicious = count( $result['suspicious'] ?? [] );

        if ( $suspicious > 0 ) {
            return "[{$site_name}] 🚨 {$suspicious} suspicious file(s) + {$total} change(s) detected!";
        }

        if ( $total > 0 ) {
            return "[{$site_name}] ⚠ {$total} file change(s) detected!";
        }

        return "[{$site_name}] File Monitor — scan complete, no changes";
    }

    /**
     * Build notification body.
     */
    private function build_body( $result ) {
        $site_name = get_bloginfo( 'name' );
        $site_url  = home_url();
        $core      = $result['core'] ?? [];
        $changes   = $result['changes'] ?? [];
        $suspicious = $result['suspicious'] ?? [];

        $body = "Hello,\n\n";

        if ( $result['is_first_run'] ) {
            $body .= "File Integrity Monitor has been initialized on {$site_name}.\n";
            $body .= "{$result['file_count']} files indexed as baseline.\n";
            if ( ! empty( $core ) && ! $core['api_error'] ) {
                $body .= "{$core['verified']} core PHP files verified against WordPress.org checksums.\n";
            }
            $body .= "From the next scan onwards, you will receive alerts for any changes.\n";
            $body .= "\n--\nWP File Monitor — {$site_name}";
            return $body;
        }

        $body .= "File changes detected on {$site_name} ({$site_url})\n";
        $body .= "Time: {$result['scan_time']} ({$result['elapsed_seconds']}s)\n\n";

        // ── Core Integrity ──
        if ( ! empty( $core ) && ! $core['api_error'] ) {
            $core_issues = count( $core['modified'] ) + count( $core['unknown'] ) + count( $core['missing'] );

            if ( $core_issues > 0 ) {
                $body .= str_repeat( '=', 50 ) . "\n";
                $body .= "🔒 CORE INTEGRITY — {$core_issues} issue(s)\n";
                $body .= str_repeat( '=', 50 ) . "\n\n";

                if ( ! empty( $core['modified'] ) ) {
                    $body .= "⚠ MODIFIED CORE FILES (" . count( $core['modified'] ) . "):\n";
                    foreach ( $core['modified'] as $f ) {
                        $body .= "  ⚠ {$f['path']} (hash mismatch)\n";
                        $body .= "    Expected: {$f['expected_hash']}\n";
                        $body .= "    Actual:   {$f['actual_hash']}\n";
                    }
                    $body .= "\n";
                }

                if ( ! empty( $core['unknown'] ) ) {
                    $body .= "🆕 UNKNOWN FILES IN CORE (" . count( $core['unknown'] ) . "):\n";
                    foreach ( $core['unknown'] as $f ) {
                        $size = size_format( $f['size'] );
                        $body .= "  🆕 {$f['path']} ({$size}, {$f['mtime']})\n";
                    }
                    $body .= "\n";
                }

                if ( ! empty( $core['missing'] ) ) {
                    $body .= "🗑 MISSING CORE FILES (" . count( $core['missing'] ) . "):\n";
                    foreach ( $core['missing'] as $f ) {
                        $body .= "  🗑 {$f['path']}\n";
                    }
                    $body .= "\n";
                }
            } else {
                $body .= "🔒 Core: ✅ {$core['verified']} PHP files verified — all intact\n\n";
            }
        } elseif ( ! empty( $core['api_error'] ) ) {
            $body .= "🔒 Core: ⚠ Checksum API unavailable — core not verified\n\n";
        }

        // ── wp-content Changes ──
        $content_total = count( $changes['new_files'] )
                       + count( $changes['modified_files'] )
                       + count( $changes['deleted_files'] );

        if ( $content_total > 0 ) {
            $body .= str_repeat( '=', 50 ) . "\n";
            $body .= "📁 WP-CONTENT — {$content_total} change(s)\n";
            $body .= str_repeat( '=', 50 ) . "\n\n";

            if ( ! empty( $changes['new_files'] ) ) {
                $count = count( $changes['new_files'] );
                $body .= "🆕 NEW FILES ({$count}):\n";
                foreach ( $changes['new_files'] as $f ) {
                    $size = size_format( $f['size'] );
                    $body .= "  + {$f['path']} ({$size})\n";
                }
                $body .= "\n";
            }

            if ( ! empty( $changes['modified_files'] ) ) {
                $count = count( $changes['modified_files'] );
                $body .= "✏️ MODIFIED FILES ({$count}):\n";
                foreach ( $changes['modified_files'] as $f ) {
                    $old_size = size_format( $f['old_size'] );
                    $new_size = size_format( $f['new_size'] );
                    $body .= "  ~ {$f['path']}\n";
                    $body .= "    Before: {$f['old_time']} ({$old_size})\n";
                    $body .= "    After:  {$f['new_time']} ({$new_size})\n";
                }
                $body .= "\n";
            }

            if ( ! empty( $changes['deleted_files'] ) ) {
                $count = count( $changes['deleted_files'] );
                $body .= "🗑️ DELETED FILES ({$count}):\n";
                foreach ( $changes['deleted_files'] as $f ) {
                    $body .= "  - {$f['path']}\n";
                }
                $body .= "\n";
            }
        }

        // ── Suspicious Patterns ──
        if ( ! empty( $suspicious ) ) {
            $body .= str_repeat( '=', 50 ) . "\n";
            $body .= "🚨 SUSPICIOUS PATTERNS — " . count( $suspicious ) . " file(s)\n";
            $body .= str_repeat( '=', 50 ) . "\n\n";

            foreach ( $suspicious as $f ) {
                $body .= "  ⚠ {$f['path']}\n";
                foreach ( $f['patterns'] as $p ) {
                    $body .= "    → {$p}\n";
                }
            }
            $body .= "\n";
        }

        // ── Summary ──
        if ( $result['total_changes'] === 0 && empty( $suspicious ) ) {
            $body .= "✅ No changes detected. All files intact.\n";
        } else {
            $body .= "If you did NOT make these changes, check your server immediately!\n";
        }

        $body .= "\n--\nWP File Monitor — {$site_name}";

        return $body;
    }

    /**
     * Send email notification.
     */
    private function send_email( $subject, $body ) {
        $to = $this->settings['email'] ?? get_option( 'admin_email' );
        if ( empty( $to ) ) {
            return false;
        }

        $headers = [ 'Content-Type: text/plain; charset=UTF-8' ];
        return wp_mail( $to, $subject, $body, $headers );
    }

    /**
     * Send Telegram notification.
     */
    private function send_telegram( $subject, $body ) {
        $token   = $this->settings['telegram_token'] ?? '';
        $chat_id = $this->settings['telegram_chat_id'] ?? '';

        if ( empty( $token ) || empty( $chat_id ) ) {
            return false;
        }

        $message = $subject . "\n\n" . mb_substr( $body, 0, 3500 );

        $response = wp_remote_post(
            "https://api.telegram.org/bot{$token}/sendMessage",
            [
                'timeout' => 10,
                'body'    => [
                    'chat_id'    => $chat_id,
                    'text'       => $message,
                    'parse_mode' => 'HTML',
                ],
            ]
        );

        return ! is_wp_error( $response );
    }
}
