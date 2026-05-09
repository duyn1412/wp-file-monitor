/**
 * WP File Monitor — Admin JS
 */
(function ($) {
    'use strict';

    const $scanBtn = $('#wpfm-scan-now');
    const $resetBtn = $('#wpfm-reset');
    const $msg = $('#wpfm-status-msg');
    const $result = $('#wpfm-scan-result');

    // Scan Now
    $scanBtn.on('click', function () {
        $scanBtn.prop('disabled', true).text('Scanning…');
        $msg.text('').removeClass('wpfm-msg--ok wpfm-msg--error');
        $result.hide();

        $.post(wpfm.ajax_url, {
            action: 'wpfm_run_scan',
            nonce: wpfm.nonce
        })
        .done(function (res) {
            if (res.success) {
                const d = res.data;
                $msg.text('Scan complete! (' + d.elapsed_seconds + 's)').addClass('wpfm-msg--ok');
                renderResult(d);
                setTimeout(function () { location.reload(); }, 3000);
            } else {
                $msg.text('Scan failed: ' + (res.data || 'Unknown error')).addClass('wpfm-msg--error');
            }
        })
        .fail(function () {
            $msg.text('Request failed. Check console.').addClass('wpfm-msg--error');
        })
        .always(function () {
            $scanBtn.prop('disabled', false).html(
                '<span class="dashicons dashicons-search" style="margin-top:4px"></span> Scan Now'
            );
        });
    });

    // Reset Baseline
    $resetBtn.on('click', function () {
        if (!confirm('Reset the file snapshot and core cache? The next scan will create a new baseline.')) {
            return;
        }
        $.post(wpfm.ajax_url, {
            action: 'wpfm_reset_snapshot',
            nonce: wpfm.nonce
        })
        .done(function (res) {
            if (res.success) {
                $msg.text(res.data.message).addClass('wpfm-msg--ok');
            }
        });
    });

    // Render scan result in terminal style
    function renderResult(data) {
        let html = '<span class="info">Scan completed at ' + data.scan_time + ' (' + data.elapsed_seconds + 's)</span>\n';
        html += '<span class="info">wp-content files monitored: ' + data.file_count + '</span>\n\n';

        if (data.is_first_run) {
            html += '<span class="info">✅ First run — baseline snapshot created.</span>\n';
            if (data.core && !data.core.api_error) {
                html += '<span class="info">🔒 Core: ' + data.core.verified + ' PHP files verified against WordPress.org</span>\n';
            }
            $result.html(html).show();
            return;
        }

        // ── Core Integrity ──
        if (data.core && !data.core.api_error) {
            var coreIssues = (data.core.modified || []).length
                           + (data.core.unknown || []).length
                           + (data.core.missing || []).length;

            if (coreIssues > 0) {
                html += '<span class="suspicious">═══ 🔒 CORE INTEGRITY — ' + coreIssues + ' issue(s) ═══</span>\n';

                if (data.core.modified && data.core.modified.length) {
                    data.core.modified.forEach(function (f) {
                        html += '<span class="suspicious">  ⚠ MODIFIED: ' + f.path + '</span>\n';
                        html += '    Expected: ' + f.expected_hash + '\n';
                        html += '    Actual:   ' + f.actual_hash + '\n';
                    });
                }
                if (data.core.unknown && data.core.unknown.length) {
                    data.core.unknown.forEach(function (f) {
                        html += '<span class="new">  🆕 UNKNOWN: ' + f.path + ' (' + f.mtime + ')</span>\n';
                    });
                }
                if (data.core.missing && data.core.missing.length) {
                    data.core.missing.forEach(function (f) {
                        html += '<span class="deleted">  🗑 MISSING: ' + f.path + '</span>\n';
                    });
                }
                html += '\n';
            } else {
                html += '<span class="info">🔒 Core: ✅ ' + data.core.verified + ' PHP files verified — all intact</span>\n\n';
            }
        } else if (data.core && data.core.api_error) {
            html += '<span class="modified">🔒 Core: ⚠ Checksum API unavailable</span>\n\n';
        }

        // ── wp-content changes ──
        var c = data.changes || {};

        if (c.new_files && c.new_files.length) {
            html += '<span class="new">═══ 🆕 NEW FILES (' + c.new_files.length + ') ═══</span>\n';
            c.new_files.forEach(function (f) {
                html += '<span class="new">  + ' + f.path + '</span>\n';
            });
            html += '\n';
        }

        if (c.modified_files && c.modified_files.length) {
            html += '<span class="modified">═══ ✏️ MODIFIED FILES (' + c.modified_files.length + ') ═══</span>\n';
            c.modified_files.forEach(function (f) {
                html += '<span class="modified">  ~ ' + f.path + '</span>\n';
                html += '    Before: ' + f.old_time + ' (' + f.old_size + ' bytes)\n';
                html += '    After:  ' + f.new_time + ' (' + f.new_size + ' bytes)\n';
            });
            html += '\n';
        }

        if (c.deleted_files && c.deleted_files.length) {
            html += '<span class="deleted">═══ 🗑 DELETED FILES (' + c.deleted_files.length + ') ═══</span>\n';
            c.deleted_files.forEach(function (f) {
                html += '<span class="deleted">  - ' + f.path + '</span>\n';
            });
            html += '\n';
        }

        // ── Suspicious patterns ──
        if (data.suspicious && data.suspicious.length) {
            html += '<span class="suspicious">═══ 🚨 SUSPICIOUS PATTERNS (' + data.suspicious.length + ') ═══</span>\n';
            data.suspicious.forEach(function (f) {
                html += '<span class="suspicious">  ⚠ ' + f.path + '</span>\n';
                f.patterns.forEach(function (p) {
                    html += '    → ' + p + '\n';
                });
            });
            html += '\n';
        }

        if (data.total_changes === 0 && (!data.suspicious || !data.suspicious.length)) {
            html += '<span class="info">✅ No changes detected. All files intact.</span>\n';
        }

        $result.html(html).show();
    }

    // Test Email
    $('#wpfm-test-email').on('click', function () {
        var $btn = $(this);
        var $msg2 = $('#wpfm-test-email-msg');
        $btn.prop('disabled', true);
        $msg2.text('Sending…').css('color', '#666');

        $.post(wpfm.ajax_url, {
            action: 'wpfm_test_email',
            nonce: wpfm.nonce
        })
        .done(function (res) {
            if (res.success) {
                $msg2.text('✅ ' + res.data.message).css('color', '#00a32a');
            } else {
                $msg2.text('❌ ' + (res.data.message || 'Failed')).css('color', '#d63638');
            }
        })
        .fail(function () {
            $msg2.text('❌ Request failed').css('color', '#d63638');
        })
        .always(function () {
            $btn.prop('disabled', false);
        });
    });

    // Toggle Scan History Details
    $(document).on('click', '.wpfm-toggle-details', function (e) {
        e.preventDefault();
        var target = $(this).data('target');
        var $row = $('#' + target);
        $row.toggle();
        $(this).text($row.is(':visible') ? 'Hide ▴' : 'View ▾');
    });

})(jQuery);
