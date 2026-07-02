<?php
/**
 * Plugin Name: UXPA Network Performance & Guard
 * Description: Intercepts user enumeration attempts early and prevents cron option data pollution.
 * Version: 1.4
 * Author: Greg Miller for UXPA International
 * Author URI: https://shrinkraylabs.com
 * Text Domain: uxpa-network-performance-guard
 * Network: true
 */

if ( ! defined( 'ABSPATH' ) ) exit;

class UxpaNetworkPerformanceGuard {

    private const SETTINGS_KEY = 'uxpa_network_guard_settings';
    private const LOGS_KEY     = 'uxpa_network_guard_blocked_log';

    private $settings = [];
    private $is_network_active = false;

    public function __construct() {
        $this->check_activation_context();
        $this->load_settings();

        // 1. Intercept user enumeration early (before theme loads, after pluggable is loaded)
        add_action( 'setup_theme', [ $this, 'fast_block_enumeration' ] );

        // 2. Intercept and clean bloated cron options before updates fail
        add_filter( 'pre_update_option_cron', [ $this, 'clean_cron_option_on_update' ] );
        add_filter( 'pre_update_site_option_cron', [ $this, 'clean_cron_option_on_update' ] );

        // 3. Register settings page
        add_action( 'admin_menu', [ $this, 'register_admin_settings_page' ] );
        add_action( 'network_admin_menu', [ $this, 'register_network_settings_page' ] );

        // 4. Action Scheduler optimizations
        add_filter( 'action_scheduler_retention_period', [ $this, 'set_action_scheduler_retention' ] );

        // 5. Reporting and Cron schedules
        add_filter( 'cron_schedules', [ $this, 'register_custom_cron_intervals' ] );
        add_action( 'uxpa_guard_send_scheduled_report', [ $this, 'send_scheduled_report' ] );
        add_action( 'admin_init', [ $this, 'handle_csv_export' ] );
    }

    private function check_activation_context(): void {
        if ( is_multisite() ) {
            $active_plugins = get_site_option( 'active_sitewide_plugins', [] );
            $plugin_path = plugin_basename( __FILE__ );
            if ( isset( $active_plugins[ $plugin_path ] ) ) {
                $this->is_network_active = true;
            }
        }
    }

    private function get_guard_option( string $key, $default = [] ) {
        if ( $this->is_network_active ) {
            return get_site_option( $key, $default );
        } else {
            return get_option( $key, $default );
        }
    }

    private function update_guard_option( string $key, $value ): void {
        if ( $this->is_network_active ) {
            update_site_option( $key, $value );
        } else {
            update_option( $key, $value, false );
        }
    }

    public function register_custom_cron_intervals( $schedules ) {
        if ( ! isset( $schedules['weekly'] ) ) {
            $schedules['weekly'] = [
                'interval' => WEEK_IN_SECONDS,
                'display'  => __( 'Once Weekly', 'uxpa-network-performance-guard' ),
            ];
        }
        if ( ! isset( $schedules['monthly'] ) ) {
            $schedules['monthly'] = [
                'interval' => DAY_IN_SECONDS * 30,
                'display'  => __( 'Once Monthly', 'uxpa-network-performance-guard' ),
            ];
        }
        return $schedules;
    }

    private function load_settings(): void {
        $stored = $this->get_guard_option( self::SETTINGS_KEY, [] );
        if ( ! is_array( $stored ) ) {
            $stored = [];
        }

        $this->settings = [
            'block_author'        => isset( $stored['block_author'] ) ? (bool) $stored['block_author'] : true,
            'block_rest'          => isset( $stored['block_rest'] ) ? (bool) $stored['block_rest'] : true,
            'cron_threshold'      => isset( $stored['cron_threshold'] ) ? (int) $stored['cron_threshold'] : 5,
            'report_admin_user'   => isset( $stored['report_admin_user'] ) ? sanitize_text_field( $stored['report_admin_user'] ) : '',
            'report_interval'     => isset( $stored['report_interval'] ) ? sanitize_text_field( $stored['report_interval'] ) : 'disabled',
        ];
    }

    public function fast_block_enumeration(): void {
        // Block author queries (e.g. ?author=1)
        if ( $this->settings['block_author'] && ! is_user_logged_in() && isset( $_GET['author'] ) && is_numeric( $_GET['author'] ) ) {
            $this->log_blocked_attempt( 'author', $_GET['author'] );
            status_header( 403 );
            die( 'Access denied.' );
        }

        // Block REST API user enumeration (e.g. /wp-json/wp/v2/users)
        if ( $this->settings['block_rest'] && ! is_user_logged_in() && isset( $_SERVER['REQUEST_URI'] ) ) {
            if ( preg_match( '#/wp-json/wp/v2/users#i', $_SERVER['REQUEST_URI'] ) ) {
                $this->log_blocked_attempt( 'rest', $_SERVER['REQUEST_URI'] );
                status_header( 403 );
                die( 'Access denied.' );
            }
        }
    }

    private function log_blocked_attempt( string $type, string $target ): void {
        $logs = $this->get_guard_option( self::LOGS_KEY, [] );
        if ( ! is_array( $logs ) ) {
            $logs = [];
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
        if ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            $ip = sanitize_text_field( $_SERVER['HTTP_X_FORWARDED_FOR'] );
        }

        $new_entry = [
            'timestamp' => time(),
            'ip'        => $ip,
            'type'      => $type,
            'target'    => sanitize_text_field( $target ),
            'blog_id'   => get_current_blog_id(),
        ];

        array_unshift( $logs, $new_entry );
        $logs = array_slice( $logs, 0, 50 ); // Store up to 50 logs for reporting
        $this->update_guard_option( self::LOGS_KEY, $logs );
        
        // Update a simple counter
        $count = (int) $this->get_guard_option( 'uxpa_network_guard_blocked_count', 0 );
        $this->update_guard_option( 'uxpa_network_guard_blocked_count', $count + 1 );

        // Track daily stats
        $daily_stats = $this->get_guard_option( 'uxpa_network_guard_daily_stats', [] );
        if ( ! is_array( $daily_stats ) ) {
            $daily_stats = [];
        }
        $today = date( 'Y-m-d' );
        if ( ! isset( $daily_stats[ $today ] ) ) {
            $daily_stats[ $today ] = 0;
        }
        $daily_stats[ $today ]++;

        // Prune daily stats older than 30 entries
        krsort( $daily_stats );
        $daily_stats = array_slice( $daily_stats, 0, 30, true );
        $this->update_guard_option( 'uxpa_network_guard_daily_stats', $daily_stats );
    }

    public function set_action_scheduler_retention(): int {
        return DAY_IN_SECONDS * 7; // Keeps logs for 7 days instead of 30
    }

    public function clean_cron_option_on_update( $new_value ) {
        if ( ! is_array( $new_value ) ) {
            return $new_value;
        }
        
        $max_duplicates_per_hook = $this->settings['cron_threshold'];
        $counts = [];
        
        foreach ( $new_value as $timestamp => $hooks ) {
            if ( ! is_array( $hooks ) ) {
                continue;
            }
            foreach ( $hooks as $hook_name => $hook_events ) {
                if ( ! isset( $counts[ $hook_name ] ) ) {
                    $counts[ $hook_name ] = 0;
                }
                $counts[ $hook_name ] += count( $hook_events );
                
                // If the same hook is scheduled excessively, prune subsequent ones
                if ( $counts[ $hook_name ] > $max_duplicates_per_hook ) {
                    unset( $new_value[ $timestamp ][ $hook_name ] );
                    if ( empty( $new_value[ $timestamp ] ) ) {
                        unset( $new_value[ $timestamp ] );
                    }
                }
            }
        }
        return $new_value;
    }

    public function register_admin_settings_page(): void {
        if ( $this->is_network_active ) {
            return; // Managed network-wide on Multisite
        }
        add_options_page(
            'UXPA Performance Guard',
            'UXPA Performance Guard',
            'manage_options',
            'uxpa-performance-guard',
            [ $this, 'render_settings_page' ]
        );
    }

    public function register_network_settings_page(): void {
        if ( ! $this->is_network_active ) {
            return; // Only register under Network Admin if network-activated
        }
        add_submenu_page(
            'settings.php',
            'UXPA Performance Guard',
            'UXPA Performance Guard',
            'manage_network_options',
            'uxpa-performance-guard',
            [ $this, 'render_settings_page' ]
        );
    }

    public function handle_csv_export(): void {
        if ( ! isset( $_GET['action'] ) || $_GET['action'] !== 'uxpa_export_csv' ) {
            return;
        }

        if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'uxpa_export_csv_nonce' ) ) {
            wp_die( 'Security check failed.' );
        }

        $can_manage = $this->is_network_active ? current_user_can( 'manage_network_options' ) : current_user_can( 'manage_options' );
        if ( ! $can_manage ) {
            wp_die( 'Permission denied.' );
        }

        $logs = $this->get_guard_option( self::LOGS_KEY, [] );

        header( 'Content-Type: text/csv; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="uxpa-security-intercept-report-' . date( 'Y-m-d' ) . '.csv"' );
        
        $output = fopen( 'php://output', 'w' );
        
        $headers = [ 'Time', 'IP Address', 'Block Type', 'Target Route / Query' ];
        if ( is_multisite() ) {
            array_splice( $headers, 1, 0, 'Sub-Site' );
        }
        fputcsv( $output, $headers );

        foreach ( $logs as $entry ) {
            $row = [
                date( 'Y-m-d H:i:s', $entry['timestamp'] ),
                $entry['ip'],
                $entry['type'] === 'rest' ? 'REST API' : 'Query Parameter',
                $entry['target']
            ];
            if ( is_multisite() ) {
                $blog_id = $entry['blog_id'] ?? 1;
                $details = get_blog_details( $blog_id );
                $sub_site = $details ? $details->blogname : "Site #{$blog_id}";
                array_splice( $row, 1, 0, $sub_site );
            }
            fputcsv( $output, $row );
        }

        fclose( $output );
        exit;
    }

    private function reschedule_report_cron( string $interval ): void {
        wp_clear_scheduled_hook( 'uxpa_guard_send_scheduled_report' );
        if ( $interval !== 'disabled' ) {
            wp_schedule_event( time() + 30, $interval, 'uxpa_guard_send_scheduled_report' );
        }
    }

    public function send_scheduled_report(): void {
        $stored = $this->get_guard_option( self::SETTINGS_KEY, [] );
        $username = isset( $stored['report_admin_user'] ) ? $stored['report_admin_user'] : '';
        
        if ( empty( $username ) ) {
            return;
        }

        $user = get_user_by( 'login', $username );
        if ( ! $user ) {
            return;
        }

        $to = $user->user_email;
        $subject = '[' . get_option( 'blogname' ) . '] UXPA Security & Performance Guard Report';

        $total_intercepted = (int) $this->get_guard_option( 'uxpa_network_guard_blocked_count', 0 );
        
        $daily_stats = $this->get_guard_option( 'uxpa_network_guard_daily_stats', [] );
        $seven_days_total = 0;
        $thirty_days_total = 0;
        $idx = 0;
        if ( is_array( $daily_stats ) ) {
            foreach ( $daily_stats as $date => $count ) {
                if ( $idx < 7 ) {
                    $seven_days_total += $count;
                }
                if ( $idx < 30 ) {
                    $thirty_days_total += $count;
                }
                $idx++;
            }
        }

        $logs = $this->get_guard_option( self::LOGS_KEY, [] );
        $logs_html = '';
        if ( empty( $logs ) ) {
            $logs_html = '<p>No security blocks logged recently.</p>';
        } else {
            $logs_html .= '<table style="width: 100%; border-collapse: collapse; margin-top: 10px;">';
            $logs_html .= '<thead><tr style="background-color: #f8f9fa; border-bottom: 2px solid #dee2e6;">';
            $logs_html .= '<th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">Time</th>';
            if ( is_multisite() ) {
                $logs_html .= '<th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">Sub-Site</th>';
            }
            $logs_html .= '<th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">IP Address</th>';
            $logs_html .= '<th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">Block Type</th>';
            $logs_html .= '<th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">Target Route / Query</th>';
            $logs_html .= '</tr></thead><tbody>';
            
            $display_logs = array_slice( $logs, 0, 15 );
            foreach ( $display_logs as $entry ) {
                $time = date( 'Y-m-d H:i:s', $entry['timestamp'] );
                $ip = esc_html( $entry['ip'] );
                $type = $entry['type'] === 'rest' ? 'REST API' : 'Query Parameter';
                $target = esc_html( $entry['target'] );
                
                $logs_html .= '<tr style="border-bottom: 1px solid #dee2e6;">';
                $logs_html .= '<td style="padding: 8px; border: 1px solid #dee2e6;">' . $time . '</td>';
                if ( is_multisite() ) {
                    $blog_id = $entry['blog_id'] ?? 1;
                    $details = get_blog_details( $blog_id );
                    $sub_site = $details ? $details->blogname : "Site #{$blog_id}";
                    $logs_html .= '<td style="padding: 8px; border: 1px solid #dee2e6;">' . esc_html( $sub_site ) . '</td>';
                }
                $logs_html .= '<td style="padding: 8px; border: 1px solid #dee2e6;"><code>' . $ip . '</code></td>';
                $logs_html .= '<td style="padding: 8px; border: 1px solid #dee2e6;">' . $type . '</td>';
                $logs_html .= '<td style="padding: 8px; border: 1px solid #dee2e6;"><code>' . $target . '</code></td>';
                $logs_html .= '</tr>';
            }
            $logs_html .= '</tbody></table>';
        }

        $cron_option = get_option( 'cron', [] );
        $cron_serialized = maybe_serialize( $cron_option );
        $cron_size = strlen( $cron_serialized );
        $formatted_cron_size = size_format( $cron_size, 2 );

        $body = '
        <html>
        <head>
            <title>Security and Performance Guard Report</title>
        </head>
        <body style="font-family: Arial, sans-serif; color: #333333; line-height: 1.6;">
            <div style="max-width: 700px; margin: 0 auto; padding: 20px; border: 1px solid #e9ecef; border-radius: 5px;">
                <h1 style="color: #0073aa; border-bottom: 2px solid #0073aa; padding-bottom: 10px;">UXPA Security & Performance Guard Report</h1>
                
                <p>Hello ' . esc_html( $user->display_name ) . ',</p>
                <p>This is your automated security and performance summary for <strong>' . esc_html( get_option( 'blogname' ) ) . '</strong>.</p>
                
                <h2 style="color: #495057; margin-top: 30px;">🛡️ Security Statistics</h2>
                <ul style="list-style-type: none; padding-left: 0;">
                    <li style="margin-bottom: 10px;"><strong>Total Blocked Attempts (Cumulative):</strong> <span style="font-size: 16px; font-weight: bold; color: #d63638;">' . number_format_i18n( $total_intercepted ) . '</span></li>
                    <li style="margin-bottom: 10px;"><strong>Blocked in Last 7 Days:</strong> <span style="font-size: 16px; font-weight: bold; color: #d63638;">' . number_format_i18n( $seven_days_total ) . '</span></li>
                    <li style="margin-bottom: 10px;"><strong>Blocked in Last 30 Days:</strong> <span style="font-size: 16px; font-weight: bold; color: #d63638;">' . number_format_i18n( $thirty_days_total ) . '</span></li>
                </ul>

                <h2 style="color: #495057; margin-top: 30px;">⚡ Cron Database Health</h2>
                <ul style="list-style-type: none; padding-left: 0;">
                    <li style="margin-bottom: 10px;"><strong>Cron Option Storage Size:</strong> ' . esc_html( $formatted_cron_size ) . '</li>
                </ul>

                <h2 style="color: #495057; margin-top: 30px;">📋 Recent Blocked Attempts (Latest 15)</h2>
                ' . $logs_html . '
                
                <p style="margin-top: 40px; font-size: 12px; color: #6c757d; border-top: 1px solid #dee2e6; padding-top: 10px;">
                    This email is auto-generated by the UXPA Network Performance & Guard plugin installed on ' . esc_url( site_url() ) . '. To change settings, log in and visit the plugin options page.
                </p>
            </div>
        </body>
        </html>';

        $headers = [ 'Content-Type: text/html; charset=UTF-8' ];

        wp_mail( $to, $subject, $body, $headers );
    }

    public function render_settings_page(): void {
        $can_manage = $this->is_network_active ? current_user_can( 'manage_network_options' ) : current_user_can( 'manage_options' );
        if ( ! $can_manage ) {
            wp_die( 'You do not have permission to access this page.' );
        }

        $active_tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'dashboard';

        // Process Settings Save
        if ( isset( $_POST['uxpa_guard_save_settings'] ) ) {
            check_admin_referer( 'uxpa_guard_settings_nonce' );

            $tab = isset( $_POST['tab_submitted'] ) ? sanitize_key( $_POST['tab_submitted'] ) : 'security';
            
            if ( $tab === 'security' ) {
                $new_settings = [
                    'block_author'        => isset( $_POST['block_author'] ),
                    'block_rest'          => isset( $_POST['block_rest'] ),
                    'cron_threshold'      => $this->settings['cron_threshold'],
                    'report_admin_user'   => isset( $_POST['report_admin_user'] ) ? sanitize_text_field( trim( $_POST['report_admin_user'] ) ) : $this->settings['report_admin_user'],
                    'report_interval'     => isset( $_POST['report_interval'] ) ? sanitize_text_field( $_POST['report_interval'] ) : $this->settings['report_interval'],
                ];
            } else {
                $new_settings = [
                    'block_author'        => $this->settings['block_author'],
                    'block_rest'          => $this->settings['block_rest'],
                    'cron_threshold'      => isset( $_POST['cron_threshold'] ) ? max( 1, (int) $_POST['cron_threshold'] ) : 5,
                    'report_admin_user'   => $this->settings['report_admin_user'],
                    'report_interval'     => $this->settings['report_interval'],
                ];
            }

            // Validate Username if report_interval is not disabled
            $username_error = '';
            if ( $new_settings['report_interval'] !== 'disabled' && ! empty( $new_settings['report_admin_user'] ) ) {
                $user = get_user_by( 'login', $new_settings['report_admin_user'] );
                if ( ! $user ) {
                    $username_error = 'The configured username does not exist.';
                } else {
                    $is_admin = $this->is_network_active ? user_can( $user->ID, 'manage_network_options' ) : user_can( $user->ID, 'manage_options' );
                    if ( ! $is_admin ) {
                        $username_error = 'The configured user does not have administrator privileges.';
                    }
                }
            } elseif ( $new_settings['report_interval'] !== 'disabled' && empty( $new_settings['report_admin_user'] ) ) {
                $username_error = 'Please provide an administrator username to schedule reports.';
            }

            if ( $username_error ) {
                $new_settings['report_interval'] = 'disabled'; // Fallback to disabled
                echo '<div class="notice notice-error is-dismissible"><p><strong>Error: ' . esc_html( $username_error ) . ' Email reporting has been disabled.</strong></p></div>';
            } else {
                // Reschedule WP-Cron
                $this->reschedule_report_cron( $new_settings['report_interval'] );
                echo '<div class="notice notice-success is-dismissible"><p><strong>Settings saved successfully.</strong></p></div>';
            }

            $this->update_guard_option( self::SETTINGS_KEY, $new_settings );
            $this->load_settings();
        }

        // Process Settings Reset
        if ( isset( $_POST['uxpa_guard_reset_logs'] ) ) {
            check_admin_referer( 'uxpa_guard_settings_nonce' );
            $this->update_guard_option( self::LOGS_KEY, [] );
            $this->update_guard_option( 'uxpa_network_guard_blocked_count', 0 );
            $this->update_guard_option( 'uxpa_network_guard_daily_stats', [] );
            echo '<div class="notice notice-info is-dismissible"><p><strong>Interception counters and logs cleared.</strong></p></div>';
        }

        // Process Action Scheduler Manual Purge
        if ( isset( $_POST['uxpa_guard_purge_action_scheduler'] ) ) {
            check_admin_referer( 'uxpa_guard_settings_nonce' );
            if ( class_exists( 'ActionScheduler_QueueCleaner' ) ) {
                $cleaner = new ActionScheduler_QueueCleaner();
                $cleaner->delete_old_actions();
                echo '<div class="notice notice-success is-dismissible"><p><strong>Action Scheduler logs pruned successfully.</strong></p></div>';
            } else {
                echo '<div class="notice notice-error is-dismissible"><p><strong>Action Scheduler cleaner class not found.</strong></p></div>';
            }
        }
        ?>

        <div class="wrap">
            <h1>UXPA Network Performance & Guard</h1>
            <p class="description">Lightweight diagnostics and controls to block bots and prevent WP-Cron option bloat.</p>

            <h2 class="nav-tab-wrapper">
                <a href="?page=uxpa-performance-guard&tab=dashboard" class="nav-tab <?php echo $active_tab === 'dashboard' ? 'nav-tab-active' : ''; ?>">Dashboard</a>
                <a href="?page=uxpa-performance-guard&tab=security" class="nav-tab <?php echo $active_tab === 'security' ? 'nav-tab-active' : ''; ?>">Security Settings</a>
                <a href="?page=uxpa-performance-guard&tab=cron" class="nav-tab <?php echo $active_tab === 'cron' ? 'nav-tab-active' : ''; ?>">Cron Health</a>
            </h2>

            <div class="tab-content" style="margin-top: 15px;">
                <?php
                switch ( $active_tab ) {
                    case 'dashboard':
                        $this->render_dashboard_tab();
                        break;
                    case 'security':
                        $this->render_security_tab();
                        break;
                    case 'cron':
                        $this->render_cron_tab();
                        break;
                }
                ?>
            </div>
        </div>
        <?php
    }

    private function render_dashboard_tab(): void {
        $blocked_count = $this->get_guard_option( 'uxpa_network_guard_blocked_count', 0 );
        $recent_logs   = $this->get_guard_option( self::LOGS_KEY, [] );
        
        // Calculate 7-day and 30-day statistics
        $daily_stats = $this->get_guard_option( 'uxpa_network_guard_daily_stats', [] );
        $seven_days_total = 0;
        $thirty_days_total = 0;
        $idx = 0;
        if ( is_array( $daily_stats ) ) {
            foreach ( $daily_stats as $date => $count ) {
                if ( $idx < 7 ) {
                    $seven_days_total += $count;
                }
                if ( $idx < 30 ) {
                    $thirty_days_total += $count;
                }
                $idx++;
            }
        }

        $csv_export_url = wp_nonce_url( admin_url( 'index.php?action=uxpa_export_csv' ), 'uxpa_export_csv_nonce' );
        ?>
        <div style="display: flex; gap: 20px; margin-bottom: 20px;">
            <div class="card" style="flex: 1; min-width: 200px; margin-top: 0; background: #fff; border: 1px solid #c3c4c7; padding: 15px; border-radius: 4px; border-left: 4px solid #d63638;">
                <h3>Total Blocked Attempts</h3>
                <p style="font-size: 24px; font-weight: bold; margin: 10px 0; color: #d63638;">
                    <?php echo esc_html( number_format_i18n( $blocked_count ) ); ?>
                </p>
                <p class="description">Cumulative harvesting attempts intercepted since reset.</p>
            </div>
            <div class="card" style="flex: 1; min-width: 200px; margin-top: 0; background: #fff; border: 1px solid #c3c4c7; padding: 15px; border-radius: 4px;">
                <h3>Blocked (Last 7 Days)</h3>
                <p style="font-size: 24px; font-weight: bold; margin: 10px 0;">
                    <?php echo esc_html( number_format_i18n( $seven_days_total ) ); ?>
                </p>
                <p class="description">Attack interceptions over the past week.</p>
            </div>
            <div class="card" style="flex: 1; min-width: 200px; margin-top: 0; background: #fff; border: 1px solid #c3c4c7; padding: 15px; border-radius: 4px;">
                <h3>Blocked (Last 30 Days)</h3>
                <p style="font-size: 24px; font-weight: bold; margin: 10px 0;">
                    <?php echo esc_html( number_format_i18n( $thirty_days_total ) ); ?>
                </p>
                <p class="description">Attack interceptions over the past 30 days.</p>
            </div>
        </div>

        <div style="margin-bottom: 20px; display: flex; gap: 10px; align-items: center;">
            <a href="<?php echo esc_url( $csv_export_url ); ?>" class="button button-primary">Download CSV Report</a>
            <?php if ( ! empty( $recent_logs ) ) : ?>
                <form method="post" style="display: inline;">
                    <?php wp_nonce_field( 'uxpa_guard_settings_nonce' ); ?>
                    <input type="submit" name="uxpa_guard_reset_logs" class="button button-secondary" value="Clear Interception Logs & Counter" />
                </form>
            <?php endif; ?>
        </div>

        <h3>Recent Intercepted Attempts (Last 50 Logs)</h3>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th style="width: 18%;">Time</th>
                    <?php if ( is_multisite() ) : ?>
                        <th style="width: 15%;">Sub-Site</th>
                    <?php endif; ?>
                    <th style="width: 18%;">IP Address</th>
                    <th style="width: 15%;">Block Type</th>
                    <th>Target Query / Route</th>
                </tr>
            </thead>
            <tbody>
                <?php if ( empty( $recent_logs ) ) : ?>
                    <tr>
                        <td colspan="<?php echo is_multisite() ? 5 : 4; ?>">No blocked harvesting attempts recorded yet.</td>
                    </tr>
                <?php else : ?>
                    <?php foreach ( $recent_logs as $entry ) : ?>
                        <tr>
                            <td><?php echo esc_html( date_i18n( 'Y-m-d H:i:s', $entry['timestamp'] ) ); ?></td>
                            <?php if ( is_multisite() ) : ?>
                                <td>
                                    <?php 
                                    $blog_id = $entry['blog_id'] ?? 1;
                                    $details = get_blog_details( $blog_id );
                                    echo esc_html( $details ? $details->blogname : "Site #{$blog_id}" );
                                    ?>
                                </td>
                            <?php endif; ?>
                            <td><code><?php echo esc_html( $entry['ip'] ); ?></code></td>
                            <td>
                                <span class="badge" style="background: #f0f0f1; border: 1px solid #c3c4c7; padding: 2px 6px; border-radius: 3px; font-size: 11px;">
                                    <?php echo ( isset( $entry['type'] ) && $entry['type'] === 'rest' ) ? 'REST API' : 'Query Parameter'; ?>
                                </span>
                            </td>
                            <td><code><?php echo esc_html( $entry['target'] ); ?></code></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
        <?php
    }

    private function render_security_tab(): void {
        ?>
        <form method="post">
            <?php wp_nonce_field( 'uxpa_guard_settings_nonce' ); ?>
            <input type="hidden" name="tab_submitted" value="security" />
            
            <h2>Interception Toggles</h2>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row">Query User Enumeration</th>
                    <td>
                        <label for="block_author">
                            <input name="block_author" type="checkbox" id="block_author" value="1" <?php checked( $this->settings['block_author'] ); ?> />
                            Block author query-string harvesting (e.g. <code>/?author=N</code>)
                        </label>
                        <p class="description">Terminates unauthenticated requests instantly with a 403 Access Denied header.</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">REST API User Enumeration</th>
                    <td>
                        <label for="block_rest">
                            <input name="block_rest" type="checkbox" id="block_rest" value="1" <?php checked( $this->settings['block_rest'] ); ?> />
                            Block unauthenticated REST API user endpoints (e.g. <code>/wp-json/wp/v2/users</code>)
                        </label>
                        <p class="description">Excludes unauthenticated requests from harvesting usernames via standard endpoints.</p>
                    </td>
                </tr>
            </table>

            <h2>Automated Email Reports</h2>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><label for="report_admin_user">Recipient Admin Username</label></th>
                    <td>
                        <input name="report_admin_user" type="text" id="report_admin_user" class="regular-text" value="<?php echo esc_attr( $this->settings['report_admin_user'] ); ?>" placeholder="e.g. admin_username" />
                        <p class="description">Provide the WordPress login username of the administrator to receive reports. This username must exist and have administrative capabilities.</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="report_interval">Email Frequency</label></th>
                    <td>
                        <select name="report_interval" id="report_interval">
                            <option value="disabled" <?php selected( $this->settings['report_interval'], 'disabled' ); ?>>Disabled</option>
                            <option value="daily" <?php selected( $this->settings['report_interval'], 'daily' ); ?>>Daily</option>
                            <option value="weekly" <?php selected( $this->settings['report_interval'], 'weekly' ); ?>>Weekly</option>
                            <option value="monthly" <?php selected( $this->settings['report_interval'], 'monthly' ); ?>>Monthly</option>
                        </select>
                        <p class="description">Select the recurring schedule to dispatch security reports to the configured administrator.</p>
                    </td>
                </tr>
            </table>

            <?php submit_button( 'Save Security & Reporting Settings', 'primary', 'uxpa_guard_save_settings' ); ?>
        </form>
        <?php
    }

    private function render_cron_tab(): void {
        // Handle target blog selection in Multisite
        $target_blog_id = get_current_blog_id();
        if ( $this->is_network_active && isset( $_GET['cron_blog_id'] ) ) {
            $target_blog_id = (int) $_GET['cron_blog_id'];
        }

        if ( is_multisite() ) {
            switch_to_blog( $target_blog_id );
        }

        $cron_option = get_option( 'cron', [] );
        $cron_serialized = maybe_serialize( $cron_option );
        $cron_size = strlen( $cron_serialized );
        
        $total_events = 0;
        $hook_frequencies = [];
        if ( is_array( $cron_option ) ) {
            foreach ( $cron_option as $timestamp => $hooks ) {
                if ( is_array( $hooks ) ) {
                    foreach ( $hooks as $hook_name => $hook_events ) {
                        $count = count( $hook_events );
                        $total_events += $count;
                        if ( ! isset( $hook_frequencies[ $hook_name ] ) ) {
                            $hook_frequencies[ $hook_name ] = 0;
                        }
                        $hook_frequencies[ $hook_name ] += $count;
                    }
                }
            }
        }
        arsort( $hook_frequencies );
        $top_hooks = array_slice( $hook_frequencies, 0, 5 );

        if ( is_multisite() ) {
            restore_current_blog();
        }
        ?>

        <?php if ( $this->is_network_active ) : ?>
            <div style="margin-bottom: 20px; background: #fff; border: 1px solid #c3c4c7; padding: 15px; border-radius: 4px;">
                <form method="get" action="">
                    <input type="hidden" name="page" value="uxpa-performance-guard" />
                    <input type="hidden" name="tab" value="cron" />
                    <label for="cron_blog_id"><strong>Select Sub-Site to Inspect:</strong></label>
                    <select name="cron_blog_id" id="cron_blog_id" onchange="this.form.submit()">
                        <?php
                        $sites = get_sites( [ 'number' => 100 ] );
                        foreach ( $sites as $site ) {
                            $details = get_blog_details( $site->blog_id );
                            printf(
                                '<option value="%d" %s>%s (ID: %d)</option>',
                                (int) $site->blog_id,
                                selected( $target_blog_id, $site->blog_id, false ),
                                esc_html( $details ? $details->blogname : $site->domain ),
                                (int) $site->blog_id
                            );
                        }
                        ?>
                    </select>
                </form>
            </div>
        <?php endif; ?>

        <div style="display: flex; gap: 20px; margin-bottom: 20px;">
            <div class="card" style="flex: 1; min-width: 200px; margin-top: 0; background: #fff; border: 1px solid #c3c4c7; padding: 15px; border-radius: 4px;">
                <h3>Cron Option Size</h3>
                <p style="font-size: 24px; font-weight: bold; margin: 10px 0;">
                    <?php echo esc_html( size_format( $cron_size, 2 ) ); ?>
                </p>
                <p class="description">Total serialized byte count of the <code>cron</code> option row.</p>
            </div>
            <div class="card" style="flex: 1; min-width: 200px; margin-top: 0; background: #fff; border: 1px solid #c3c4c7; padding: 15px; border-radius: 4px;">
                <h3>Total Scheduled Events</h3>
                <p style="font-size: 24px; font-weight: bold; margin: 10px 0;">
                    <?php echo esc_html( $total_events ); ?>
                </p>
                <p class="description">Total number of events registered inside the scheduler queue.</p>
            </div>
        </div>

        <h3>Cron Option Composition (Top 5 Hooks)</h3>
        <table class="wp-list-table widefat fixed striped" style="margin-bottom: 30px;">
            <thead>
                <tr>
                    <th>Hook Name</th>
                    <th style="width: 25%;">Frequency Count</th>
                </tr>
            </thead>
            <tbody>
                <?php if ( empty( $top_hooks ) ) : ?>
                    <tr>
                        <td colspan="2">No scheduled cron events detected.</td>
                    </tr>
                <?php else : ?>
                    <?php foreach ( $top_hooks as $hook => $freq ) : ?>
                        <tr>
                            <td><code><?php echo esc_html( $hook ); ?></code></td>
                            <td><strong><?php echo esc_html( $freq ); ?></strong></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>

        <div style="margin-bottom: 30px; background: #fff; border: 1px solid #c3c4c7; padding: 15px; border-radius: 4px;">
            <h3>Action Scheduler Maintenance</h3>
            <p class="description" style="margin-bottom: 15px;">The system automatically retains Action Scheduler action logs for <strong>7 days</strong> (reduced from the default 30 days). You can force an immediate database queue cleanup below.</p>
            <form method="post" style="display: inline;">
                <?php wp_nonce_field( 'uxpa_guard_settings_nonce' ); ?>
                <input type="submit" name="uxpa_guard_purge_action_scheduler" class="button button-secondary" value="Purge Old Action Logs Now" />
            </form>
        </div>

        <form method="post">
            <?php wp_nonce_field( 'uxpa_guard_settings_nonce' ); ?>
            <input type="hidden" name="tab_submitted" value="cron" />

            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><label for="cron_threshold">Duplicate Event Limit</label></th>
                    <td>
                        <input name="cron_threshold" type="number" id="cron_threshold" min="1" max="100" class="small-text" value="<?php echo esc_attr( $this->settings['cron_threshold'] ); ?>" />
                        <p class="description">Maximum allowed occurrences of a single hook within the scheduled cron array before subsequent duplicates are pruned.</p>
                    </td>
                </tr>
            </table>
            <?php submit_button( 'Save Cron Settings', 'primary', 'uxpa_guard_save_settings' ); ?>
        </form>
        <?php
    }
}

new UxpaNetworkPerformanceGuard();
