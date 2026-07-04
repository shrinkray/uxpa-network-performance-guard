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

        // 6. AJAX Action for Toggling Cloudflare IPs
        add_action( 'wp_ajax_uxpa_toggle_cloudflare_blocked', [ $this, 'ajax_toggle_cloudflare_blocked' ] );
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

    public function ajax_toggle_cloudflare_blocked(): void {
        check_ajax_referer( 'uxpa_guard_ajax_nonce', 'nonce' );

        $can_manage = $this->is_network_active ? current_user_can( 'manage_network_options' ) : current_user_can( 'manage_options' );
        if ( ! $can_manage ) {
            wp_send_json_error( [ 'message' => __( 'Permission denied.', 'uxpa-network-performance-guard' ) ] );
        }

        $ip = isset( $_POST['ip'] ) ? sanitize_text_field( $_POST['ip'] ) : '';
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            wp_send_json_error( [ 'message' => __( 'Invalid IP address.', 'uxpa-network-performance-guard' ) ] );
        }

        $blocked_ips = $this->get_guard_option( 'uxpa_network_guard_cloudflare_blocked_ips', [] );
        if ( ! is_array( $blocked_ips ) ) {
            $blocked_ips = [];
        }

        $is_blocked = false;
        if ( in_array( $ip, $blocked_ips, true ) ) {
            $blocked_ips = array_values( array_diff( $blocked_ips, [ $ip ] ) );
        } else {
            $blocked_ips[] = $ip;
            $is_blocked = true;
        }

        $this->update_guard_option( 'uxpa_network_guard_cloudflare_blocked_ips', $blocked_ips );

        wp_send_json_success( [
            'ip'         => $ip,
            'is_blocked' => $is_blocked,
            'blocked_ips'=> $blocked_ips,
        ] );
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

        $active_tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'welcome';
        $valid_tabs = [ 'welcome', 'dashboard', 'security', 'cron' ];
        if ( ! in_array( $active_tab, $valid_tabs, true ) ) {
            $active_tab = 'welcome';
        }

        // Process Settings Save
        if ( isset( $_POST['uxpa_guard_save_settings'] ) ) {
            check_admin_referer( 'uxpa_guard_settings_nonce' );

            $tab = isset( $_POST['tab_submitted'] ) ? sanitize_key( $_POST['tab_submitted'] ) : 'security';
            if ( ! in_array( $tab, [ 'security', 'cron' ], true ) ) {
                $tab = 'security';
            }
            
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
                    $username_error = __( 'The configured username does not exist.', 'uxpa-network-performance-guard' );
                } else {
                    $is_admin = $this->is_network_active ? user_can( $user->ID, 'manage_network_options' ) : user_can( $user->ID, 'manage_options' );
                    if ( ! $is_admin ) {
                        $username_error = __( 'The configured user does not have administrator privileges.', 'uxpa-network-performance-guard' );
                    }
                }
            } elseif ( $new_settings['report_interval'] !== 'disabled' && empty( $new_settings['report_admin_user'] ) ) {
                $username_error = __( 'Please provide an administrator username to schedule reports.', 'uxpa-network-performance-guard' );
            }

            if ( $username_error ) {
                $new_settings['report_interval'] = 'disabled'; // Fallback to disabled
                echo '<div class="notice notice-error is-dismissible"><p><strong>' . esc_html__( 'Error:', 'uxpa-network-performance-guard' ) . ' ' . esc_html( $username_error ) . ' ' . esc_html__( 'Email reporting has been disabled.', 'uxpa-network-performance-guard' ) . '</strong></p></div>';
            } else {
                // Reschedule WP-Cron
                $this->reschedule_report_cron( $new_settings['report_interval'] );
                echo '<div class="notice notice-success is-dismissible"><p><strong>' . esc_html__( 'Settings saved successfully.', 'uxpa-network-performance-guard' ) . '</strong></p></div>';
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
            echo '<div class="notice notice-info is-dismissible"><p><strong>' . esc_html__( 'Interception counters and logs cleared.', 'uxpa-network-performance-guard' ) . '</strong></p></div>';
        }

        // Process Action Scheduler Manual Purge
        if ( isset( $_POST['uxpa_guard_purge_action_scheduler'] ) ) {
            check_admin_referer( 'uxpa_guard_settings_nonce' );
            if ( class_exists( 'ActionScheduler_QueueCleaner' ) ) {
                $cleaner = new ActionScheduler_QueueCleaner();
                $cleaner->delete_old_actions();
                echo '<div class="notice notice-success is-dismissible"><p><strong>' . esc_html__( 'Action Scheduler logs pruned successfully.', 'uxpa-network-performance-guard' ) . '</strong></p></div>';
            } else {
                echo '<div class="notice notice-error is-dismissible"><p><strong>' . esc_html__( 'Action Scheduler cleaner class not found.', 'uxpa-network-performance-guard' ) . '</strong></p></div>';
            }
        }
        ?>

        <?php
        $base_url = $this->is_network_active ? network_admin_url( 'settings.php' ) : admin_url( 'options-general.php' );
        $base_url = add_query_arg( [ 'page' => 'uxpa-performance-guard' ], $base_url );
        ?>
        <div class="wrap">
            <h1><?php esc_html_e( 'UXPA Network Performance & Guard', 'uxpa-network-performance-guard' ); ?></h1>
            <p class="description"><?php esc_html_e( 'Lightweight diagnostics and controls to block bots and prevent WP-Cron option bloat.', 'uxpa-network-performance-guard' ); ?></p>

            <h2 class="nav-tab-wrapper">
                <a href="<?php echo esc_url( add_query_arg( 'tab', 'welcome', $base_url ) ); ?>" class="nav-tab <?php echo $active_tab === 'welcome' ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Welcome', 'uxpa-network-performance-guard' ); ?></a>
                <a href="<?php echo esc_url( add_query_arg( 'tab', 'dashboard', $base_url ) ); ?>" class="nav-tab <?php echo $active_tab === 'dashboard' ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Dashboard', 'uxpa-network-performance-guard' ); ?></a>
                <a href="<?php echo esc_url( add_query_arg( 'tab', 'security', $base_url ) ); ?>" class="nav-tab <?php echo $active_tab === 'security' ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Security Settings', 'uxpa-network-performance-guard' ); ?></a>
                <a href="<?php echo esc_url( add_query_arg( 'tab', 'cron', $base_url ) ); ?>" class="nav-tab <?php echo $active_tab === 'cron' ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Cron Health', 'uxpa-network-performance-guard' ); ?></a>
            </h2>

            <div class="settings-container-two-columns" style="display: flex; gap: 30px; margin-top: 20px; align-items: flex-start;">
                <div class="main-settings-content" style="flex: 3; min-width: 0;">
                    <?php
                    switch ( $active_tab ) {
                        case 'welcome':
                            $this->render_welcome_tab();
                            break;
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

                <div class="sidebar-settings-guide" style="flex: 1; min-width: 280px; max-width: 360px; background: #fff; border: 1px solid #ccd0d4; padding: 20px; border-radius: 4px; box-shadow: 0 1px 1px rgba(0,0,0,.04); box-sizing: border-box;">
                    <?php $this->render_sidebar_guide( $active_tab ); ?>
                </div>
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

        $cloudflare_blocked_ips = $this->get_guard_option( 'uxpa_network_guard_cloudflare_blocked_ips', [] );
        if ( ! is_array( $cloudflare_blocked_ips ) ) {
            $cloudflare_blocked_ips = [];
        }

        // Aggregate Top Offending IPs from the log entries
        $top_offenders = [];
        if ( is_array( $recent_logs ) ) {
            foreach ( $recent_logs as $entry ) {
                $ip = $entry['ip'];
                if ( ! isset( $top_offenders[ $ip ] ) ) {
                    $top_offenders[ $ip ] = [
                        'ip'         => $ip,
                        'hits'       => 0,
                        'first_seen' => $entry['timestamp'],
                        'last_seen'  => $entry['timestamp'],
                    ];
                }
                $top_offenders[ $ip ]['hits']++;
                if ( $entry['timestamp'] < $top_offenders[ $ip ]['first_seen'] ) {
                    $top_offenders[ $ip ]['first_seen'] = $entry['timestamp'];
                }
                if ( $entry['timestamp'] > $top_offenders[ $ip ]['last_seen'] ) {
                    $top_offenders[ $ip ]['last_seen'] = $entry['timestamp'];
                }
            }
        }
        
        // Sort top offenders by hits count descending, then by last_seen descending
        uasort( $top_offenders, function( $a, $b ) {
            if ( $a['hits'] === $b['hits'] ) {
                return $b['last_seen'] <=> $a['last_seen'];
            }
            return $b['hits'] <=> $a['hits'];
        } );

        $csv_export_url = wp_nonce_url( admin_url( 'index.php?action=uxpa_export_csv' ), 'uxpa_export_csv_nonce' );
        $ajax_nonce = wp_create_nonce( 'uxpa_guard_ajax_nonce' );
        ?>
        <!-- Include Nonce for JS -->
        <input type="hidden" id="uxpa_guard_ajax_nonce" value="<?php echo esc_attr( $ajax_nonce ); ?>" />

        <!-- Styles for Sorting, Badges, and Toggle Actions -->
        <style>
            th.sortable {
                cursor: pointer;
                position: relative;
                user-select: none;
                transition: background 0.15s ease;
                padding: 10px 12px !important;
                white-space: nowrap;
            }
            th.sortable:hover {
                background: #f0f0f1 !important;
                color: #2271b1 !important;
            }
            th.sortable::after {
                content: ' ↕';
                opacity: 0.3;
                font-size: 10px;
                margin-left: 5px;
                display: inline-block;
            }
            th.sortable.asc::after {
                content: ' ▲';
                opacity: 0.9;
                color: #2271b1;
            }
            th.sortable.desc::after {
                content: ' ▼';
                opacity: 0.9;
                color: #2271b1;
            }
            .cf-blocked-badge {
                background: #fbe8e8 !important;
                color: #ba1a1a !important;
                border: 1px solid #f8c2c2 !important;
                padding: 3px 8px !important;
                border-radius: 4px !important;
                font-size: 11px !important;
                font-weight: 500 !important;
                display: inline-block;
            }
            .cf-active-badge {
                background: #e7f4ec !important;
                color: #0f5132 !important;
                border: 1px solid #badbcc !important;
                padding: 3px 8px !important;
                border-radius: 4px !important;
                font-size: 11px !important;
                font-weight: 500 !important;
                display: inline-block;
            }
            .row-cf-blocked {
                background-color: #fdfafb !important;
                opacity: 0.85;
            }
            .button-primary-outline {
                background: transparent !important;
                border-color: #2271b1 !important;
                color: #2271b1 !important;
                transition: all 0.2s ease !important;
            }
            .button-primary-outline:hover {
                background: #2271b1 !important;
                color: #fff !important;
            }
            .updating {
                opacity: 0.5 !important;
                pointer-events: none !important;
            }
            .button-success {
                background: #46b450 !important;
                border-color: #46b450 !important;
                color: #fff !important;
            }
        </style>

        <div style="display: flex; gap: 20px; margin-bottom: 20px;">
            <div class="card" style="flex: 1; min-width: 200px; margin-top: 0; background: #fff; border: 1px solid #c3c4c7; padding: 15px; border-radius: 4px; border-left: 4px solid #d63638;">
                <h3><?php esc_html_e( 'Total Blocked Attempts', 'uxpa-network-performance-guard' ); ?></h3>
                <p style="font-size: 24px; font-weight: bold; margin: 10px 0; color: #d63638;">
                    <?php echo esc_html( number_format_i18n( $blocked_count ) ); ?>
                </p>
                <p class="description"><?php esc_html_e( 'Cumulative harvesting attempts intercepted since reset.', 'uxpa-network-performance-guard' ); ?></p>
            </div>
            <div class="card" style="flex: 1; min-width: 200px; margin-top: 0; background: #fff; border: 1px solid #c3c4c7; padding: 15px; border-radius: 4px;">
                <h3><?php esc_html_e( 'Blocked (Last 7 Days)', 'uxpa-network-performance-guard' ); ?></h3>
                <p style="font-size: 24px; font-weight: bold; margin: 10px 0;">
                    <?php echo esc_html( number_format_i18n( $seven_days_total ) ); ?>
                </p>
                <p class="description"><?php esc_html_e( 'Attack interceptions over the past week.', 'uxpa-network-performance-guard' ); ?></p>
            </div>
            <div class="card" style="flex: 1; min-width: 200px; margin-top: 0; background: #fff; border: 1px solid #c3c4c7; padding: 15px; border-radius: 4px;">
                <h3><?php esc_html_e( 'Blocked (Last 30 Days)', 'uxpa-network-performance-guard' ); ?></h3>
                <p style="font-size: 24px; font-weight: bold; margin: 10px 0;">
                    <?php echo esc_html( number_format_i18n( $thirty_days_total ) ); ?>
                </p>
                <p class="description"><?php esc_html_e( 'Attack interceptions over the past 30 days.', 'uxpa-network-performance-guard' ); ?></p>
            </div>
        </div>

        <div style="margin-bottom: 25px; display: flex; gap: 10px; align-items: center;">
            <a href="<?php echo esc_url( $csv_export_url ); ?>" class="button button-primary"><?php esc_html_e( 'Download CSV Report', 'uxpa-network-performance-guard' ); ?></a>
            <?php if ( ! empty( $recent_logs ) ) : ?>
                <form method="post" style="display: inline;">
                    <?php wp_nonce_field( 'uxpa_guard_settings_nonce' ); ?>
                    <input type="submit" name="uxpa_guard_reset_logs" class="button button-secondary" value="<?php esc_attr_e( 'Clear Interception Logs & Counter', 'uxpa-network-performance-guard' ); ?>" />
                </form>
            <?php endif; ?>
        </div>

        <!-- Section 1: Top Offending IPs -->
        <div style="margin-bottom: 40px;">
            <h3 style="font-size: 16px; font-weight: 600; margin-bottom: 12px;"><?php esc_html_e( 'Top Offending IP Addresses', 'uxpa-network-performance-guard' ); ?></h3>
            <table class="wp-list-table widefat fixed striped" id="uxpa-top-offenders-table">
                <thead>
                    <tr>
                        <th class="sortable" data-type="ip" style="width: 20%;"><?php esc_html_e( 'IP Address', 'uxpa-network-performance-guard' ); ?></th>
                        <th class="sortable desc" data-type="number" style="width: 10%;"><?php esc_html_e( 'Hits Count', 'uxpa-network-performance-guard' ); ?></th>
                        <th class="sortable" data-type="date" style="width: 20%;"><?php esc_html_e( 'First Intercepted', 'uxpa-network-performance-guard' ); ?></th>
                        <th class="sortable" data-type="date" style="width: 20%;"><?php esc_html_e( 'Last Intercepted', 'uxpa-network-performance-guard' ); ?></th>
                        <th class="sortable" data-type="string" style="width: 18%;"><?php esc_html_e( 'Edge Block Status', 'uxpa-network-performance-guard' ); ?></th>
                        <th style="width: 12%;"><?php esc_html_e( 'Actions', 'uxpa-network-performance-guard' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ( empty( $top_offenders ) ) : ?>
                        <tr>
                            <td colspan="6"><?php esc_html_e( 'No statistics recorded yet.', 'uxpa-network-performance-guard' ); ?></td>
                        </tr>
                    <?php else : ?>
                        <?php foreach ( $top_offenders as $offender ) : 
                            $is_blocked = in_array( $offender['ip'], $cloudflare_blocked_ips, true );
                            $row_class = $is_blocked ? 'row-cf-blocked' : '';
                            ?>
                            <tr class="<?php echo esc_attr( $row_class ); ?>">
                                <td>
                                    <code class="ip-address"><?php echo esc_html( $offender['ip'] ); ?></code>
                                    <a href="<?php echo esc_url( 'https://abuseipdb.com/check/' . $offender['ip'] ); ?>" target="_blank" rel="noopener noreferrer" style="font-size: 10px; margin-left: 6px; text-decoration: none;" title="<?php esc_attr_e( 'Check IP reputation on AbuseIPDB', 'uxpa-network-performance-guard' ); ?>">
                                        <span class="dashicons dashicons-external" style="font-size: 12px; width: 12px; height: 12px;"></span>
                                    </a>
                                </td>
                                <td><strong><?php echo esc_html( $offender['hits'] ); ?></strong></td>
                                <td><?php echo esc_html( date_i18n( 'Y-m-d H:i:s', $offender['first_seen'] ) ); ?></td>
                                <td><?php echo esc_html( date_i18n( 'Y-m-d H:i:s', $offender['last_seen'] ) ); ?></td>
                                <td class="cloudflare-status-cell">
                                    <?php if ( $is_blocked ) : ?>
                                        <span class="badge cf-blocked-badge"><?php esc_html_e( 'Blocked at Edge', 'uxpa-network-performance-guard' ); ?></span>
                                    <?php else : ?>
                                        <span class="badge cf-active-badge"><?php esc_html_e( 'Logged (Active)', 'uxpa-network-performance-guard' ); ?></span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ( $is_blocked ) : ?>
                                        <button type="button" class="uxpa-toggle-cloudflare button button-secondary" data-ip="<?php echo esc_attr( $offender['ip'] ); ?>"><?php esc_html_e( 'Remove Block', 'uxpa-network-performance-guard' ); ?></button>
                                    <?php else : ?>
                                        <button type="button" class="uxpa-toggle-cloudflare button button-primary-outline" data-ip="<?php echo esc_attr( $offender['ip'] ); ?>"><?php esc_html_e( 'Mark Blocked', 'uxpa-network-performance-guard' ); ?></button>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <!-- Section 2: Recent Logs -->
        <div>
            <h3 style="font-size: 16px; font-weight: 600; margin-bottom: 12px;"><?php esc_html_e( 'Recent Intercepted Attempts (Last 50 Logs)', 'uxpa-network-performance-guard' ); ?></h3>
            <table class="wp-list-table widefat fixed striped" id="uxpa-recent-logs-table">
                <thead>
                    <tr>
                        <th class="sortable desc" data-type="date" style="width: 15%;"><?php esc_html_e( 'Time', 'uxpa-network-performance-guard' ); ?></th>
                        <?php if ( is_multisite() ) : ?>
                            <th class="sortable" data-type="string" style="width: 12%;"><?php esc_html_e( 'Sub-Site', 'uxpa-network-performance-guard' ); ?></th>
                        <?php endif; ?>
                        <th class="sortable" data-type="ip" style="width: 15%;"><?php esc_html_e( 'IP Address', 'uxpa-network-performance-guard' ); ?></th>
                        <th class="sortable" data-type="string" style="width: 12%;"><?php esc_html_e( 'Block Type', 'uxpa-network-performance-guard' ); ?></th>
                        <th class="sortable" data-type="string" style="width: <?php echo is_multisite() ? '24%' : '36%'; ?>;"><?php esc_html_e( 'Target Query / Route', 'uxpa-network-performance-guard' ); ?></th>
                        <th class="sortable" data-type="string" style="width: 12%;"><?php esc_html_e( 'Edge Block Status', 'uxpa-network-performance-guard' ); ?></th>
                        <th style="width: 10%;"><?php esc_html_e( 'Actions', 'uxpa-network-performance-guard' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ( empty( $recent_logs ) ) : ?>
                        <tr>
                            <td colspan="<?php echo is_multisite() ? 7 : 6; ?>"><?php esc_html_e( 'No blocked harvesting attempts recorded yet.', 'uxpa-network-performance-guard' ); ?></td>
                        </tr>
                    <?php else : ?>
                        <?php foreach ( $recent_logs as $entry ) : 
                            $is_blocked = in_array( $entry['ip'], $cloudflare_blocked_ips, true );
                            $row_class = $is_blocked ? 'row-cf-blocked' : '';
                            ?>
                            <tr class="<?php echo esc_attr( $row_class ); ?>">
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
                                <td>
                                    <code class="ip-address"><?php echo esc_html( $entry['ip'] ); ?></code>
                                    <a href="<?php echo esc_url( 'https://abuseipdb.com/check/' . $entry['ip'] ); ?>" target="_blank" rel="noopener noreferrer" style="font-size: 10px; margin-left: 6px; text-decoration: none;" title="<?php esc_attr_e( 'Check IP reputation on AbuseIPDB', 'uxpa-network-performance-guard' ); ?>">
                                        <span class="dashicons dashicons-external" style="font-size: 12px; width: 12px; height: 12px;"></span>
                                    </a>
                                </td>
                                <td>
                                    <span class="badge" style="background: #f0f0f1; border: 1px solid #c3c4c7; padding: 2px 6px; border-radius: 3px; font-size: 11px;">
                                        <?php echo ( isset( $entry['type'] ) && $entry['type'] === 'rest' ) ? esc_html__( 'REST API', 'uxpa-network-performance-guard' ) : esc_html__( 'Query Parameter', 'uxpa-network-performance-guard' ); ?>
                                    </span>
                                </td>
                                <td><code><?php echo esc_html( $entry['target'] ); ?></code></td>
                                <td class="cloudflare-status-cell">
                                    <?php if ( $is_blocked ) : ?>
                                        <span class="badge cf-blocked-badge"><?php esc_html_e( 'Blocked at Edge', 'uxpa-network-performance-guard' ); ?></span>
                                    <?php else : ?>
                                        <span class="badge cf-active-badge"><?php esc_html_e( 'Logged (Active)', 'uxpa-network-performance-guard' ); ?></span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ( $is_blocked ) : ?>
                                        <button type="button" class="uxpa-toggle-cloudflare button button-secondary" data-ip="<?php echo esc_attr( $entry['ip'] ); ?>"><?php esc_html_e( 'Remove Block', 'uxpa-network-performance-guard' ); ?></button>
                                    <?php else : ?>
                                        <button type="button" class="uxpa-toggle-cloudflare button button-primary-outline" data-ip="<?php echo esc_attr( $entry['ip'] ); ?>"><?php esc_html_e( 'Mark Blocked', 'uxpa-network-performance-guard' ); ?></button>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <!-- Client-Side Sorter & AJAX Script -->
        <script>
        jQuery(document).ready(function($) {
            // Localized Translation Strings
            const txtBlockedAtEdge = <?php echo wp_json_encode( __( 'Blocked at Edge', 'uxpa-network-performance-guard' ) ); ?>;
            const txtLoggedActive  = <?php echo wp_json_encode( __( 'Logged (Active)', 'uxpa-network-performance-guard' ) ); ?>;
            const txtRemoveBlock   = <?php echo wp_json_encode( __( 'Remove Block', 'uxpa-network-performance-guard' ) ); ?>;
            const txtMarkBlocked   = <?php echo wp_json_encode( __( 'Mark Blocked', 'uxpa-network-performance-guard' ) ); ?>;
            const txtErrOccurred   = <?php echo wp_json_encode( __( 'An error occurred.', 'uxpa-network-performance-guard' ) ); ?>;
            const txtReqFailed     = <?php echo wp_json_encode( __( 'Request failed. Please try again.', 'uxpa-network-performance-guard' ) ); ?>;
            const txtCopied        = <?php echo wp_json_encode( __( 'Copied!', 'uxpa-network-performance-guard' ) ); ?>;
            const txtCopyFail      = <?php echo wp_json_encode( __( 'Could not copy to clipboard. Please copy manually.', 'uxpa-network-performance-guard' ) ); ?>;

            // Client-Side Sorting
            $('th.sortable').on('click', function() {
                const th = $(this);
                const table = th.closest('table')[0];
                const index = th.index();
                const type = th.data('type') || 'string';
                
                // Determine direction
                let asc = true;
                if (th.hasClass('asc')) {
                    asc = false;
                }
                
                // Clear directions on other sibling headers of the same table
                th.closest('tr').find('th').removeClass('asc desc');
                
                // Add direction class
                th.addClass(asc ? 'asc' : 'desc');
                
                // Sort table rows
                sortTable(table, index, type, asc);
            });

            function sortTable(table, columnIndex, type, asc) {
                const tbody = table.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr'));
                
                if (rows.length <= 1 && $(rows[0]).find('td').length <= 1) return;

                rows.sort((a, b) => {
                    let valA = a.cells[columnIndex] ? a.cells[columnIndex].innerText.trim() : '';
                    let valB = b.cells[columnIndex] ? b.cells[columnIndex].innerText.trim() : '';

                    // For IP sorting (with IPv6 fallback)
                    if (type === 'ip') {
                        const ipToNum = ip => {
                            const clean = ip.replace(/[^0-9.]/g, '').split('.');
                            if (clean.length !== 4) return null;
                            return clean.reduce((acc, octet) => (acc * 256) + parseInt(octet, 10), 0);
                        };
                        const numA = ipToNum(valA);
                        const numB = ipToNum(valB);
                        if (numA === null || numB === null) {
                            return asc ? valA.localeCompare(valB) : valB.localeCompare(valA);
                        }
                        return asc ? numA - numB : numB - numA;
                    }

                    // For numeric sorting
                    if (type === 'number') {
                        const numA = parseFloat(valA.replace(/[^0-9.-]/g, '')) || 0;
                        const numB = parseFloat(valB.replace(/[^0-9.-]/g, '')) || 0;
                        return asc ? numA - numB : numB - numA;
                    }

                    // For Date/Time sorting (standard Y-m-d H:i:s)
                    if (type === 'date') {
                        const dateA = new Date(valA.replace(/-/g, '/')).getTime() || 0;
                        const dateB = new Date(valB.replace(/-/g, '/')).getTime() || 0;
                        return asc ? dateA - dateB : dateB - dateA;
                    }

                    // Alphabetical
                    return asc ? valA.localeCompare(valB) : valB.localeCompare(valA);
                });

                tbody.innerHTML = '';
                rows.forEach(row => tbody.appendChild(row));
            }

            // AJAX Toggle Cloudflare Block
            $(document).on('click', '.uxpa-toggle-cloudflare', function(e) {
                e.preventDefault();
                const btn = $(this);
                const ip = btn.data('ip');
                const nonce = $('#uxpa_guard_ajax_nonce').val();

                btn.prop('disabled', true).addClass('updating');

                $.post(ajaxurl, {
                    action: 'uxpa_toggle_cloudflare_blocked',
                    ip: ip,
                    nonce: nonce
                }, function(response) {
                    btn.prop('disabled', false).removeClass('updating');
                    if (response.success) {
                        const isBlocked = response.data.is_blocked;
                        const blockedIps = response.data.blocked_ips;
                        
                        // Update UI for this IP everywhere on the page
                        updateIPStatusUI(ip, isBlocked);
                        
                        // Update the Copy Assistant in the sidebar
                        updateCopyAssistant(blockedIps);
                    } else {
                        alert(response.data.message || txtErrOccurred);
                    }
                }).fail(function() {
                    btn.prop('disabled', false).removeClass('updating');
                    alert(txtReqFailed);
                });
            });

            function updateIPStatusUI(ip, isBlocked) {
                const badgeHtml = isBlocked 
                    ? '<span class="badge cf-blocked-badge">' + txtBlockedAtEdge + '</span>'
                    : '<span class="badge cf-active-badge">' + txtLoggedActive + '</span>';
                    
                const btnText = isBlocked ? txtRemoveBlock : txtMarkBlocked;
                const btnClass = isBlocked ? 'button button-secondary' : 'button button-primary-outline';
                
                $('tr').each(function() {
                    const row = $(this);
                    const ipCode = row.find('code.ip-address');
                    if (ipCode.length && ipCode.text().trim() === ip) {
                        row.find('.cloudflare-status-cell').html(badgeHtml);
                        const toggleBtn = row.find('.uxpa-toggle-cloudflare');
                        toggleBtn.text(btnText).attr('class', 'uxpa-toggle-cloudflare ' + btnClass);
                        
                        if (isBlocked) {
                            row.addClass('row-cf-blocked');
                        } else {
                            row.removeClass('row-cf-blocked');
                        }
                    }
                });
            }

            function updateCopyAssistant(blockedIps) {
                const textarea = $('#cf-blocked-list-text');
                const badge = $('#cf-blocked-count-badge');
                const emptyMsg = $('#cf-empty-msg');
                const copyBtn = $('#copy-cf-list');

                textarea.val(blockedIps.join('\n'));
                badge.text(blockedIps.length);

                if (blockedIps.length === 0) {
                    emptyMsg.show();
                    textarea.hide();
                    copyBtn.hide();
                } else {
                    emptyMsg.hide();
                    textarea.show();
                    copyBtn.show();
                }
            }

            // Copy to Clipboard Assistant
            $(document).on('click', '#copy-cf-list', function() {
                const textarea = document.getElementById('cf-blocked-list-text');
                textarea.select();
                textarea.setSelectionRange(0, 99999); // For mobile devices

                const triggerSuccessUI = () => {
                    const copyBtn = $('#copy-cf-list');
                    const origHtml = copyBtn.html();
                    copyBtn.html('<span class="dashicons dashicons-yes"></span> ' + txtCopied).addClass('button-success');
                    setTimeout(() => {
                        copyBtn.html(origHtml).removeClass('button-success');
                    }, 2000);
                };

                const fallbackCopy = () => {
                    try {
                        document.execCommand('copy');
                        triggerSuccessUI();
                    } catch (err) {
                        alert(txtCopyFail);
                    }
                };

                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(textarea.value)
                        .then(triggerSuccessUI)
                        .catch(fallbackCopy);
                } else {
                    fallbackCopy();
                }
            });
        });
        </script>
        <?php
    }

    private function render_security_tab(): void {
        ?>
        <form method="post">
            <?php wp_nonce_field( 'uxpa_guard_settings_nonce' ); ?>
            <input type="hidden" name="tab_submitted" value="security" />
            
            <h2><?php esc_html_e( 'Interception Toggles', 'uxpa-network-performance-guard' ); ?></h2>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><?php esc_html_e( 'Query User Enumeration', 'uxpa-network-performance-guard' ); ?></th>
                    <td>
                        <label for="block_author">
                            <input name="block_author" type="checkbox" id="block_author" value="1" <?php checked( $this->settings['block_author'] ); ?> />
                            <?php echo wp_kses_post( __( 'Block author query-string harvesting (e.g. <code>/?author=N</code>)', 'uxpa-network-performance-guard' ) ); ?>
                        </label>
                        <p class="description"><?php esc_html_e( 'Terminates unauthenticated requests instantly with a 403 Access Denied header.', 'uxpa-network-performance-guard' ); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e( 'REST API User Enumeration', 'uxpa-network-performance-guard' ); ?></th>
                    <td>
                        <label for="block_rest">
                            <input name="block_rest" type="checkbox" id="block_rest" value="1" <?php checked( $this->settings['block_rest'] ); ?> />
                            <?php echo wp_kses_post( __( 'Block unauthenticated REST API user endpoints (e.g. <code>/wp-json/wp/v2/users</code>)', 'uxpa-network-performance-guard' ) ); ?>
                        </label>
                        <p class="description"><?php esc_html_e( 'Excludes unauthenticated requests from harvesting usernames via standard endpoints.', 'uxpa-network-performance-guard' ); ?></p>
                    </td>
                </tr>
            </table>

            <h2><?php esc_html_e( 'Automated Email Reports', 'uxpa-network-performance-guard' ); ?></h2>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><label for="report_admin_user"><?php esc_html_e( 'Recipient Admin Username', 'uxpa-network-performance-guard' ); ?></label></th>
                    <td>
                        <input name="report_admin_user" type="text" id="report_admin_user" class="regular-text" value="<?php echo esc_attr( $this->settings['report_admin_user'] ); ?>" placeholder="e.g. admin_username" />
                        <p class="description"><?php esc_html_e( 'Provide the WordPress login username of the administrator to receive reports. This username must exist and have administrative capabilities.', 'uxpa-network-performance-guard' ); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="report_interval"><?php esc_html_e( 'Email Frequency', 'uxpa-network-performance-guard' ); ?></label></th>
                    <td>
                        <select name="report_interval" id="report_interval">
                            <option value="disabled" <?php selected( $this->settings['report_interval'], 'disabled' ); ?>><?php esc_html_e( 'Disabled', 'uxpa-network-performance-guard' ); ?></option>
                            <option value="daily" <?php selected( $this->settings['report_interval'], 'daily' ); ?>><?php esc_html_e( 'Daily', 'uxpa-network-performance-guard' ); ?></option>
                            <option value="weekly" <?php selected( $this->settings['report_interval'], 'weekly' ); ?>><?php esc_html_e( 'Weekly', 'uxpa-network-performance-guard' ); ?></option>
                            <option value="monthly" <?php selected( $this->settings['report_interval'], 'monthly' ); ?>><?php esc_html_e( 'Monthly', 'uxpa-network-performance-guard' ); ?></option>
                        </select>
                        <p class="description"><?php esc_html_e( 'Select the recurring schedule to dispatch security reports to the configured administrator.', 'uxpa-network-performance-guard' ); ?></p>
                    </td>
                </tr>
            </table>

            <?php submit_button( esc_html__( 'Save Security & Reporting Settings', 'uxpa-network-performance-guard' ), 'primary', 'uxpa_guard_save_settings' ); ?>
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
                    <label for="cron_blog_id"><strong><?php esc_html_e( 'Select Sub-Site to Inspect:', 'uxpa-network-performance-guard' ); ?></strong></label>
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
                <h3><?php esc_html_e( 'Cron Option Size', 'uxpa-network-performance-guard' ); ?></h3>
                <p style="font-size: 24px; font-weight: bold; margin: 10px 0;">
                    <?php echo esc_html( size_format( $cron_size, 2 ) ); ?>
                </p>
                <p class="description"><?php esc_html_e( 'Total serialized byte count of the cron option row.', 'uxpa-network-performance-guard' ); ?></p>
            </div>
            <div class="card" style="flex: 1; min-width: 200px; margin-top: 0; background: #fff; border: 1px solid #c3c4c7; padding: 15px; border-radius: 4px;">
                <h3><?php esc_html_e( 'Total Scheduled Events', 'uxpa-network-performance-guard' ); ?></h3>
                <p style="font-size: 24px; font-weight: bold; margin: 10px 0;">
                    <?php echo esc_html( $total_events ); ?>
                </p>
                <p class="description"><?php esc_html_e( 'Total number of events registered inside the scheduler queue.', 'uxpa-network-performance-guard' ); ?></p>
            </div>
        </div>

        <h3><?php esc_html_e( 'Cron Option Composition (Top 5 Hooks)', 'uxpa-network-performance-guard' ); ?></h3>
        <table class="wp-list-table widefat fixed striped" style="margin-bottom: 30px;">
            <thead>
                <tr>
                    <th><?php esc_html_e( 'Hook Name', 'uxpa-network-performance-guard' ); ?></th>
                    <th style="width: 25%;"><?php esc_html_e( 'Frequency Count', 'uxpa-network-performance-guard' ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php if ( empty( $top_hooks ) ) : ?>
                    <tr>
                        <td colspan="2"><?php esc_html_e( 'No scheduled cron events detected.', 'uxpa-network-performance-guard' ); ?></td>
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
            <h3><?php esc_html_e( 'Action Scheduler Maintenance', 'uxpa-network-performance-guard' ); ?></h3>
            <p class="description" style="margin-bottom: 15px;"><?php esc_html_e( 'The system automatically retains Action Scheduler action logs for 7 days (reduced from the default 30 days). You can force an immediate database queue cleanup below.', 'uxpa-network-performance-guard' ); ?></p>
            <form method="post" style="display: inline;">
                <?php wp_nonce_field( 'uxpa_guard_settings_nonce' ); ?>
                <input type="submit" name="uxpa_guard_purge_action_scheduler" class="button button-secondary" value="<?php esc_attr_e( 'Purge Old Action Logs Now', 'uxpa-network-performance-guard' ); ?>" />
            </form>
        </div>

        <form method="post">
            <?php wp_nonce_field( 'uxpa_guard_settings_nonce' ); ?>
            <input type="hidden" name="tab_submitted" value="cron" />

            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><label for="cron_threshold"><?php esc_html_e( 'Duplicate Event Limit', 'uxpa-network-performance-guard' ); ?></label></th>
                    <td>
                        <input name="cron_threshold" type="number" id="cron_threshold" min="1" max="100" class="small-text" value="<?php echo esc_attr( $this->settings['cron_threshold'] ); ?>" />
                        <p class="description"><?php esc_html_e( 'Maximum allowed occurrences of a single hook within the scheduled cron array before subsequent duplicates are pruned.', 'uxpa-network-performance-guard' ); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button( esc_html__( 'Save Cron Settings', 'uxpa-network-performance-guard' ), 'primary', 'uxpa_guard_save_settings' ); ?>
        </form>
        <?php
    }

    /**
     * Render Welcome settings tab.
     */
    private function render_welcome_tab(): void {
        ?>
        <h2><?php esc_html_e( 'Welcome to UXPA Network Performance & Guard Suite', 'uxpa-network-performance-guard' ); ?></h2>
        <p class="description" style="font-size: 14px; margin-bottom: 20px;">
            <?php esc_html_e( 'A lightweight, high-performance security and database optimization engine designed to protect site operations and maintain a clean scheduler backend.', 'uxpa-network-performance-guard' ); ?>
        </p>

        <div style="background: #fff; border: 1px solid #ccd0d4; padding: 20px; border-radius: 4px; box-shadow: 0 1px 1px rgba(0,0,0,.04); margin-bottom: 30px;">
            <h3 style="margin-top: 0; font-size: 16px; border-bottom: 1px solid #eee; padding-bottom: 8px;">
                <span class="dashicons dashicons-yes-alt" aria-hidden="true" style="color: #46b450; vertical-align: text-bottom; margin-right: 6px;"></span>
                <?php esc_html_e( 'Key Problems We Solve', 'uxpa-network-performance-guard' ); ?>
            </h3>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-top: 15px;">
                <div>
                    <h4 style="margin: 0 0 6px 0; font-size: 14px;">
                        <span class="dashicons dashicons-shield" aria-hidden="true" style="vertical-align: text-bottom; margin-right: 4px; color: #2271b1;"></span>
                        <?php esc_html_e( 'Early-Exit Bot Firewall', 'uxpa-network-performance-guard' ); ?>
                    </h4>
                    <p style="margin: 0; font-size: 13px; color: #646970;">
                        <?php echo wp_kses_post( __( 'Blocks malicious bot scans that list site usernames via <code>?author=N</code> query parameters or REST API requests, preventing credential harvesting before WordPress loads heavy database tasks.', 'uxpa-network-performance-guard' ) ); ?>
                    </p>
                </div>
                <div>
                    <h4 style="margin: 0 0 6px 0; font-size: 14px;">
                        <span class="dashicons dashicons-admin-plugins" aria-hidden="true" style="vertical-align: text-bottom; margin-right: 4px; color: #2271b1;"></span>
                        <?php esc_html_e( 'Cron Database Health & Pruning', 'uxpa-network-performance-guard' ); ?>
                    </h4>
                    <p style="margin: 0; font-size: 13px; color: #646970;">
                        <?php esc_html_e( 'Automatically filters, cleans, and prevents cron option bloat from runaway duplicate scheduler queues or core transient issues.', 'uxpa-network-performance-guard' ); ?>
                    </p>
                </div>
                <div>
                    <h4 style="margin: 0 0 6px 0; font-size: 14px;">
                        <span class="dashicons dashicons-chart-bar" aria-hidden="true" style="vertical-align: text-bottom; margin-right: 4px; color: #2271b1;"></span>
                        <?php esc_html_e( 'Daily Interception Stat Tracking', 'uxpa-network-performance-guard' ); ?>
                    </h4>
                    <p style="margin: 0; font-size: 13px; color: #646970;">
                        <?php esc_html_e( 'Actively logs intrusion attempt histories, recording IP addresses, sub-sites, block types, and target query parameters for transparent auditing.', 'uxpa-network-performance-guard' ); ?>
                    </p>
                </div>
                <div>
                    <h4 style="margin: 0 0 6px 0; font-size: 14px;">
                        <span class="dashicons dashicons-email-alt" aria-hidden="true" style="vertical-align: text-bottom; margin-right: 4px; color: #2271b1;"></span>
                        <?php esc_html_e( 'Automated Email Reporting', 'uxpa-network-performance-guard' ); ?>
                    </h4>
                    <p style="margin: 0; font-size: 13px; color: #646970;">
                        <?php esc_html_e( 'Dispatches regular email summaries of blocked security attempts and cron table health metrics to a validated, authorized administrator.', 'uxpa-network-performance-guard' ); ?>
                    </p>
                </div>
                <div>
                    <h4 style="margin: 0 0 6px 0; font-size: 14px;">
                        <span class="dashicons dashicons-database-export" aria-hidden="true" style="vertical-align: text-bottom; margin-right: 4px; color: #2271b1;"></span>
                        <?php esc_html_e( 'CSV Security Logs Export', 'uxpa-network-performance-guard' ); ?>
                    </h4>
                    <p style="margin: 0; font-size: 13px; color: #646970;">
                        <?php esc_html_e( 'Enables downloading the entire blocked-attack log history as a formatted CSV file for external audit processing.', 'uxpa-network-performance-guard' ); ?>
                    </p>
                </div>
                <div>
                    <h4 style="margin: 0 0 6px 0; font-size: 14px;">
                        <span class="dashicons dashicons-clock" aria-hidden="true" style="vertical-align: text-bottom; margin-right: 4px; color: #2271b1;"></span>
                        <?php esc_html_e( 'Action Scheduler Retention Control', 'uxpa-network-performance-guard' ); ?>
                    </h4>
                    <p style="margin: 0; font-size: 13px; color: #646970;">
                        <?php esc_html_e( 'Optimizes retention periods for action scheduler queues down to 7 days, and offers a single-click manual database pruning utility.', 'uxpa-network-performance-guard' ); ?>
                    </p>
                </div>
            </div>
        </div>

        <div style="background: #f0f6fc; border-left: 4px solid #72aee6; padding: 25px; border-radius: 0 4px 4px 0; box-shadow: 0 1px 2px rgba(0,0,0,.05);">
            <h3 style="margin-top: 0; font-size: 18px; color: #1d2327;">
                <span class="dashicons dashicons-awards" aria-hidden="true" style="vertical-align: text-bottom; margin-right: 6px; color: #135e96; font-size: 24px; width: 24px; height: 24px;"></span>
                <?php esc_html_e( 'Need Custom WordPress Solutions & Optimization?', 'uxpa-network-performance-guard' ); ?>
            </h3>
            <p style="font-size: 14px; line-height: 1.5; color: #2c3338; max-width: 800px; margin-bottom: 20px;">
                <?php esc_html_e( 'This plugin was designed and developed by Greg Miller at Shrinkray Labs. We specialize in high-performance WordPress engineering, custom plugin development, backend dashboard automation, and security/database tuning.', 'uxpa-network-performance-guard' ); ?>
            </p>
            <div style="margin: 0; display:flex;">
                <a href="<?php echo esc_url( 'https://shrinkraylabs.com' ); ?>" target="_blank" rel="noopener noreferrer" class="button button-primary button-large" style="display: flex; justify-content: center; align-items: center;" aria-label="<?php esc_attr_e( 'Visit Shrinkray Labs (opens in a new tab)', 'uxpa-network-performance-guard' ); ?>">
                    <span class="dashicons dashicons-external" aria-hidden="true" style="font-size: 16px; width: 16px; height: 16px; line-height: 1.3; margin-bottom: 0.4rem; margin-right: 0.2rem; color:white;"></span>
                    <?php esc_html_e( 'Visit Shrinkray Labs', 'uxpa-network-performance-guard' ); ?>
                </a>
            </div>
        </div>
        <?php
    }

    /**
     * Render sidebar guide for the active tab.
     */
    private function render_sidebar_guide( string $tab ): void {
        $base_url = $this->is_network_active ? network_admin_url( 'settings.php' ) : admin_url( 'options-general.php' );
        $base_url = add_query_arg( [ 'page' => 'uxpa-performance-guard' ], $base_url );
        switch ( $tab ) {
            case 'welcome':
                ?>
                <h3 style="margin-top: 0; font-size: 16px; border-bottom: 1px solid #eee; padding-bottom: 8px;">
                    <span class="dashicons dashicons-admin-settings" aria-hidden="true" style="vertical-align: text-bottom; margin-right: 4px;"></span>
                    <?php esc_html_e( 'Plugin Metadata', 'uxpa-network-performance-guard' ); ?>
                </h3>
                <table class="wp-list-table widefat fixed striped" style="border: none; background: transparent; box-shadow: none; margin-top: 10px;">
                    <tbody>
                        <tr>
                            <td style="padding: 6px 0; border: none;"><strong><?php esc_html_e( 'Version:', 'uxpa-network-performance-guard' ); ?></strong></td>
                            <td style="padding: 6px 0; border: none; text-align: right;">
                                <?php
                                if ( ! function_exists( 'get_plugin_data' ) ) {
                                    require_once ABSPATH . 'wp-admin/includes/plugin.php';
                                }
                                $plugin_data = get_plugin_data( __FILE__ );
                                echo esc_html( isset( $plugin_data['Version'] ) ? $plugin_data['Version'] : '1.4' );
                                ?>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 6px 0; border: none;"><strong><?php esc_html_e( 'Developer:', 'uxpa-network-performance-guard' ); ?></strong></td>
                            <td style="padding: 6px 0; border: none; text-align: right;"><a href="<?php echo esc_url( 'https://shrinkraylabs.com' ); ?>" target="_blank" rel="noopener noreferrer" aria-label="<?php esc_attr_e( 'Greg Miller (opens in a new tab)', 'uxpa-network-performance-guard' ); ?>"><?php esc_html_e( 'Greg Miller', 'uxpa-network-performance-guard' ); ?></a></td>
                        </tr>
                        <tr>
                            <td style="padding: 6px 0; border: none;"><strong><?php esc_html_e( 'Organization:', 'uxpa-network-performance-guard' ); ?></strong></td>
                            <td style="padding: 6px 0; border: none; text-align: right;"><?php esc_html_e( 'UXPA International', 'uxpa-network-performance-guard' ); ?></td>
                        </tr>
                    </tbody>
                </table>
                <hr style="margin: 15px 0; border-top: 1px solid #eee;" />
                <h4 style="margin: 0 0 10px 0; font-size: 14px;"><?php esc_html_e( 'Quick Shortcuts', 'uxpa-network-performance-guard' ); ?></h4>
                <ul style="list-style: none; padding-left: 0; margin: 0; font-size: 13px;">
                    <li style="margin-bottom: 8px;">
                        <a href="<?php echo esc_url( add_query_arg( 'tab', 'dashboard', $base_url ) ); ?>" style="text-decoration: none; display: flex; align-items: center; gap: 6px;">
                            <span class="dashicons dashicons-chart-bar" aria-hidden="true" style="font-size: 16px; width: 16px; height: 16px;"></span>
                            <?php esc_html_e( 'Security Dashboard', 'uxpa-network-performance-guard' ); ?>
                        </a>
                    </li>
                    <li style="margin-bottom: 8px;">
                        <a href="<?php echo esc_url( add_query_arg( 'tab', 'security', $base_url ) ); ?>" style="text-decoration: none; display: flex; align-items: center; gap: 6px;">
                            <span class="dashicons dashicons-shield" aria-hidden="true" style="font-size: 16px; width: 16px; height: 16px;"></span>
                            <?php esc_html_e( 'Interception Settings', 'uxpa-network-performance-guard' ); ?>
                        </a>
                    </li>
                    <li style="margin-bottom: 0;">
                        <a href="<?php echo esc_url( add_query_arg( 'tab', 'cron', $base_url ) ); ?>" style="text-decoration: none; display: flex; align-items: center; gap: 6px;">
                            <span class="dashicons dashicons-clock" aria-hidden="true" style="font-size: 16px; width: 16px; height: 16px;"></span>
                            <?php esc_html_e( 'Cron & Queue Health', 'uxpa-network-performance-guard' ); ?>
                        </a>
                    </li>
                </ul>
                <?php
                break;

            case 'dashboard':
                $cf_blocked_ips = $this->get_guard_option( 'uxpa_network_guard_cloudflare_blocked_ips', [] );
                if ( ! is_array( $cf_blocked_ips ) ) {
                    $cf_blocked_ips = [];
                }
                $ips_text = implode( "\n", $cf_blocked_ips );
                ?>
                <div class="cloudflare-assistant-card" style="margin-bottom: 25px; padding-bottom: 20px; border-bottom: 1px solid #eee;">
                    <h3 style="margin-top: 0; font-size: 16px; border-bottom: 1px solid #eee; padding-bottom: 8px; color: #d63638;">
                        <span class="dashicons dashicons-shield-alt" aria-hidden="true" style="vertical-align: text-bottom; margin-right: 4px; color: #d63638;"></span>
                        <?php esc_html_e( 'Cloudflare Block Assistant', 'uxpa-network-performance-guard' ); ?>
                    </h3>
                    <p style="font-size: 13px; line-height: 1.4; color: #50575e;">
                        <?php esc_html_e( 'Flag worst-offending IPs in the tables to add them to this edge block list. Copy and paste this list directly into Cloudflare WAF or WPEngine.', 'uxpa-network-performance-guard' ); ?>
                    </p>
                    
                    <div style="margin: 15px 0 10px 0;">
                        <strong><?php esc_html_e( 'Flagged IPs:', 'uxpa-network-performance-guard' ); ?> 
                            <span id="cf-blocked-count-badge" style="background: #d63638; color: #fff; padding: 2px 8px; border-radius: 10px; font-size: 11px; margin-left: 5px;">
                                <?php echo count( $cf_blocked_ips ); ?>
                            </span>
                        </strong>
                    </div>

                    <p id="cf-empty-msg" style="font-style: italic; color: #8c8f94; font-size: 13px; display: <?php echo empty( $cf_blocked_ips ) ? 'block' : 'none'; ?>;">
                        <?php esc_html_e( 'No IPs flagged yet. Click "Mark Blocked" on the offending IPs table to populate.', 'uxpa-network-performance-guard' ); ?>
                    </p>

                    <textarea id="cf-blocked-list-text" readonly style="width: 100%; height: 120px; font-family: monospace; font-size: 12px; line-height: 1.4; padding: 8px; background: #f6f7f7; border: 1px solid #8c8f94; border-radius: 4px; resize: none; box-sizing: border-box; display: <?php echo empty( $cf_blocked_ips ) ? 'none' : 'block'; ?>;"><?php echo esc_textarea( $ips_text ); ?></textarea>
                    
                    <button type="button" id="copy-cf-list" class="button button-secondary" style="width: 100%; margin-top: 10px; display: <?php echo empty( $cf_blocked_ips ) ? 'none' : 'flex'; ?>; justify-content: center; align-items: center; gap: 5px;">
                        <span class="dashicons dashicons-admin-page" style="font-size: 16px; width: 16px; height: 16px; margin-top: 3px;"></span>
                        <?php esc_html_e( 'Copy IP List to Clipboard', 'uxpa-network-performance-guard' ); ?>
                    </button>
                </div>

                <h3 style="margin-top: 0; font-size: 16px; border-bottom: 1px solid #eee; padding-bottom: 8px;">
                    <span class="dashicons dashicons-chart-bar" aria-hidden="true" style="vertical-align: text-bottom; margin-right: 4px;"></span>
                    <?php esc_html_e( 'Dashboard Guide', 'uxpa-network-performance-guard' ); ?>
                </h3>
                <p><strong><?php esc_html_e( 'Security Overview', 'uxpa-network-performance-guard' ); ?></strong></p>
                <p><?php esc_html_e( 'The dashboard displays real-time statistics of blocked malicious requests attempting to harvest admin usernames. The logged data lists the timestamp, IP address, and target URI.', 'uxpa-network-performance-guard' ); ?></p>
                <p><strong><?php esc_html_e( 'Actions:', 'uxpa-network-performance-guard' ); ?></strong></p>
                <ul style="list-style-type: disc; padding-left: 20px; margin: 10px 0;">
                    <li><?php esc_html_e( 'Download a complete CSV report to audit IP addresses blocklists offline.', 'uxpa-network-performance-guard' ); ?></li>
                    <li><?php esc_html_e( 'Clear the logs and reset counter statistics as needed.', 'uxpa-network-performance-guard' ); ?></li>
                </ul>
                <?php
                break;

            case 'security':
                ?>
                <h3 style="margin-top: 0; font-size: 16px; border-bottom: 1px solid #eee; padding-bottom: 8px;">
                    <span class="dashicons dashicons-shield" aria-hidden="true" style="vertical-align: text-bottom; margin-right: 4px;"></span>
                    <?php esc_html_e( 'Security Guide', 'uxpa-network-performance-guard' ); ?>
                </h3>
                <p><strong><?php esc_html_e( 'Bot Mitigation', 'uxpa-network-performance-guard' ); ?></strong></p>
                <p><?php esc_html_e( 'Configure security interceptors to actively drop user-list enumeration queries. Recommended default: keep both parameters enabled.', 'uxpa-network-performance-guard' ); ?></p>
                <p><strong><?php esc_html_e( 'Email Digests:', 'uxpa-network-performance-guard' ); ?></strong></p>
                <p><?php esc_html_e( 'Provide a valid administrator username to receive periodic statistics. Email schedules are dispatched using the Action Scheduler queue.', 'uxpa-network-performance-guard' ); ?></p>
                <?php
                break;

            case 'cron':
                ?>
                <h3 style="margin-top: 0; font-size: 16px; border-bottom: 1px solid #eee; padding-bottom: 8px;">
                    <span class="dashicons dashicons-clock" aria-hidden="true" style="vertical-align: text-bottom; margin-right: 4px;"></span>
                    <?php esc_html_e( 'Cron Health Guide', 'uxpa-network-performance-guard' ); ?>
                </h3>
                <p><strong><?php esc_html_e( 'Avoiding Bloat', 'uxpa-network-performance-guard' ); ?></strong></p>
                <p><?php esc_html_e( 'Runaway cron tasks pollute the options table, stalling the scheduler daemon. The Duplicate Event Limit automatically prunes repeated executions of identical task hooks.', 'uxpa-network-performance-guard' ); ?></p>
                <p><strong><?php esc_html_e( 'Manual Purging:', 'uxpa-network-performance-guard' ); ?></strong></p>
                <p><?php esc_html_e( 'Click "Purge Old Action Logs Now" to instantly delete historic log rows in the Action Scheduler database, freeing up table space.', 'uxpa-network-performance-guard' ); ?></p>
                <?php
                break;
        }
    }
}

new UxpaNetworkPerformanceGuard();
