<?php
/**
 * Plugin Name: UXPA Network Performance & Guard
 * Description: Intercepts user enumeration attempts early and prevents cron option data pollution.
 * Version: 1.3
 * Author: Greg Miller for UXPA International
 * Author URI: https://shrinkraylabs.com
 * Text Domain: uxpa-network-performance-guard
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

    private function load_settings(): void {
        $stored = $this->get_guard_option( self::SETTINGS_KEY, [] );
        if ( ! is_array( $stored ) ) {
            $stored = [];
        }

        $this->settings = [
            'block_author'   => isset( $stored['block_author'] ) ? (bool) $stored['block_author'] : true,
            'block_rest'     => isset( $stored['block_rest'] ) ? (bool) $stored['block_rest'] : true,
            'cron_threshold' => isset( $stored['cron_threshold'] ) ? (int) $stored['cron_threshold'] : 5,
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
        $logs = array_slice( $logs, 0, 10 ); // Keep only latest 10
        $this->update_guard_option( self::LOGS_KEY, $logs );
        
        // Update a simple counter
        $count = (int) $this->get_guard_option( 'uxpa_network_guard_blocked_count', 0 );
        $this->update_guard_option( 'uxpa_network_guard_blocked_count', $count + 1 );
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

    public function render_settings_page(): void {
        $can_manage = $this->is_network_active ? current_user_can( 'manage_network_options' ) : current_user_can( 'manage_options' );
        if ( ! $can_manage ) {
            wp_die( 'You do not have permission to access this page.' );
        }

        $active_tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'dashboard';

        // Process Settings Save
        if ( isset( $_POST['uxpa_guard_save_settings'] ) ) {
            check_admin_referer( 'uxpa_guard_settings_nonce' );

            $new_settings = [
                'block_author'   => isset( $_POST['block_author'] ),
                'block_rest'     => isset( $_POST['block_rest'] ),
                'cron_threshold' => isset( $_POST['cron_threshold'] ) ? max( 1, (int) $_POST['cron_threshold'] ) : 5,
            ];

            $this->update_guard_option( self::SETTINGS_KEY, $new_settings );
            $this->load_settings();
            echo '<div class="notice notice-success is-dismissible"><p><strong>Settings saved successfully.</strong></p></div>';
        }

        // Process Settings Reset
        if ( isset( $_POST['uxpa_guard_reset_logs'] ) ) {
            check_admin_referer( 'uxpa_guard_settings_nonce' );
            $this->update_guard_option( self::LOGS_KEY, [] );
            $this->update_guard_option( 'uxpa_network_guard_blocked_count', 0 );
            echo '<div class="notice notice-info is-dismissible"><p><strong>Interception counters and logs cleared.</strong></p></div>';
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
        ?>
        <div class="welcome-panel" style="padding: 20px; margin-bottom: 20px;">
            <div class="welcome-panel-content">
                <h2>Security Status Overview</h2>
                <p class="about-description">Currently shielding user archives and REST API routes from harvesting loops.</p>
                <div style="font-size: 24px; font-weight: bold; color: #d63638; margin: 15px 0;">
                    <?php echo esc_html( number_format_i18n( $blocked_count ) ); ?> <span style="font-size: 16px; font-weight: normal; color: #50575e;">malicious harvesting attempts intercepted.</span>
                </div>
            </div>
        </div>

        <h3>Recent Intercepted Attempts</h3>
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

        <?php if ( ! empty( $recent_logs ) ) : ?>
            <form method="post" style="margin-top: 15px;">
                <?php wp_nonce_field( 'uxpa_guard_settings_nonce' ); ?>
                <input type="submit" name="uxpa_guard_reset_logs" class="button button-secondary" value="Clear Interception Logs & Counter" />
            </form>
        <?php endif; ?>
        <?php
    }

    private function render_security_tab(): void {
        ?>
        <form method="post">
            <?php wp_nonce_field( 'uxpa_guard_settings_nonce' ); ?>
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
            <?php submit_button( 'Save Security Settings', 'primary', 'uxpa_guard_save_settings' ); ?>
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

        // Fetch raw cron data for the target blog
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

        <form method="post">
            <?php wp_nonce_field( 'uxpa_guard_settings_nonce' ); ?>
            <input type="hidden" name="block_author" value="<?php echo $this->settings['block_author'] ? '1' : ''; ?>" />
            <input type="hidden" name="block_rest" value="<?php echo $this->settings['block_rest'] ? '1' : ''; ?>" />

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
