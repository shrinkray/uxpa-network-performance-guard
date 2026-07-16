<?php

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Custom-table storage and lifecycle operations for interception logs.
 *
 * The consuming class supplies the database constants, network activation
 * state, and network-aware option helpers.
 */
trait UxpaNetworkPerformanceGuardLogStorage {

    /**
     * Resolve the log table name. Network-active installs share one table on the
     * base prefix; single-site installs use the site prefix.
     */
    private function get_log_table(): string {
        global $wpdb;
        $prefix = $this->is_network_active ? $wpdb->base_prefix : $wpdb->prefix;
        return $prefix . self::TABLE_BASENAME;
    }

    /**
     * Create or upgrade the log table when the stored schema version is behind.
     */
    public function maybe_upgrade_db(): void {
        if ( (string) $this->get_guard_option( self::DB_VERSION_KEY, '0' ) === self::DB_VERSION ) {
            return;
        }

        $this->install_log_table();
        $this->migrate_legacy_option_logs();
        $this->update_guard_option( self::DB_VERSION_KEY, self::DB_VERSION );
    }

    private function install_log_table(): void {
        global $wpdb;

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $table           = $this->get_log_table();
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            blocked_at DATETIME NOT NULL,
            ip VARCHAR(45) NOT NULL DEFAULT '',
            block_type VARCHAR(20) NOT NULL DEFAULT '',
            target TEXT NOT NULL,
            blog_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            PRIMARY KEY  (id),
            KEY blocked_at (blocked_at),
            KEY ip (ip)
        ) {$charset_collate};";

        dbDelta( $sql );
    }

    /**
     * Copy legacy option logs into the table, then remove the old telemetry rows.
     */
    private function migrate_legacy_option_logs(): void {
        global $wpdb;

        $legacy_logs = $this->get_guard_option( self::LOGS_KEY, [] );
        if ( is_array( $legacy_logs ) && ! empty( $legacy_logs ) ) {
            $table = $this->get_log_table();
            foreach ( array_reverse( $legacy_logs ) as $entry ) {
                if ( ! is_array( $entry ) ) {
                    continue;
                }

                $timestamp = isset( $entry['timestamp'] ) ? (int) $entry['timestamp'] : time();
                $wpdb->insert(
                    $table,
                    [
                        'blocked_at' => gmdate( 'Y-m-d H:i:s', $timestamp ),
                        'ip'         => isset( $entry['ip'] ) ? substr( (string) $entry['ip'], 0, 45 ) : '',
                        'block_type' => isset( $entry['type'] ) ? substr( (string) $entry['type'], 0, 20 ) : '',
                        'target'     => isset( $entry['target'] ) ? (string) $entry['target'] : '',
                        'blog_id'    => isset( $entry['blog_id'] ) ? (int) $entry['blog_id'] : 0,
                    ],
                    [ '%s', '%s', '%s', '%s', '%d' ]
                );
            }
        }

        if ( $this->is_network_active ) {
            delete_site_option( self::LOGS_KEY );
            delete_site_option( 'uxpa_network_guard_blocked_count' );
            delete_site_option( 'uxpa_network_guard_daily_stats' );
        } else {
            delete_option( self::LOGS_KEY );
            delete_option( 'uxpa_network_guard_blocked_count' );
            delete_option( 'uxpa_network_guard_daily_stats' );
        }
    }

    public function maybe_schedule_prune(): void {
        if ( ! wp_next_scheduled( self::PRUNE_HOOK ) ) {
            wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::PRUNE_HOOK );
        }
    }

    public function prune_old_logs(): void {
        global $wpdb;
        $table  = $this->get_log_table();
        $cutoff = gmdate( 'Y-m-d H:i:s', time() - ( self::RETENTION_DAYS * DAY_IN_SECONDS ) );
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE blocked_at < %s", $cutoff ) );
    }

    /**
     * Insert one interception without touching option storage.
     */
    private function insert_log_entry( string $type, string $target, string $ip ): void {
        global $wpdb;
        $wpdb->insert(
            $this->get_log_table(),
            [
                'blocked_at' => gmdate( 'Y-m-d H:i:s' ),
                'ip'         => substr( $ip, 0, 45 ),
                'block_type' => substr( $type, 0, 20 ),
                'target'     => $target,
                'blog_id'    => get_current_blog_id(),
            ],
            [ '%s', '%s', '%s', '%s', '%d' ]
        );
    }

    /**
     * Return recent rows in the legacy renderer shape.
     */
    private function get_recent_logs( int $limit = 50 ): array {
        global $wpdb;
        $table = $this->get_log_table();
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $rows = $wpdb->get_results( $wpdb->prepare( "SELECT blocked_at, ip, block_type, target, blog_id FROM {$table} ORDER BY blocked_at DESC, id DESC LIMIT %d", $limit ) );

        $logs = [];
        if ( is_array( $rows ) ) {
            foreach ( $rows as $row ) {
                $logs[] = [
                    'timestamp' => strtotime( $row->blocked_at . ' UTC' ),
                    'ip'        => $row->ip,
                    'type'      => $row->block_type,
                    'target'    => $row->target,
                    'blog_id'   => (int) $row->blog_id,
                ];
            }
        }
        return $logs;
    }

    private function get_total_blocked_count(): int {
        global $wpdb;
        $table = $this->get_log_table();
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
    }

    private function get_blocked_count_since( int $days ): int {
        global $wpdb;
        $table  = $this->get_log_table();
        $cutoff = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE blocked_at >= %s", $cutoff ) );
    }

    /**
     * Aggregate the worst-offending IPs across all retained rows.
     */
    private function get_top_offenders( int $limit = 20 ): array {
        global $wpdb;
        $table = $this->get_log_table();
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT ip, COUNT(*) AS hits, MIN(blocked_at) AS first_seen, MAX(blocked_at) AS last_seen
             FROM {$table}
             GROUP BY ip
             ORDER BY hits DESC, last_seen DESC
             LIMIT %d",
            $limit
        ) );

        $offenders = [];
        if ( is_array( $rows ) ) {
            foreach ( $rows as $row ) {
                $offenders[] = [
                    'ip'         => $row->ip,
                    'hits'       => (int) $row->hits,
                    'first_seen' => strtotime( $row->first_seen . ' UTC' ),
                    'last_seen'  => strtotime( $row->last_seen . ' UTC' ),
                ];
            }
        }
        return $offenders;
    }

    private function clear_logs(): void {
        global $wpdb;
        $table = $this->get_log_table();
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $wpdb->query( "TRUNCATE TABLE {$table}" );
    }

    public function activate(): void {
        $this->maybe_upgrade_db();
        $this->maybe_schedule_prune();
    }

    public function deactivate(): void {
        wp_clear_scheduled_hook( self::PRUNE_HOOK );
    }
}
