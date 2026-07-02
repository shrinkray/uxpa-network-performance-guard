<?php
/**
 * Plugin Name: UXPA Network Performance & Guard
 * Description: Intercepts user enumeration attempts early and prevents cron option data pollution.
 * Version: 1.1
 */

if ( ! defined( 'ABSPATH' ) ) exit;

// 1. Intercept user enumeration early (before theme loads)
add_action( 'plugins_loaded', 'uxpa_fast_block_enumeration' );
function uxpa_fast_block_enumeration() {
    // Block author queries (e.g. ?author=1)
    if ( ! is_user_logged_in() && isset( $_GET['author'] ) && is_numeric( $_GET['author'] ) ) {
        status_header( 403 );
        die( 'Access denied.' );
    }

    // Block REST API user enumeration (e.g. /wp-json/wp/v2/users)
    if ( ! is_user_logged_in() && isset( $_SERVER['REQUEST_URI'] ) ) {
        if ( preg_match( '#/wp-json/wp/v2/users#i', $_SERVER['REQUEST_URI'] ) ) {
            status_header( 403 );
            die( 'Access denied.' );
        }
    }
}

// 2. Intercept and clean bloated cron options before updates fail
add_filter( 'pre_update_option_cron', 'uxpa_clean_cron_option_on_update' );
add_filter( 'pre_update_site_option_cron', 'uxpa_clean_cron_option_on_update' );
function uxpa_clean_cron_option_on_update( $new_value ) {
    if ( ! is_array( $new_value ) ) {
        return $new_value;
    }
    
    $max_duplicates_per_hook = 5;
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
