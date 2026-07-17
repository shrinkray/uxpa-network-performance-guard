# Changelog

All notable changes to the **UXPA Network Performance & Guard** plugin will be documented in this file.

## [1.5] - 2026-07-16

### Added
- Added independent web-host IP block tracking alongside edge blocking.
- Added separate edge and web-host status badges, toggle actions, counters, and copyable IP lists to the security dashboard.

### Changed
- Split dashboard CSS, JavaScript, and custom-table storage into dedicated `assets/` and `includes/` files to keep the plugin bootstrap and admin renderer readable.
- Replaced admin UI inline colors and layout styles with reusable CSS classes in `assets/css/admin-dashboard.css`.
- Migrated interception logging from serialized option rows to a dedicated `{prefix}uxpa_security_logs` database table (installed via `dbDelta`), decoupling high-volume telemetry from autoloaded/preloaded option and `wp_sitemeta` storage.
- Reduced the front-end interception path to a single indexed `INSERT`, eliminating the per-request read-modify-write of the log array, cumulative counter, and daily-stats options.
- Derived dashboard/report statistics (totals, 7/30-day counts, top offenders) from indexed SQL queries, and lifted the previous 50-entry retention cap in favor of a scheduled 90-day pruning job.

### Fixed
- Normalized stored block lists before rendering and returning AJAX responses so only valid IP addresses are displayed and JSON lists remain consistently encoded as arrays.
- Preserved flex alignment when dynamically showing block-list copy buttons.

### Migration
- Existing option-based logs are copied into the new table on first load after upgrade, after which the legacy `uxpa_network_guard_blocked_log`, `uxpa_network_guard_blocked_count`, and `uxpa_network_guard_daily_stats` option rows are removed.

## [1.4] - 2026-07-03

### Added
- Added a two-column layout settings interface with tab-specific interactive sidebar guides.
- Created a **Welcome** tab highlighting key problems solved (Firewall, Cron optimization, stats, alerts, csv logs) and a services advertisement widget for Greg Miller / Shrinkray Labs.
- Added strict GET/POST tab whitelist validation to prevent fall-through rendering on malformed tab parameters.
- Replaced hardcoded version display in the sidebar with dynamic metadata extraction using `get_plugin_data()`.

### Changed
- Migrated settings tabs and sidebar shortcut links from raw relative strings to dynamically built URLs utilizing `admin_url()`, `network_admin_url()`, and `add_query_arg()`.

### Fixed
- Applied proper escaping functions (`esc_url()`, `esc_html()`, etc.) to all output links and attributes.
- Implemented accessibility remediations, including adding `aria-hidden="true"` to decorative icons and `rel="noopener noreferrer"` alongside descriptive screen-reader `aria-label` tags for external links.
