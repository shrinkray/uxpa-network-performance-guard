# Changelog

All notable changes to the **UXPA Network Performance & Guard** plugin will be documented in this file.

## [Unreleased]

### Added
- Added independent web-host IP block tracking alongside edge blocking.
- Added separate edge and web-host status badges, toggle actions, counters, and copyable IP lists to the security dashboard.

### Fixed
- Normalized stored block lists before rendering and returning AJAX responses so only valid IP addresses are displayed and JSON lists remain consistently encoded as arrays.
- Preserved flex alignment when dynamically showing block-list copy buttons.

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
