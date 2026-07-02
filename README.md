# UXPA Network Performance & Guard

A lightweight WordPress performance and security plugin designed specifically for multisite networks (supporting both network-wide activation and sub-site specific activation). It intercepts aggressive bot scanning early during bootstrap and prevents database serialization errors caused by `cron` options bloat.

## Features

### 🛡️ Early Interception of Bot Scanning
* **Author Query Blocking**: Instantly blocks requests targeting author archives via query arguments (e.g., `?author=N`) for unauthenticated users, terminating with a lightweight `403 Access Denied` response before heavy theme/query resources load.
* **REST API Protection**: Intercepts unauthenticated REST API queries to the users resource list (`/wp-json/wp/v2/users`) to prevent usernames from being harvested.
* **Logging Dashboard**: Keeps a rolling trace of the latest 10 blocked enumeration attempts showing timestamp, IP address, request type, and target query.

### ⚡ Cron Bloat Protection
* **Automatic Cron Pruning**: Intercepts updates to the core `cron` option (via `pre_update_option_cron` and `pre_update_site_option_cron`) to scan and prune duplicate scheduled events.
* **Size & Composition Diagnostics**: Displays the exact serialized size (in bytes/KB) of the target site's `cron` option database row and calculates hook frequency counts.
* **Adjustable Duplicate Limits**: Allows admins to set a threshold limit (default is `5`) for how many times a single hook is allowed to queue itself before subsequent duplicates are automatically cleaned.

---

## Activation Modes & Option Storage

The plugin adapts its interface and database usage depending on how it is activated on a WordPress Multisite network:

### 1. Network-Activated Mode
* **Location**: Registered under **Network Admin Settings -> UXPA Performance Guard**.
* **Storage**: Saves configuration settings and interception logs network-wide (`get_site_option` / `update_site_option`).
* **Cross-Site Inspection**: Adds a sub-site selector on the **Cron Health** tab, permitting super-administrators to switch blog contexts and inspect option sizes and composition across all network sub-sites.

### 2. Sub-Site Activated Mode (Individual Activation)
* **Location**: Registered under the local sub-site's **Settings -> UXPA Performance Guard** page.
* **Storage**: Saves configuration settings and interception logs locally in that sub-site's option tables (`get_option` / `update_option`). Logs and configurations are isolated per site.
* **Security Controls**: The sub-site selector on the **Cron Health** tab is hidden, preventing local administrators from accessing other sub-sites' data.

---

## Core Requirements
* PHP 7.4+
* WordPress 5.6+
