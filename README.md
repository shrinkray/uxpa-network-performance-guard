# UXPA Network Performance & Guard

A lightweight WordPress performance and security plugin designed specifically for multisite networks (with single-site fallback support). It intercepts aggressive bot scanning early during bootstrap and prevents database serialization errors caused by `cron` options bloat.

## Features

### 🛡️ Early Interception of Bot Scanning
* **Author Query Blocking**: Instantly blocks requests targeting author archives via query arguments (e.g., `?author=N`) for unauthenticated users, terminating with a lightweight `403 Access Denied` response before heavy theme/query resources load.
* **REST API Protection**: Intercepts unauthenticated REST API queries to the users resource list (`/wp-json/wp/v2/users`) to prevent usernames from being harvested.
* **Logging Dashboard**: Keeps a rolling trace of the latest 10 blocked enumeration attempts showing timestamp, IP address, request type, and target query.

### ⚡ Cron Bloat Protection
* **Automatic Cron Pruning**: Intercepts updates to the core `cron` option (via `pre_update_option_cron` and `pre_update_site_option_cron`) to scan and prune duplicate scheduled events.
* **Size & Composition Diagnostics**: Displays the exact serialized size (in bytes/KB) of the main site's `cron` option database row and calculates hook frequency counts.
* **Adjustable Duplicate Limits**: Allows network admins to set a threshold limit (default is `5`) for how many times a single hook is allowed to queue itself before subsequent duplicates are automatically cleaned.

---

## Architecture & Configuration

The settings page supports a tabbed interface available under the settings panel:
* **Multisite Networks**: Accessible network-wide via **Network Admin Settings -> UXPA Performance Guard**.
* **Single-site Installs**: Gracefully falls back to standard **Settings -> UXPA Performance Guard**.

### Core Requirements
* PHP 7.4+
* WordPress 5.6+
