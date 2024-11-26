<?php
/*
Plugin Name: IP Access Logger and Ban with Whitelist
Description: Logs IP addresses, detects Cloudflare-proxied IPs, bans IPs for excessive access, allows whitelisting IPs, and cleans up old records.
Version: 1.41
Author: Conor Armstrong
*/

defined('ABSPATH') or die('No script kiddies please!');

class IPAccessLogger {
    private $log_table;
    private $whitelist_table;

    public function __construct() {
        global $wpdb;
        $this->log_table = $wpdb->prefix . 'ip_access_log';
        $this->whitelist_table = $wpdb->prefix . 'ip_whitelist';
        register_activation_hook(__FILE__, [$this, 'create_tables']);
        add_action('init', [$this, 'log_access']);
        add_action('init', [$this, 'check_and_ban']);
        add_action('init', [$this, 'cleanup_table']);
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_post_add_whitelist_ip', [$this, 'add_whitelist_ip']);
        add_action('admin_post_remove_whitelist_ip', [$this, 'remove_whitelist_ip']);
    }

    public function create_tables() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        $log_sql = "CREATE TABLE {$this->log_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(45) NOT NULL,
            accessed_at DATETIME NOT NULL,
            banned_until DATETIME NOT NULL DEFAULT '2000-01-01 00:00:00',
            PRIMARY KEY (id),
            INDEX idx_ip_address (ip_address),
            INDEX idx_banned_until (banned_until)
	) $charset_collate;";

        $whitelist_sql = "CREATE TABLE {$this->whitelist_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(45) NOT NULL UNIQUE,
            PRIMARY KEY (id)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($log_sql);
        dbDelta($whitelist_sql);
    }

    private function get_client_ip() {
        if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return $_SERVER['HTTP_CF_CONNECTING_IP']; // Original IP via Cloudflare
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'; // Fallback
    }

    private function is_whitelisted($ip_address) {
        global $wpdb;
        $result = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->whitelist_table} WHERE ip_address = %s",
            $ip_address
        ));
        return $result > 0;
    }

    public function log_access() {
        global $wpdb;
        $ip_address = $this->get_client_ip();

        // Skip logging and banning for whitelisted IPs
        if ($this->is_whitelisted($ip_address)) {
            return;
        }

        $now = current_time('mysql');
        $wpdb->insert($this->log_table, [
            'ip_address' => $ip_address,
            'accessed_at' => $now,
        ]);

	// Check if the IP is currently banned
        $banned_until = $wpdb->get_var($wpdb->prepare(
            "SELECT banned_until FROM {$this->log_table} WHERE ip_address = %s ORDER BY banned_until DESC LIMIT 1",
            $ip_address
	));

	if ($banned_until && strtotime($banned_until) > time()) {
            header('HTTP/1.1 429 Too Many Requests');
            die('Your IP is temporarily banned due to excessive requests.');
	}
    }

    public function check_and_ban() {
        global $wpdb;
        $now = current_time('mysql');
        $one_minute_ago = date('Y-m-d H:i:s', strtotime('-1 minute'));

        // Get IPs with more than 50 accesses in the last minute
        $ips_to_ban = $wpdb->get_col($wpdb->prepare(
            "SELECT ip_address FROM {$this->log_table} 
             WHERE accessed_at > %s 
             GROUP BY ip_address 
             HAVING COUNT(*) > 20",
            $one_minute_ago
        ));

        foreach ($ips_to_ban as $ip) {
            // Skip banning for whitelisted IPs
            if ($this->is_whitelisted($ip)) {
                continue;
            }
            $wpdb->update($this->log_table, 
                ['banned_until' => date('Y-m-d H:i:s', strtotime('+10 minutes'))], 
                ['ip_address' => $ip]
            );
        }
    }

    public function cleanup_table() {
        global $wpdb;
        $one_hour_ago = date('Y-m-d H:i:s', strtotime('-1 hour'));
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$this->log_table} WHERE accessed_at < %s",
            $one_hour_ago
        ));
    }

    public function add_admin_menu() {
        add_menu_page(
            'IP Logs and Whitelist',
            'IP Logs',
            'manage_options',
            'ip-access-logger',
            [$this, 'admin_interface'],
            'dashicons-shield',
            20
        );
    }

public function admin_interface() {
    global $wpdb;
    $banned_ips = $wpdb->get_results("
        SELECT ip_address, MAX(banned_until) AS banned_until 
        FROM {$this->log_table} 
	WHERE banned_until IS NOT NULL
        AND banned_until >= CURRENT_TIMESTAMP 
        GROUP BY ip_address 
        ORDER BY banned_until DESC
    ");
    $access_logs = $wpdb->get_results("
        SELECT ip_address, COUNT(*) AS access_count, MAX(accessed_at) AS last_access 
        FROM {$this->log_table} 
        GROUP BY ip_address 
        ORDER BY last_access DESC 
        LIMIT 20
    ");
    $whitelist_ips = $wpdb->get_results("
        SELECT ip_address 
        FROM {$this->whitelist_table} 
        ORDER BY ip_address ASC
    ");

    echo '<div class="wrap">';
    echo '<h1>IP Logs and Whitelist</h1>';

    // Whitelist Management
    echo '<h2>Whitelisted IPs</h2>';
    echo '<table class="wp-list-table widefat fixed striped">';
    echo '<thead><tr><th>IP Address</th><th>Actions</th></tr></thead><tbody>';
    foreach ($whitelist_ips as $ip) {
        echo '<tr>';
        echo '<td>' . esc_html($ip->ip_address) . '</td>';
        echo '<td><form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="remove_whitelist_ip">';
        echo '<input type="hidden" name="ip_address" value="' . esc_attr($ip->ip_address) . '">';
        echo '<button type="submit" class="button">Remove</button>';
        echo '</form></td>';
        echo '</tr>';
    }
    echo '</tbody></table>';
    echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
    echo '<input type="hidden" name="action" value="add_whitelist_ip">';
    echo '<input type="text" name="ip_address" placeholder="IP Address" required>';
    echo '<button type="submit" class="button">Add to Whitelist</button>';
    echo '</form>';

    // Banned IPs
    echo '<h2>Banned IPs</h2>';
    echo '<table class="wp-list-table widefat fixed striped">';
    echo '<thead><tr><th>IP Address</th><th>Banned Until</th><th>Actions</th></tr></thead><tbody>';
    foreach ($banned_ips as $ip) {
        echo '<tr>';
	echo '<td><a href="https://whatismyipaddress.com/ip/' . esc_attr($ip->ip_address) . '" target="_blank" rel="noopener noreferrer">' . esc_html($ip->ip_address) . '</a></td>';
        echo '<td>' . esc_html($ip->banned_until) . '</td>';
        echo '<td><form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="unban_ip">';
        echo '<input type="hidden" name="ip_address" value="' . esc_attr($ip->ip_address) . '">';
        echo '<button type="submit" class="button">Unban</button>';
        echo '</form></td>';
        echo '</tr>';
    }
    echo '</tbody></table>';

    // Access Logs
    echo '<h2>Access Logs</h2>';
    echo '<table class="wp-list-table widefat fixed striped">';
    echo '<thead><tr><th>IP Address</th><th>Access Count</th><th>Last Access</th></tr></thead><tbody>';
    foreach ($access_logs as $log) {
        echo '<tr>';
	echo '<td><a href="https://whatismyipaddress.com/ip/' . esc_attr($log->ip_address) . '" target="_blank" rel="noopener noreferrer">' . esc_html($log->ip_address) . '</a></td>';

        echo '<td>' . esc_html($log->access_count) . '</td>';
        echo '<td>' . esc_html($log->last_access) . '</td>';
        echo '</tr>';
    }
    echo '</tbody></table>';

    echo '</div>';
}

    public function add_whitelist_ip() {
        if (!current_user_can('manage_options') || !isset($_POST['ip_address'])) {
            wp_die('Unauthorized action');
        }

        global $wpdb;
        $ip_address = sanitize_text_field($_POST['ip_address']);
        $wpdb->insert($this->whitelist_table, ['ip_address' => $ip_address]);
        wp_redirect(admin_url('admin.php?page=ip-access-logger'));
        exit;
    }

    public function remove_whitelist_ip() {
        if (!current_user_can('manage_options') || !isset($_POST['ip_address'])) {
            wp_die('Unauthorized action');
        }

        global $wpdb;
        $ip_address = sanitize_text_field($_POST['ip_address']);
        $wpdb->delete($this->whitelist_table, ['ip_address' => $ip_address]);
        wp_redirect(admin_url('admin.php?page=ip-access-logger'));
        exit;
    }
}

new IPAccessLogger();

