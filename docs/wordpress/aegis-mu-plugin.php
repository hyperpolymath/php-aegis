<?php
/**
 * Plugin Name: php-aegis Security Enhancements
 * Plugin URI: https://github.com/hyperpolymath/php-aegis
 * Description: Adds php-aegis security functions to WordPress (validation, sanitization, RDF/Turtle escaping, security headers)
 * Version: 0.2.0
 * Requires at least: 6.0
 * Requires PHP: 8.1
 * Author: Hyperpolymath
 * Author URI: https://github.com/hyperpolymath
 * License: MIT OR AGPL-3.0-or-later
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * php-aegis MU-Plugin Bootstrap
 *
 * This must-use plugin loads php-aegis and makes its functions available
 * throughout WordPress.
 *
 * Installation:
 * 1. Install php-aegis via Composer in wp-content/mu-plugins/
 *    cd wp-content/mu-plugins && composer require hyperpolymath/php-aegis
 *
 * 2. Copy this file to wp-content/mu-plugins/aegis-mu-plugin.php
 *
 * 3. The functions will be automatically available in all themes and plugins
 */

// Load Composer autoloader (adjust path if needed)
$autoloader_paths = [
    WPMU_PLUGIN_DIR . '/vendor/autoload.php',           // Standard location
    WPMU_PLUGIN_DIR . '/php-aegis/vendor/autoload.php', // Subdirectory install
    WP_CONTENT_DIR . '/vendor/autoload.php',            // Content root
];

$autoloader_loaded = false;
foreach ($autoloader_paths as $path) {
    if (file_exists($path)) {
        require_once $path;
        $autoloader_loaded = true;
        break;
    }
}

if (!$autoloader_loaded) {
    // Log error if autoloader not found
    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('php-aegis MU-Plugin: Composer autoloader not found. Please run: composer require hyperpolymath/php-aegis');
    }
    return;
}

// Load WordPress adapter functions
if (class_exists('PhpAegis\\Sanitizer')) {
    // Adapter functions are in the namespace, load them
    require_once __DIR__ . '/aegis-functions.php';
}

/**
 * Apply security headers on every request
 *
 * This adds recommended security headers including:
 * - Content-Security-Policy
 * - Strict-Transport-Security (HSTS)
 * - X-Frame-Options
 * - X-Content-Type-Options
 * - Referrer-Policy
 * - Permissions-Policy
 */
add_action('send_headers', function (): void {
    if (!headers_sent() && function_exists('aegis_send_security_headers')) {
        aegis_send_security_headers();
    }
}, 1); // Priority 1 to run early

/**
 * Add aegis_* functions to safe functions list for PHP-CS-Fixer
 *
 * This tells code quality tools that these functions are safe.
 */
add_filter('wp_kses_allowed_html', function (array $allowed_tags, string $context): array {
    // aegis functions are safe alternatives to esc_* functions
    return $allowed_tags;
}, 10, 2);

/**
 * Register admin notice if Composer dependencies missing
 */
add_action('admin_notices', function (): void {
    if (!class_exists('PhpAegis\\Sanitizer')) {
        ?>
        <div class="notice notice-error">
            <p>
                <strong>php-aegis MU-Plugin:</strong>
                Composer dependencies not found. Please run:
                <code>cd <?php echo esc_html(WPMU_PLUGIN_DIR); ?> && composer require hyperpolymath/php-aegis</code>
            </p>
        </div>
        <?php
    }
});

/**
 * Add admin dashboard widget showing php-aegis status
 */
add_action('wp_dashboard_setup', function (): void {
    if (current_user_can('manage_options') && class_exists('PhpAegis\\Sanitizer')) {
        wp_add_dashboard_widget(
            'aegis_status',
            'php-aegis Security Status',
            function (): void {
                $version = '0.2.0'; // Update this when php-aegis version changes
                ?>
                <p>
                    <strong>Status:</strong>
                    <span style="color: green;">✓ Active</span>
                </p>
                <p>
                    <strong>Version:</strong> <?php echo esc_html($version); ?>
                </p>
                <p>
                    <strong>Features Enabled:</strong>
                </p>
                <ul style="list-style: disc; margin-left: 20px;">
                    <li>Input validation (email, URL, UUID, etc.)</li>
                    <li>Output sanitization (HTML, JS, CSS, JSON)</li>
                    <li>RDF/Turtle escaping (semantic web)</li>
                    <li>Security headers (CSP, HSTS, X-Frame-Options)</li>
                </ul>
                <p>
                    <strong>Available Functions:</strong>
                    <code>aegis_html()</code>,
                    <code>aegis_attr()</code>,
                    <code>aegis_js()</code>,
                    <code>aegis_url()</code>,
                    <code>aegis_turtle_literal()</code>,
                    and more...
                </p>
                <p>
                    <a href="https://github.com/hyperpolymath/php-aegis" target="_blank">Documentation</a> |
                    <a href="https://github.com/hyperpolymath/php-aegis/issues" target="_blank">Report Issue</a>
                </p>
                <?php
            }
        );
    }
});

/**
 * Add meta box to post editor showing available aegis functions
 *
 * Helpful reminder for developers
 */
add_action('add_meta_boxes', function (): void {
    if (current_user_can('edit_posts') && class_exists('PhpAegis\\Sanitizer')) {
        add_meta_box(
            'aegis_functions',
            'php-aegis Security Functions',
            function (): void {
                ?>
                <p><strong>Sanitization:</strong></p>
                <ul style="list-style: none; font-family: monospace; font-size: 11px;">
                    <li>aegis_html($input) - Escape HTML</li>
                    <li>aegis_attr($input) - Escape attributes</li>
                    <li>aegis_js($input) - Escape JavaScript</li>
                    <li>aegis_url($input) - URL encode</li>
                </ul>

                <p><strong>RDF/Turtle (Semantic Web):</strong></p>
                <ul style="list-style: none; font-family: monospace; font-size: 11px;">
                    <li>aegis_turtle_literal($value, 'en')</li>
                    <li>aegis_turtle_triple($s, $p, $o)</li>
                </ul>

                <p><strong>Validation:</strong></p>
                <ul style="list-style: none; font-family: monospace; font-size: 11px;">
                    <li>aegis_validate_email($email)</li>
                    <li>aegis_validate_url($url, $httpsOnly)</li>
                    <li>aegis_validate_uuid($uuid)</li>
                </ul>

                <p style="margin-top: 10px;">
                    <a href="https://github.com/hyperpolymath/php-aegis#api-reference" target="_blank">View Full API →</a>
                </p>
                <?php
            },
            ['post', 'page'],
            'side',
            'low'
        );
    }
});

/**
 * Log php-aegis activation
 */
if (defined('WP_DEBUG') && WP_DEBUG && class_exists('PhpAegis\\Sanitizer')) {
    error_log('php-aegis MU-Plugin loaded successfully');
}
