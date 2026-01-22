<?php
/**
 * Load php-aegis WordPress adapter functions
 *
 * This file loads all aegis_* functions for use in WordPress themes and plugins.
 *
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Ensure php-aegis classes are available
if (!class_exists('PhpAegis\\Sanitizer')) {
    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('php-aegis classes not found. Please ensure Composer autoloader is loaded.');
    }
    return;
}

// Load WordPress adapter functions
require_once dirname(dirname(__DIR__)) . '/src/WordPress/Adapter.php';

/**
 * Check if php-aegis is properly loaded
 *
 * @return bool True if php-aegis is available
 */
function aegis_is_loaded(): bool
{
    return function_exists('aegis_html')
        && function_exists('aegis_turtle_literal')
        && class_exists('PhpAegis\\Sanitizer');
}

/**
 * Get php-aegis version
 *
 * @return string Version string
 */
function aegis_version(): string
{
    return '0.2.0';
}

/**
 * Get list of all available aegis functions
 *
 * @return array<string, string> Function name => description
 */
function aegis_get_functions(): array
{
    return [
        // Sanitization
        'aegis_html' => 'Escape for HTML content (like esc_html)',
        'aegis_attr' => 'Escape for HTML attributes (like esc_attr)',
        'aegis_js' => 'Escape for JavaScript strings (like esc_js)',
        'aegis_url' => 'URL encode (like esc_url)',
        'aegis_css' => 'Escape for CSS values',
        'aegis_json' => 'Safe JSON encoding (like wp_json_encode)',
        'aegis_strip_tags' => 'Remove HTML tags (like wp_strip_all_tags)',
        'aegis_filename' => 'Sanitize filename (like sanitize_file_name)',

        // RDF/Turtle (UNIQUE)
        'aegis_turtle_string' => 'Escape string for Turtle literal',
        'aegis_turtle_iri' => 'Escape IRI for Turtle',
        'aegis_turtle_literal' => 'Build complete Turtle literal with language',
        'aegis_turtle_triple' => 'Build complete RDF triple',

        // Validation
        'aegis_validate_email' => 'Validate email (like is_email)',
        'aegis_validate_url' => 'Validate URL (like wp_http_validate_url)',
        'aegis_validate_ip' => 'Validate IP address',
        'aegis_validate_uuid' => 'Validate UUID (RFC 4122)',
        'aegis_validate_slug' => 'Validate URL slug',
        'aegis_validate_json' => 'Validate JSON string',
        'aegis_validate_semver' => 'Validate semantic version',
        'aegis_validate_domain' => 'Validate domain name',

        // Security Headers
        'aegis_send_security_headers' => 'Apply all security headers',
        'aegis_csp' => 'Set Content-Security-Policy',
        'aegis_hsts' => 'Set Strict-Transport-Security',
    ];
}

/**
 * Output available functions as HTML list (for admin dashboard)
 *
 * @return void
 */
function aegis_print_functions(): void
{
    $functions = aegis_get_functions();

    echo '<h3>Sanitization Functions</h3>';
    echo '<ul style="font-family: monospace; font-size: 11px;">';
    foreach (array_slice($functions, 0, 8) as $func => $desc) {
        printf(
            '<li><strong>%s</strong> - %s</li>',
            esc_html($func . '()'),
            esc_html($desc)
        );
    }
    echo '</ul>';

    echo '<h3>RDF/Turtle Functions (Unique!)</h3>';
    echo '<ul style="font-family: monospace; font-size: 11px;">';
    foreach (array_slice($functions, 8, 4) as $func => $desc) {
        printf(
            '<li><strong>%s</strong> - %s</li>',
            esc_html($func . '()'),
            esc_html($desc)
        );
    }
    echo '</ul>';

    echo '<h3>Validation Functions</h3>';
    echo '<ul style="font-family: monospace; font-size: 11px;">';
    foreach (array_slice($functions, 12, 8) as $func => $desc) {
        printf(
            '<li><strong>%s</strong> - %s</li>',
            esc_html($func . '()'),
            esc_html($desc)
        );
    }
    echo '</ul>';

    echo '<h3>Security Header Functions</h3>';
    echo '<ul style="font-family: monospace; font-size: 11px;">';
    foreach (array_slice($functions, 20, 3) as $func => $desc) {
        printf(
            '<li><strong>%s</strong> - %s</li>',
            esc_html($func . '()'),
            esc_html($desc)
        );
    }
    echo '</ul>';
}
