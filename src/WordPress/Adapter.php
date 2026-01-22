<?php

/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\WordPress;

use PhpAegis\Validator;
use PhpAegis\Sanitizer;
use PhpAegis\TurtleEscaper;
use PhpAegis\Headers;

/**
 * WordPress adapter functions following WordPress naming conventions.
 *
 * These functions provide WordPress-style wrappers around php-aegis methods
 * for developers familiar with esc_html(), esc_attr(), etc.
 *
 * All functions check if they're already defined to avoid conflicts.
 */

if (!function_exists('aegis_html')) {
    /**
     * Escape for HTML content context (prevents XSS).
     *
     * WordPress equivalent: esc_html()
     *
     * @param string $input Raw user input
     * @return string HTML-safe output
     */
    function aegis_html(string $input): string
    {
        return Sanitizer::html($input);
    }
}

if (!function_exists('aegis_attr')) {
    /**
     * Escape for HTML attribute context.
     *
     * WordPress equivalent: esc_attr()
     *
     * @param string $input Raw user input
     * @return string Attribute-safe output
     */
    function aegis_attr(string $input): string
    {
        return Sanitizer::attr($input);
    }
}

if (!function_exists('aegis_js')) {
    /**
     * Escape for JavaScript string context.
     *
     * WordPress equivalent: esc_js()
     *
     * @param string $input Raw user input
     * @return string JavaScript-safe output
     */
    function aegis_js(string $input): string
    {
        return Sanitizer::js($input);
    }
}

if (!function_exists('aegis_url')) {
    /**
     * Encode for URL parameter context.
     *
     * WordPress equivalent: esc_url() (though WP does more validation)
     *
     * @param string $input Raw URL component
     * @return string URL-encoded output
     */
    function aegis_url(string $input): string
    {
        return Sanitizer::url($input);
    }
}

if (!function_exists('aegis_css')) {
    /**
     * Escape for CSS string context.
     *
     * WordPress equivalent: esc_css() (WP doesn't have this)
     *
     * @param string $input Raw CSS value
     * @return string CSS-safe output
     */
    function aegis_css(string $input): string
    {
        return Sanitizer::css($input);
    }
}

if (!function_exists('aegis_json')) {
    /**
     * Safe JSON encoding with security flags.
     *
     * WordPress equivalent: wp_json_encode()
     *
     * @param mixed $input Data to encode
     * @return string JSON output
     */
    function aegis_json(mixed $input): string
    {
        return Sanitizer::json($input);
    }
}

if (!function_exists('aegis_strip_tags')) {
    /**
     * Remove all HTML/PHP tags from input.
     *
     * WordPress equivalent: wp_strip_all_tags()
     *
     * @param string $input HTML content
     * @return string Plain text
     */
    function aegis_strip_tags(string $input): string
    {
        return Sanitizer::stripTags($input);
    }
}

if (!function_exists('aegis_filename')) {
    /**
     * Sanitize filename (remove path components and dangerous characters).
     *
     * WordPress equivalent: sanitize_file_name()
     *
     * @param string $input Raw filename
     * @return string Safe filename
     */
    function aegis_filename(string $input): string
    {
        return Sanitizer::filename($input);
    }
}

// ============================================================================
// RDF/Turtle Functions (UNIQUE - WordPress doesn't have these!)
// ============================================================================

if (!function_exists('aegis_turtle_string')) {
    /**
     * Escape string for Turtle string literal.
     *
     * UNIQUE FEATURE: No WordPress equivalent!
     * Essential for semantic web themes outputting RDF Turtle.
     *
     * @param string $input Raw string content
     * @return string Turtle-escaped string
     */
    function aegis_turtle_string(string $input): string
    {
        return TurtleEscaper::string($input);
    }
}

if (!function_exists('aegis_turtle_iri')) {
    /**
     * Escape and validate IRI for Turtle.
     *
     * UNIQUE FEATURE: No WordPress equivalent!
     *
     * @param string $iri Raw IRI
     * @return string Turtle-safe IRI
     */
    function aegis_turtle_iri(string $iri): string
    {
        return TurtleEscaper::iri($iri);
    }
}

if (!function_exists('aegis_turtle_literal')) {
    /**
     * Build complete Turtle literal with language tag or datatype.
     *
     * UNIQUE FEATURE: No WordPress equivalent!
     *
     * @param string $value Literal value
     * @param string|null $language Language tag (e.g., 'en', 'fr')
     * @param string|null $datatype Datatype IRI (e.g., 'xsd:integer')
     * @return string Complete Turtle literal
     */
    function aegis_turtle_literal(
        string $value,
        ?string $language = null,
        ?string $datatype = null
    ): string {
        return TurtleEscaper::literal($value, $language, $datatype);
    }
}

if (!function_exists('aegis_turtle_triple')) {
    /**
     * Build complete RDF triple in Turtle syntax.
     *
     * UNIQUE FEATURE: No WordPress equivalent!
     *
     * @param string $subject Subject IRI
     * @param string $predicate Predicate IRI
     * @param string $object Object value
     * @param string|null $language Optional language tag
     * @return string Complete Turtle triple
     */
    function aegis_turtle_triple(
        string $subject,
        string $predicate,
        string $object,
        ?string $language = null
    ): string {
        return TurtleEscaper::triple($subject, $predicate, $object, $language);
    }
}

// ============================================================================
// Validation Functions
// ============================================================================

if (!function_exists('aegis_validate_email')) {
    /**
     * Validate email address.
     *
     * WordPress equivalent: is_email()
     *
     * @param string $email Email to validate
     * @return bool True if valid
     */
    function aegis_validate_email(string $email): bool
    {
        return Validator::email($email);
    }
}

if (!function_exists('aegis_validate_url')) {
    /**
     * Validate URL.
     *
     * WordPress equivalent: wp_http_validate_url()
     *
     * @param string $url URL to validate
     * @param bool $httpsOnly Require HTTPS (default: false)
     * @return bool True if valid
     */
    function aegis_validate_url(string $url, bool $httpsOnly = false): bool
    {
        return $httpsOnly ? Validator::httpsUrl($url) : Validator::url($url);
    }
}

if (!function_exists('aegis_validate_ip')) {
    /**
     * Validate IP address (v4 or v6).
     *
     * WordPress equivalent: rest_is_ip_address()
     *
     * @param string $ip IP address
     * @return bool True if valid
     */
    function aegis_validate_ip(string $ip): bool
    {
        return Validator::ip($ip);
    }
}

if (!function_exists('aegis_validate_uuid')) {
    /**
     * Validate UUID (RFC 4122).
     *
     * UNIQUE FEATURE: No WordPress equivalent!
     *
     * @param string $uuid UUID string
     * @return bool True if valid
     */
    function aegis_validate_uuid(string $uuid): bool
    {
        return Validator::uuid($uuid);
    }
}

if (!function_exists('aegis_validate_slug')) {
    /**
     * Validate URL-safe slug.
     *
     * WordPress equivalent: sanitize_title_with_dashes() (but that sanitizes, doesn't validate)
     *
     * @param string $slug Slug to validate
     * @return bool True if valid
     */
    function aegis_validate_slug(string $slug): bool
    {
        return Validator::slug($slug);
    }
}

if (!function_exists('aegis_validate_json')) {
    /**
     * Validate JSON string.
     *
     * UNIQUE FEATURE: No WordPress equivalent!
     *
     * @param string $json JSON to validate
     * @return bool True if valid
     */
    function aegis_validate_json(string $json): bool
    {
        return Validator::json($json);
    }
}

if (!function_exists('aegis_validate_semver')) {
    /**
     * Validate semantic version string.
     *
     * UNIQUE FEATURE: No WordPress equivalent!
     *
     * @param string $version Version string (e.g., "1.2.3-beta.1")
     * @return bool True if valid
     */
    function aegis_validate_semver(string $version): bool
    {
        return Validator::semver($version);
    }
}

if (!function_exists('aegis_validate_domain')) {
    /**
     * Validate domain name.
     *
     * UNIQUE FEATURE: No WordPress equivalent!
     *
     * @param string $domain Domain name
     * @return bool True if valid
     */
    function aegis_validate_domain(string $domain): bool
    {
        return Validator::domain($domain);
    }
}

// ============================================================================
// Security Headers
// ============================================================================

if (!function_exists('aegis_send_security_headers')) {
    /**
     * Apply all recommended security headers.
     *
     * UNIQUE FEATURE: WordPress doesn't provide header helpers!
     *
     * Call this on 'send_headers' action:
     * add_action('send_headers', 'aegis_send_security_headers');
     */
    function aegis_send_security_headers(): void
    {
        if (!headers_sent()) {
            Headers::secure();
        }
    }
}

if (!function_exists('aegis_csp')) {
    /**
     * Set Content Security Policy header.
     *
     * UNIQUE FEATURE: WordPress doesn't have CSP helpers!
     *
     * @param array<string, string[]> $directives CSP directives
     */
    function aegis_csp(array $directives): void
    {
        if (!headers_sent()) {
            Headers::contentSecurityPolicy($directives);
        }
    }
}

if (!function_exists('aegis_hsts')) {
    /**
     * Set Strict-Transport-Security header.
     *
     * UNIQUE FEATURE: WordPress doesn't have HSTS helpers!
     *
     * @param int $maxAge Max age in seconds (default: 1 year)
     * @param bool $includeSubdomains Include subdomains
     * @param bool $preload Enable HSTS preload
     */
    function aegis_hsts(
        int $maxAge = 31536000,
        bool $includeSubdomains = true,
        bool $preload = false
    ): void {
        if (!headers_sent()) {
            Headers::strictTransportSecurity($maxAge, $includeSubdomains, $preload);
        }
    }
}
