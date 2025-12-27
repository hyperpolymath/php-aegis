<?php

/**
 * SPDX-License-Identifier: MIT OR AGPL-3.0-or-later
 * SPDX-FileCopyrightText: 2024-2025 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis;

/**
 * Input validation utilities.
 *
 * All methods are static for convenience - no instance state is needed.
 */
final class Validator
{
    /**
     * Validate email address.
     */
    public static function email(string $email): bool
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * Validate URL.
     */
    public static function url(string $url): bool
    {
        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }

    /**
     * Validate URL is HTTPS (security requirement).
     */
    public static function httpsUrl(string $url): bool
    {
        if (!self::url($url)) {
            return false;
        }

        $scheme = parse_url($url, PHP_URL_SCHEME);
        return $scheme === 'https';
    }

    /**
     * Validate IPv4 address.
     */
    public static function ipv4(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    /**
     * Validate IPv6 address.
     */
    public static function ipv6(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    /**
     * Validate IP address (v4 or v6).
     */
    public static function ip(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * Validate UUID (RFC 4122).
     */
    public static function uuid(string $uuid): bool
    {
        $pattern = '/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';
        return preg_match($pattern, $uuid) === 1;
    }

    /**
     * Validate URL-safe slug.
     */
    public static function slug(string $slug): bool
    {
        return preg_match('/^[a-z0-9]+(?:-[a-z0-9]+)*$/', $slug) === 1;
    }

    /**
     * Validate string contains no null bytes (path traversal prevention).
     */
    public static function noNullBytes(string $input): bool
    {
        return strpos($input, "\0") === false;
    }

    /**
     * Validate filename is safe (no path traversal).
     */
    public static function safeFilename(string $filename): bool
    {
        if (!self::noNullBytes($filename)) {
            return false;
        }

        // Reject path separators and traversal
        if (preg_match('/[\/\\\\]/', $filename)) {
            return false;
        }

        // Reject . and ..
        if ($filename === '.' || $filename === '..') {
            return false;
        }

        // Reject hidden files (Unix convention)
        if (str_starts_with($filename, '.')) {
            return false;
        }

        return true;
    }

    /**
     * Validate JSON string.
     */
    public static function json(string $json): bool
    {
        json_decode($json);
        return json_last_error() === JSON_ERROR_NONE;
    }

    /**
     * Validate integer (string representation).
     *
     * @param string $value The string to validate
     * @param int|null $min Optional minimum value
     * @param int|null $max Optional maximum value
     */
    public static function int(string $value, ?int $min = null, ?int $max = null): bool
    {
        $options = [];

        if ($min !== null) {
            $options['min_range'] = $min;
        }

        if ($max !== null) {
            $options['max_range'] = $max;
        }

        $result = filter_var(
            $value,
            FILTER_VALIDATE_INT,
            empty($options) ? [] : ['options' => $options]
        );

        return $result !== false;
    }

    /**
     * Validate domain name.
     *
     * Validates according to RFC 1035 with modern extensions.
     */
    public static function domain(string $domain): bool
    {
        // Must not be empty and must not exceed 253 characters
        if ($domain === '' || strlen($domain) > 253) {
            return false;
        }

        // Each label must be 1-63 characters, alphanumeric with hyphens (not at start/end)
        $pattern = '/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/';

        if (!preg_match($pattern, $domain)) {
            return false;
        }

        // TLD must be at least 2 characters and alphabetic (or valid IDN)
        $parts = explode('.', $domain);
        $tld = end($parts);

        return strlen($tld) >= 2 && preg_match('/^[a-zA-Z]+$/', $tld) === 1;
    }

    /**
     * Validate hostname (domain or IP).
     */
    public static function hostname(string $host): bool
    {
        return self::domain($host) || self::ip($host);
    }

    /**
     * Validate string contains only printable ASCII characters.
     */
    public static function printable(string $input): bool
    {
        // Printable ASCII: 0x20 (space) to 0x7E (~)
        return preg_match('/^[\x20-\x7E]*$/', $input) === 1;
    }

    /**
     * Validate semantic version string (semver).
     */
    public static function semver(string $version): bool
    {
        // SemVer 2.0.0 pattern
        $pattern = '/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/';
        return preg_match($pattern, $version) === 1;
    }

    /**
     * Validate ISO 8601 datetime string.
     */
    public static function iso8601(string $datetime): bool
    {
        // Common ISO 8601 formats
        $formats = [
            'Y-m-d',
            'Y-m-d\TH:i:s',
            'Y-m-d\TH:i:sP',
            'Y-m-d\TH:i:s.uP',
            'Y-m-d\TH:i:s\Z',
            'Y-m-d\TH:i:s.u\Z',
        ];

        foreach ($formats as $format) {
            $parsed = \DateTimeImmutable::createFromFormat($format, $datetime);
            if ($parsed !== false && $parsed->format($format) === $datetime) {
                return true;
            }
        }

        return false;
    }

    /**
     * Validate hex color code.
     */
    public static function hexColor(string $color): bool
    {
        return preg_match('/^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/', $color) === 1;
    }
}
