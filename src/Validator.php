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
}
