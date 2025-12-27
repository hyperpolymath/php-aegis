<?php

/**
 * SPDX-License-Identifier: MIT OR AGPL-3.0-or-later
 * SPDX-FileCopyrightText: 2024-2025 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis;

/**
 * HTTP Security Headers utilities.
 *
 * Provides easy-to-use methods for setting security headers.
 * Call these methods before any output is sent.
 */
final class Headers
{
    /**
     * Apply all recommended security headers with sensible defaults.
     *
     * This is the easiest way to secure your application - just call Headers::secure()
     * before sending any output.
     */
    public static function secure(): void
    {
        self::contentTypeOptions();
        self::frameOptions();
        self::xssProtection();
        self::referrerPolicy();
        self::strictTransportSecurity();
        self::contentSecurityPolicy([
            'default-src' => ["'self'"],
        ]);
    }

    /**
     * Set Content-Security-Policy header.
     *
     * @param array<string, array<string>> $directives CSP directives
     * @param bool $reportOnly If true, use Content-Security-Policy-Report-Only
     */
    public static function contentSecurityPolicy(array $directives, bool $reportOnly = false): void
    {
        $parts = [];

        foreach ($directives as $directive => $values) {
            if (empty($values)) {
                $parts[] = $directive;
            } else {
                $parts[] = $directive . ' ' . implode(' ', $values);
            }
        }

        $headerName = $reportOnly
            ? 'Content-Security-Policy-Report-Only'
            : 'Content-Security-Policy';

        header($headerName . ': ' . implode('; ', $parts));
    }

    /**
     * Set Strict-Transport-Security header (HSTS).
     *
     * @param int $maxAge Max age in seconds (default: 1 year)
     * @param bool $includeSubDomains Include subdomains
     * @param bool $preload Include in HSTS preload list
     */
    public static function strictTransportSecurity(
        int $maxAge = 31536000,
        bool $includeSubDomains = true,
        bool $preload = false
    ): void {
        $value = 'max-age=' . $maxAge;

        if ($includeSubDomains) {
            $value .= '; includeSubDomains';
        }

        if ($preload) {
            $value .= '; preload';
        }

        header('Strict-Transport-Security: ' . $value);
    }

    /**
     * Set X-Frame-Options header to prevent clickjacking.
     *
     * @param string $value DENY, SAMEORIGIN, or ALLOW-FROM uri
     */
    public static function frameOptions(string $value = 'DENY'): void
    {
        $allowed = ['DENY', 'SAMEORIGIN'];

        if (!in_array($value, $allowed, true) && !str_starts_with($value, 'ALLOW-FROM ')) {
            throw new \InvalidArgumentException(
                'X-Frame-Options must be DENY, SAMEORIGIN, or ALLOW-FROM uri'
            );
        }

        header('X-Frame-Options: ' . $value);
    }

    /**
     * Set X-Content-Type-Options to prevent MIME sniffing.
     */
    public static function contentTypeOptions(): void
    {
        header('X-Content-Type-Options: nosniff');
    }

    /**
     * Set X-XSS-Protection header.
     *
     * Note: This header is deprecated in modern browsers but still useful
     * for legacy browser support.
     *
     * @param bool $enable Enable XSS filter
     * @param bool $block Block page instead of sanitizing
     */
    public static function xssProtection(bool $enable = true, bool $block = true): void
    {
        if (!$enable) {
            header('X-XSS-Protection: 0');
            return;
        }

        $value = '1';
        if ($block) {
            $value .= '; mode=block';
        }

        header('X-XSS-Protection: ' . $value);
    }

    /**
     * Set Referrer-Policy header.
     *
     * @param string $policy Referrer policy value
     */
    public static function referrerPolicy(string $policy = 'strict-origin-when-cross-origin'): void
    {
        $allowed = [
            'no-referrer',
            'no-referrer-when-downgrade',
            'origin',
            'origin-when-cross-origin',
            'same-origin',
            'strict-origin',
            'strict-origin-when-cross-origin',
            'unsafe-url',
        ];

        if (!in_array($policy, $allowed, true)) {
            throw new \InvalidArgumentException(
                'Invalid Referrer-Policy: ' . $policy
            );
        }

        header('Referrer-Policy: ' . $policy);
    }

    /**
     * Set Permissions-Policy header (replaces Feature-Policy).
     *
     * @param array<string, array<string>> $permissions Feature permissions
     */
    public static function permissionsPolicy(array $permissions): void
    {
        $parts = [];

        foreach ($permissions as $feature => $allowlist) {
            if (empty($allowlist)) {
                $parts[] = $feature . '=()';
            } else {
                $quoted = array_map(
                    static fn(string $v): string => $v === 'self' ? 'self' : '"' . $v . '"',
                    $allowlist
                );
                $parts[] = $feature . '=(' . implode(' ', $quoted) . ')';
            }
        }

        header('Permissions-Policy: ' . implode(', ', $parts));
    }

    /**
     * Set Cross-Origin-Embedder-Policy header.
     *
     * @param string $policy require-corp, credentialless, or unsafe-none
     */
    public static function crossOriginEmbedderPolicy(string $policy = 'require-corp'): void
    {
        $allowed = ['require-corp', 'credentialless', 'unsafe-none'];

        if (!in_array($policy, $allowed, true)) {
            throw new \InvalidArgumentException(
                'Invalid Cross-Origin-Embedder-Policy: ' . $policy
            );
        }

        header('Cross-Origin-Embedder-Policy: ' . $policy);
    }

    /**
     * Set Cross-Origin-Opener-Policy header.
     *
     * @param string $policy same-origin, same-origin-allow-popups, or unsafe-none
     */
    public static function crossOriginOpenerPolicy(string $policy = 'same-origin'): void
    {
        $allowed = ['same-origin', 'same-origin-allow-popups', 'unsafe-none'];

        if (!in_array($policy, $allowed, true)) {
            throw new \InvalidArgumentException(
                'Invalid Cross-Origin-Opener-Policy: ' . $policy
            );
        }

        header('Cross-Origin-Opener-Policy: ' . $policy);
    }

    /**
     * Set Cross-Origin-Resource-Policy header.
     *
     * @param string $policy same-origin, same-site, or cross-origin
     */
    public static function crossOriginResourcePolicy(string $policy = 'same-origin'): void
    {
        $allowed = ['same-origin', 'same-site', 'cross-origin'];

        if (!in_array($policy, $allowed, true)) {
            throw new \InvalidArgumentException(
                'Invalid Cross-Origin-Resource-Policy: ' . $policy
            );
        }

        header('Cross-Origin-Resource-Policy: ' . $policy);
    }

    /**
     * Remove potentially dangerous headers that leak information.
     */
    public static function removeInsecureHeaders(): void
    {
        header_remove('X-Powered-By');
        header_remove('Server');
    }
}
