<?php

/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\IndieWeb;

use PhpAegis\Validator;

/**
 * Webmention security utilities with SSRF prevention.
 *
 * Webmentions allow websites to notify each other when one links to another.
 * This class provides critical SSRF (Server-Side Request Forgery) protection.
 *
 * @link https://www.w3.org/TR/webmention/
 */
final class Webmention
{
    /**
     * Private IPv4 ranges (RFC 1918, RFC 6598, loopback, link-local).
     *
     * @var array<string, array{string, string}>
     */
    private const PRIVATE_IPV4_RANGES = [
        ['10.0.0.0', '10.255.255.255'],           // RFC 1918: 10.0.0.0/8
        ['172.16.0.0', '172.31.255.255'],         // RFC 1918: 172.16.0.0/12
        ['192.168.0.0', '192.168.255.255'],       // RFC 1918: 192.168.0.0/16
        ['127.0.0.0', '127.255.255.255'],         // Loopback: 127.0.0.0/8
        ['169.254.0.0', '169.254.255.255'],       // Link-local: 169.254.0.0/16
        ['100.64.0.0', '100.127.255.255'],        // RFC 6598: 100.64.0.0/10
    ];

    /**
     * Check if IP address is internal/private (SSRF prevention).
     *
     * This prevents Webmention source URLs from targeting internal IPs,
     * which could be used to probe internal network infrastructure.
     *
     * @param string $ip IP address to check
     * @return bool True if internal/private
     */
    public static function isInternalIp(string $ip): bool
    {
        if (!Validator::ip($ip)) {
            return false;
        }

        // Use PHP's built-in filter first (most reliable)
        $filtered = filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );

        // If filter_var says it's private, trust it
        if ($filtered === false) {
            return true;
        }

        // Double-check against our explicit ranges for IPv4
        if (Validator::ipv4($ip)) {
            $longIp = ip2long($ip);
            if ($longIp === false) {
                return true; // Err on safe side
            }

            foreach (self::PRIVATE_IPV4_RANGES as [$start, $end]) {
                $longStart = ip2long($start);
                $longEnd = ip2long($end);

                if ($longStart !== false && $longEnd !== false) {
                    if ($longIp >= $longStart && $longIp <= $longEnd) {
                        return true;
                    }
                }
            }
        }

        // For IPv6, check common private ranges
        if (Validator::ipv6($ip)) {
            // Loopback ::1
            if ($ip === '::1' || $ip === '::') {
                return true;
            }

            // Link-local fe80::/10
            if (str_starts_with($ip, 'fe80:')) {
                return true;
            }

            // Unique local fc00::/7
            if (str_starts_with($ip, 'fc') || str_starts_with($ip, 'fd')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Validate Webmention source URL (prevent internal requests).
     *
     * Ensures the source URL:
     * - Is a valid HTTPS URL (HTTP allowed for localhost in dev)
     * - Does not resolve to an internal IP address
     * - Is not a localhost/127.0.0.1 address
     *
     * @param string $url Source URL to validate
     * @param bool $allowHttp Allow HTTP URLs (default: false, use only for dev)
     * @return bool True if safe to fetch
     */
    public static function validateSource(string $url, bool $allowHttp = false): bool
    {
        // Must be valid URL
        if (!Validator::url($url)) {
            return false;
        }

        // Require HTTPS in production
        if (!$allowHttp && !Validator::httpsUrl($url)) {
            return false;
        }

        $parts = parse_url($url);
        if ($parts === false || !isset($parts['host'])) {
            return false;
        }

        $host = $parts['host'];

        // Check if host is already an IP address
        if (Validator::ip($host)) {
            return !self::isInternalIp($host);
        }

        // Resolve hostname to IP addresses
        $ips = self::resolveHost($host);
        if ($ips === null) {
            // Could not resolve - reject for safety
            return false;
        }

        // Check if any resolved IP is internal
        foreach ($ips as $ip) {
            if (self::isInternalIp($ip)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Validate Webmention target matches your domain.
     *
     * The target must:
     * - Be a valid URL
     * - Have a host matching your domain
     * - Not be an IP address
     *
     * @param string $url Target URL
     * @param string $yourDomain Your domain (e.g., "example.com")
     * @return bool True if target is your domain
     */
    public static function validateTarget(string $url, string $yourDomain): bool
    {
        if (!Validator::url($url)) {
            return false;
        }

        $parts = parse_url($url);
        if ($parts === false || !isset($parts['host'])) {
            return false;
        }

        $host = $parts['host'];

        // Target must be a domain, not IP
        if (Validator::ip($host)) {
            return false;
        }

        // Host must match your domain (or be a subdomain)
        return $host === $yourDomain || str_ends_with($host, '.' . $yourDomain);
    }

    /**
     * Resolve hostname to IP addresses.
     *
     * @param string $host Hostname to resolve
     * @return string[]|null Array of IP addresses, or null if resolution failed
     */
    private static function resolveHost(string $host): ?array
    {
        // Try DNS lookup for A and AAAA records
        $ips = [];

        // Get IPv4 addresses
        $ipv4Records = @dns_get_record($host, DNS_A);
        if ($ipv4Records !== false) {
            foreach ($ipv4Records as $record) {
                if (isset($record['ip'])) {
                    $ips[] = $record['ip'];
                }
            }
        }

        // Get IPv6 addresses
        $ipv6Records = @dns_get_record($host, DNS_AAAA);
        if ($ipv6Records !== false) {
            foreach ($ipv6Records as $record) {
                if (isset($record['ipv6'])) {
                    $ips[] = $record['ipv6'];
                }
            }
        }

        // Fallback to gethostbyname if no DNS records found
        if (empty($ips)) {
            $ip = @gethostbyname($host);
            if ($ip !== $host) {
                $ips[] = $ip;
            }
        }

        return empty($ips) ? null : $ips;
    }

    /**
     * Validate Webmention source and target together.
     *
     * Convenience method that validates both URLs at once.
     *
     * @param string $source Source URL
     * @param string $target Target URL
     * @param string $yourDomain Your domain
     * @param bool $allowHttp Allow HTTP for source (dev only)
     * @return array{valid: bool, errors: string[]}
     */
    public static function validateWebmention(
        string $source,
        string $target,
        string $yourDomain,
        bool $allowHttp = false
    ): array {
        $errors = [];

        if (!self::validateSource($source, $allowHttp)) {
            $errors[] = 'Invalid or unsafe source URL (may resolve to internal IP)';
        }

        if (!self::validateTarget($target, $yourDomain)) {
            $errors[] = 'Invalid target URL or does not match your domain';
        }

        // Source and target must be different
        if ($source === $target) {
            $errors[] = 'Source and target cannot be the same URL';
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors,
        ];
    }

    /**
     * Detect Time-of-Check-Time-of-Use (TOCTOU) DNS rebinding attacks.
     *
     * Re-resolves hostname after initial validation to detect DNS changes.
     *
     * @param string $url URL to check
     * @param string[] $originalIps Original resolved IPs
     * @return bool True if IPs have changed (possible attack)
     */
    public static function detectDnsRebinding(string $url, array $originalIps): bool
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['host'])) {
            return true; // Suspicious change
        }

        $host = $parts['host'];
        $currentIps = self::resolveHost($host);

        if ($currentIps === null) {
            return true; // Resolution failed - suspicious
        }

        // Check if any new IPs are different from original
        $newIps = array_diff($currentIps, $originalIps);

        // If we got new IPs, that's suspicious
        return !empty($newIps);
    }

    /**
     * Generate safe timeout for Webmention verification request.
     *
     * Returns a reasonable timeout to prevent hanging requests.
     *
     * @return int Timeout in seconds
     */
    public static function getSafeTimeout(): int
    {
        // 10 seconds is reasonable for most web requests
        // Not too long to tie up resources, not too short to miss slow servers
        return 10;
    }

    /**
     * Generate safe user agent for Webmention verification.
     *
     * Returns a descriptive user agent that identifies the request as a Webmention.
     *
     * @param string $yourDomain Your domain
     * @return string User agent string
     */
    public static function generateUserAgent(string $yourDomain): string
    {
        return sprintf(
            'Webmention-Verifier (+https://%s/)',
            $yourDomain
        );
    }
}
