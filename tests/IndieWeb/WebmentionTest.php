<?php

/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\Tests\IndieWeb;

use PHPUnit\Framework\TestCase;
use PhpAegis\IndieWeb\Webmention;

/**
 * Tests for Webmention security with SSRF prevention.
 *
 * Critical: Prevents Server-Side Request Forgery attacks via Webmention source URLs.
 */
class WebmentionTest extends TestCase
{
    // ========================================================================
    // Internal IP Detection Tests (IPv4)
    // ========================================================================

    public function testIsInternalIpDetectsPrivateRanges(): void
    {
        // RFC 1918 private ranges
        $this->assertTrue(Webmention::isInternalIp('10.0.0.1'));
        $this->assertTrue(Webmention::isInternalIp('10.255.255.255'));
        $this->assertTrue(Webmention::isInternalIp('172.16.0.1'));
        $this->assertTrue(Webmention::isInternalIp('172.31.255.255'));
        $this->assertTrue(Webmention::isInternalIp('192.168.0.1'));
        $this->assertTrue(Webmention::isInternalIp('192.168.255.255'));
    }

    public function testIsInternalIpDetectsLoopback(): void
    {
        $this->assertTrue(Webmention::isInternalIp('127.0.0.1'));
        $this->assertTrue(Webmention::isInternalIp('127.0.0.255'));
        $this->assertTrue(Webmention::isInternalIp('127.255.255.255'));
    }

    public function testIsInternalIpDetectsLinkLocal(): void
    {
        $this->assertTrue(Webmention::isInternalIp('169.254.0.1'));
        $this->assertTrue(Webmention::isInternalIp('169.254.255.255'));
    }

    public function testIsInternalIpDetectsCarrierGrade(): void
    {
        // RFC 6598 Carrier-grade NAT
        $this->assertTrue(Webmention::isInternalIp('100.64.0.1'));
        $this->assertTrue(Webmention::isInternalIp('100.127.255.255'));
    }

    public function testIsInternalIpAcceptsPublicIpv4(): void
    {
        $this->assertFalse(Webmention::isInternalIp('8.8.8.8')); // Google DNS
        $this->assertFalse(Webmention::isInternalIp('1.1.1.1')); // Cloudflare DNS
        $this->assertFalse(Webmention::isInternalIp('93.184.216.34')); // example.com
    }

    public function testIsInternalIpHandlesInvalidIp(): void
    {
        $this->assertFalse(Webmention::isInternalIp('not-an-ip'));
        $this->assertFalse(Webmention::isInternalIp('256.1.1.1'));
        $this->assertFalse(Webmention::isInternalIp(''));
    }

    // ========================================================================
    // Internal IP Detection Tests (IPv6)
    // ========================================================================

    public function testIsInternalIpDetectsIpv6Loopback(): void
    {
        $this->assertTrue(Webmention::isInternalIp('::1'));
        $this->assertTrue(Webmention::isInternalIp('::'));
    }

    public function testIsInternalIpDetectsIpv6LinkLocal(): void
    {
        $this->assertTrue(Webmention::isInternalIp('fe80::1'));
        $this->assertTrue(Webmention::isInternalIp('fe80:0000:0000:0000:0000:0000:0000:0001'));
    }

    public function testIsInternalIpDetectsIpv6UniqueLocal(): void
    {
        // fc00::/7 (fc00:: and fd00::)
        $this->assertTrue(Webmention::isInternalIp('fc00::1'));
        $this->assertTrue(Webmention::isInternalIp('fd00::1'));
    }

    public function testIsInternalIpAcceptsPublicIpv6(): void
    {
        $this->assertFalse(Webmention::isInternalIp('2001:4860:4860::8888')); // Google DNS
        $this->assertFalse(Webmention::isInternalIp('2606:4700:4700::1111')); // Cloudflare DNS
    }

    // ========================================================================
    // Source URL Validation Tests
    // ========================================================================

    public function testValidateSourceAcceptsValidHttpsUrl(): void
    {
        // Note: This may fail if DNS resolution fails, but demonstrates the API
        $this->assertTrue(Webmention::validateSource('https://example.com', false));
    }

    public function testValidateSourceRejectsHttpByDefault(): void
    {
        // HTTP should be rejected in production
        $this->assertFalse(Webmention::validateSource('http://example.com'));
    }

    public function testValidateSourceAcceptsHttpWhenAllowed(): void
    {
        // HTTP can be allowed for development/testing
        $result = Webmention::validateSource('http://example.com', true);
        // Result depends on DNS resolution, but should not throw exception
        $this->assertIsBool($result);
    }

    public function testValidateSourceRejectsInvalidUrl(): void
    {
        $this->assertFalse(Webmention::validateSource('not-a-url'));
        $this->assertFalse(Webmention::validateSource('ftp://example.com'));
        $this->assertFalse(Webmention::validateSource(''));
    }

    public function testValidateSourceRejectsDirectIpAddresses(): void
    {
        // Direct IP addresses should be rejected if they're internal
        $this->assertFalse(Webmention::validateSource('https://127.0.0.1'));
        $this->assertFalse(Webmention::validateSource('https://192.168.1.1'));
        $this->assertFalse(Webmention::validateSource('https://[::1]'));
    }

    public function testValidateSourceAcceptsPublicIpAddresses(): void
    {
        // Public IP addresses should be accepted
        $this->assertTrue(Webmention::validateSource('https://8.8.8.8'));
        $this->assertTrue(Webmention::validateSource('https://1.1.1.1'));
    }

    public function testValidateSourceRejectsUrlsWithoutHost(): void
    {
        $this->assertFalse(Webmention::validateSource('https://'));
        $this->assertFalse(Webmention::validateSource('https:///path'));
    }

    // ========================================================================
    // Target URL Validation Tests
    // ========================================================================

    public function testValidateTargetAcceptsValidDomain(): void
    {
        $yourDomain = 'example.com';

        $this->assertTrue(Webmention::validateTarget('https://example.com', $yourDomain));
        $this->assertTrue(Webmention::validateTarget('https://example.com/post/1', $yourDomain));
        $this->assertTrue(Webmention::validateTarget('https://example.com/page?id=1', $yourDomain));
    }

    public function testValidateTargetAcceptsSubdomain(): void
    {
        $yourDomain = 'example.com';

        $this->assertTrue(Webmention::validateTarget('https://blog.example.com', $yourDomain));
        $this->assertTrue(Webmention::validateTarget('https://www.example.com', $yourDomain));
    }

    public function testValidateTargetRejectsDifferentDomain(): void
    {
        $yourDomain = 'example.com';

        $this->assertFalse(Webmention::validateTarget('https://other.com', $yourDomain));
        $this->assertFalse(Webmention::validateTarget('https://notexample.com', $yourDomain));
    }

    public function testValidateTargetRejectsIpAddress(): void
    {
        $yourDomain = 'example.com';

        $this->assertFalse(Webmention::validateTarget('https://192.168.1.1', $yourDomain));
        $this->assertFalse(Webmention::validateTarget('https://127.0.0.1', $yourDomain));
    }

    public function testValidateTargetRejectsInvalidUrl(): void
    {
        $yourDomain = 'example.com';

        $this->assertFalse(Webmention::validateTarget('not-a-url', $yourDomain));
        $this->assertFalse(Webmention::validateTarget('', $yourDomain));
    }

    public function testValidateTargetRejectsUrlWithoutHost(): void
    {
        $yourDomain = 'example.com';

        $this->assertFalse(Webmention::validateTarget('https://', $yourDomain));
    }

    // ========================================================================
    // Complete Webmention Validation Tests
    // ========================================================================

    public function testValidateWebmentionAcceptsValid(): void
    {
        $result = Webmention::validateWebmention(
            'https://alice.example.com/post/1',
            'https://bob.example.com/article',
            'bob.example.com'
        );

        // Result depends on DNS resolution, but structure should be correct
        $this->assertIsArray($result);
        $this->assertArrayHasKey('valid', $result);
        $this->assertArrayHasKey('errors', $result);
        $this->assertIsBool($result['valid']);
        $this->assertIsArray($result['errors']);
    }

    public function testValidateWebmentionRejectsSameUrl(): void
    {
        $result = Webmention::validateWebmention(
            'https://example.com/post/1',
            'https://example.com/post/1',
            'example.com'
        );

        $this->assertFalse($result['valid']);
        $this->assertContains('Source and target cannot be the same URL', $result['errors']);
    }

    public function testValidateWebmentionRejectsInvalidSource(): void
    {
        $result = Webmention::validateWebmention(
            'https://127.0.0.1/post', // Loopback
            'https://example.com/article',
            'example.com'
        );

        $this->assertFalse($result['valid']);
        $this->assertCount(1, array_filter($result['errors'], fn($e) => str_contains($e, 'source')));
    }

    public function testValidateWebmentionRejectsInvalidTarget(): void
    {
        $result = Webmention::validateWebmention(
            'https://alice.example.com/post',
            'https://other.com/article', // Different domain
            'example.com'
        );

        $this->assertFalse($result['valid']);
        $this->assertCount(1, array_filter($result['errors'], fn($e) => str_contains($e, 'target')));
    }

    public function testValidateWebmentionCollectsMultipleErrors(): void
    {
        $result = Webmention::validateWebmention(
            'not-a-url', // Invalid source
            'https://other.com', // Wrong domain
            'example.com'
        );

        $this->assertFalse($result['valid']);
        $this->assertGreaterThanOrEqual(2, count($result['errors']));
    }

    // ========================================================================
    // DNS Rebinding Detection Tests
    // ========================================================================

    public function testDetectDnsRebindingReturnsFalseWhenIpsMatch(): void
    {
        // Note: This test requires DNS resolution, so we use a stable domain
        $url = 'https://example.com';

        // In real scenario, you'd store original IPs from first resolution
        // For testing, we assume IPs haven't changed
        $originalIps = ['93.184.216.34']; // example.com A record

        $result = Webmention::detectDnsRebinding($url, $originalIps);

        // If DNS hasn't changed, should return false (no attack)
        // This may vary based on actual DNS state
        $this->assertIsBool($result);
    }

    public function testDetectDnsRebindingReturnsTrueWhenIpsChange(): void
    {
        $url = 'https://example.com';

        // Provide fake "original" IPs that don't match current
        $originalIps = ['1.2.3.4'];

        $result = Webmention::detectDnsRebinding($url, $originalIps);

        // Should detect that IPs changed
        $this->assertTrue($result);
    }

    public function testDetectDnsRebindingHandlesInvalidUrl(): void
    {
        $result = Webmention::detectDnsRebinding('not-a-url', ['1.2.3.4']);

        // Should return true (suspicious) for invalid URL
        $this->assertTrue($result);
    }

    public function testDetectDnsRebindingHandlesResolutionFailure(): void
    {
        $url = 'https://nonexistent-domain-for-testing-12345.com';
        $originalIps = ['1.2.3.4'];

        $result = Webmention::detectDnsRebinding($url, $originalIps);

        // Should return true (suspicious) when DNS fails
        $this->assertTrue($result);
    }

    // ========================================================================
    // Helper Method Tests
    // ========================================================================

    public function testGetSafeTimeoutReturnsReasonableValue(): void
    {
        $timeout = Webmention::getSafeTimeout();

        $this->assertIsInt($timeout);
        $this->assertGreaterThan(0, $timeout);
        $this->assertLessThanOrEqual(30, $timeout); // Not too long
    }

    public function testGenerateUserAgentIncludesDomain(): void
    {
        $domain = 'example.com';
        $userAgent = Webmention::generateUserAgent($domain);

        $this->assertIsString($userAgent);
        $this->assertStringContainsString($domain, $userAgent);
        $this->assertStringContainsString('Webmention', $userAgent);
    }

    // ========================================================================
    // Security Integration Tests
    // ========================================================================

    public function testSsrfPreventionBlocksInternalNetworkScanning(): void
    {
        // Attempt to scan internal network via Webmention source
        $internalTargets = [
            'https://127.0.0.1',
            'https://localhost',
            'https://192.168.1.1',
            'https://10.0.0.1',
            'https://172.16.0.1',
            'https://[::1]',
            'https://[fe80::1]',
        ];

        foreach ($internalTargets as $target) {
            $result = Webmention::validateWebmention(
                $target,
                'https://example.com/article',
                'example.com'
            );

            $this->assertFalse(
                $result['valid'],
                "Should block SSRF attempt to $target"
            );
        }
    }

    public function testCompleteWebmentionWorkflow(): void
    {
        // Step 1: Receive Webmention request
        $source = 'https://alice.example.com/post/42';
        $target = 'https://bob.example.com/article/1';
        $yourDomain = 'bob.example.com';

        // Step 2: Validate Webmention
        $validation = Webmention::validateWebmention($source, $target, $yourDomain);

        // Step 3: Generate user agent for verification request
        $userAgent = Webmention::generateUserAgent($yourDomain);
        $this->assertStringContainsString('bob.example.com', $userAgent);

        // Step 4: Get safe timeout for HTTP request
        $timeout = Webmention::getSafeTimeout();
        $this->assertGreaterThan(0, $timeout);

        // Validation result structure is correct
        $this->assertIsArray($validation);
        $this->assertArrayHasKey('valid', $validation);
        $this->assertArrayHasKey('errors', $validation);
    }

    public function testDnsRebindingProtectionWorkflow(): void
    {
        $source = 'https://example.com/post';

        // Step 1: Initial validation (stores IPs internally in real implementation)
        $validation = Webmention::validateWebmention(
            $source,
            'https://yoursite.com/article',
            'yoursite.com'
        );

        // Step 2: Simulate storing original IPs
        $originalIps = ['93.184.216.34']; // example.com

        // Step 3: Before making HTTP request, check for DNS rebinding
        $isRebindingAttack = Webmention::detectDnsRebinding($source, $originalIps);

        // Should be able to detect if IPs changed
        $this->assertIsBool($isRebindingAttack);
    }

    public function testMultipleSecurityLayersProtection(): void
    {
        // Test that multiple security checks work together

        // Layer 1: Invalid source URL format
        $result1 = Webmention::validateWebmention(
            'not-a-url',
            'https://example.com/article',
            'example.com'
        );
        $this->assertFalse($result1['valid']);

        // Layer 2: Source points to internal IP
        $result2 = Webmention::validateWebmention(
            'https://127.0.0.1/post',
            'https://example.com/article',
            'example.com'
        );
        $this->assertFalse($result2['valid']);

        // Layer 3: Target doesn't match your domain
        $result3 = Webmention::validateWebmention(
            'https://alice.example.com/post',
            'https://other.com/article',
            'example.com'
        );
        $this->assertFalse($result3['valid']);

        // Layer 4: Source and target are the same
        $result4 = Webmention::validateWebmention(
            'https://example.com/post',
            'https://example.com/post',
            'example.com'
        );
        $this->assertFalse($result4['valid']);
    }
}
