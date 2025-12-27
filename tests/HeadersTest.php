<?php

/**
 * SPDX-License-Identifier: MIT OR AGPL-3.0-or-later
 * SPDX-FileCopyrightText: 2024-2025 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use PhpAegis\Headers;

#[CoversClass(Headers::class)]
final class HeadersTest extends TestCase
{
    // =========================================================================
    // Frame Options (OWASP A01 - Broken Access Control / Clickjacking)
    // =========================================================================

    #[RunInSeparateProcess]
    public function testFrameOptionsDefault(): void
    {
        Headers::frameOptions();

        $headers = xdebug_get_headers();
        self::assertContains('X-Frame-Options: DENY', $headers);
    }

    #[RunInSeparateProcess]
    public function testFrameOptionsDeny(): void
    {
        Headers::frameOptions('DENY');

        $headers = xdebug_get_headers();
        self::assertContains('X-Frame-Options: DENY', $headers);
    }

    #[RunInSeparateProcess]
    public function testFrameOptionsSameOrigin(): void
    {
        Headers::frameOptions('SAMEORIGIN');

        $headers = xdebug_get_headers();
        self::assertContains('X-Frame-Options: SAMEORIGIN', $headers);
    }

    #[RunInSeparateProcess]
    public function testFrameOptionsAllowFrom(): void
    {
        Headers::frameOptions('ALLOW-FROM https://example.com');

        $headers = xdebug_get_headers();
        self::assertContains('X-Frame-Options: ALLOW-FROM https://example.com', $headers);
    }

    public function testFrameOptionsRejectsInvalid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('X-Frame-Options must be DENY, SAMEORIGIN, or ALLOW-FROM uri');

        Headers::frameOptions('INVALID');
    }

    // =========================================================================
    // Content-Type Options (OWASP A05 - Security Misconfiguration)
    // =========================================================================

    #[RunInSeparateProcess]
    public function testContentTypeOptions(): void
    {
        Headers::contentTypeOptions();

        $headers = xdebug_get_headers();
        self::assertContains('X-Content-Type-Options: nosniff', $headers);
    }

    // =========================================================================
    // XSS Protection (OWASP A03 - Legacy Browser Protection)
    // =========================================================================

    #[RunInSeparateProcess]
    public function testXssProtectionDefault(): void
    {
        Headers::xssProtection();

        $headers = xdebug_get_headers();
        self::assertContains('X-XSS-Protection: 1; mode=block', $headers);
    }

    #[RunInSeparateProcess]
    public function testXssProtectionEnabled(): void
    {
        Headers::xssProtection(true, true);

        $headers = xdebug_get_headers();
        self::assertContains('X-XSS-Protection: 1; mode=block', $headers);
    }

    #[RunInSeparateProcess]
    public function testXssProtectionEnabledNoBlock(): void
    {
        Headers::xssProtection(true, false);

        $headers = xdebug_get_headers();
        self::assertContains('X-XSS-Protection: 1', $headers);
    }

    #[RunInSeparateProcess]
    public function testXssProtectionDisabled(): void
    {
        Headers::xssProtection(false);

        $headers = xdebug_get_headers();
        self::assertContains('X-XSS-Protection: 0', $headers);
    }

    // =========================================================================
    // Referrer Policy (OWASP A05 - Security Misconfiguration)
    // =========================================================================

    #[RunInSeparateProcess]
    public function testReferrerPolicyDefault(): void
    {
        Headers::referrerPolicy();

        $headers = xdebug_get_headers();
        self::assertContains('Referrer-Policy: strict-origin-when-cross-origin', $headers);
    }

    #[DataProvider('validReferrerPoliciesProvider')]
    #[RunInSeparateProcess]
    public function testReferrerPolicyValid(string $policy): void
    {
        Headers::referrerPolicy($policy);

        $headers = xdebug_get_headers();
        self::assertContains("Referrer-Policy: {$policy}", $headers);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validReferrerPoliciesProvider(): array
    {
        return [
            'no-referrer' => ['no-referrer'],
            'no-referrer-when-downgrade' => ['no-referrer-when-downgrade'],
            'origin' => ['origin'],
            'origin-when-cross-origin' => ['origin-when-cross-origin'],
            'same-origin' => ['same-origin'],
            'strict-origin' => ['strict-origin'],
            'strict-origin-when-cross-origin' => ['strict-origin-when-cross-origin'],
            'unsafe-url' => ['unsafe-url'],
        ];
    }

    public function testReferrerPolicyRejectsInvalid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid Referrer-Policy');

        Headers::referrerPolicy('invalid-policy');
    }

    // =========================================================================
    // Strict Transport Security (OWASP A02 - Cryptographic Failures)
    // =========================================================================

    #[RunInSeparateProcess]
    public function testStrictTransportSecurityDefault(): void
    {
        Headers::strictTransportSecurity();

        $headers = xdebug_get_headers();
        self::assertContains('Strict-Transport-Security: max-age=31536000; includeSubDomains', $headers);
    }

    #[RunInSeparateProcess]
    public function testStrictTransportSecurityWithPreload(): void
    {
        Headers::strictTransportSecurity(31536000, true, true);

        $headers = xdebug_get_headers();
        self::assertContains(
            'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            $headers
        );
    }

    #[RunInSeparateProcess]
    public function testStrictTransportSecurityNoSubdomains(): void
    {
        Headers::strictTransportSecurity(86400, false, false);

        $headers = xdebug_get_headers();
        self::assertContains('Strict-Transport-Security: max-age=86400', $headers);
    }

    #[RunInSeparateProcess]
    public function testStrictTransportSecurityCustomMaxAge(): void
    {
        Headers::strictTransportSecurity(3600);

        $headers = xdebug_get_headers();
        self::assertContains('Strict-Transport-Security: max-age=3600; includeSubDomains', $headers);
    }

    // =========================================================================
    // Content Security Policy (OWASP A03, A05, A08)
    // =========================================================================

    #[RunInSeparateProcess]
    public function testContentSecurityPolicySingleDirective(): void
    {
        Headers::contentSecurityPolicy([
            'default-src' => ["'self'"],
        ]);

        $headers = xdebug_get_headers();
        self::assertContains("Content-Security-Policy: default-src 'self'", $headers);
    }

    #[RunInSeparateProcess]
    public function testContentSecurityPolicyMultipleDirectives(): void
    {
        Headers::contentSecurityPolicy([
            'default-src' => ["'self'"],
            'script-src' => ["'self'", 'https://cdn.example.com'],
            'style-src' => ["'self'", "'unsafe-inline'"],
        ]);

        $headers = xdebug_get_headers();

        // Find the CSP header
        $cspHeader = null;
        foreach ($headers as $header) {
            if (str_starts_with($header, 'Content-Security-Policy:')) {
                $cspHeader = $header;
                break;
            }
        }

        self::assertNotNull($cspHeader);
        self::assertStringContainsString("default-src 'self'", $cspHeader);
        self::assertStringContainsString('script-src', $cspHeader);
        self::assertStringContainsString('style-src', $cspHeader);
    }

    #[RunInSeparateProcess]
    public function testContentSecurityPolicyReportOnly(): void
    {
        Headers::contentSecurityPolicy([
            'default-src' => ["'self'"],
        ], true);

        $headers = xdebug_get_headers();

        $found = false;
        foreach ($headers as $header) {
            if (str_starts_with($header, 'Content-Security-Policy-Report-Only:')) {
                $found = true;
                break;
            }
        }

        self::assertTrue($found, 'Expected Content-Security-Policy-Report-Only header');
    }

    #[RunInSeparateProcess]
    public function testContentSecurityPolicyEmptyDirective(): void
    {
        Headers::contentSecurityPolicy([
            'upgrade-insecure-requests' => [],
        ]);

        $headers = xdebug_get_headers();
        self::assertContains('Content-Security-Policy: upgrade-insecure-requests', $headers);
    }

    // =========================================================================
    // Permissions Policy (OWASP A05 - Security Misconfiguration)
    // =========================================================================

    #[RunInSeparateProcess]
    public function testPermissionsPolicyEmpty(): void
    {
        Headers::permissionsPolicy([
            'camera' => [],
            'microphone' => [],
        ]);

        $headers = xdebug_get_headers();

        $found = null;
        foreach ($headers as $header) {
            if (str_starts_with($header, 'Permissions-Policy:')) {
                $found = $header;
                break;
            }
        }

        self::assertNotNull($found);
        self::assertStringContainsString('camera=()', $found);
        self::assertStringContainsString('microphone=()', $found);
    }

    #[RunInSeparateProcess]
    public function testPermissionsPolicySelf(): void
    {
        Headers::permissionsPolicy([
            'geolocation' => ['self'],
        ]);

        $headers = xdebug_get_headers();
        self::assertContains('Permissions-Policy: geolocation=(self)', $headers);
    }

    #[RunInSeparateProcess]
    public function testPermissionsPolicyWithOrigins(): void
    {
        Headers::permissionsPolicy([
            'camera' => ['self', 'https://example.com'],
        ]);

        $headers = xdebug_get_headers();

        $found = null;
        foreach ($headers as $header) {
            if (str_starts_with($header, 'Permissions-Policy:')) {
                $found = $header;
                break;
            }
        }

        self::assertNotNull($found);
        self::assertStringContainsString('camera=(self "https://example.com")', $found);
    }

    // =========================================================================
    // Cross-Origin Policies (OWASP A01 - Broken Access Control)
    // =========================================================================

    #[RunInSeparateProcess]
    public function testCrossOriginEmbedderPolicyDefault(): void
    {
        Headers::crossOriginEmbedderPolicy();

        $headers = xdebug_get_headers();
        self::assertContains('Cross-Origin-Embedder-Policy: require-corp', $headers);
    }

    #[DataProvider('validCoepPoliciesProvider')]
    #[RunInSeparateProcess]
    public function testCrossOriginEmbedderPolicyValid(string $policy): void
    {
        Headers::crossOriginEmbedderPolicy($policy);

        $headers = xdebug_get_headers();
        self::assertContains("Cross-Origin-Embedder-Policy: {$policy}", $headers);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validCoepPoliciesProvider(): array
    {
        return [
            'require-corp' => ['require-corp'],
            'credentialless' => ['credentialless'],
            'unsafe-none' => ['unsafe-none'],
        ];
    }

    public function testCrossOriginEmbedderPolicyRejectsInvalid(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Headers::crossOriginEmbedderPolicy('invalid');
    }

    #[RunInSeparateProcess]
    public function testCrossOriginOpenerPolicyDefault(): void
    {
        Headers::crossOriginOpenerPolicy();

        $headers = xdebug_get_headers();
        self::assertContains('Cross-Origin-Opener-Policy: same-origin', $headers);
    }

    #[DataProvider('validCoopPoliciesProvider')]
    #[RunInSeparateProcess]
    public function testCrossOriginOpenerPolicyValid(string $policy): void
    {
        Headers::crossOriginOpenerPolicy($policy);

        $headers = xdebug_get_headers();
        self::assertContains("Cross-Origin-Opener-Policy: {$policy}", $headers);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validCoopPoliciesProvider(): array
    {
        return [
            'same-origin' => ['same-origin'],
            'same-origin-allow-popups' => ['same-origin-allow-popups'],
            'unsafe-none' => ['unsafe-none'],
        ];
    }

    public function testCrossOriginOpenerPolicyRejectsInvalid(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Headers::crossOriginOpenerPolicy('invalid');
    }

    #[RunInSeparateProcess]
    public function testCrossOriginResourcePolicyDefault(): void
    {
        Headers::crossOriginResourcePolicy();

        $headers = xdebug_get_headers();
        self::assertContains('Cross-Origin-Resource-Policy: same-origin', $headers);
    }

    #[DataProvider('validCorpPoliciesProvider')]
    #[RunInSeparateProcess]
    public function testCrossOriginResourcePolicyValid(string $policy): void
    {
        Headers::crossOriginResourcePolicy($policy);

        $headers = xdebug_get_headers();
        self::assertContains("Cross-Origin-Resource-Policy: {$policy}", $headers);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validCorpPoliciesProvider(): array
    {
        return [
            'same-origin' => ['same-origin'],
            'same-site' => ['same-site'],
            'cross-origin' => ['cross-origin'],
        ];
    }

    public function testCrossOriginResourcePolicyRejectsInvalid(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Headers::crossOriginResourcePolicy('invalid');
    }

    // =========================================================================
    // Remove Insecure Headers (OWASP A05 - Security Misconfiguration)
    // =========================================================================

    #[RunInSeparateProcess]
    public function testRemoveInsecureHeaders(): void
    {
        // Set headers that should be removed
        header('X-Powered-By: PHP/8.3.0');
        header('Server: Apache/2.4.41');

        Headers::removeInsecureHeaders();

        $headers = xdebug_get_headers();

        // These headers should be removed
        foreach ($headers as $header) {
            self::assertStringNotContainsString('X-Powered-By', $header);
            self::assertStringNotContainsString('Server:', $header);
        }
    }

    // =========================================================================
    // Secure() - All-in-one (OWASP A05 - Secure Defaults)
    // =========================================================================

    #[RunInSeparateProcess]
    public function testSecureSetsAllHeaders(): void
    {
        Headers::secure();

        $headers = xdebug_get_headers();

        // Check for essential security headers
        $hasContentType = false;
        $hasFrameOptions = false;
        $hasXssProtection = false;
        $hasReferrerPolicy = false;
        $hasHsts = false;
        $hasCsp = false;
        $hasPermissions = false;

        foreach ($headers as $header) {
            if (str_starts_with($header, 'X-Content-Type-Options:')) {
                $hasContentType = true;
            }
            if (str_starts_with($header, 'X-Frame-Options:')) {
                $hasFrameOptions = true;
            }
            if (str_starts_with($header, 'X-XSS-Protection:')) {
                $hasXssProtection = true;
            }
            if (str_starts_with($header, 'Referrer-Policy:')) {
                $hasReferrerPolicy = true;
            }
            if (str_starts_with($header, 'Strict-Transport-Security:')) {
                $hasHsts = true;
            }
            if (str_starts_with($header, 'Content-Security-Policy:')) {
                $hasCsp = true;
            }
            if (str_starts_with($header, 'Permissions-Policy:')) {
                $hasPermissions = true;
            }
        }

        self::assertTrue($hasContentType, 'Missing X-Content-Type-Options');
        self::assertTrue($hasFrameOptions, 'Missing X-Frame-Options');
        self::assertTrue($hasXssProtection, 'Missing X-XSS-Protection');
        self::assertTrue($hasReferrerPolicy, 'Missing Referrer-Policy');
        self::assertTrue($hasHsts, 'Missing Strict-Transport-Security');
        self::assertTrue($hasCsp, 'Missing Content-Security-Policy');
        self::assertTrue($hasPermissions, 'Missing Permissions-Policy');
    }
}
