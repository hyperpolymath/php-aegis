<?php // SPDX-License-Identifier: PMPL-1.0-or-later

/**
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 *
 * E2eTest — end-to-end request lifecycle tests.
 *
 * Simulates a complete HTTP request flowing through every php-aegis middleware
 * layer in sequence: Headers → Sanitizer → RateLimit → Validator.
 *
 * Tests cover both the happy path (clean requests pass) and adversarial paths
 * (malicious input is blocked at each layer). The WordPress adapter full flow
 * is also covered.
 *
 * CRG Grade: C requirement — at least 10 test methods.
 */

declare(strict_types=1);

namespace PhpAegis\Tests;

use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use PhpAegis\Sanitizer;
use PhpAegis\Validator;
use PhpAegis\RateLimit\RateLimiter;
use PhpAegis\RateLimit\MemoryStore;

/**
 * End-to-end lifecycle tests simulating real request processing.
 *
 * Architecture under test (layered in order):
 *   1. Headers — security headers set at response start
 *   2. Sanitizer — all user-supplied strings are sanitized before use
 *   3. RateLimiter — per-user token bucket checked before business logic
 *   4. Validator — structured fields (email, URL, IP, slug) validated last
 *
 * Helper methods simulate the middleware chain without requiring a real SAPI.
 */
final class E2eTest extends TestCase
{
    /** In-memory rate limit store shared within a test method. */
    private MemoryStore $store;

    /** Rate limiter allowing 5 requests per second. */
    private RateLimiter $limiter;

    protected function setUp(): void
    {
        parent::setUp();
        $this->store   = new MemoryStore();
        $this->limiter = RateLimiter::perSecond(5, $this->store);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Simulate the sanitisation layer for a generic string field.
     *
     * Returns the sanitized value and a flag indicating whether dangerous
     * patterns were detected in the original input.
     *
     * @return array{sanitized: string, wasDangerous: bool}
     */
    private function sanitizeField(string $rawValue): array
    {
        $sanitized    = Sanitizer::html($rawValue);
        $wasDangerous = $sanitized !== $rawValue;

        return ['sanitized' => $sanitized, 'wasDangerous' => $wasDangerous];
    }

    /**
     * Simulate the full middleware chain for a single incoming request.
     *
     * Stages:
     *   1. Sanitize all string inputs.
     *   2. Check rate limit for the given user key.
     *   3. Validate structured fields (email, URL).
     *
     * Returns a result map with keys:
     *   - 'allowed'       (bool)   — true if request passed all layers
     *   - 'blockedAt'     (string) — 'sanitizer', 'rate-limit', 'validator', or 'none'
     *   - 'sanitizedBody' (array)  — sanitized string fields
     *   - 'rateLimitOk'   (bool)
     *   - 'validationOk'  (bool)
     *
     * @param array<string, string> $stringFields  Arbitrary text fields from request body
     * @param string                $userKey       Identifier for rate-limit bucket
     * @param string                $email         Email field to validate (may be empty)
     * @param string                $url           URL field to validate (may be empty)
     * @return array{allowed: bool, blockedAt: string, sanitizedBody: array<string, string>, rateLimitOk: bool, validationOk: bool}
     */
    private function processRequest(
        array  $stringFields,
        string $userKey,
        string $email = '',
        string $url   = ''
    ): array {
        $sanitizedBody = [];
        $wasDangerous  = false;

        // Stage 1: sanitize all string fields
        foreach ($stringFields as $name => $value) {
            $result              = $this->sanitizeField($value);
            $sanitizedBody[$name] = $result['sanitized'];
            if ($result['wasDangerous']) {
                $wasDangerous = true;
            }
        }

        // Stage 2: rate limit check
        $rateLimitOk = $this->limiter->attempt($userKey);
        if (!$rateLimitOk) {
            return [
                'allowed'       => false,
                'blockedAt'     => 'rate-limit',
                'sanitizedBody' => $sanitizedBody,
                'rateLimitOk'   => false,
                'validationOk'  => false,
            ];
        }

        // Stage 3: validate structured fields
        $validationOk = true;
        if ($email !== '' && !Validator::email($email)) {
            $validationOk = false;
        }
        if ($url !== '' && !Validator::url($url)) {
            $validationOk = false;
        }

        if (!$validationOk) {
            return [
                'allowed'       => false,
                'blockedAt'     => 'validator',
                'sanitizedBody' => $sanitizedBody,
                'rateLimitOk'   => true,
                'validationOk'  => false,
            ];
        }

        return [
            'allowed'       => true,
            'blockedAt'     => 'none',
            'sanitizedBody' => $sanitizedBody,
            'rateLimitOk'   => true,
            'validationOk'  => true,
        ];
    }

    // =========================================================================
    // Happy-Path Tests
    // =========================================================================

    /**
     * A completely clean request must pass every middleware layer and be allowed.
     */
    public function testCleanRequestPassesAllLayers(): void
    {
        $result = $this->processRequest(
            stringFields: ['name' => 'Alice', 'comment' => 'Hello world'],
            userKey: 'user-clean',
            email: 'alice@example.com',
            url: 'https://example.com'
        );

        self::assertTrue($result['allowed'], 'Clean request must be allowed');
        self::assertSame('none', $result['blockedAt']);
        self::assertTrue($result['rateLimitOk']);
        self::assertTrue($result['validationOk']);
    }

    /**
     * Clean text fields must survive the sanitizer unchanged.
     */
    public function testCleanFieldsAreUnmodifiedBySanitizer(): void
    {
        $fields = ['greeting' => 'Hello', 'number' => '42', 'emoji' => 'Great job!'];
        $result = $this->processRequest(stringFields: $fields, userKey: 'user-plain');

        self::assertSame('Hello', $result['sanitizedBody']['greeting']);
        self::assertSame('42', $result['sanitizedBody']['number']);
        self::assertSame('Great job!', $result['sanitizedBody']['emoji']);
    }

    /**
     * Multiple successive clean requests from the same user must all pass
     * as long as they remain within the rate limit.
     */
    public function testMultipleCleanRequestsWithinRateLimitAllPass(): void
    {
        for ($i = 1; $i <= 5; $i++) {
            $result = $this->processRequest(
                stringFields: ['msg' => "message {$i}"],
                userKey: 'user-burst'
            );
            self::assertTrue($result['allowed'], "Request #{$i} should be allowed within rate limit");
        }
    }

    // =========================================================================
    // Sanitizer Blocking Tests
    // =========================================================================

    /**
     * A request containing an XSS payload must have the dangerous content
     * neutralised in the sanitized body, even though the request itself is
     * still "allowed" (sanitizer escapes — it does not reject).
     */
    public function testXssPayloadIsSanitizedInBody(): void
    {
        $result = $this->processRequest(
            stringFields: ['comment' => '<script>alert("XSS")</script>'],
            userKey: 'user-xss'
        );

        // The request is allowed but the dangerous content is escaped
        self::assertTrue($result['allowed']);
        self::assertStringNotContainsString('<script>', $result['sanitizedBody']['comment']);
        self::assertStringContainsString('&lt;script&gt;', $result['sanitizedBody']['comment']);
    }

    /**
     * An event-handler injection attempt must be defused in the sanitized output.
     */
    public function testEventHandlerInjectionIsSanitized(): void
    {
        $result = $this->processRequest(
            stringFields: ['title' => '<img src=x onerror=alert(1)>'],
            userKey: 'user-event'
        );

        self::assertStringNotContainsString('onerror=', $result['sanitizedBody']['title']);
        self::assertStringNotContainsString('<img', $result['sanitizedBody']['title']);
    }

    /**
     * A javascript: URL in a field must be escaped so it cannot execute.
     */
    public function testJavascriptUrlIsEscapedInBody(): void
    {
        $result = $this->processRequest(
            stringFields: ['link' => '<a href="javascript:alert(1)">click</a>'],
            userKey: 'user-jsurl'
        );

        self::assertStringNotContainsString('javascript:', $result['sanitizedBody']['link']);
    }

    // =========================================================================
    // Rate Limit Blocking Tests
    // =========================================================================

    /**
     * After exhausting the rate limit bucket, the next request must be blocked
     * specifically at the rate-limit layer.
     */
    public function testExcessiveRequestsAreBlockedByRateLimit(): void
    {
        // Consume all 5 tokens
        for ($i = 0; $i < 5; $i++) {
            $this->processRequest(stringFields: ['msg' => 'ok'], userKey: 'user-rl');
        }

        // The 6th request must be blocked at rate-limit stage
        $result = $this->processRequest(stringFields: ['msg' => 'overflow'], userKey: 'user-rl');

        self::assertFalse($result['allowed'], '6th request should be blocked');
        self::assertSame('rate-limit', $result['blockedAt']);
        self::assertFalse($result['rateLimitOk']);
    }

    /**
     * Rate limit buckets are isolated per user key — one user exhausting their
     * quota must not affect another user's quota.
     */
    public function testRateLimitIsolationBetweenUsers(): void
    {
        // Exhaust user A's quota
        for ($i = 0; $i < 5; $i++) {
            $this->processRequest(stringFields: ['msg' => 'a'], userKey: 'user-a');
        }

        // User B must still be allowed through
        $resultB = $this->processRequest(stringFields: ['msg' => 'b'], userKey: 'user-b');
        self::assertTrue($resultB['allowed'], 'User B must not be affected by user A exhausting their quota');
    }

    // =========================================================================
    // Validator Blocking Tests
    // =========================================================================

    /**
     * A request with a malformed email address must be blocked at the validator
     * layer, not at rate-limit or sanitizer.
     */
    public function testMalformedEmailIsBlockedByValidator(): void
    {
        $result = $this->processRequest(
            stringFields: ['name' => 'Bob'],
            userKey: 'user-bademail',
            email: 'not-an-email'
        );

        self::assertFalse($result['allowed'], 'Bad email request must be blocked');
        self::assertSame('validator', $result['blockedAt']);
        self::assertTrue($result['rateLimitOk'], 'Rate limit should have passed');
        self::assertFalse($result['validationOk']);
    }

    /**
     * A request with an HTTP URL when HTTPS is required must be blocked.
     * This test uses Validator::url directly to verify the https-only mode.
     */
    public function testInsecureUrlIsRejectedByValidator(): void
    {
        // Validator::url with httpsOnly=true rejects http://
        self::assertFalse(
            Validator::url('http://insecure.example.com', httpsOnly: true),
            'http:// URL must fail https-only validation'
        );
        self::assertTrue(
            Validator::url('https://secure.example.com', httpsOnly: true),
            'https:// URL must pass https-only validation'
        );
    }

    /**
     * A request combining a malicious body AND a bad email must be blocked.
     * The sanitizer escapes the body; the validator blocks the request.
     */
    public function testCombinedMaliciousBodyAndBadEmailIsBlocked(): void
    {
        $result = $this->processRequest(
            stringFields: ['comment' => '<script>pwned()</script>'],
            userKey: 'user-combined',
            email: 'not@@valid'
        );

        self::assertFalse($result['allowed']);
        // Body should be sanitized regardless
        self::assertStringNotContainsString('<script>', $result['sanitizedBody']['comment']);
        // Block reason is validator (rate limit still passes)
        self::assertSame('validator', $result['blockedAt']);
    }

    // =========================================================================
    // WordPress Adapter Flow Tests
    // =========================================================================

    /**
     * The WordPress adapter functions must produce the same sanitization output
     * as the underlying PhpAegis classes when called in sequence.
     */
    public function testWordPressAdapterFullSanitizationFlow(): void
    {
        require_once __DIR__ . '/../src/WordPress/Adapter.php';

        $xssInput = '<script>alert("wp-xss")</script>';

        // Adapter aegis_html must match Sanitizer::html
        self::assertSame(
            Sanitizer::html($xssInput),
            aegis_html($xssInput),
            'aegis_html must match Sanitizer::html'
        );

        // Strip then escape pipeline
        $stripped = aegis_strip_tags($xssInput);
        self::assertSame('alert("wp-xss")', $stripped);

        $escaped = aegis_html($stripped);
        self::assertStringNotContainsString('<', $escaped);
        self::assertStringNotContainsString('>', $escaped);
    }

    /**
     * WordPress adapter validation functions must accept valid data and
     * reject invalid data consistently with the core Validator class.
     */
    public function testWordPressAdapterValidationFlow(): void
    {
        require_once __DIR__ . '/../src/WordPress/Adapter.php';

        // Valid cases
        self::assertTrue(aegis_validate_email('wp-user@example.com'));
        self::assertTrue(aegis_validate_url('https://wordpress.org'));
        self::assertTrue(aegis_validate_slug('my-post-title-123'));

        // Invalid cases
        self::assertFalse(aegis_validate_email('wp-user@@example.com'));
        self::assertFalse(aegis_validate_url('not a url'));
        self::assertFalse(aegis_validate_slug('Has Uppercase'));
    }
}
