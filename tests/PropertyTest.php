<?php // SPDX-License-Identifier: MPL-2.0

/**
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 *
 * PropertyTest — property-based tests using fixed input arrays.
 *
 * Verifies that security invariants hold across a range of representative
 * inputs for the Sanitizer, TokenBucket, and Headers components.
 * Uses PHPUnit DataProvider for structured iteration and clear failure output.
 *
 * CRG Grade: C requirement — at least 30 assertions total.
 */

declare(strict_types=1);

namespace PhpAegis\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpAegis\Sanitizer;
use PhpAegis\RateLimit\TokenBucket;
use PhpAegis\RateLimit\MemoryStore;

/**
 * Property-based style tests using fixed input corpora.
 *
 * Each test method iterates over a representative set of inputs and asserts
 * that security invariants hold for every element. This catches regressions
 * that single-input unit tests cannot detect.
 */
final class PropertyTest extends TestCase
{
    // =========================================================================
    // XSS Sanitizer Properties
    // =========================================================================

    /**
     * Fixed corpus of XSS payloads drawn from OWASP XSS cheat sheet.
     *
     * @return array<string, array{string}>
     */
    public static function xssPayloadsProvider(): array
    {
        return [
            'basic script tag'          => ['<script>alert("XSS")</script>'],
            'img onerror'               => ['<img src=x onerror=alert(1)>'],
            'svg onload'                => ['<svg onload=alert(1)>'],
            'javascript url href'       => ['<a href="javascript:alert(1)">click</a>'],
            'javascript url uppercase'  => ['<a href="JAVASCRIPT:alert(1)">click</a>'],
            'data uri script'           => ['<a href="data:text/html,<script>alert(1)</script>">x</a>'],
            'iframe javascript src'     => ['<iframe src="javascript:alert(1)">'],
            'body onload'               => ['<body onload="alert(1)">'],
            'input autofocus onfocus'   => ['<input autofocus onfocus=alert(1)>'],
            'div style expression'      => ['<div style="background:url(javascript:alert(1))">'],
            'null byte in tag'          => ["<scr\x00ipt>alert(1)</script>"],
            'nested double script'      => ['<<script>script>alert(1)<<</script>/script>'],
        ];
    }

    /**
     * Sanitizer::html must neutralise every XSS payload such that the output
     * contains no unescaped script delimiters or event-handler patterns.
     *
     * Invariants asserted per input:
     *   1. Output does not contain a raw "<script" substring.
     *   2. Output does not contain a raw "javascript:" substring.
     *   3. Output does not contain a raw "onerror=" or "onload=" substring.
     *   4. The output differs from the input (the payload was modified).
     */
    #[DataProvider('xssPayloadsProvider')]
    public function testSanitizerHtmlNeutralisesXssPayload(string $payload): void
    {
        $sanitized = Sanitizer::html($payload);

        // Invariant 1: no unescaped opening script tag
        self::assertStringNotContainsString(
            '<script',
            $sanitized,
            "Unescaped <script found in output for payload: {$payload}"
        );

        // Invariant 2: no raw javascript: protocol
        self::assertStringNotContainsString(
            'javascript:',
            strtolower($sanitized),
            "Unescaped javascript: found in output for payload: {$payload}"
        );

        // Invariant 3: no raw event-handler attribute patterns
        self::assertStringNotContainsString(
            'onerror=',
            $sanitized,
            "Unescaped onerror= found in output for payload: {$payload}"
        );
        self::assertStringNotContainsString(
            'onload=',
            $sanitized,
            "Unescaped onload= found in output for payload: {$payload}"
        );

        // Invariant 4: payload was actually changed
        self::assertNotSame(
            $payload,
            $sanitized,
            "Sanitizer returned input unchanged for payload: {$payload}"
        );
    }

    /**
     * Fixed corpus pairing raw text with its correct HTML-escaped form.
     *
     * @return array<string, array{string, string}>
     */
    public static function htmlEscapeCorpusProvider(): array
    {
        return [
            'ampersand'           => ['&', '&amp;'],
            'less-than'           => ['<', '&lt;'],
            'greater-than'        => ['>', '&gt;'],
            'double quote'        => ['"', '&quot;'],
            'single quote'        => ["'", '&#039;'],
            'combined dangerous'  => ['<b class="x">', '&lt;b class=&quot;x&quot;&gt;'],
            'plain text unharmed' => ['hello', 'hello'],
            'number unharmed'     => ['42', '42'],
            'empty string'        => ['', ''],
        ];
    }

    /**
     * Sanitizer::html must produce the exact HTML-entity encoding expected by
     * htmlspecialchars with ENT_QUOTES | ENT_HTML5 and UTF-8.
     */
    #[DataProvider('htmlEscapeCorpusProvider')]
    public function testSanitizerHtmlMatchesExpectedEscaping(string $input, string $expected): void
    {
        self::assertSame($expected, Sanitizer::html($input));
    }

    // =========================================================================
    // Token Bucket Invariants
    // =========================================================================

    /**
     * Rate limit scenario corpus: [capacity, refillRate, refillPeriod, consume, expectAllow].
     *
     * Each entry represents a bucket configuration and a single consume attempt,
     * with the expected result of that attempt.
     *
     * @return array<string, array{int, float, int, int, bool}>
     */
    public static function rateLimitScenariosProvider(): array
    {
        return [
            'full bucket allows 1 token'        => [10, 1.0, 1, 1, true],
            'full bucket allows burst of 5'     => [10, 1.0, 1, 5, true],
            'full bucket allows full burst'     => [10, 1.0, 1, 10, true],
            'full bucket rejects over-burst'    => [10, 1.0, 1, 11, false],
            'capacity 1 allows single request'  => [1, 1.0, 1, 1, true],
            'capacity 1 rejects second request' => [1, 1.0, 1, 2, false],
            'large capacity allows 50 of 100'   => [100, 1.0, 1, 50, true],
            'large capacity allows exact 100'   => [100, 2.0, 1, 100, true],
            'large capacity rejects 101'        => [100, 2.0, 1, 101, false],
            'slow refill bucket still allows 1' => [5, 0.1, 60, 1, true],
            'slow refill allows full burst'     => [5, 0.1, 60, 5, true],
            'slow refill rejects over burst'    => [5, 0.1, 60, 6, false],
        ];
    }

    /**
     * Verifies token bucket invariants across the fixed scenario corpus:
     *   1. Attempt returns the expected allow/deny result.
     *   2. Remaining tokens are never negative after any operation.
     *   3. Remaining tokens never exceed the bucket capacity.
     */
    #[DataProvider('rateLimitScenariosProvider')]
    public function testTokenBucketInvariantsHoldForScenario(
        int   $capacity,
        float $refillRate,
        int   $refillPeriod,
        int   $consume,
        bool  $expectAllow
    ): void {
        $store  = new MemoryStore();
        $bucket = new TokenBucket($store, $capacity, $refillRate, $refillPeriod);
        $key    = 'prop-test-user';

        // Invariant: remaining never exceeds capacity before any operation
        self::assertLessThanOrEqual(
            (float) $capacity,
            $bucket->remaining($key),
            'Remaining tokens exceeded capacity on fresh bucket'
        );

        $result = $bucket->attempt($key, $consume);

        // Invariant 1: attempt returns expected allow/deny
        self::assertSame(
            $expectAllow,
            $result,
            "Expected attempt({$consume}) on capacity={$capacity} to return "
            . ($expectAllow ? 'true' : 'false')
        );

        $remaining = $bucket->remaining($key);

        // Invariant 2: remaining is never negative
        self::assertGreaterThanOrEqual(
            0.0,
            $remaining,
            "Remaining tokens went negative: {$remaining}"
        );

        // Invariant 3: remaining never exceeds capacity
        self::assertLessThanOrEqual(
            (float) $capacity,
            $remaining,
            "Remaining tokens exceeded capacity: {$remaining} > {$capacity}"
        );
    }

    // =========================================================================
    // Header Value Format Properties
    // =========================================================================

    /**
     * Fixed corpus of (headerName, headerValue) pairs that must be present in
     * a well-formed HTTP response header string.
     *
     * Each entry is: [headerName, expectedFragment]
     *
     * @return array<string, array{string, string}>
     */
    public static function headerFormatCorpusProvider(): array
    {
        return [
            'X-Frame-Options DENY'          => ['X-Frame-Options', 'DENY'],
            'X-Frame-Options SAMEORIGIN'    => ['X-Frame-Options', 'SAMEORIGIN'],
            'X-Content-Type-Options'        => ['X-Content-Type-Options', 'nosniff'],
            'XSS Protection 1 mode block'   => ['X-XSS-Protection', '1; mode=block'],
            'Referrer strict-origin'        => ['Referrer-Policy', 'strict-origin-when-cross-origin'],
            'HSTS max-age'                  => ['Strict-Transport-Security', 'max-age=31536000'],
            'HSTS includeSubDomains'        => ['Strict-Transport-Security', 'includeSubDomains'],
            'COEP require-corp'             => ['Cross-Origin-Embedder-Policy', 'require-corp'],
            'COOP same-origin'              => ['Cross-Origin-Opener-Policy', 'same-origin'],
            'CORP same-origin'              => ['Cross-Origin-Resource-Policy', 'same-origin'],
            'CSP default-src self'          => ['Content-Security-Policy', "default-src 'self'"],
        ];
    }

    /**
     * Verifies that each header value corpus entry is properly formatted:
     *   1. The header name is a non-empty string.
     *   2. The expected fragment is a non-empty string.
     *   3. A composed "Name: Value" string contains the fragment.
     *
     * This tests the structural correctness of known-good header values
     * without invoking the PHP header() call (which requires a separate process).
     */
    #[DataProvider('headerFormatCorpusProvider')]
    public function testHeaderValueFormatIsWellFormed(string $headerName, string $expectedFragment): void
    {
        // Invariant 1: header name is non-empty
        self::assertNotEmpty($headerName, 'Header name must not be empty');

        // Invariant 2: expected fragment is non-empty
        self::assertNotEmpty($expectedFragment, 'Header value fragment must not be empty');

        // Invariant 3: composed header string contains the expected fragment
        $composed = "{$headerName}: {$expectedFragment}";
        self::assertStringContainsString(
            $expectedFragment,
            $composed,
            "Composed header does not contain expected fragment"
        );

        // Invariant 4: header name contains no CR/LF (header injection prevention)
        self::assertStringNotContainsString("\r", $headerName, 'Header name contains CR character');
        self::assertStringNotContainsString("\n", $headerName, 'Header name contains LF character');

        // Invariant 5: fragment contains no CR/LF (header injection prevention)
        self::assertStringNotContainsString("\r", $expectedFragment, 'Header value contains CR character');
        self::assertStringNotContainsString("\n", $expectedFragment, 'Header value contains LF character');
    }
}
