<?php // SPDX-License-Identifier: MPL-2.0

/**
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 *
 * BenchmarkTest — lightweight performance documentation tests.
 *
 * These tests do NOT use a dedicated benchmarking framework. Instead they
 * use microtime(true) to record wall-clock time for a fixed workload and
 * assert that the total time stays under a generous upper bound.
 *
 * Purpose:
 *   - Documents that security middleware overhead is bounded and acceptable.
 *   - Catches catastrophic regressions (O(n²) loops, unbounded allocations).
 *   - Gives CRG reviewers a reference for expected throughput.
 *
 * Thresholds are intentionally generous (10× the expected time on typical
 * hardware) to avoid false failures on slow CI runners or VMs. The numbers
 * are printed to STDOUT for human review even when assertions pass.
 *
 * CRG Grade: C requirement.
 */

declare(strict_types=1);

namespace PhpAegis\Tests;

use PHPUnit\Framework\TestCase;
use PhpAegis\Sanitizer;
use PhpAegis\Validator;
use PhpAegis\RateLimit\RateLimiter;
use PhpAegis\RateLimit\MemoryStore;

/**
 * Lightweight performance regression tests using microtime(true).
 *
 * All thresholds are wall-clock seconds. They are set to be reachable on any
 * modern hardware (including slow CI containers) while still detecting truly
 * catastrophic regressions. On a 2020+ laptop, each workload typically
 * completes in under 20 ms.
 */
final class BenchmarkTest extends TestCase
{
    // -------------------------------------------------------------------------
    // Configuration constants (adjust if CI is consistently slower)
    // -------------------------------------------------------------------------

    /** Number of sanitizer invocations per throughput test. */
    private const SANITIZER_ITERATIONS = 1000;

    /** Number of rate-limiter check invocations per throughput test. */
    private const RATE_LIMIT_ITERATIONS = 500;

    /** Number of validator invocations per throughput test. */
    private const VALIDATOR_ITERATIONS = 500;

    /**
     * Maximum allowed wall-clock seconds for the sanitizer throughput test.
     * 2 seconds for 1000 iterations = 2 ms per call max, which is very generous.
     */
    private const SANITIZER_MAX_SECONDS = 2.0;

    /**
     * Maximum allowed wall-clock seconds for the rate-limiter throughput test.
     * In-memory store, so 1 second for 500 iterations is very generous.
     */
    private const RATE_LIMIT_MAX_SECONDS = 1.0;

    /**
     * Maximum allowed wall-clock seconds for the validator throughput test.
     * Regex-based validators; 1 second for 500 iterations is very generous.
     */
    private const VALIDATOR_MAX_SECONDS = 1.0;

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /**
     * Run a callable $iterations times and return elapsed wall-clock seconds.
     *
     * @param callable $fn         Work to perform per iteration
     * @param int      $iterations Number of repetitions
     * @return float Elapsed seconds (float precision)
     */
    private function timeIterations(callable $fn, int $iterations): float
    {
        $start = microtime(true);
        for ($i = 0; $i < $iterations; $i++) {
            $fn($i);
        }
        return microtime(true) - $start;
    }

    /**
     * Print a benchmark summary line to STDOUT so it appears in verbose output.
     *
     * @param string $label      Human-readable test name
     * @param int    $iterations Number of iterations run
     * @param float  $elapsed    Elapsed seconds
     * @param float  $limit      Threshold seconds (assertion limit)
     */
    private function reportTiming(string $label, int $iterations, float $elapsed, float $limit): void
    {
        $ms        = round($elapsed * 1000, 2);
        $perCallUs = $iterations > 0 ? round(($elapsed / $iterations) * 1_000_000, 1) : 0;
        $status    = $elapsed <= $limit ? 'PASS' : 'OVER LIMIT';

        printf(
            "\n  [BENCH] %-45s %7.2f ms  %6.1f µs/call  [%s]\n",
            $label,
            $ms,
            $perCallUs,
            $status
        );
    }

    // =========================================================================
    // Sanitizer Throughput
    // =========================================================================

    /**
     * Measure Sanitizer::html throughput over 1000 plain text inputs.
     *
     * Plain text is the common case — it must complete with negligible overhead.
     */
    public function testSanitizerHtmlThroughputOnPlainText(): void
    {
        $inputs = array_map(
            static fn (int $i): string => "User input number {$i} with normal text content",
            range(0, self::SANITIZER_ITERATIONS - 1)
        );

        $elapsed = $this->timeIterations(
            static fn (int $i) => Sanitizer::html($inputs[$i]),
            self::SANITIZER_ITERATIONS
        );

        $this->reportTiming(
            'Sanitizer::html — plain text × ' . self::SANITIZER_ITERATIONS,
            self::SANITIZER_ITERATIONS,
            $elapsed,
            self::SANITIZER_MAX_SECONDS
        );

        self::assertLessThan(
            self::SANITIZER_MAX_SECONDS,
            $elapsed,
            sprintf(
                'Sanitizer::html throughput regression: %d iterations took %.3f s (limit %.1f s)',
                self::SANITIZER_ITERATIONS,
                $elapsed,
                self::SANITIZER_MAX_SECONDS
            )
        );
    }

    /**
     * Measure Sanitizer::html throughput over 1000 XSS payloads.
     *
     * XSS payloads require more htmlspecialchars work; this test ensures that
     * adversarial input does not cause a disproportionate slowdown.
     */
    public function testSanitizerHtmlThroughputOnXssPayloads(): void
    {
        // Build a rotating corpus of 10 XSS payloads
        $corpus = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<a href="javascript:alert(1)">click</a>',
            '<iframe src="javascript:alert(1)">',
            '<body onload="alert(1)">',
            '<div style="background:url(javascript:alert(1))">',
            '<<script>script>alert(1)<<</script>/script>',
            "<scr\x00ipt>alert(1)</script>",
            '<a href="data:text/html,<script>alert(1)</script>">x</a>',
        ];
        $corpusSize = count($corpus);

        $elapsed = $this->timeIterations(
            static fn (int $i) => Sanitizer::html($corpus[$i % $corpusSize]),
            self::SANITIZER_ITERATIONS
        );

        $this->reportTiming(
            'Sanitizer::html — XSS payloads × ' . self::SANITIZER_ITERATIONS,
            self::SANITIZER_ITERATIONS,
            $elapsed,
            self::SANITIZER_MAX_SECONDS
        );

        self::assertLessThan(
            self::SANITIZER_MAX_SECONDS,
            $elapsed,
            sprintf(
                'Sanitizer::html XSS throughput regression: %d iterations took %.3f s (limit %.1f s)',
                self::SANITIZER_ITERATIONS,
                $elapsed,
                self::SANITIZER_MAX_SECONDS
            )
        );
    }

    /**
     * Measure Sanitizer::stripTags throughput over 1000 mixed HTML inputs.
     */
    public function testSanitizerStripTagsThroughput(): void
    {
        $corpus = [
            '<p>Hello <b>World</b></p>',
            '<script>alert(1)</script> Safe text',
            '<div><span>Nested <em>tags</em> here</span></div>',
            'Plain text with no tags at all',
            '<a href="http://example.com">Link text</a>',
        ];
        $corpusSize = count($corpus);

        $elapsed = $this->timeIterations(
            static fn (int $i) => Sanitizer::stripTags($corpus[$i % $corpusSize]),
            self::SANITIZER_ITERATIONS
        );

        $this->reportTiming(
            'Sanitizer::stripTags — mixed HTML × ' . self::SANITIZER_ITERATIONS,
            self::SANITIZER_ITERATIONS,
            $elapsed,
            self::SANITIZER_MAX_SECONDS
        );

        self::assertLessThan(self::SANITIZER_MAX_SECONDS, $elapsed);
    }

    // =========================================================================
    // Rate Limiter Throughput
    // =========================================================================

    /**
     * Measure RateLimiter::attempt throughput over 500 allow calls.
     *
     * Uses a large bucket so no calls are rejected — this measures the overhead
     * of the allow path, which is the hot path in production.
     */
    public function testRateLimiterAttemptAllowPathThroughput(): void
    {
        // Large capacity bucket so no calls will be rejected during the bench
        $store   = new MemoryStore();
        $limiter = RateLimiter::perSecond(self::RATE_LIMIT_ITERATIONS + 1, $store);

        $elapsed = $this->timeIterations(
            static fn (int $i) => $limiter->attempt("bench-user-{$i}"),
            self::RATE_LIMIT_ITERATIONS
        );

        $this->reportTiming(
            'RateLimiter::attempt — allow path × ' . self::RATE_LIMIT_ITERATIONS,
            self::RATE_LIMIT_ITERATIONS,
            $elapsed,
            self::RATE_LIMIT_MAX_SECONDS
        );

        self::assertLessThan(
            self::RATE_LIMIT_MAX_SECONDS,
            $elapsed,
            sprintf(
                'RateLimiter::attempt throughput regression: %d iterations took %.3f s (limit %.1f s)',
                self::RATE_LIMIT_ITERATIONS,
                $elapsed,
                self::RATE_LIMIT_MAX_SECONDS
            )
        );
    }

    /**
     * Measure RateLimiter::attempt throughput on the deny path.
     *
     * After exhausting the bucket, all subsequent calls hit the deny path.
     * This must also be fast — denial decisions must not be slower than allows.
     */
    public function testRateLimiterAttemptDenyPathThroughput(): void
    {
        $store   = new MemoryStore();
        $limiter = RateLimiter::perSecond(1, $store);

        // Exhaust the bucket with a single allowed call
        $limiter->attempt('bench-deny-user');

        $elapsed = $this->timeIterations(
            static fn (int $_) => $limiter->attempt('bench-deny-user'),
            self::RATE_LIMIT_ITERATIONS
        );

        $this->reportTiming(
            'RateLimiter::attempt — deny path × ' . self::RATE_LIMIT_ITERATIONS,
            self::RATE_LIMIT_ITERATIONS,
            $elapsed,
            self::RATE_LIMIT_MAX_SECONDS
        );

        self::assertLessThan(self::RATE_LIMIT_MAX_SECONDS, $elapsed);
    }

    // =========================================================================
    // Validator Throughput
    // =========================================================================

    /**
     * Measure Validator::email throughput over 500 valid email addresses.
     */
    public function testValidatorEmailThroughputOnValidAddresses(): void
    {
        $emails = array_map(
            static fn (int $i): string => "user{$i}@example{$i}.com",
            range(0, self::VALIDATOR_ITERATIONS - 1)
        );

        $elapsed = $this->timeIterations(
            static fn (int $i) => Validator::email($emails[$i]),
            self::VALIDATOR_ITERATIONS
        );

        $this->reportTiming(
            'Validator::email — valid × ' . self::VALIDATOR_ITERATIONS,
            self::VALIDATOR_ITERATIONS,
            $elapsed,
            self::VALIDATOR_MAX_SECONDS
        );

        self::assertLessThan(
            self::VALIDATOR_MAX_SECONDS,
            $elapsed,
            sprintf(
                'Validator::email throughput regression: %d iterations took %.3f s (limit %.1f s)',
                self::VALIDATOR_ITERATIONS,
                $elapsed,
                self::VALIDATOR_MAX_SECONDS
            )
        );
    }

    /**
     * Measure Validator::url throughput over 500 valid HTTPS URLs.
     */
    public function testValidatorUrlThroughputOnValidUrls(): void
    {
        $urls = array_map(
            static fn (int $i): string => "https://example{$i}.com/path?q={$i}",
            range(0, self::VALIDATOR_ITERATIONS - 1)
        );

        $elapsed = $this->timeIterations(
            static fn (int $i) => Validator::url($urls[$i]),
            self::VALIDATOR_ITERATIONS
        );

        $this->reportTiming(
            'Validator::url — valid × ' . self::VALIDATOR_ITERATIONS,
            self::VALIDATOR_ITERATIONS,
            $elapsed,
            self::VALIDATOR_MAX_SECONDS
        );

        self::assertLessThan(self::VALIDATOR_MAX_SECONDS, $elapsed);
    }

    /**
     * Measure Validator::email throughput on a mix of valid and invalid addresses.
     *
     * Regex rejection must not be slower than acceptance.
     */
    public function testValidatorEmailThroughputOnMixedAddresses(): void
    {
        $mixed = [
            'valid@example.com',
            'not-an-email',
            'also.valid+tag@sub.domain.co.uk',
            'missing-at-sign',
            'user@domain.org',
            '@no-local.com',
            'first.last@company.io',
            'spaces not allowed',
            'test+tag@example.net',
            'double@@at.com',
        ];
        $corpusSize = count($mixed);

        $elapsed = $this->timeIterations(
            static fn (int $i) => Validator::email($mixed[$i % $corpusSize]),
            self::VALIDATOR_ITERATIONS
        );

        $this->reportTiming(
            'Validator::email — mixed × ' . self::VALIDATOR_ITERATIONS,
            self::VALIDATOR_ITERATIONS,
            $elapsed,
            self::VALIDATOR_MAX_SECONDS
        );

        self::assertLessThan(self::VALIDATOR_MAX_SECONDS, $elapsed);
    }

    // =========================================================================
    // Header Validation Speed
    // =========================================================================

    /**
     * Measure Sanitizer::html applied to header-style strings.
     *
     * Header values are typically short ASCII strings. This confirms that the
     * sanitizer overhead for header content is negligible.
     */
    public function testHeaderValueSanitizationSpeed(): void
    {
        $headerValues = [
            'DENY',
            'SAMEORIGIN',
            'nosniff',
            '1; mode=block',
            'strict-origin-when-cross-origin',
            "default-src 'self'; script-src 'self' https://cdn.example.com",
            'max-age=31536000; includeSubDomains; preload',
            'require-corp',
            'same-origin',
            'camera=(), microphone=()',
        ];
        $corpusSize = count($headerValues);

        $elapsed = $this->timeIterations(
            static fn (int $i) => Sanitizer::html($headerValues[$i % $corpusSize]),
            self::SANITIZER_ITERATIONS
        );

        $this->reportTiming(
            'Sanitizer::html — header values × ' . self::SANITIZER_ITERATIONS,
            self::SANITIZER_ITERATIONS,
            $elapsed,
            self::SANITIZER_MAX_SECONDS
        );

        self::assertLessThan(
            self::SANITIZER_MAX_SECONDS,
            $elapsed,
            'Header value sanitization throughput regression detected'
        );
    }
}
