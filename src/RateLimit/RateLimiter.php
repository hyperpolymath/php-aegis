<?php

/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\RateLimit;

/**
 * High-level rate limiter with preset configurations.
 *
 * Provides convenient preset configurations for common use cases:
 * - API rate limiting
 * - Login attempt limiting
 * - Form submission limiting
 *
 * Usage:
 * ```php
 * $limiter = RateLimiter::perMinute(60, new FileStore('/tmp/ratelimit'));
 * if (!$limiter->attempt($userId)) {
 *     throw new TooManyRequestsException('Rate limit exceeded');
 * }
 * ```
 */
final class RateLimiter
{
    private TokenBucket $bucket;

    /**
     * Create a new rate limiter.
     *
     * @param TokenBucket $bucket Token bucket instance
     */
    public function __construct(TokenBucket $bucket)
    {
        $this->bucket = $bucket;
    }

    /**
     * Create a per-second rate limiter.
     *
     * @param int $maxRequests Maximum requests per second
     * @param RateLimitStoreInterface $store Storage backend
     * @return self
     */
    public static function perSecond(int $maxRequests, RateLimitStoreInterface $store): self
    {
        return new self(new TokenBucket(
            $store,
            $maxRequests,
            (float) $maxRequests,
            1
        ));
    }

    /**
     * Create a per-minute rate limiter.
     *
     * @param int $maxRequests Maximum requests per minute
     * @param RateLimitStoreInterface $store Storage backend
     * @param int $burstAllowance Burst allowance (default: same as maxRequests)
     * @return self
     */
    public static function perMinute(
        int $maxRequests,
        RateLimitStoreInterface $store,
        int $burstAllowance = 0
    ): self {
        $burst = $burstAllowance > 0 ? $burstAllowance : $maxRequests;

        return new self(new TokenBucket(
            $store,
            $burst,
            (float) $maxRequests / 60,
            1
        ));
    }

    /**
     * Create a per-hour rate limiter.
     *
     * @param int $maxRequests Maximum requests per hour
     * @param RateLimitStoreInterface $store Storage backend
     * @param int $burstAllowance Burst allowance (default: maxRequests / 10)
     * @return self
     */
    public static function perHour(
        int $maxRequests,
        RateLimitStoreInterface $store,
        int $burstAllowance = 0
    ): self {
        $burst = $burstAllowance > 0 ? $burstAllowance : (int) ($maxRequests / 10);

        return new self(new TokenBucket(
            $store,
            $burst,
            (float) $maxRequests / 3600,
            1
        ));
    }

    /**
     * Create a per-day rate limiter.
     *
     * @param int $maxRequests Maximum requests per day
     * @param RateLimitStoreInterface $store Storage backend
     * @param int $burstAllowance Burst allowance (default: maxRequests / 100)
     * @return self
     */
    public static function perDay(
        int $maxRequests,
        RateLimitStoreInterface $store,
        int $burstAllowance = 0
    ): self {
        $burst = $burstAllowance > 0 ? $burstAllowance : (int) ($maxRequests / 100);

        return new self(new TokenBucket(
            $store,
            $burst,
            (float) $maxRequests / 86400,
            1
        ));
    }

    /**
     * Attempt a request.
     *
     * @param string $key Unique identifier (e.g., user ID, IP address)
     * @param int $tokens Number of tokens to consume (default: 1)
     * @return bool True if request is allowed
     */
    public function attempt(string $key, int $tokens = 1): bool
    {
        return $this->bucket->attempt($key, $tokens);
    }

    /**
     * Get remaining requests for a key.
     *
     * @param string $key Unique identifier
     * @return float Number of requests remaining
     */
    public function remaining(string $key): float
    {
        return $this->bucket->remaining($key);
    }

    /**
     * Get seconds until rate limit resets.
     *
     * @param string $key Unique identifier
     * @return int Seconds until reset (0 if requests available)
     */
    public function resetAt(string $key): int
    {
        return $this->bucket->resetAt($key);
    }

    /**
     * Reset rate limit for a key.
     *
     * @param string $key Unique identifier
     * @return void
     */
    public function reset(string $key): void
    {
        $this->bucket->reset($key);
    }

    /**
     * Get the underlying token bucket.
     *
     * @return TokenBucket
     */
    public function getTokenBucket(): TokenBucket
    {
        return $this->bucket;
    }
}
