<?php

/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\RateLimit;

/**
 * Token bucket rate limiter.
 *
 * Implements the token bucket algorithm for rate limiting:
 * - Bucket starts with N tokens
 * - Each request consumes a token
 * - Tokens refill at a constant rate
 * - Requests are allowed if tokens are available
 *
 * This provides smooth rate limiting with burst allowance.
 *
 * @link https://en.wikipedia.org/wiki/Token_bucket
 */
final class TokenBucket
{
    private RateLimitStoreInterface $store;
    private int $capacity;
    private float $refillRate;
    private int $refillPeriod;

    /**
     * Create a new token bucket.
     *
     * @param RateLimitStoreInterface $store Storage backend
     * @param int $capacity Maximum tokens in bucket (burst allowance)
     * @param float $refillRate Tokens added per refill period
     * @param int $refillPeriod Refill period in seconds (default: 1)
     */
    public function __construct(
        RateLimitStoreInterface $store,
        int $capacity,
        float $refillRate,
        int $refillPeriod = 1
    ) {
        if ($capacity <= 0) {
            throw new \InvalidArgumentException('Capacity must be positive');
        }

        if ($refillRate <= 0) {
            throw new \InvalidArgumentException('Refill rate must be positive');
        }

        if ($refillPeriod <= 0) {
            throw new \InvalidArgumentException('Refill period must be positive');
        }

        $this->store = $store;
        $this->capacity = $capacity;
        $this->refillRate = $refillRate;
        $this->refillPeriod = $refillPeriod;
    }

    /**
     * Attempt to consume tokens.
     *
     * @param string $key Unique identifier (e.g., user ID, IP address)
     * @param int $tokens Number of tokens to consume (default: 1)
     * @return bool True if tokens were available and consumed
     */
    public function attempt(string $key, int $tokens = 1): bool
    {
        if ($tokens <= 0) {
            throw new \InvalidArgumentException('Tokens must be positive');
        }

        $bucket = $this->getBucket($key);
        $availableTokens = $bucket['tokens'];

        if ($availableTokens < $tokens) {
            // Not enough tokens
            return false;
        }

        // Consume tokens
        $bucket['tokens'] -= $tokens;
        $this->saveBucket($key, $bucket);

        return true;
    }

    /**
     * Get remaining tokens for a key.
     *
     * @param string $key Unique identifier
     * @return float Number of tokens available
     */
    public function remaining(string $key): float
    {
        $bucket = $this->getBucket($key);
        return max(0.0, $bucket['tokens']);
    }

    /**
     * Get time until next token is available (seconds).
     *
     * @param string $key Unique identifier
     * @return int Seconds until next refill (0 if tokens available)
     */
    public function resetAt(string $key): int
    {
        $bucket = $this->getBucket($key);

        if ($bucket['tokens'] >= 1) {
            return 0; // Tokens available now
        }

        // Calculate seconds until next token
        $now = time();
        $elapsedSeconds = $now - $bucket['lastRefill'];
        $periodsSinceRefill = floor($elapsedSeconds / $this->refillPeriod);
        $secondsIntoCurrentPeriod = $elapsedSeconds % $this->refillPeriod;
        $secondsUntilNextPeriod = $this->refillPeriod - $secondsIntoCurrentPeriod;

        return (int) $secondsUntilNextPeriod;
    }

    /**
     * Reset bucket for a key (fill to capacity).
     *
     * @param string $key Unique identifier
     * @return void
     */
    public function reset(string $key): void
    {
        $this->store->delete($key);
    }

    /**
     * Get bucket state with token refill applied.
     *
     * @param string $key Unique identifier
     * @return array{tokens: float, lastRefill: int}
     */
    private function getBucket(string $key): array
    {
        $now = time();
        $bucket = $this->store->get($key);

        if ($bucket === null) {
            // Initialize new bucket
            return [
                'tokens' => (float) $this->capacity,
                'lastRefill' => $now,
            ];
        }

        // Calculate tokens to add based on elapsed time
        $elapsedSeconds = $now - $bucket['lastRefill'];
        $periods = floor($elapsedSeconds / $this->refillPeriod);
        $tokensToAdd = $periods * $this->refillRate;

        if ($tokensToAdd > 0) {
            $bucket['tokens'] = min(
                $this->capacity,
                $bucket['tokens'] + $tokensToAdd
            );
            $bucket['lastRefill'] = $now;
        }

        return $bucket;
    }

    /**
     * Save bucket state to storage.
     *
     * @param string $key Unique identifier
     * @param array{tokens: float, lastRefill: int} $bucket Bucket state
     * @return void
     */
    private function saveBucket(string $key, array $bucket): void
    {
        // TTL: capacity / refillRate gives time to refill completely
        // Add some buffer to prevent premature expiration
        $ttl = (int) (($this->capacity / $this->refillRate) * $this->refillPeriod * 2);

        $this->store->set($key, $bucket, $ttl);
    }
}
