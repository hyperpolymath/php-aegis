<?php

/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\RateLimit;

/**
 * Storage interface for rate limiting data.
 *
 * Implementations provide different storage backends (memory, file, Redis, etc.)
 * for persisting token bucket state.
 */
interface RateLimitStoreInterface
{
    /**
     * Get bucket data for a key.
     *
     * @param string $key Unique identifier (e.g., user ID, IP address)
     * @return array{tokens: float, lastRefill: int}|null Bucket state or null if not found
     */
    public function get(string $key): ?array;

    /**
     * Set bucket data for a key.
     *
     * @param string $key Unique identifier
     * @param array{tokens: float, lastRefill: int} $data Bucket state
     * @param int $ttl Time-to-live in seconds
     * @return void
     */
    public function set(string $key, array $data, int $ttl): void;

    /**
     * Delete bucket data for a key.
     *
     * @param string $key Unique identifier
     * @return void
     */
    public function delete(string $key): void;

    /**
     * Clear all bucket data.
     *
     * @return void
     */
    public function clear(): void;
}
