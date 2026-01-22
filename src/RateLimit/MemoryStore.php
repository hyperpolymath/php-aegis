<?php

/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\RateLimit;

/**
 * In-memory rate limit storage.
 *
 * Stores token bucket data in PHP memory. Data is lost when the process ends.
 * Suitable for development, testing, or single-request scenarios.
 *
 * WARNING: Not suitable for production across multiple processes/servers.
 * Use FileStore, RedisStore, or database-backed store for production.
 */
final class MemoryStore implements RateLimitStoreInterface
{
    /**
     * In-memory storage.
     *
     * @var array<string, array{tokens: float, lastRefill: int, expiresAt: int}>
     */
    private array $storage = [];

    /**
     * Get bucket data for a key.
     *
     * @param string $key Unique identifier
     * @return array{tokens: float, lastRefill: int}|null Bucket state or null if not found
     */
    public function get(string $key): ?array
    {
        if (!isset($this->storage[$key])) {
            return null;
        }

        $data = $this->storage[$key];

        // Check if expired
        if ($data['expiresAt'] < time()) {
            unset($this->storage[$key]);
            return null;
        }

        return [
            'tokens' => $data['tokens'],
            'lastRefill' => $data['lastRefill'],
        ];
    }

    /**
     * Set bucket data for a key.
     *
     * @param string $key Unique identifier
     * @param array{tokens: float, lastRefill: int} $data Bucket state
     * @param int $ttl Time-to-live in seconds
     * @return void
     */
    public function set(string $key, array $data, int $ttl): void
    {
        $this->storage[$key] = [
            'tokens' => $data['tokens'],
            'lastRefill' => $data['lastRefill'],
            'expiresAt' => time() + $ttl,
        ];
    }

    /**
     * Delete bucket data for a key.
     *
     * @param string $key Unique identifier
     * @return void
     */
    public function delete(string $key): void
    {
        unset($this->storage[$key]);
    }

    /**
     * Clear all bucket data.
     *
     * @return void
     */
    public function clear(): void
    {
        $this->storage = [];
    }

    /**
     * Garbage collection: remove expired entries.
     *
     * Call this periodically to free memory from expired buckets.
     *
     * @return int Number of entries removed
     */
    public function gc(): int
    {
        $removed = 0;
        $now = time();

        foreach ($this->storage as $key => $data) {
            if ($data['expiresAt'] < $now) {
                unset($this->storage[$key]);
                $removed++;
            }
        }

        return $removed;
    }
}
