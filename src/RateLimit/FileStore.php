<?php

/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\RateLimit;

use PhpAegis\Sanitizer;

/**
 * File-based rate limit storage.
 *
 * Stores token bucket data as JSON files in a directory.
 * Suitable for production use on single-server deployments.
 *
 * Features:
 * - Atomic writes with file locking
 * - Automatic garbage collection of expired entries
 * - Safe filename generation (prevents path traversal)
 *
 * For multi-server deployments, use Redis or database-backed store.
 */
final class FileStore implements RateLimitStoreInterface
{
    private string $directory;
    private string $prefix;

    /**
     * Create a new file-based store.
     *
     * @param string $directory Storage directory (must be writable)
     * @param string $prefix Filename prefix (default: 'ratelimit_')
     * @throws \RuntimeException If directory is not writable
     */
    public function __construct(string $directory, string $prefix = 'ratelimit_')
    {
        $this->directory = rtrim($directory, '/');
        $this->prefix = $prefix;

        // Ensure directory exists and is writable
        if (!is_dir($this->directory)) {
            if (!mkdir($this->directory, 0755, true)) {
                throw new \RuntimeException("Cannot create directory: {$this->directory}");
            }
        }

        if (!is_writable($this->directory)) {
            throw new \RuntimeException("Directory not writable: {$this->directory}");
        }
    }

    /**
     * Get bucket data for a key.
     *
     * @param string $key Unique identifier
     * @return array{tokens: float, lastRefill: int}|null Bucket state or null if not found
     */
    public function get(string $key): ?array
    {
        $filename = $this->getFilename($key);

        if (!file_exists($filename)) {
            return null;
        }

        // Read file with shared lock
        $fp = fopen($filename, 'r');
        if ($fp === false) {
            return null;
        }

        if (!flock($fp, LOCK_SH)) {
            fclose($fp);
            return null;
        }

        $content = stream_get_contents($fp);
        flock($fp, LOCK_UN);
        fclose($fp);

        if ($content === false) {
            return null;
        }

        $data = json_decode($content, true);
        if (!is_array($data)) {
            return null;
        }

        // Check if expired
        if (isset($data['expiresAt']) && $data['expiresAt'] < time()) {
            @unlink($filename);
            return null;
        }

        if (!isset($data['tokens']) || !isset($data['lastRefill'])) {
            return null;
        }

        return [
            'tokens' => (float) $data['tokens'],
            'lastRefill' => (int) $data['lastRefill'],
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
        $filename = $this->getFilename($key);

        $content = json_encode([
            'tokens' => $data['tokens'],
            'lastRefill' => $data['lastRefill'],
            'expiresAt' => time() + $ttl,
        ], JSON_THROW_ON_ERROR);

        // Write atomically with exclusive lock
        $fp = fopen($filename, 'c');
        if ($fp === false) {
            throw new \RuntimeException("Cannot open file for writing: {$filename}");
        }

        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            throw new \RuntimeException("Cannot acquire exclusive lock: {$filename}");
        }

        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, $content);
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
    }

    /**
     * Delete bucket data for a key.
     *
     * @param string $key Unique identifier
     * @return void
     */
    public function delete(string $key): void
    {
        $filename = $this->getFilename($key);

        if (file_exists($filename)) {
            @unlink($filename);
        }
    }

    /**
     * Clear all bucket data.
     *
     * WARNING: This deletes all rate limit files in the directory.
     *
     * @return void
     */
    public function clear(): void
    {
        $files = glob($this->directory . '/' . $this->prefix . '*');

        if ($files === false) {
            return;
        }

        foreach ($files as $file) {
            if (is_file($file)) {
                @unlink($file);
            }
        }
    }

    /**
     * Garbage collection: remove expired entries.
     *
     * @return int Number of files removed
     */
    public function gc(): int
    {
        $removed = 0;
        $now = time();
        $files = glob($this->directory . '/' . $this->prefix . '*');

        if ($files === false) {
            return 0;
        }

        foreach ($files as $file) {
            if (!is_file($file)) {
                continue;
            }

            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $data = json_decode($content, true);
            if (!is_array($data) || !isset($data['expiresAt'])) {
                continue;
            }

            if ($data['expiresAt'] < $now) {
                @unlink($file);
                $removed++;
            }
        }

        return $removed;
    }

    /**
     * Generate safe filename for a key.
     *
     * Prevents path traversal attacks by sanitizing the key.
     *
     * @param string $key Unique identifier
     * @return string Full path to file
     */
    private function getFilename(string $key): string
    {
        // Hash the key to get a safe filename
        $hash = hash('sha256', $key);

        return $this->directory . '/' . $this->prefix . $hash . '.json';
    }
}
