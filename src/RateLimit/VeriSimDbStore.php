<?php

/**
 * SPDX-License-Identifier: MPL-2.0
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\RateLimit;

/**
 * VeriSimDB-backed rate limit storage.
 *
 * Stores token bucket state in VeriSimDB via its REST API
 * (collection: php-aegis:rate-limits). Suitable for multi-server
 * deployments where all nodes must share rate limit state.
 *
 * ## Environment variables
 *
 * - `VERISIMDB_URL`: Base URL of the VeriSimDB instance
 *   (default: `http://localhost:8080`).
 *
 * ## Fallback behaviour
 *
 * On VeriSimDB connectivity failure (curl error, non-2xx response),
 * operations fail open: get() returns null (no throttling), set() and
 * delete() become no-ops. This ensures PHP-Aegis never blocks legitimate
 * traffic due to a VeriSimDB outage. Use the FileStore fallback if you
 * prefer fail-closed semantics.
 *
 * ## Collection schema
 *
 * Documents are stored under the key `<prefix><key>` with shape:
 * ```json
 * { "tokens": 9.5, "lastRefill": 1740000000 }
 * ```
 *
 * TTL is enforced by a separate sweep job; VeriSimDB v1 does not natively
 * support document-level TTL. Use cron or a Hypatia rule to expire old docs.
 */
final class VeriSimDbStore implements RateLimitStoreInterface
{
    private const COLLECTION = 'php-aegis:rate-limits';
    private const DEFAULT_URL = 'http://localhost:8080';
    private const CONNECT_TIMEOUT_S = 2;
    private const REQUEST_TIMEOUT_S  = 5;

    private string $baseUrl;
    private string $prefix;

    /**
     * Create a new VeriSimDB-backed store.
     *
     * @param string|null $baseUrl VeriSimDB base URL
     *                             (overrides VERISIMDB_URL env var)
     * @param string      $prefix  Key prefix for namespacing buckets
     *                             (default: 'bucket_')
     */
    public function __construct(?string $baseUrl = null, string $prefix = 'bucket_')
    {
        $this->baseUrl = $baseUrl
            ?? (getenv('VERISIMDB_URL') ?: self::DEFAULT_URL);
        // Strip trailing slash for consistent URL construction
        $this->baseUrl = rtrim($this->baseUrl, '/');
        $this->prefix  = $prefix;
    }

    /**
     * {@inheritDoc}
     *
     * Returns null (allow-by-default) on VeriSimDB connectivity failure.
     */
    public function get(string $key): ?array
    {
        $response = $this->request('GET', $this->docUrl($key), null);
        if ($response === null) {
            return null;
        }

        $data = json_decode($response, true);
        if (!is_array($data)
            || !isset($data['tokens'], $data['lastRefill'])
            || !is_numeric($data['tokens'])
            || !is_int($data['lastRefill'])) {
            return null;
        }

        return ['tokens' => (float) $data['tokens'], 'lastRefill' => (int) $data['lastRefill']];
    }

    /**
     * {@inheritDoc}
     *
     * Becomes a no-op on VeriSimDB connectivity failure.
     * The $ttl parameter is stored as metadata but not enforced by VeriSimDB v1.
     */
    public function set(string $key, array $data, int $ttl): void
    {
        $payload = json_encode([
            'tokens'    => $data['tokens'],
            'lastRefill' => $data['lastRefill'],
            'ttl'       => $ttl,
            'expiresAt' => time() + $ttl,
        ]);

        $this->request('PUT', $this->docUrl($key), $payload);
    }

    /**
     * {@inheritDoc}
     *
     * Becomes a no-op on VeriSimDB connectivity failure.
     */
    public function delete(string $key): void
    {
        $this->request('DELETE', $this->docUrl($key), null);
    }

    /**
     * {@inheritDoc}
     *
     * NOTE: VeriSimDB v1 does not support collection-level deletes.
     * This method is a no-op in the VeriSimDB store. Use a Hypatia
     * rule or scheduled job to bulk-delete the collection if needed.
     */
    public function clear(): void
    {
        // Intentional no-op for VeriSimDB store.
        // Bulk collection delete is not supported in VeriSimDB v1 REST API.
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * Build the full document URL for a given key.
     *
     * @param string $key Bucket key (e.g., user ID or IP address)
     */
    private function docUrl(string $key): string
    {
        $docId = rawurlencode($this->prefix . $key);
        return sprintf('%s/v1/%s/%s', $this->baseUrl, self::COLLECTION, $docId);
    }

    /**
     * Execute a cURL request against VeriSimDB.
     *
     * Returns the response body as a string on success (2xx), or null on
     * network failure or non-2xx response.
     *
     * @param string      $method  HTTP method (GET, PUT, DELETE)
     * @param string      $url     Full request URL
     * @param string|null $body    JSON request body (null for GET/DELETE)
     */
    private function request(string $method, string $url, ?string $body): ?string
    {
        $ch = curl_init($url);
        if ($ch === false) {
            return null;
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT_S,
            CURLOPT_TIMEOUT        => self::REQUEST_TIMEOUT_S,
            CURLOPT_CUSTOMREQUEST  => $method,
        ]);

        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Content-Type: application/json',
                'Content-Length: ' . strlen($body),
            ]);
        }

        $response = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($response === false || $curlError !== '' || $httpCode < 200 || $httpCode >= 300) {
            // Fail open: log and return null rather than throwing.
            error_log(sprintf(
                'PhpAegis\RateLimit\VeriSimDbStore: %s %s failed (HTTP %d, curl: %s)',
                $method, $url, $httpCode, $curlError
            ));
            return null;
        }

        return (string) $response;
    }
}
