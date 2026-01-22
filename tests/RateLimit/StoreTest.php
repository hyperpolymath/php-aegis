<?php

/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\Tests\RateLimit;

use PHPUnit\Framework\TestCase;
use PhpAegis\RateLimit\MemoryStore;
use PhpAegis\RateLimit\FileStore;
use PhpAegis\RateLimit\RateLimitStoreInterface;

/**
 * Tests for rate limit storage implementations.
 */
class StoreTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/php_aegis_test_' . uniqid();
        if (!is_dir($this->tempDir)) {
            mkdir($this->tempDir, 0755, true);
        }
    }

    protected function tearDown(): void
    {
        if (is_dir($this->tempDir)) {
            $this->deleteDirectory($this->tempDir);
        }
    }

    private function deleteDirectory(string $dir): void
    {
        $files = glob($dir . '/*');
        if ($files === false) {
            return;
        }

        foreach ($files as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
        rmdir($dir);
    }

    // ========================================================================
    // MemoryStore Tests
    // ========================================================================

    public function testMemoryStoreGetReturnsNullForNonexistentKey(): void
    {
        $store = new MemoryStore();
        $this->assertNull($store->get('nonexistent'));
    }

    public function testMemoryStoreSetAndGet(): void
    {
        $store = new MemoryStore();
        $data = ['tokens' => 5.0, 'lastRefill' => time()];

        $store->set('key1', $data, 3600);
        $retrieved = $store->get('key1');

        $this->assertNotNull($retrieved);
        $this->assertSame(5.0, $retrieved['tokens']);
        $this->assertSame($data['lastRefill'], $retrieved['lastRefill']);
    }

    public function testMemoryStoreDeleteRemovesKey(): void
    {
        $store = new MemoryStore();
        $data = ['tokens' => 5.0, 'lastRefill' => time()];

        $store->set('key1', $data, 3600);
        $this->assertNotNull($store->get('key1'));

        $store->delete('key1');
        $this->assertNull($store->get('key1'));
    }

    public function testMemoryStoreClearRemovesAllKeys(): void
    {
        $store = new MemoryStore();
        $data = ['tokens' => 5.0, 'lastRefill' => time()];

        $store->set('key1', $data, 3600);
        $store->set('key2', $data, 3600);

        $this->assertNotNull($store->get('key1'));
        $this->assertNotNull($store->get('key2'));

        $store->clear();

        $this->assertNull($store->get('key1'));
        $this->assertNull($store->get('key2'));
    }

    public function testMemoryStoreExpirationWorks(): void
    {
        $store = new MemoryStore();
        $data = ['tokens' => 5.0, 'lastRefill' => time()];

        // Set with 1 second TTL
        $store->set('key1', $data, 1);

        // Should exist immediately
        $this->assertNotNull($store->get('key1'));

        // Wait 2 seconds
        sleep(2);

        // Should be expired
        $this->assertNull($store->get('key1'));
    }

    public function testMemoryStoreGarbageCollection(): void
    {
        $store = new MemoryStore();
        $data = ['tokens' => 5.0, 'lastRefill' => time()];

        // Set some keys with short TTL
        $store->set('key1', $data, 1);
        $store->set('key2', $data, 1);
        $store->set('key3', $data, 3600); // Long TTL

        sleep(2);

        $removed = $store->gc();

        // Should have removed 2 expired keys
        $this->assertSame(2, $removed);

        // key3 should still exist
        $this->assertNotNull($store->get('key3'));
    }

    // ========================================================================
    // FileStore Tests
    // ========================================================================

    public function testFileStoreCreatesDirectory(): void
    {
        $dir = $this->tempDir . '/subdir';
        $store = new FileStore($dir);

        $this->assertDirectoryExists($dir);
    }

    public function testFileStoreThrowsIfDirectoryNotWritable(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('Permission test not reliable on Windows');
        }

        $dir = $this->tempDir . '/readonly';
        mkdir($dir, 0555); // Read-only

        $this->expectException(\RuntimeException::class);
        new FileStore($dir);

        chmod($dir, 0755); // Cleanup
    }

    public function testFileStoreGetReturnsNullForNonexistentKey(): void
    {
        $store = new FileStore($this->tempDir);
        $this->assertNull($store->get('nonexistent'));
    }

    public function testFileStoreSetAndGet(): void
    {
        $store = new FileStore($this->tempDir);
        $data = ['tokens' => 5.0, 'lastRefill' => time()];

        $store->set('key1', $data, 3600);
        $retrieved = $store->get('key1');

        $this->assertNotNull($retrieved);
        $this->assertSame(5.0, $retrieved['tokens']);
        $this->assertSame($data['lastRefill'], $retrieved['lastRefill']);
    }

    public function testFileStoreDeleteRemovesFile(): void
    {
        $store = new FileStore($this->tempDir);
        $data = ['tokens' => 5.0, 'lastRefill' => time()];

        $store->set('key1', $data, 3600);
        $this->assertNotNull($store->get('key1'));

        $store->delete('key1');
        $this->assertNull($store->get('key1'));
    }

    public function testFileStoreClearRemovesAllFiles(): void
    {
        $store = new FileStore($this->tempDir);
        $data = ['tokens' => 5.0, 'lastRefill' => time()];

        $store->set('key1', $data, 3600);
        $store->set('key2', $data, 3600);

        $this->assertNotNull($store->get('key1'));
        $this->assertNotNull($store->get('key2'));

        $store->clear();

        $this->assertNull($store->get('key1'));
        $this->assertNull($store->get('key2'));
    }

    public function testFileStoreExpirationWorks(): void
    {
        $store = new FileStore($this->tempDir);
        $data = ['tokens' => 5.0, 'lastRefill' => time()];

        // Set with 1 second TTL
        $store->set('key1', $data, 1);

        // Should exist immediately
        $this->assertNotNull($store->get('key1'));

        // Wait 2 seconds
        sleep(2);

        // Should be expired
        $this->assertNull($store->get('key1'));
    }

    public function testFileStoreGarbageCollection(): void
    {
        $store = new FileStore($this->tempDir);
        $data = ['tokens' => 5.0, 'lastRefill' => time()];

        // Set some keys with short TTL
        $store->set('key1', $data, 1);
        $store->set('key2', $data, 1);
        $store->set('key3', $data, 3600); // Long TTL

        sleep(2);

        $removed = $store->gc();

        // Should have removed 2 expired files
        $this->assertSame(2, $removed);

        // key3 should still exist
        $this->assertNotNull($store->get('key3'));
    }

    public function testFileStoreHandlesSpecialCharactersInKey(): void
    {
        $store = new FileStore($this->tempDir);
        $data = ['tokens' => 5.0, 'lastRefill' => time()];

        // Keys with special characters should be safely hashed
        $keys = [
            'user@example.com',
            '../../../etc/passwd',
            'key with spaces',
            'key/with/slashes',
        ];

        foreach ($keys as $key) {
            $store->set($key, $data, 3600);
            $retrieved = $store->get($key);

            $this->assertNotNull($retrieved);
            $this->assertSame(5.0, $retrieved['tokens']);
        }
    }

    public function testFileStorePersistsAcrossInstances(): void
    {
        $data = ['tokens' => 5.0, 'lastRefill' => time()];

        // Create first store instance and save data
        $store1 = new FileStore($this->tempDir);
        $store1->set('key1', $data, 3600);

        // Create second store instance and read data
        $store2 = new FileStore($this->tempDir);
        $retrieved = $store2->get('key1');

        $this->assertNotNull($retrieved);
        $this->assertSame(5.0, $retrieved['tokens']);
    }

    public function testFileStoreWithCustomPrefix(): void
    {
        $store = new FileStore($this->tempDir, 'custom_prefix_');
        $data = ['tokens' => 5.0, 'lastRefill' => time()];

        $store->set('key1', $data, 3600);

        // Check that file has custom prefix
        $files = glob($this->tempDir . '/custom_prefix_*');
        $this->assertNotEmpty($files);
    }

    // ========================================================================
    // Interface Compliance Tests
    // ========================================================================

    /**
     * @dataProvider storeProvider
     */
    public function testStoreImplementsInterface(RateLimitStoreInterface $store): void
    {
        $this->assertInstanceOf(RateLimitStoreInterface::class, $store);
    }

    /**
     * @dataProvider storeProvider
     */
    public function testStoreBasicOperations(RateLimitStoreInterface $store): void
    {
        $data = ['tokens' => 5.0, 'lastRefill' => time()];

        // Get non-existent key
        $this->assertNull($store->get('test_key'));

        // Set and get
        $store->set('test_key', $data, 3600);
        $retrieved = $store->get('test_key');

        $this->assertNotNull($retrieved);
        $this->assertSame(5.0, $retrieved['tokens']);

        // Delete
        $store->delete('test_key');
        $this->assertNull($store->get('test_key'));
    }

    public static function storeProvider(): array
    {
        $tempDir = sys_get_temp_dir() . '/php_aegis_provider_' . uniqid();
        if (!is_dir($tempDir)) {
            mkdir($tempDir, 0755, true);
        }

        return [
            'MemoryStore' => [new MemoryStore()],
            'FileStore' => [new FileStore($tempDir)],
        ];
    }

    // ========================================================================
    // Performance Tests
    // ========================================================================

    public function testFileStoreConcurrency(): void
    {
        $store = new FileStore($this->tempDir);
        $data = ['tokens' => 5.0, 'lastRefill' => time()];

        // Simulate concurrent writes
        for ($i = 0; $i < 100; $i++) {
            $store->set('concurrent_key', $data, 3600);
        }

        // Should be able to read final value
        $retrieved = $store->get('concurrent_key');
        $this->assertNotNull($retrieved);
    }
}
