<?php

/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\Tests\RateLimit;

use PHPUnit\Framework\TestCase;
use PhpAegis\RateLimit\TokenBucket;
use PhpAegis\RateLimit\MemoryStore;

/**
 * Tests for TokenBucket rate limiter.
 */
class TokenBucketTest extends TestCase
{
    private MemoryStore $store;

    protected function setUp(): void
    {
        $this->store = new MemoryStore();
    }

    // ========================================================================
    // Construction Tests
    // ========================================================================

    public function testConstructorAcceptsValidParameters(): void
    {
        $bucket = new TokenBucket($this->store, 10, 1.0, 1);
        $this->assertInstanceOf(TokenBucket::class, $bucket);
    }

    public function testConstructorRejectsZeroCapacity(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new TokenBucket($this->store, 0, 1.0, 1);
    }

    public function testConstructorRejectsNegativeCapacity(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new TokenBucket($this->store, -1, 1.0, 1);
    }

    public function testConstructorRejectsZeroRefillRate(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new TokenBucket($this->store, 10, 0.0, 1);
    }

    public function testConstructorRejectsNegativeRefillRate(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new TokenBucket($this->store, 10, -1.0, 1);
    }

    public function testConstructorRejectsZeroRefillPeriod(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new TokenBucket($this->store, 10, 1.0, 0);
    }

    // ========================================================================
    // Basic Consumption Tests
    // ========================================================================

    public function testInitialBucketStartsFull(): void
    {
        $bucket = new TokenBucket($this->store, 10, 1.0, 1);

        $this->assertSame(10.0, $bucket->remaining('user1'));
    }

    public function testAttemptConsumesToken(): void
    {
        $bucket = new TokenBucket($this->store, 10, 1.0, 1);

        $this->assertTrue($bucket->attempt('user1'));
        $this->assertSame(9.0, $bucket->remaining('user1'));
    }

    public function testAttemptConsumesMultipleTokens(): void
    {
        $bucket = new TokenBucket($this->store, 10, 1.0, 1);

        $this->assertTrue($bucket->attempt('user1', 3));
        $this->assertSame(7.0, $bucket->remaining('user1'));
    }

    public function testAttemptRejectsWhenInsufficientTokens(): void
    {
        $bucket = new TokenBucket($this->store, 5, 1.0, 1);

        // Consume 5 tokens
        $this->assertTrue($bucket->attempt('user1', 5));

        // Try to consume 1 more - should fail
        $this->assertFalse($bucket->attempt('user1'));
    }

    public function testAttemptRejectsZeroTokens(): void
    {
        $bucket = new TokenBucket($this->store, 10, 1.0, 1);

        $this->expectException(\InvalidArgumentException::class);
        $bucket->attempt('user1', 0);
    }

    public function testAttemptRejectsNegativeTokens(): void
    {
        $bucket = new TokenBucket($this->store, 10, 1.0, 1);

        $this->expectException(\InvalidArgumentException::class);
        $bucket->attempt('user1', -1);
    }

    // ========================================================================
    // Refill Tests
    // ========================================================================

    public function testTokensRefillOverTime(): void
    {
        $bucket = new TokenBucket($this->store, 10, 2.0, 1); // 2 tokens per second

        // Consume 5 tokens
        $this->assertTrue($bucket->attempt('user1', 5));
        $this->assertSame(5.0, $bucket->remaining('user1'));

        // Simulate 2 seconds passing by manipulating store
        $data = $this->store->get('user1');
        $this->assertNotNull($data);
        $data['lastRefill'] -= 2; // 2 seconds ago
        $this->store->set('user1', $data, 3600);

        // Should have refilled 4 tokens (2 tokens/sec * 2 sec)
        $this->assertSame(9.0, $bucket->remaining('user1'));
    }

    public function testTokensRefillToCapacity(): void
    {
        $bucket = new TokenBucket($this->store, 10, 2.0, 1);

        // Consume 8 tokens
        $this->assertTrue($bucket->attempt('user1', 8));
        $this->assertSame(2.0, $bucket->remaining('user1'));

        // Simulate 10 seconds (would refill 20 tokens, but capped at capacity)
        $data = $this->store->get('user1');
        $this->assertNotNull($data);
        $data['lastRefill'] -= 10;
        $this->store->set('user1', $data, 3600);

        // Should be at capacity (10)
        $this->assertSame(10.0, $bucket->remaining('user1'));
    }

    public function testTokensDoNotRefillBeforeFullPeriod(): void
    {
        $bucket = new TokenBucket($this->store, 10, 1.0, 60); // 1 token per 60 seconds

        // Consume 5 tokens
        $this->assertTrue($bucket->attempt('user1', 5));
        $this->assertSame(5.0, $bucket->remaining('user1'));

        // Simulate 30 seconds (half period - no refill yet)
        $data = $this->store->get('user1');
        $this->assertNotNull($data);
        $data['lastRefill'] -= 30;
        $this->store->set('user1', $data, 3600);

        // Should still have 5 tokens (no refill yet)
        $this->assertSame(5.0, $bucket->remaining('user1'));
    }

    public function testTokensRefillAfterFullPeriod(): void
    {
        $bucket = new TokenBucket($this->store, 10, 1.0, 60); // 1 token per 60 seconds

        // Consume 5 tokens
        $this->assertTrue($bucket->attempt('user1', 5));

        // Simulate 60 seconds (full period)
        $data = $this->store->get('user1');
        $this->assertNotNull($data);
        $data['lastRefill'] -= 60;
        $this->store->set('user1', $data, 3600);

        // Should have refilled 1 token
        $this->assertSame(6.0, $bucket->remaining('user1'));
    }

    // ========================================================================
    // Reset Tests
    // ========================================================================

    public function testResetFillsBucketToCapacity(): void
    {
        $bucket = new TokenBucket($this->store, 10, 1.0, 1);

        // Consume 8 tokens
        $this->assertTrue($bucket->attempt('user1', 8));
        $this->assertSame(2.0, $bucket->remaining('user1'));

        // Reset
        $bucket->reset('user1');

        // Should be back to full capacity
        $this->assertSame(10.0, $bucket->remaining('user1'));
    }

    // ========================================================================
    // ResetAt Tests
    // ========================================================================

    public function testResetAtReturnsZeroWhenTokensAvailable(): void
    {
        $bucket = new TokenBucket($this->store, 10, 1.0, 1);

        $this->assertSame(0, $bucket->resetAt('user1'));
    }

    public function testResetAtReturnsSecondsUntilNextToken(): void
    {
        $bucket = new TokenBucket($this->store, 10, 1.0, 60); // 1 token per 60 seconds

        // Consume all tokens
        $this->assertTrue($bucket->attempt('user1', 10));

        $resetAt = $bucket->resetAt('user1');
        $this->assertGreaterThan(0, $resetAt);
        $this->assertLessThanOrEqual(60, $resetAt);
    }

    // ========================================================================
    // Isolation Tests
    // ========================================================================

    public function testDifferentKeysAreIsolated(): void
    {
        $bucket = new TokenBucket($this->store, 10, 1.0, 1);

        // User1 consumes 5 tokens
        $this->assertTrue($bucket->attempt('user1', 5));
        $this->assertSame(5.0, $bucket->remaining('user1'));

        // User2 still has full capacity
        $this->assertSame(10.0, $bucket->remaining('user2'));

        // User2 consumes 3 tokens
        $this->assertTrue($bucket->attempt('user2', 3));
        $this->assertSame(7.0, $bucket->remaining('user2'));

        // User1 still has 5
        $this->assertSame(5.0, $bucket->remaining('user1'));
    }

    // ========================================================================
    // Burst Tests
    // ========================================================================

    public function testBurstAllowsMultipleRequests(): void
    {
        $bucket = new TokenBucket($this->store, 10, 0.1, 1); // 10 burst, slow refill

        // Can make 10 requests immediately
        for ($i = 0; $i < 10; $i++) {
            $this->assertTrue($bucket->attempt('user1'));
        }

        // 11th request fails
        $this->assertFalse($bucket->attempt('user1'));
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    public function testFractionalTokenRefill(): void
    {
        $bucket = new TokenBucket($this->store, 10, 0.5, 1); // 0.5 tokens per second

        // Consume 5 tokens
        $this->assertTrue($bucket->attempt('user1', 5));

        // Simulate 3 seconds (should refill 1.5 tokens)
        $data = $this->store->get('user1');
        $this->assertNotNull($data);
        $data['lastRefill'] -= 3;
        $this->store->set('user1', $data, 3600);

        // Should have 5 + 1.5 = 6.5 tokens
        $this->assertSame(6.5, $bucket->remaining('user1'));
    }

    public function testRemainingNeverGoesNegative(): void
    {
        $bucket = new TokenBucket($this->store, 5, 1.0, 1);

        // Consume all tokens
        $this->assertTrue($bucket->attempt('user1', 5));

        // Try to consume more (should fail)
        $this->assertFalse($bucket->attempt('user1'));

        // Remaining should be 0, not negative
        $this->assertSame(0.0, $bucket->remaining('user1'));
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    public function testRealisticApiRateLimiting(): void
    {
        // 60 requests per minute with burst of 10
        $bucket = new TokenBucket($this->store, 10, 1.0, 1);

        // Burst: 10 immediate requests
        for ($i = 0; $i < 10; $i++) {
            $this->assertTrue($bucket->attempt('api_user'));
        }

        // 11th request fails
        $this->assertFalse($bucket->attempt('api_user'));

        // Simulate 1 second (1 token refilled)
        $data = $this->store->get('api_user');
        $this->assertNotNull($data);
        $data['lastRefill'] -= 1;
        $this->store->set('api_user', $data, 3600);

        // Can make 1 more request
        $this->assertTrue($bucket->attempt('api_user'));
    }

    public function testRealisticLoginRateLimiting(): void
    {
        // 5 login attempts per 15 minutes
        $bucket = new TokenBucket($this->store, 5, 1.0, 180); // 1 token per 180 seconds

        // 5 attempts
        for ($i = 0; $i < 5; $i++) {
            $this->assertTrue($bucket->attempt('login_user'));
        }

        // 6th attempt fails
        $this->assertFalse($bucket->attempt('login_user'));

        // Simulate 180 seconds (1 token refilled)
        $data = $this->store->get('login_user');
        $this->assertNotNull($data);
        $data['lastRefill'] -= 180;
        $this->store->set('login_user', $data, 3600);

        // Can make 1 more attempt
        $this->assertTrue($bucket->attempt('login_user'));
    }
}
