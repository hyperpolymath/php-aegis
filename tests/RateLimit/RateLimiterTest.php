<?php

/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\Tests\RateLimit;

use PHPUnit\Framework\TestCase;
use PhpAegis\RateLimit\RateLimiter;
use PhpAegis\RateLimit\MemoryStore;

/**
 * Tests for high-level RateLimiter API.
 */
class RateLimiterTest extends TestCase
{
    private MemoryStore $store;

    protected function setUp(): void
    {
        $this->store = new MemoryStore();
    }

    // ========================================================================
    // Factory Method Tests
    // ========================================================================

    public function testPerSecondFactory(): void
    {
        $limiter = RateLimiter::perSecond(10, $this->store);
        $this->assertInstanceOf(RateLimiter::class, $limiter);

        // Should allow 10 requests immediately
        for ($i = 0; $i < 10; $i++) {
            $this->assertTrue($limiter->attempt('user1'));
        }

        // 11th should fail
        $this->assertFalse($limiter->attempt('user1'));
    }

    public function testPerMinuteFactory(): void
    {
        $limiter = RateLimiter::perMinute(60, $this->store);
        $this->assertInstanceOf(RateLimiter::class, $limiter);

        // Should have burst allowance of 60
        $this->assertSame(60.0, $limiter->remaining('user1'));
    }

    public function testPerMinuteFactoryWithCustomBurst(): void
    {
        $limiter = RateLimiter::perMinute(60, $this->store, 10);

        // Should have burst allowance of 10
        $this->assertSame(10.0, $limiter->remaining('user1'));
    }

    public function testPerHourFactory(): void
    {
        $limiter = RateLimiter::perHour(1000, $this->store);
        $this->assertInstanceOf(RateLimiter::class, $limiter);

        // Should have burst allowance of 100 (1000 / 10)
        $this->assertSame(100.0, $limiter->remaining('user1'));
    }

    public function testPerHourFactoryWithCustomBurst(): void
    {
        $limiter = RateLimiter::perHour(1000, $this->store, 50);

        // Should have burst allowance of 50
        $this->assertSame(50.0, $limiter->remaining('user1'));
    }

    public function testPerDayFactory(): void
    {
        $limiter = RateLimiter::perDay(10000, $this->store);
        $this->assertInstanceOf(RateLimiter::class, $limiter);

        // Should have burst allowance of 100 (10000 / 100)
        $this->assertSame(100.0, $limiter->remaining('user1'));
    }

    public function testPerDayFactoryWithCustomBurst(): void
    {
        $limiter = RateLimiter::perDay(10000, $this->store, 200);

        // Should have burst allowance of 200
        $this->assertSame(200.0, $limiter->remaining('user1'));
    }

    // ========================================================================
    // Attempt Tests
    // ========================================================================

    public function testAttemptConsumesRequest(): void
    {
        $limiter = RateLimiter::perSecond(10, $this->store);

        $this->assertTrue($limiter->attempt('user1'));
        $this->assertSame(9.0, $limiter->remaining('user1'));
    }

    public function testAttemptConsumesMultipleRequests(): void
    {
        $limiter = RateLimiter::perSecond(10, $this->store);

        $this->assertTrue($limiter->attempt('user1', 3));
        $this->assertSame(7.0, $limiter->remaining('user1'));
    }

    public function testAttemptRejectsWhenLimitExceeded(): void
    {
        $limiter = RateLimiter::perSecond(5, $this->store);

        // Consume all 5 requests
        for ($i = 0; $i < 5; $i++) {
            $this->assertTrue($limiter->attempt('user1'));
        }

        // 6th should fail
        $this->assertFalse($limiter->attempt('user1'));
    }

    // ========================================================================
    // Remaining Tests
    // ========================================================================

    public function testRemainingReturnsAvailableRequests(): void
    {
        $limiter = RateLimiter::perSecond(10, $this->store);

        $this->assertSame(10.0, $limiter->remaining('user1'));

        $limiter->attempt('user1', 3);
        $this->assertSame(7.0, $limiter->remaining('user1'));
    }

    // ========================================================================
    // Reset Tests
    // ========================================================================

    public function testResetRestoresLimit(): void
    {
        $limiter = RateLimiter::perSecond(10, $this->store);

        // Consume all requests
        $limiter->attempt('user1', 10);
        $this->assertSame(0.0, $limiter->remaining('user1'));

        // Reset
        $limiter->reset('user1');

        // Should have full capacity
        $this->assertSame(10.0, $limiter->remaining('user1'));
    }

    // ========================================================================
    // ResetAt Tests
    // ========================================================================

    public function testResetAtReturnsZeroWhenRequestsAvailable(): void
    {
        $limiter = RateLimiter::perSecond(10, $this->store);

        $this->assertSame(0, $limiter->resetAt('user1'));
    }

    public function testResetAtReturnsPositiveWhenLimitExceeded(): void
    {
        $limiter = RateLimiter::perSecond(5, $this->store);

        // Consume all requests
        $limiter->attempt('user1', 5);

        $resetAt = $limiter->resetAt('user1');
        $this->assertGreaterThanOrEqual(0, $resetAt);
    }

    // ========================================================================
    // Use Case Tests
    // ========================================================================

    public function testApiRateLimiting(): void
    {
        // API: 1000 requests per hour with burst of 100
        $limiter = RateLimiter::perHour(1000, $this->store, 100);

        // Burst: 100 immediate requests
        for ($i = 0; $i < 100; $i++) {
            $this->assertTrue($limiter->attempt('api_user'));
        }

        // 101st fails
        $this->assertFalse($limiter->attempt('api_user'));
    }

    public function testLoginRateLimiting(): void
    {
        // Login: 5 attempts per minute
        $limiter = RateLimiter::perMinute(5, $this->store, 5);

        // 5 attempts
        for ($i = 0; $i < 5; $i++) {
            $this->assertTrue($limiter->attempt('login_user'));
        }

        // 6th fails
        $this->assertFalse($limiter->attempt('login_user'));

        $resetAt = $limiter->resetAt('login_user');
        $this->assertGreaterThan(0, $resetAt);
    }

    public function testFormSubmissionRateLimiting(): void
    {
        // Forms: 10 submissions per minute
        $limiter = RateLimiter::perMinute(10, $this->store);

        // Can submit 10 times
        for ($i = 0; $i < 10; $i++) {
            $this->assertTrue($limiter->attempt('form_user'));
        }

        // 11th fails
        $this->assertFalse($limiter->attempt('form_user'));
    }

    public function testSearchRateLimiting(): void
    {
        // Search: 100 queries per minute with burst of 20
        $limiter = RateLimiter::perMinute(100, $this->store, 20);

        // Burst: 20 immediate queries
        for ($i = 0; $i < 20; $i++) {
            $this->assertTrue($limiter->attempt('search_user'));
        }

        // 21st fails
        $this->assertFalse($limiter->attempt('search_user'));
    }

    // ========================================================================
    // Different User Isolation Tests
    // ========================================================================

    public function testDifferentUsersAreIsolated(): void
    {
        $limiter = RateLimiter::perSecond(5, $this->store);

        // User1 consumes 3 requests
        $limiter->attempt('user1', 3);
        $this->assertSame(2.0, $limiter->remaining('user1'));

        // User2 still has full capacity
        $this->assertSame(5.0, $limiter->remaining('user2'));

        // User2 consumes 2 requests
        $limiter->attempt('user2', 2);
        $this->assertSame(3.0, $limiter->remaining('user2'));

        // User1 still has 2
        $this->assertSame(2.0, $limiter->remaining('user1'));
    }

    // ========================================================================
    // IP-Based Rate Limiting Tests
    // ========================================================================

    public function testIpBasedRateLimiting(): void
    {
        $limiter = RateLimiter::perMinute(60, $this->store);

        $ip1 = '192.168.1.1';
        $ip2 = '192.168.1.2';

        // IP1 consumes 30 requests
        $limiter->attempt($ip1, 30);
        $this->assertSame(30.0, $limiter->remaining($ip1));

        // IP2 still has full capacity
        $this->assertSame(60.0, $limiter->remaining($ip2));
    }

    // ========================================================================
    // TokenBucket Access Tests
    // ========================================================================

    public function testGetTokenBucket(): void
    {
        $limiter = RateLimiter::perSecond(10, $this->store);

        $bucket = $limiter->getTokenBucket();
        $this->assertInstanceOf(\PhpAegis\RateLimit\TokenBucket::class, $bucket);
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    public function testCompleteRateLimitingWorkflow(): void
    {
        $limiter = RateLimiter::perMinute(60, $this->store);

        $userId = 'user123';

        // Check initial limit
        $this->assertSame(60.0, $limiter->remaining($userId));

        // Make some requests
        for ($i = 0; $i < 10; $i++) {
            $this->assertTrue($limiter->attempt($userId));
        }

        // Check remaining
        $this->assertSame(50.0, $limiter->remaining($userId));

        // Make more requests until limit
        for ($i = 0; $i < 50; $i++) {
            $this->assertTrue($limiter->attempt($userId));
        }

        // Should be at limit
        $this->assertFalse($limiter->attempt($userId));
        $this->assertSame(0.0, $limiter->remaining($userId));

        // Check reset time
        $resetAt = $limiter->resetAt($userId);
        $this->assertGreaterThan(0, $resetAt);

        // Admin resets limit
        $limiter->reset($userId);

        // User can make requests again
        $this->assertTrue($limiter->attempt($userId));
        $this->assertSame(59.0, $limiter->remaining($userId));
    }

    public function testMultiTierRateLimiting(): void
    {
        // Free tier: 100 requests/hour
        $freeLimiter = RateLimiter::perHour(100, $this->store, 10);

        // Paid tier: 10000 requests/hour
        $paidLimiter = RateLimiter::perHour(10000, $this->store, 100);

        // Free user
        $freeUser = 'free_user';
        for ($i = 0; $i < 10; $i++) {
            $this->assertTrue($freeLimiter->attempt($freeUser));
        }
        $this->assertFalse($freeLimiter->attempt($freeUser));

        // Paid user
        $paidUser = 'paid_user';
        for ($i = 0; $i < 100; $i++) {
            $this->assertTrue($paidLimiter->attempt($paidUser));
        }
        $this->assertFalse($paidLimiter->attempt($paidUser));
    }
}
