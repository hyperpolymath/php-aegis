# Rate Limiting Guide

Advanced rate limiting with token bucket algorithm.

## Overview

php-aegis provides rate limiting using the **token bucket algorithm**:
- Bucket starts with N tokens (capacity)
- Each request consumes tokens
- Tokens refill at constant rate
- Requests allowed if tokens available

This provides smooth rate limiting with burst allowance.

## Quick Start

```php
use PhpAegis\RateLimit\RateLimiter;
use PhpAegis\RateLimit\FileStore;

$store = new FileStore('/var/ratelimit');
$limiter = RateLimiter::perMinute(60, $store);

if (!$limiter->attempt($userId)) {
    header('HTTP/1.1 429 Too Many Requests');
    header('Retry-After: ' . $limiter->resetAt($userId));
    exit('Rate limit exceeded');
}
```

## Storage Backends

### MemoryStore (Development)
```php
use PhpAegis\RateLimit\MemoryStore;

$store = new MemoryStore();
```
- **Pros**: Fast, no setup
- **Cons**: Data lost on restart, not shared across processes
- **Use**: Development, testing, single-request scripts

### FileStore (Production)
```php
use PhpAegis\RateLimit\FileStore;

$store = new FileStore('/var/ratelimit', 'prefix_');
```
- **Pros**: Persistent, no external dependencies
- **Cons**: File I/O overhead
- **Use**: Production single-server deployments

### Custom Store (Redis, Database)
```php
class RedisStore implements RateLimitStoreInterface {
    // Implement interface methods
}

$store = new RedisStore($redisClient);
```

## Preset Configurations

### Per-Second Limiting
```php
$limiter = RateLimiter::perSecond(10, $store);
// 10 requests per second
```

### Per-Minute Limiting
```php
$limiter = RateLimiter::perMinute(60, $store);
// 60 requests per minute, burst allowance: 60

$limiter = RateLimiter::perMinute(60, $store, 10);
// 60 requests per minute, burst allowance: 10
```

### Per-Hour Limiting
```php
$limiter = RateLimiter::perHour(1000, $store);
// 1000 requests per hour, burst: 100 (automatic)

$limiter = RateLimiter::perHour(1000, $store, 50);
// 1000 requests per hour, burst: 50
```

### Per-Day Limiting
```php
$limiter = RateLimiter::perDay(10000, $store);
// 10000 requests per day, burst: 100 (automatic)
```

## Advanced Usage

### Custom Token Bucket
```php
use PhpAegis\RateLimit\TokenBucket;

// 100 capacity, 2 tokens per 60 seconds
$bucket = new TokenBucket($store, 100, 2.0, 60);

if ($bucket->attempt($key)) {
    // Allowed
}
```

### Consuming Multiple Tokens
```php
// Standard request: 1 token
$limiter->attempt($userId);

// Expensive operation: 5 tokens
$limiter->attempt($userId, 5);
```

### Checking Remaining Capacity
```php
$remaining = $limiter->remaining($userId);
echo "You have $remaining requests left";
```

### Reset Time
```php
$seconds = $limiter->resetAt($userId);
if ($seconds > 0) {
    echo "Rate limit resets in $seconds seconds";
}
```

### Manual Reset
```php
// Admin resets user's limit
$limiter->reset($userId);
```

## Use Cases

### API Rate Limiting
```php
// 1000 requests/hour, 100 burst
$apiLimiter = RateLimiter::perHour(1000, $store, 100);

$apiKey = $_SERVER['HTTP_X_API_KEY'];

if (!$apiLimiter->attempt($apiKey)) {
    http_response_code(429);
    header('X-RateLimit-Remaining: 0');
    header('Retry-After: ' . $apiLimiter->resetAt($apiKey));
    exit(json_encode(['error' => 'rate_limit_exceeded']));
}

header('X-RateLimit-Remaining: ' . (int)$apiLimiter->remaining($apiKey));
```

### Login Attempt Limiting
```php
// 5 attempts per 15 minutes
$loginLimiter = RateLimiter::perHour(20, $store, 5);

$identifier = $_SERVER['REMOTE_ADDR'];

if (!$loginLimiter->attempt($identifier)) {
    $wait = $loginLimiter->resetAt($identifier);
    exit("Too many login attempts. Try again in $wait seconds.");
}

// Process login
if ($loginSuccessful) {
    $loginLimiter->reset($identifier); // Reset on success
}
```

### Form Submission Limiting
```php
// 10 submissions per minute
$formLimiter = RateLimiter::perMinute(10, $store);

if (!$formLimiter->attempt($_SERVER['REMOTE_ADDR'])) {
    exit('Too many submissions. Please wait.');
}
```

### Search Rate Limiting
```php
// 100 searches per minute, 20 burst
$searchLimiter = RateLimiter::perMinute(100, $store, 20);

if (!$searchLimiter->attempt($userId)) {
    exit('Search rate limit exceeded.');
}
```

## Multi-Tier Rate Limiting

```php
// Free tier: 100/hour
$freeLimiter = RateLimiter::perHour(100, $store, 10);

// Paid tier: 10000/hour
$paidLimiter = RateLimiter::perHour(10000, $store, 100);

// Enterprise tier: 100000/hour
$enterpriseLimiter = RateLimiter::perHour(100000, $store, 1000);

$limiter = match($user->tier) {
    'free' => $freeLimiter,
    'paid' => $paidLimiter,
    'enterprise' => $enterpriseLimiter,
};

if (!$limiter->attempt($user->id)) {
    exit('Upgrade your plan for higher limits');
}
```

## Monitoring

### Track Rate Limit Status
```php
$remaining = $limiter->remaining($userId);
$resetAt = $limiter->resetAt($userId);

header('X-RateLimit-Limit: 60');
header('X-RateLimit-Remaining: ' . (int)$remaining);
header('X-RateLimit-Reset: ' . (time() + $resetAt));
```

### Logging
```php
if (!$limiter->attempt($userId)) {
    error_log("Rate limit exceeded for user: $userId");
}
```

## Performance

### FileStore Benchmarks
- Writes: ~1000/sec
- Reads: ~5000/sec
- Storage: ~100 bytes per key

### Optimization Tips
1. Use FileStore for production (persistent)
2. Run garbage collection periodically:
   ```php
   $store->gc(); // Remove expired entries
   ```
3. Use appropriate TTL for buckets
4. Consider Redis for high-traffic multi-server deployments

## Troubleshooting

### Directory Not Writable
```bash
chmod 755 /var/ratelimit
chown www-data:www-data /var/ratelimit
```

### Rate Limits Not Persisting
- Check FileStore directory exists and is writable
- Verify TTL is appropriate for your use case
- Ensure same directory used across requests

### Performance Issues
- Use Redis instead of FileStore for high traffic
- Increase burst allowance to reduce storage writes
- Run garbage collection less frequently

## Security Considerations

### Key Selection
Use appropriate identifiers:
- **User ID**: For authenticated users
- **IP Address**: For anonymous users
- **API Key**: For API clients
- **Session ID**: For temporary limits

### Bypass Prevention
```php
// Don't allow empty keys
if (empty($userId)) {
    $userId = $_SERVER['REMOTE_ADDR'];
}

// Sanitize keys
$userId = preg_replace('/[^a-zA-Z0-9_-]/', '', $userId);
```

### DoS Protection
```php
// Separate limits for anonymous vs authenticated
$limit = $isAuthenticated ? 1000 : 100;
$limiter = RateLimiter::perHour($limit, $store);
```

## Best Practices

1. **Apply rate limits early** in request handling
2. **Use descriptive keys** (e.g., `api:user:123`, `login:192.168.1.1`)
3. **Set appropriate burst allowances** for user experience
4. **Return clear error messages** with retry information
5. **Monitor rate limit hits** to adjust limits
6. **Reset on success** for login/auth attempts
7. **Use tiered limits** for different user levels
8. **Test limits** in staging before production

## Next Steps

- [User Guide](User-Guide.md) - General php-aegis usage
- [Developer Guide](Developer-Guide.md) - API reference
- [Examples](Examples.md) - Code examples
