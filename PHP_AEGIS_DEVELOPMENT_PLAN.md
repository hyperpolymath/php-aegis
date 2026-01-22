# php-aegis Development Plan
**Created**: 2026-01-22
**Project Phase**: Active Development
**Current Completion**: 65%
**Target Completion**: 95% (Production Ready)

---

## Executive Summary

php-aegis is a PHP 8.1+ security and hardening toolkit providing input validation, sanitization, and security utilities. This plan outlines the path from 65% to 95%+ completion with production-ready status.

### Current State

**Working Features** (65% complete):
- ✅ Validator class (17 methods): email, URL, IP, UUID, slug, JSON, filename safety, semver, ISO 8601, hex colors
- ✅ Sanitizer class (10 methods): HTML, JS, CSS, URL, JSON, stripTags, filename, removeNullBytes
- ✅ **TurtleEscaper class** (UNIQUE VALUE): W3C-compliant RDF Turtle escaping - no other PHP library does this
- ✅ Headers class: CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy
- ✅ Crypto utilities: Cryptographic functions and secure random generation
- ✅ Comprehensive test suite: 4 test files (67KB), PHPUnit configured
- ✅ Static methods throughout (no instance state needed)
- ✅ SPDX license headers on all files
- ✅ Composer package (MIT license, PHP 8.1+ requirement)

**Code Metrics**:
- Total lines: 3,173
- Source files: 5 (Validator.php, Sanitizer.php, Headers.php, TurtleEscaper.php, Crypto.php)
- Test files: 4 (ValidatorTest.php, SanitizerTest.php, HeadersTest.php, TurtleEscaperTest.php)
- Dependencies: zero runtime dependencies

### Gap Analysis

**Critical Blockers** (Medium Priority):
1. WordPress integration (0%) - Adapter functions, mu-plugin pattern
2. sanctify-php coordination (0%) - Safe sink recognition
3. Packagist publication (0%) - Not published yet
4. Real-world validation (0%) - No test integrations

**Feature Gaps**:
1. IndieWeb security (0%) - Micropub, IndieAuth, Webmention validators
2. Rate limiting (0%) - Token bucket implementation
3. Framework adapters (0%) - Laravel service provider, Symfony bundle

**Documentation Gaps** (30% complete):
1. API reference incomplete
2. WordPress integration guide missing
3. IndieWeb examples missing
4. Deployment guide incomplete

---

## Development Roadmap (65% → 95%)

### Phase 1: WordPress Integration (65% → 72%)

**Goal**: Enable seamless WordPress integration with wrapper functions and best practices guide.

#### 1.1 WordPress Adapter Functions
Create `src/WordPress/Adapter.php`:

```php
<?php
// SPDX-License-Identifier: PMPL-1.0-or-later

declare(strict_types=1);

namespace PhpAegis\WordPress;

use PhpAegis\Validator;
use PhpAegis\Sanitizer;
use PhpAegis\TurtleEscaper;

/**
 * WordPress adapter functions following WordPress naming conventions.
 *
 * These functions provide WordPress-style wrappers around php-aegis methods
 * for developers familiar with esc_html(), esc_attr(), etc.
 */

if (!function_exists('aegis_html')) {
    function aegis_html(string $input): string {
        return Sanitizer::html($input);
    }
}

if (!function_exists('aegis_attr')) {
    function aegis_attr(string $input): string {
        return Sanitizer::attr($input);
    }
}

if (!function_exists('aegis_js')) {
    function aegis_js(string $input): string {
        return Sanitizer::js($input);
    }
}

if (!function_exists('aegis_url')) {
    function aegis_url(string $input): string {
        return Sanitizer::url($input);
    }
}

if (!function_exists('aegis_turtle_literal')) {
    function aegis_turtle_literal(
        string $value,
        ?string $language = null,
        ?string $datatype = null
    ): string {
        return TurtleEscaper::literal($value, $language, $datatype);
    }
}

if (!function_exists('aegis_validate_email')) {
    function aegis_validate_email(string $email): bool {
        return Validator::email($email);
    }
}

if (!function_exists('aegis_validate_url')) {
    function aegis_validate_url(string $url, bool $httpsOnly = false): bool {
        return $httpsOnly ? Validator::httpsUrl($url) : Validator::url($url);
    }
}

if (!function_exists('aegis_send_security_headers')) {
    function aegis_send_security_headers(): void {
        \PhpAegis\Headers::secure();
    }
}
```

#### 1.2 WordPress MU-Plugin Template
Create `docs/wordpress/aegis-mu-plugin.php`:

```php
<?php
/**
 * Plugin Name: php-aegis Security Enhancements
 * Description: Adds php-aegis security functions to WordPress
 * Version: 0.2.0
 * SPDX-License-Identifier: PMPL-1.0-or-later
 */

declare(strict_types=1);

// Load Composer autoloader (adjust path if needed)
if (file_exists(WPMU_PLUGIN_DIR . '/vendor/autoload.php')) {
    require_once WPMU_PLUGIN_DIR . '/vendor/autoload.php';
}

// Load WordPress adapter functions
if (class_exists('PhpAegis\\WordPress\\Adapter')) {
    require_once dirname(__FILE__) . '/aegis-functions.php';
}

// Apply security headers on init
add_action('send_headers', function () {
    if (!headers_sent()) {
        \PhpAegis\Headers::secure();
    }
});
```

#### 1.3 WordPress Integration Tests
Create `tests/WordPress/AdapterTest.php`:

```php
<?php
// SPDX-License-Identifier: PMPL-1.0-or-later

declare(strict_types=1);

namespace PhpAegis\Tests\WordPress;

use PHPUnit\Framework\TestCase;

class AdapterTest extends TestCase
{
    public function testAegisHtmlFunction(): void
    {
        require_once __DIR__ . '/../../src/WordPress/Adapter.php';

        $input = '<script>alert("xss")</script>';
        $output = aegis_html($input);

        $this->assertStringNotContainsString('<script>', $output);
        $this->assertStringContainsString('&lt;script&gt;', $output);
    }

    public function testAegisTurtleLiteralFunction(): void
    {
        $input = 'Hello "World"';
        $output = aegis_turtle_literal($input, 'en');

        $this->assertStringContainsString('"Hello \\"World\\""@en', $output);
    }
}
```

#### 1.4 WordPress Documentation
Create `docs/wordpress/WORDPRESS_INTEGRATION.md`:

```markdown
# WordPress Integration Guide

## Installation

### Method 1: Composer (Recommended)
```bash
cd wp-content/mu-plugins
composer require hyperpolymath/php-aegis
```

### Method 2: Manual Installation
Download and place in `wp-content/mu-plugins/php-aegis/`

## Usage in Themes

### Basic Sanitization
```php
<?php
// In template files
<h1><?= aegis_html($post_title) ?></h1>
<input value="<?= aegis_attr($user_input) ?>">
```

### RDF/Turtle Output (Unique Feature!)
```php
<?php
// For semantic themes outputting Turtle
header('Content-Type: text/turtle; charset=utf-8');

$subject = get_permalink();
$label = get_the_title();

echo aegis_turtle_literal($subject, 'en');
```

### Security Headers
```php
<?php
// In functions.php
add_action('send_headers', function () {
    aegis_send_security_headers();
});
```

## When to Use php-aegis vs WordPress Functions

| Scenario | Use WordPress | Use php-aegis |
|----------|--------------|--------------|
| HTML output | `esc_html()` | `aegis_html()` |
| Attribute output | `esc_attr()` | `aegis_attr()` |
| **RDF/Turtle output** | ❌ Not available | ✅ `aegis_turtle_literal()` |
| **Security headers** | ❌ Manual | ✅ `aegis_send_security_headers()` |
| UUID validation | ❌ Not built-in | ✅ `aegis_validate_uuid()` |
| Semantic versioning | ❌ Not built-in | ✅ `Validator::semver()` |

## Real-World Example: Semantic Blog Theme

```php
<?php
/**
 * Template: Single post with RDF metadata
 */

// Set up Turtle output
add_action('wp_head', function () {
    if (is_single()) {
        echo '<link rel="alternate" type="text/turtle" href="' .
             get_permalink() . '/turtle" />';
    }
});

// Turtle endpoint
add_action('template_redirect', function () {
    if (get_query_var('format') === 'turtle') {
        header('Content-Type: text/turtle; charset=utf-8');

        $subject = '<' . get_permalink() . '>';
        $title = aegis_turtle_literal(get_the_title(), 'en');
        $content = aegis_turtle_literal(get_the_content(), 'en');

        echo "$subject <http://schema.org/name> $title .\n";
        echo "$subject <http://schema.org/articleBody> $content .\n";

        exit;
    }
});
```
```

**Completion Criteria**:
- [ ] WordPress adapter functions implemented
- [ ] MU-plugin template created
- [ ] WordPress integration tests passing
- [ ] WordPress documentation complete
- [ ] Tested with at least 2 WordPress themes/plugins

**Time Estimate**: Remove per project policy

---

### Phase 2: IndieWeb Security Helpers (72% → 78%)

**Goal**: Provide security utilities for IndieWeb protocols (Micropub, IndieAuth, Webmention).

#### 2.1 Micropub Content Validator
Create `src/IndieWeb/Micropub.php`:

```php
<?php
// SPDX-License-Identifier: PMPL-1.0-or-later

declare(strict_types=1);

namespace PhpAegis\IndieWeb;

use PhpAegis\Validator;
use PhpAegis\Sanitizer;

final class Micropub
{
    /**
     * Validate Micropub entry (microformats2 format).
     *
     * @param array<string, mixed> $entry
     * @return array{valid: bool, errors: string[]}
     */
    public static function validateEntry(array $entry): array
    {
        $errors = [];

        // Check required fields
        if (!isset($entry['type'])) {
            $errors[] = 'Missing required field: type';
        }

        if (!isset($entry['properties'])) {
            $errors[] = 'Missing required field: properties';
        }

        // Validate content if present
        if (isset($entry['properties']['content'])) {
            $content = $entry['properties']['content'][0] ?? '';

            if (is_array($content)) {
                $html = $content['html'] ?? '';
                $text = $content['value'] ?? '';

                // Validate HTML doesn't contain dangerous scripts
                if (str_contains($html, '<script>')) {
                    $errors[] = 'Content contains dangerous script tags';
                }
            }
        }

        // Validate URLs if present
        if (isset($entry['properties']['url'])) {
            foreach ($entry['properties']['url'] as $url) {
                if (!Validator::httpsUrl($url)) {
                    $errors[] = "Invalid or non-HTTPS URL: $url";
                }
            }
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors,
        ];
    }

    /**
     * Sanitize Micropub content for storage.
     *
     * @param array<string, mixed> $entry
     * @return array<string, mixed>
     */
    public static function sanitizeEntry(array $entry): array
    {
        $sanitized = $entry;

        if (isset($sanitized['properties']['name'])) {
            $sanitized['properties']['name'] = array_map(
                fn($name) => Sanitizer::html($name),
                $sanitized['properties']['name']
            );
        }

        if (isset($sanitized['properties']['content'])) {
            foreach ($sanitized['properties']['content'] as $key => $content) {
                if (is_array($content)) {
                    if (isset($content['html'])) {
                        $sanitized['properties']['content'][$key]['html'] =
                            Sanitizer::html($content['html']);
                    }
                    if (isset($content['value'])) {
                        $sanitized['properties']['content'][$key]['value'] =
                            Sanitizer::html($content['value']);
                    }
                } else {
                    $sanitized['properties']['content'][$key] =
                        Sanitizer::html($content);
                }
            }
        }

        return $sanitized;
    }
}
```

#### 2.2 IndieAuth Token Validator
Create `src/IndieWeb/IndieAuth.php`:

```php
<?php
// SPDX-License-Identifier: PMPL-1.0-or-later

declare(strict_types=1);

namespace PhpAegis\IndieWeb;

use PhpAegis\Validator;

final class IndieAuth
{
    /**
     * Validate "me" URL (IndieAuth profile URL).
     */
    public static function validateMe(string $url): bool
    {
        if (!Validator::httpsUrl($url)) {
            return false;
        }

        // Must be a valid domain, not an IP
        $host = parse_url($url, PHP_URL_HOST);
        if ($host === null || $host === false) {
            return false;
        }

        return Validator::domain($host);
    }

    /**
     * Validate redirect URI matches client ID origin.
     */
    public static function validateRedirectUri(
        string $redirectUri,
        string $clientId
    ): bool {
        if (!Validator::httpsUrl($redirectUri) || !Validator::httpsUrl($clientId)) {
            return false;
        }

        $redirectHost = parse_url($redirectUri, PHP_URL_HOST);
        $clientHost = parse_url($clientId, PHP_URL_HOST);

        return $redirectHost === $clientHost;
    }
}
```

#### 2.3 Webmention SSRF Prevention
Create `src/IndieWeb/Webmention.php`:

```php
<?php
// SPDX-License-Identifier: PMPL-1.0-or-later

declare(strict_types=1);

namespace PhpAegis\IndieWeb;

use PhpAegis\Validator;

final class Webmention
{
    /**
     * Check if IP address is internal/private (SSRF prevention).
     */
    public static function isInternalIp(string $ip): bool
    {
        if (!Validator::ip($ip)) {
            return false;
        }

        // Check if IP is in private ranges
        return !filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }

    /**
     * Validate Webmention source URL (prevent internal requests).
     */
    public static function validateSource(string $url): bool
    {
        if (!Validator::httpsUrl($url)) {
            return false;
        }

        $host = parse_url($url, PHP_URL_HOST);
        if ($host === null || $host === false) {
            return false;
        }

        // Check if host resolves to internal IP
        $ip = gethostbyname($host);
        if ($ip === $host) {
            // Could not resolve
            return false;
        }

        return !self::isInternalIp($ip);
    }

    /**
     * Validate Webmention target matches your domain.
     */
    public static function validateTarget(string $url, string $yourDomain): bool
    {
        if (!Validator::httpsUrl($url)) {
            return false;
        }

        $host = parse_url($url, PHP_URL_HOST);
        return $host === $yourDomain;
    }
}
```

#### 2.4 IndieWeb Tests
Create `tests/IndieWeb/MicropubTest.php`, `IndieAuthTest.php`, `WebmentionTest.php`.

#### 2.5 IndieWeb Documentation
Create `docs/indieweb/INDIEWEB_SECURITY.md` with comprehensive examples.

**Completion Criteria**:
- [ ] Micropub validator implemented
- [ ] IndieAuth validator implemented
- [ ] Webmention SSRF prevention implemented
- [ ] IndieWeb tests passing (100% coverage)
- [ ] IndieWeb documentation complete

---

### Phase 3: Rate Limiting (78% → 83%)

**Goal**: Provide rate limiting without external dependencies.

#### 3.1 Token Bucket Interface
Create `src/RateLimit/RateLimitStore.php`:

```php
<?php
// SPDX-License-Identifier: PMPL-1.0-or-later

declare(strict_types=1);

namespace PhpAegis\RateLimit;

interface RateLimitStore
{
    /**
     * Get token bucket state for a key.
     */
    public function get(string $key): ?TokenBucket;

    /**
     * Store token bucket state for a key.
     */
    public function set(string $key, TokenBucket $bucket, int $ttl): void;
}
```

#### 3.2 Token Bucket Implementation
Create `src/RateLimit/TokenBucket.php`, `MemoryStore.php`, `FileStore.php`.

#### 3.3 Rate Limiter
Create `src/RateLimit/RateLimiter.php` with `attempt()`, `remaining()`, `resetAt()` methods.

**Completion Criteria**:
- [ ] Token bucket implementation
- [ ] Memory store (for development)
- [ ] File store (for production without Redis)
- [ ] Rate limiter with clear API
- [ ] Comprehensive tests (edge cases, concurrency)
- [ ] Documentation with examples

---

### Phase 4: Documentation Overhaul (83% → 90%)

**Goal**: Comprehensive documentation for all audiences.

#### 4.1 API Reference
Create `docs/api/API_REFERENCE.md`:
- Complete reference for all classes and methods
- Parameter descriptions with types
- Return value documentation
- Usage examples for each method
- Security considerations

#### 4.2 User Guide
Create `docs/user/USER_GUIDE.md`:
- Installation methods (Composer, manual)
- Quick start examples
- Common use cases
- Framework integration (WordPress, Laravel, Symfony)
- Troubleshooting

#### 4.3 Security Guide
Enhance `SECURE_DEFAULTS.md`:
- OWASP Top 10 mapping (expand existing)
- Real-world vulnerability examples
- Secure coding patterns
- CI/CD integration examples

#### 4.4 Integration Guides
- WordPress: Comprehensive guide (expand Phase 1 docs)
- Laravel: Service provider usage
- Symfony: Bundle configuration
- IndieWeb: Protocol implementations

**Completion Criteria**:
- [ ] API reference complete (100 pages)
- [ ] User guide complete (50 pages)
- [ ] Security guide enhanced (40 pages)
- [ ] Integration guides for 3 frameworks
- [ ] Code examples tested and verified

---

### Phase 5: Real-World Validation (90% → 95%)

**Goal**: Test php-aegis against real WordPress plugins/themes to validate effectiveness.

#### 5.1 Test Against WordPress Themes
Create test integrations:
1. Semantic blog theme (using TurtleEscaper)
2. E-commerce theme (using security headers)
3. Membership site theme (using validation)

#### 5.2 Test Against WordPress Plugins
Create test integrations:
1. Contact form plugin (validation + sanitization)
2. IndieWeb plugin (Micropub + Webmention)
3. API service plugin (rate limiting + headers)

#### 5.3 Create Test Report
Document:
- Real vulnerabilities found and fixed
- Performance metrics
- False positive/negative analysis
- Integration pain points
- Recommendations for improvement

**Completion Criteria**:
- [ ] Tested with 3 WordPress themes
- [ ] Tested with 3 WordPress plugins
- [ ] Created comprehensive test report
- [ ] Documented all findings
- [ ] Updated code based on feedback

---

### Phase 6: Deployment & Publishing (95% → 100%)

**Goal**: Make php-aegis easily accessible to all PHP developers.

#### 6.1 Publish to Packagist
- Register on packagist.org
- Configure GitHub webhook for auto-updates
- Add Packagist badge to README

#### 6.2 Docker Image
Create `Dockerfile` and publish to GHCR:
```dockerfile
FROM php:8.3-cli
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
RUN composer global require hyperpolymath/php-aegis
```

#### 6.3 GitHub Action
Create `hyperpolymath/php-aegis-action` for CI integration:
```yaml
- uses: hyperpolymath/php-aegis-action@v1
  with:
    path: ./src
    report: aegis-report.txt
```

#### 6.4 Pre-built Binaries
Not applicable for PHP libraries (interpreted language).

**Completion Criteria**:
- [ ] Published to Packagist
- [ ] Docker image published to GHCR
- [ ] GitHub Action created and tested
- [ ] Installation docs updated
- [ ] Version 1.0.0 released

---

## Success Metrics

### Code Quality
- [ ] 100% test coverage for core functionality
- [ ] PHPStan level 9 (strict)
- [ ] PHP-CS-Fixer (PSR-12 compliant)
- [ ] Zero critical security issues (Psalm)

### Documentation
- [ ] 200+ pages of documentation
- [ ] 50+ code examples
- [ ] 3+ framework integration guides
- [ ] 10+ real-world use cases

### Adoption
- [ ] 100+ Packagist installs/month
- [ ] 50+ GitHub stars
- [ ] 10+ contributors
- [ ] 5+ integration examples

### Security
- [ ] Zero reported vulnerabilities in library itself
- [ ] 10+ vulnerabilities prevented in user code
- [ ] OWASP Top 10 coverage documented

---

## Timeline Philosophy

Per project guidelines, no time estimates are provided. Work proceeds based on:
1. User demand (GitHub issues)
2. Security criticality
3. Contributor availability

Phases can be reordered based on community feedback.

---

## Key Differentiators

What makes php-aegis unique:

1. **TurtleEscaper** - Only PHP library with W3C-compliant RDF Turtle escaping
2. **Zero Dependencies** - Works everywhere PHP 8.1+ runs
3. **Static Methods** - No instance state, easy drop-in usage
4. **IndieWeb Focus** - First-class support for Micropub, IndieAuth, Webmention
5. **Framework Gaps** - Provides what WordPress/Laravel/Symfony don't

---

## Integration with sanctify-php

php-aegis (runtime) and sanctify-php (static analysis) are complementary:

| Tool | Role | When Used |
|------|------|-----------|
| **php-aegis** | Runtime protection | During request handling |
| **sanctify-php** | Static analysis | During development/CI |

**Synergy**: sanctify-php should recognize php-aegis methods as "safe sinks" in taint analysis:

```haskell
-- sanctify-php configuration
safeSinks = [
  "PhpAegis\\Sanitizer::html",
  "PhpAegis\\Sanitizer::attr",
  "PhpAegis\\Sanitizer::js",
  "PhpAegis\\TurtleEscaper::literal",
  "PhpAegis\\TurtleEscaper::iri"
]
```

---

## Related Projects

- **sanctify-php** - Static analysis for PHP security (finds the bugs)
- **indieweb2-bastion** - Infrastructure-layer security (network/DNS/audit)
- **wp-audit-toolkit** - WordPress security auditing

---

*Development plan created 2026-01-22. Target: Production-ready php-aegis at 95%+ completion.*
