# php-aegis Real-World Validation Suite

This directory contains a comprehensive test suite for validating php-aegis against real-world WordPress installations, popular plugins, and themes.

## Overview

The validation suite tests php-aegis in realistic scenarios to ensure:
- **Security**: XSS prevention, SSRF protection, input validation
- **Compatibility**: Works with popular WordPress plugins and themes
- **Performance**: Rate limiting and resource management
- **Standards**: IndieWeb protocols (Micropub, Webmention)

## Components

### 1. `run-validation.sh`
Main bash script that:
- Sets up a fresh WordPress test environment
- Installs php-aegis as a must-use plugin
- Tests popular plugins (Contact Form 7, WooCommerce, Yoast SEO, etc.)
- Tests popular themes (Astra, GeneratePress, etc.)
- Generates a comprehensive validation report

### 2. `RealWorldTest.php`
PHP test class with methods for:
- Core validation (email, URL, IP, UUID)
- XSS sanitization testing
- Security headers (CSP, HSTS)
- WordPress adapter functions
- Plugin/theme compatibility
- IndieWeb security (Micropub, Webmention)
- Rate limiting

### 3. `run-tests.php`
CLI runner for executing RealWorldTest and outputting results in JSON or human-readable format.

### 4. `test-cf7-xss.php`
Specialized test for Contact Form 7 XSS prevention.

## Prerequisites

### Required Software
- **PHP 8.0+**: `php --version`
- **WP-CLI**: [Installation guide](https://wp-cli.org/#installing)
- **MySQL/MariaDB**: For WordPress database
- **Web server** (optional): For browser-based testing

### Required PHP Extensions
```bash
php -m | grep -E 'curl|mbstring|xml|pdo_mysql'
```

### Database Setup
```bash
# Create test database
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS wp_phpageis_test;"
mysql -u root -p -e "GRANT ALL PRIVILEGES ON wp_phpageis_test.* TO 'root'@'localhost';"
```

## Running the Validation Suite

### Full Validation (Recommended)
```bash
cd /path/to/php-aegis
./validation/run-validation.sh
```

This will:
1. ✓ Check dependencies (PHP, WP-CLI)
2. ✓ Download and install WordPress
3. ✓ Install php-aegis as MU-plugin
4. ✓ Test 8+ popular plugins
5. ✓ Test 5+ popular themes
6. ✓ Run PHP unit tests
7. ✓ Generate validation report

**Output**: `validation/results/validation-report.md`

### PHP Tests Only
```bash
./validation/run-tests.php --verbose
```

### JSON Output (for CI)
```bash
./validation/run-tests.php --json > results.json
```

### Contact Form 7 XSS Test
```bash
# Requires WordPress + Contact Form 7 installed
./validation/test-cf7-xss.php /path/to/wordpress
```

## Configuration

Environment variables (optional):

```bash
export WP_PATH="/tmp/php-aegis-wp-test"    # WordPress installation path
export WP_URL="http://localhost:8888"       # Test site URL
export WP_ADMIN_USER="admin"                # Admin username
export WP_ADMIN_EMAIL="admin@example.com"   # Admin email
```

## Test Categories

### 1. Core Validation
Tests `Validator` class methods:
- `Validator::email()` - Email validation
- `Validator::url()` - URL validation
- `Validator::ip()` - IPv4/IPv6 validation
- `Validator::uuid()` - UUID validation

### 2. Core Sanitization
Tests `Sanitizer` class against XSS payloads:
- Script tags: `<script>alert(1)</script>`
- Event handlers: `<img src=x onerror=alert(1)>`
- JavaScript URLs: `javascript:alert(1)`
- SVG attacks: `<svg onload=alert(1)>`

### 3. Security Headers
Tests `Headers` class generation:
- Content Security Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options

### 4. WordPress Adapter
Tests adapter functions:
- `aegis_html()` - HTML sanitization
- `aegis_attr()` - Attribute sanitization
- `aegis_url()` - URL sanitization
- `aegis_email()` - Email validation

### 5. Popular Plugins
Compatibility testing with:
- **Contact Form 7** - XSS prevention in form submissions
- **WooCommerce** - E-commerce security
- **Jetpack** - Feature compatibility
- **Yoast SEO** - SEO plugin compatibility
- **Akismet** - Anti-spam integration
- **Wordfence** - Security plugin compatibility
- **Elementor** - Page builder compatibility
- **WP Super Cache** - Caching compatibility

### 6. Popular Themes
Compatibility testing with:
- **Twenty Twenty-Four** - Default WordPress theme
- **Twenty Twenty-Three** - Previous default theme
- **Astra** - Popular multipurpose theme
- **GeneratePress** - Lightweight theme
- **OceanWP** - Feature-rich theme

### 7. IndieWeb Security
Tests IndieWeb protocol security:
- **Micropub**: XSS prevention in h-entry content
- **Webmention**: SSRF prevention for internal IPs

### 8. Rate Limiting
Tests token bucket rate limiter:
- 10 requests per minute limit
- Proper allow/deny behavior
- Key-based tracking

## Validation Report

The validation suite generates a comprehensive report at:
```
validation/results/validation-report.md
```

Report sections:
- **Test Environment**: WordPress version, PHP version, paths
- **Summary**: Pass/fail statistics
- **Plugins Tested**: Compatibility results for each plugin
- **Themes Tested**: Compatibility results for each theme
- **PHP Unit Tests**: Link to detailed JSON results
- **Conclusion**: Overall validation status

## Continuous Integration

### GitHub Actions Example
```yaml
name: php-aegis Validation

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    services:
      mysql:
        image: mysql:8.0
        env:
          MYSQL_ROOT_PASSWORD: root
          MYSQL_DATABASE: wp_phpageis_test
    steps:
      - uses: actions/checkout@v4
      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'
      - name: Install WP-CLI
        run: |
          curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
          chmod +x wp-cli.phar
          sudo mv wp-cli.phar /usr/local/bin/wp
      - name: Run Validation
        run: ./validation/run-tests.php --json
```

## Troubleshooting

### WordPress Download Fails
```bash
# Manually download WordPress
wp core download --path=/tmp/php-aegis-wp-test
```

### Database Connection Error
```bash
# Check MySQL is running
systemctl status mysqld

# Test connection
mysql -u root -p -e "SELECT 1;"
```

### Plugin Installation Fails
```bash
# Clear WP-CLI cache
rm -rf ~/.wp-cli/cache

# Try manual install
wp plugin install contact-form-7 --path=/tmp/php-aegis-wp-test
```

### Permission Errors
```bash
# Ensure scripts are executable
chmod +x validation/*.sh validation/*.php
```

## Expected Results

### Passing Validation
- ✓ All core validation tests pass
- ✓ All XSS payloads neutralized
- ✓ Security headers generated correctly
- ✓ WordPress adapter functions work as expected
- ✓ No PHP errors with tested plugins
- ✓ No PHP errors with tested themes
- ✓ IndieWeb security measures effective
- ✓ Rate limiting works correctly

### Pass Rate Target
**Target**: 95%+ pass rate across all tests

## License

SPDX-License-Identifier: PMPL-1.0-or-later
