# Secure Defaults Checklist

This document provides a comprehensive checklist for secure PHP development using php-aegis. Follow these guidelines to ensure your application follows security best practices.

## Table of Contents

- [OWASP Top 10 Mapping](#owasp-top-10-mapping)
- [PHP Configuration](#php-configuration)
- [Input Validation](#input-validation)
- [Output Sanitization](#output-sanitization)
- [HTTP Security Headers](#http-security-headers)
- [Authentication & Sessions](#authentication--sessions)
- [Database Security](#database-security)
- [File Operations](#file-operations)
- [Cryptography](#cryptography)
- [Error Handling](#error-handling)
- [CI/CD Security](#cicd-security)
- [Dependency Management](#dependency-management)

---

## OWASP Top 10 Mapping

This section maps php-aegis features and checklist items to the [OWASP Top 10 2021](https://owasp.org/Top10/) vulnerabilities.

### Summary Matrix

| OWASP ID | Vulnerability | php-aegis Coverage | Section |
|----------|--------------|-------------------|---------|
| A01:2021 | Broken Access Control | Partial (Headers) | [HTTP Headers](#http-security-headers) |
| A02:2021 | Cryptographic Failures | Guidelines | [Cryptography](#cryptography) |
| A03:2021 | Injection | **Full** (Validator, Sanitizer, TurtleEscaper) | [Input](#input-validation), [Output](#output-sanitization) |
| A04:2021 | Insecure Design | Guidelines | [All Sections](#secure-defaults-checklist) |
| A05:2021 | Security Misconfiguration | **Full** (Headers) | [HTTP Headers](#http-security-headers), [PHP Config](#php-configuration) |
| A06:2021 | Vulnerable Components | Guidelines | [Dependencies](#dependency-management) |
| A07:2021 | Auth Failures | Guidelines | [Authentication](#authentication--sessions) |
| A08:2021 | Data Integrity Failures | Partial (CSP) | [HTTP Headers](#http-security-headers) |
| A09:2021 | Logging Failures | Guidelines | [Error Handling](#error-handling) |
| A10:2021 | SSRF | Partial (Validator) | [Input Validation](#input-validation) |

---

### A01:2021 - Broken Access Control

**Risk:** Attackers access unauthorized resources or perform actions outside their permissions.

**php-aegis Mitigations:**

| Control | php-aegis Feature | Code Example |
|---------|------------------|--------------|
| CSRF Prevention | `Headers::secure()` sets SameSite cookies | `Headers::secure()` |
| Clickjacking | `Headers::frameOptions('DENY')` | `Headers::frameOptions()` |
| CORS Policies | `Headers::crossOrigin*Policy()` | `Headers::crossOriginResourcePolicy()` |

**Checklist:**
- [ ] Use `Headers::frameOptions('DENY')` to prevent clickjacking
- [ ] Implement proper session management (see [Authentication](#authentication--sessions))
- [ ] Validate user permissions on every request
- [ ] Use CSRF tokens for state-changing operations
- [ ] Apply principle of least privilege

---

### A02:2021 - Cryptographic Failures

**Risk:** Sensitive data exposed due to weak/missing encryption.

**php-aegis Mitigations:**

| Control | php-aegis Feature | Code Example |
|---------|------------------|--------------|
| HTTPS Enforcement | `Validator::httpsUrl()` | `Validator::httpsUrl($url)` |
| HSTS | `Headers::strictTransportSecurity()` | `Headers::strictTransportSecurity(31536000, true, true)` |

**Checklist:**
- [ ] Use `Validator::httpsUrl()` to reject non-HTTPS URLs
- [ ] Enable HSTS with `Headers::strictTransportSecurity()`
- [ ] Never use MD5/SHA1 for security (see [Cryptography](#cryptography))
- [ ] Use `random_bytes()` for secure random data
- [ ] Use Argon2id for password hashing

**CI Enforcement:**
```yaml
# In php-lint.yml - checks for weak cryptography
- name: Check weak cryptography
  run: grep -rEn 'md5\s*\(|sha1\s*\(' --include="*.php" src/
```

---

### A03:2021 - Injection

**Risk:** Untrusted data interpreted as commands (SQL, XSS, OS, LDAP, Turtle).

**php-aegis Mitigations:**

| Attack Type | php-aegis Feature | Code Example |
|-------------|------------------|--------------|
| XSS (HTML) | `Sanitizer::html()` | `echo Sanitizer::html($input)` |
| XSS (Attr) | `Sanitizer::attr()` | `value="<?= Sanitizer::attr($v) ?>"` |
| XSS (JS) | `Sanitizer::js()` | `var x = <?= Sanitizer::js($v) ?>` |
| Path Traversal | `Validator::safeFilename()` | `Validator::safeFilename($name)` |
| Null Byte | `Validator::noNullBytes()` | `Validator::noNullBytes($path)` |
| RDF/SPARQL | `TurtleEscaper::string()` | `TurtleEscaper::literal($v)` |
| URL Injection | `Sanitizer::url()` | `href="<?= Sanitizer::url($u) ?>"` |
| JSON Injection | `Sanitizer::json()` | `Sanitizer::json($data)` |

**Checklist:**
- [ ] Use `Sanitizer::html()` for all HTML output
- [ ] Use `Sanitizer::attr()` for HTML attributes
- [ ] Use `Sanitizer::js()` for inline JavaScript
- [ ] Use `Sanitizer::json()` for JSON responses
- [ ] Use `TurtleEscaper::literal()` for RDF/Turtle data
- [ ] Use `Validator::safeFilename()` for file operations
- [ ] Use prepared statements for ALL database queries

**CI Enforcement:**
```yaml
# In php-lint.yml - checks for injection patterns
- name: Check dangerous functions
  run: |
    grep -rEn 'eval\s*\(|exec\s*\(' --include="*.php" src/
    grep -rEn 'echo\s+\$_(GET|POST)' --include="*.php" src/
```

---

### A04:2021 - Insecure Design

**Risk:** Missing or ineffective security controls in application design.

**php-aegis Mitigations:**

| Control | php-aegis Feature | Purpose |
|---------|------------------|---------|
| Secure Defaults | `Headers::secure()` | One-call security setup |
| Type Safety | All methods require `string` types | Prevents type confusion |
| Fail Secure | Validators return `false` on invalid input | Reject by default |

**Checklist:**
- [ ] Call `Headers::secure()` early in every request
- [ ] Use `declare(strict_types=1)` in all PHP files
- [ ] Validate before processing, sanitize before output
- [ ] Reject invalid input (don't try to "fix" it)
- [ ] Design with defense in depth

---

### A05:2021 - Security Misconfiguration

**Risk:** Missing security hardening, default credentials, verbose errors.

**php-aegis Mitigations:**

| Misconfiguration | php-aegis Feature | Code Example |
|-----------------|------------------|--------------|
| Missing CSP | `Headers::contentSecurityPolicy()` | `Headers::secure()` |
| Missing HSTS | `Headers::strictTransportSecurity()` | `Headers::secure()` |
| Server Leakage | `Headers::removeInsecureHeaders()` | `Headers::secure()` |
| MIME Sniffing | `Headers::contentTypeOptions()` | `Headers::secure()` |
| Missing Permissions-Policy | `Headers::permissionsPolicy()` | `Headers::secure()` |

**Headers set by `Headers::secure()`:**
```
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()
```

**Checklist:**
- [ ] Call `Headers::secure()` on every response
- [ ] Configure PHP securely (see [PHP Configuration](#php-configuration))
- [ ] Disable `display_errors` in production
- [ ] Remove default credentials and accounts
- [ ] Review all security headers with [securityheaders.com](https://securityheaders.com)

---

### A06:2021 - Vulnerable and Outdated Components

**Risk:** Using libraries with known vulnerabilities.

**php-aegis Design:**
- **Zero runtime dependencies** - Only PHP 8.1+ built-ins
- No vulnerable dependencies to track in production

**Checklist:**
- [ ] Run `composer audit` on every CI build
- [ ] Keep PHP version updated (8.1+ required)
- [ ] Review dev dependencies before adding
- [ ] Enable Dependabot/Renovate for automatic updates

**CI Enforcement:**
```yaml
# In php-lint.yml
- name: Run Composer audit
  run: composer audit --format=plain
```

---

### A07:2021 - Identification and Authentication Failures

**Risk:** Weak passwords, session hijacking, credential stuffing.

**php-aegis Mitigations:**

| Control | php-aegis Feature | Purpose |
|---------|------------------|---------|
| Session Security | `Headers::secure()` sets cookie flags | SameSite, Secure |

**Checklist:**
- [ ] Use `password_hash()` with `PASSWORD_ARGON2ID`
- [ ] Use `password_verify()` for constant-time comparison
- [ ] Regenerate session ID on login (`session_regenerate_id(true)`)
- [ ] Set session cookie flags: HttpOnly, Secure, SameSite=Strict
- [ ] Implement rate limiting for authentication
- [ ] Use MFA for sensitive operations

---

### A08:2021 - Software and Data Integrity Failures

**Risk:** Untrusted code execution, insecure CI/CD, missing integrity checks.

**php-aegis Mitigations:**

| Control | php-aegis Feature | Purpose |
|---------|------------------|---------|
| CSP | `Headers::contentSecurityPolicy()` | Prevents inline script injection |
| SRI Support | Design for external script verification | Subresource Integrity |

**Checklist:**
- [ ] Use Content-Security-Policy to block inline scripts
- [ ] Pin GitHub Actions to commit SHAs (not tags)
- [ ] Verify `composer.lock` in CI builds
- [ ] Sign commits with GPG
- [ ] Use Subresource Integrity for CDN resources

**CI Enforcement:**
```yaml
# Pin actions to SHA for integrity
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

---

### A09:2021 - Security Logging and Monitoring Failures

**Risk:** Insufficient logging, missing alerting, undetected breaches.

**Checklist:**
- [ ] Log authentication attempts (success and failure)
- [ ] Log access control failures
- [ ] Log input validation failures (potential attacks)
- [ ] Don't log sensitive data (passwords, tokens, PII)
- [ ] Set up alerting for anomalous patterns
- [ ] Monitor error logs for security issues

**Error Handler Pattern:**
```php
set_exception_handler(function (Throwable $e): void {
    // Log for operators
    error_log(sprintf('[%s] %s', get_class($e), $e->getMessage()));

    // Generic response to users
    http_response_code(500);
    echo json_encode(['error' => 'An unexpected error occurred']);
    exit(1);
});
```

---

### A10:2021 - Server-Side Request Forgery (SSRF)

**Risk:** Attacker forces server to make requests to unintended destinations.

**php-aegis Mitigations:**

| Control | php-aegis Feature | Code Example |
|---------|------------------|--------------|
| URL Validation | `Validator::url()` | `Validator::url($url)` |
| HTTPS Enforcement | `Validator::httpsUrl()` | `Validator::httpsUrl($url)` |
| Hostname Validation | `Validator::hostname()` | `Validator::hostname($host)` |
| IP Validation | `Validator::ip()`, `ipv4()`, `ipv6()` | `Validator::ip($ip)` |

**Checklist:**
- [ ] Validate all user-supplied URLs with `Validator::url()`
- [ ] Prefer `Validator::httpsUrl()` to enforce HTTPS
- [ ] Maintain allowlist of permitted domains/IPs
- [ ] Block requests to internal/private IP ranges
- [ ] Don't follow redirects blindly

**Safe URL Fetching:**
```php
use PhpAegis\Validator;

function safeFetch(string $url): string {
    // Validate URL format
    if (!Validator::httpsUrl($url)) {
        throw new InvalidArgumentException('Invalid or non-HTTPS URL');
    }

    // Parse and validate hostname
    $host = parse_url($url, PHP_URL_HOST);
    if (!$host || !Validator::domain($host)) {
        throw new InvalidArgumentException('Invalid hostname');
    }

    // Block internal/private IPs (allowlist approach is better)
    $ip = gethostbyname($host);
    if (filter_var($ip, FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        throw new InvalidArgumentException('Private/reserved IP not allowed');
    }

    // Now safe to fetch
    return file_get_contents($url);
}
```

---

### OWASP Coverage Summary

| php-aegis Class | OWASP Categories Addressed |
|----------------|---------------------------|
| `Validator` | A03, A10 |
| `Sanitizer` | A03 |
| `Headers` | A01, A02, A04, A05, A08 |
| `TurtleEscaper` | A03 |

**Legend:**
- **Full Coverage**: php-aegis provides direct protection
- **Partial Coverage**: php-aegis helps but additional measures needed
- **Guidelines**: Documentation and checklists provided

---

## PHP Configuration

### Required Settings

```ini
; Strict error reporting (development)
error_reporting = E_ALL
display_errors = Off
log_errors = On

; Session security
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = Strict
session.use_strict_mode = 1
session.use_only_cookies = 1

; Disable dangerous functions
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_multi_exec,parse_ini_file,show_source,eval

; File upload limits
upload_max_filesize = 10M
max_file_uploads = 5

; Exposure reduction
expose_php = Off
```

### Checklist

- [ ] `declare(strict_types=1)` at top of every PHP file
- [ ] Error display disabled in production (`display_errors = Off`)
- [ ] Error logging enabled (`log_errors = On`)
- [ ] Dangerous functions disabled where not needed
- [ ] PHP version exposure disabled (`expose_php = Off`)
- [ ] Session cookies are HttpOnly and Secure
- [ ] Appropriate memory and execution limits set

---

## Input Validation

### Using php-aegis Validator

```php
use PhpAegis\Validator;

// Always validate before use
$email = Validator::email($_POST['email'] ?? '') ? $_POST['email'] : null;
$url = Validator::httpsUrl($_POST['website'] ?? '') ? $_POST['website'] : null;
$id = Validator::uuid($_GET['id'] ?? '') ? $_GET['id'] : null;
```

### Checklist

- [ ] **Never trust user input** - validate ALL external data
- [ ] Use `Validator::email()` for email addresses
- [ ] Use `Validator::httpsUrl()` for URLs (enforce HTTPS)
- [ ] Use `Validator::uuid()` for identifiers
- [ ] Use `Validator::int()` with min/max bounds for integers
- [ ] Use `Validator::noNullBytes()` to prevent null byte injection
- [ ] Use `Validator::safeFilename()` for user-provided filenames
- [ ] Use `Validator::printable()` for text that should have no control chars
- [ ] Reject invalid input rather than attempting to "fix" it
- [ ] Validate data types, lengths, formats, and ranges
- [ ] Use allowlists over denylists where possible

### Validation Priority

| Input Source | Risk Level | Required Validation |
|-------------|------------|---------------------|
| `$_GET` | High | Always validate |
| `$_POST` | High | Always validate |
| `$_FILES` | Critical | Validate + scan |
| `$_COOKIE` | High | Always validate |
| `$_SERVER` | Medium | Validate if user-influenced |
| Database | Medium | Validate on retrieval |
| APIs | Medium | Validate responses |

---

## Output Sanitization

### Using php-aegis Sanitizer

```php
use PhpAegis\Sanitizer;

// HTML context
echo Sanitizer::html($userInput);

// HTML attribute context
echo '<input value="' . Sanitizer::attr($value) . '">';

// JavaScript context
echo '<script>var data = ' . Sanitizer::js($data) . ';</script>';

// URL context
echo '<a href="' . Sanitizer::url($link) . '">Link</a>';

// CSS context (limited support - prefer external stylesheets)
echo '<div style="color: ' . Sanitizer::css($color) . ';">';
```

### Checklist

- [ ] **Context-aware escaping** - use the right method for each context
- [ ] Use `Sanitizer::html()` for HTML body content
- [ ] Use `Sanitizer::attr()` for HTML attributes
- [ ] Use `Sanitizer::js()` for inline JavaScript
- [ ] Use `Sanitizer::url()` for URL components
- [ ] Use `Sanitizer::json()` for JSON output
- [ ] Use `Sanitizer::filename()` before file operations
- [ ] Never use `htmlspecialchars()` alone - it's not context-aware
- [ ] Never output user data in `<script>` without `Sanitizer::js()`
- [ ] Never use user data in CSS without validation

### XSS Prevention Matrix

| Context | Safe Method | Unsafe |
|---------|-------------|--------|
| HTML body | `Sanitizer::html()` | `echo $var` |
| HTML attribute | `Sanitizer::attr()` | `value="$var"` |
| JavaScript | `Sanitizer::js()` | `var x = '$var'` |
| URL | `Sanitizer::url()` | `href="$var"` |
| CSS | `Sanitizer::css()` | `style="$var"` |
| JSON | `Sanitizer::json()` | `json_encode()` alone |

---

## HTTP Security Headers

### Using php-aegis Headers

```php
use PhpAegis\Headers;

// Apply all recommended security headers at once
Headers::secure();

// Or configure individually
Headers::contentSecurityPolicy("default-src 'self'; script-src 'self'");
Headers::strictTransportSecurity(31536000, true, true);
Headers::frameOptions('DENY');
Headers::contentTypeOptions();
Headers::referrerPolicy('strict-origin-when-cross-origin');
Headers::permissionsPolicy([
    'camera' => [],
    'microphone' => [],
    'geolocation' => ['self'],
]);
```

### Checklist

- [ ] Call `Headers::secure()` early in request lifecycle
- [ ] Use Content-Security-Policy (CSP) to prevent XSS
- [ ] Enable HSTS with `includeSubDomains` and `preload`
- [ ] Set `X-Frame-Options: DENY` unless framing is needed
- [ ] Set `X-Content-Type-Options: nosniff`
- [ ] Configure appropriate `Referrer-Policy`
- [ ] Restrict features with `Permissions-Policy`
- [ ] Remove server identification headers

### Recommended Header Values

| Header | Recommended Value |
|--------|-------------------|
| Content-Security-Policy | `default-src 'self'; script-src 'self'; style-src 'self'` |
| Strict-Transport-Security | `max-age=31536000; includeSubDomains; preload` |
| X-Frame-Options | `DENY` |
| X-Content-Type-Options | `nosniff` |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| Permissions-Policy | `camera=(), microphone=(), geolocation=()` |

---

## Authentication & Sessions

### Checklist

- [ ] Use `password_hash()` with `PASSWORD_ARGON2ID` (or `PASSWORD_BCRYPT`)
- [ ] Use `password_verify()` for comparison (timing-safe)
- [ ] Regenerate session ID on privilege change (`session_regenerate_id(true)`)
- [ ] Set session cookie flags: `HttpOnly`, `Secure`, `SameSite=Strict`
- [ ] Implement session timeout (idle and absolute)
- [ ] Use CSRF tokens for state-changing operations
- [ ] Rate-limit authentication attempts
- [ ] Log authentication events
- [ ] Use secure password reset flows (time-limited tokens)

### Password Requirements

```php
// Minimum secure password hashing
$hash = password_hash($password, PASSWORD_ARGON2ID, [
    'memory_cost' => 65536,  // 64MB
    'time_cost' => 4,        // 4 iterations
    'threads' => 3,          // 3 parallel threads
]);

// Verify
if (password_verify($input, $hash)) {
    // Check if rehash needed (algorithm updates)
    if (password_needs_rehash($hash, PASSWORD_ARGON2ID)) {
        $newHash = password_hash($input, PASSWORD_ARGON2ID);
        // Update stored hash
    }
}
```

---

## Database Security

### Checklist

- [ ] **Always use prepared statements** with bound parameters
- [ ] Use PDO with `ATTR_EMULATE_PREPARES = false`
- [ ] Set `ATTR_ERRMODE = ERRMODE_EXCEPTION`
- [ ] Use least-privilege database accounts
- [ ] Escape identifiers (table/column names) if dynamic
- [ ] Validate and allowlist ORDER BY columns
- [ ] Limit query results appropriately
- [ ] Log slow queries and failures

### Secure PDO Configuration

```php
$pdo = new PDO($dsn, $user, $pass, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_EMULATE_PREPARES => false,      // Use real prepared statements
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::MYSQL_ATTR_MULTI_STATEMENTS => false, // Prevent multi-query attacks
]);

// Always use prepared statements
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$id]);  // $id is bound, not interpolated
```

---

## File Operations

### Checklist

- [ ] Validate file extensions against allowlist
- [ ] Validate MIME types (don't trust Content-Type header alone)
- [ ] Use `Validator::safeFilename()` for user-provided names
- [ ] Store uploads outside web root
- [ ] Generate random filenames for stored files
- [ ] Set restrictive permissions (0644 for files, 0755 for dirs)
- [ ] Limit file sizes at PHP and web server level
- [ ] Scan uploads for malware if handling untrusted files
- [ ] Never use user input in `include`/`require` paths

### Secure File Upload

```php
use PhpAegis\Validator;
use PhpAegis\Sanitizer;

$allowed = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
$maxSize = 5 * 1024 * 1024; // 5MB

$file = $_FILES['upload'] ?? null;
if (!$file || $file['error'] !== UPLOAD_ERR_OK) {
    throw new Exception('Upload failed');
}

if ($file['size'] > $maxSize) {
    throw new Exception('File too large');
}

$ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed, true)) {
    throw new Exception('Invalid file type');
}

// Generate safe filename
$safeName = bin2hex(random_bytes(16)) . '.' . $ext;
$uploadDir = '/var/uploads/';  // Outside web root!
move_uploaded_file($file['tmp_name'], $uploadDir . $safeName);
```

---

## Cryptography

### Checklist

- [ ] **Never use MD5 or SHA1** for security purposes
- [ ] Use `random_bytes()` for secure random data
- [ ] Use `hash_equals()` for timing-safe comparisons
- [ ] Use `sodium_*` functions for encryption
- [ ] Use `PASSWORD_ARGON2ID` for password hashing
- [ ] Store secrets in environment variables, not code
- [ ] Use HTTPS everywhere (no HTTP)
- [ ] Pin certificates for sensitive API connections

### Secure Defaults

| Use Case | Algorithm | PHP Function |
|----------|-----------|--------------|
| Passwords | Argon2id | `password_hash()` |
| Random tokens | CSPRNG | `random_bytes()` |
| Data hashing | SHA-256+ | `hash('sha256', ...)` |
| HMAC | SHA-256+ | `hash_hmac('sha256', ...)` |
| Encryption | XChaCha20-Poly1305 | `sodium_crypto_secretbox()` |
| Key derivation | Argon2id | `sodium_crypto_pwhash()` |
| String comparison | Timing-safe | `hash_equals()` |

---

## Error Handling

### Checklist

- [ ] Never expose stack traces to users in production
- [ ] Log errors with sufficient context for debugging
- [ ] Use custom error pages (don't reveal framework/PHP version)
- [ ] Handle exceptions at application boundaries
- [ ] Don't log sensitive data (passwords, tokens, PII)
- [ ] Monitor error logs for security issues
- [ ] Return generic error messages to clients

### Error Handler Pattern

```php
set_exception_handler(function (Throwable $e): void {
    // Log full details
    error_log(sprintf(
        "[%s] %s in %s:%d\n%s",
        get_class($e),
        $e->getMessage(),
        $e->getFile(),
        $e->getLine(),
        $e->getTraceAsString()
    ));

    // Generic response to client
    http_response_code(500);
    echo json_encode(['error' => 'An unexpected error occurred']);
    exit(1);
});
```

---

## CI/CD Security

### Required Checks

- [ ] PHPStan at level 9 (maximum strictness)
- [ ] PHP-CS-Fixer with PSR-12 standard
- [ ] PHPUnit tests with coverage requirements
- [ ] Secret scanning (TruffleHog, git-secrets)
- [ ] Dependency vulnerability scanning (Composer audit)
- [ ] SAST scanning (CodeQL, Psalm)
- [ ] License compliance checking

### Workflow Security

- [ ] Pin GitHub Actions to commit SHAs (not version tags)
- [ ] Use minimal permissions (`permissions: read-all`)
- [ ] Never store secrets in code or logs
- [ ] Require code review for main branch
- [ ] Enable branch protection rules
- [ ] Sign commits with GPG

### Sample CI Checks

```yaml
# Minimum CI checks for PHP projects
- PHPStan level 9
- PHP-CS-Fixer --dry-run
- PHPUnit with coverage
- composer audit (dependency vulnerabilities)
- TruffleHog (secret detection)
- SPDX license header check
```

---

## Dependency Management

### Checklist

- [ ] Run `composer audit` regularly
- [ ] Use `composer.lock` for reproducible builds
- [ ] Review dependencies before adding
- [ ] Minimize dependency count
- [ ] Prefer well-maintained packages
- [ ] Check licenses are compatible (SPDX)
- [ ] Enable Dependabot/Renovate for updates
- [ ] Verify package integrity (checksums)

### composer.json Best Practices

```json
{
    "config": {
        "sort-packages": true,
        "preferred-install": "dist",
        "optimize-autoloader": true,
        "secure-http": true
    },
    "minimum-stability": "stable",
    "prefer-stable": true
}
```

---

## Quick Reference

### Do ✅

- Validate all input with php-aegis Validator
- Escape all output with php-aegis Sanitizer
- Use prepared statements for all database queries
- Apply security headers with php-aegis Headers
- Use `declare(strict_types=1)` everywhere
- Use Argon2id for password hashing
- Pin CI action versions to commit SHAs
- Log security events

### Don't ❌

- Trust user input without validation
- Output user data without escaping
- Concatenate SQL queries with user input
- Use MD5/SHA1 for security
- Store secrets in code
- Expose error details to users
- Use `eval()`, `exec()`, or similar functions
- Disable HTTPS requirements

---

## Testing Your Secure Defaults

Run these commands to verify your configuration:

```bash
# Static analysis (max strictness)
composer analyze   # PHPStan level 9

# Code style
composer lint      # PHP-CS-Fixer check

# Tests
composer test      # PHPUnit

# Dependency audit
composer audit     # Check for vulnerabilities
```

---

## Resources

- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP: The Right Way - Security](https://phptherightway.com/#security)
- [OWASP Top 10](https://owasp.org/Top10/)
- [php-aegis Documentation](https://github.com/hyperpolymath/php-aegis)
