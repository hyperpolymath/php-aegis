# Handover Document: sanctify-php Integration Insights

## Context

This document summarizes findings from integrating `php-aegis` and `sanctify-php` into a WordPress semantic theme (wp-sinople-theme). It provides actionable recommendations for the `sanctify-php` team based on real-world usage patterns.

## Role Clarification

| Tool | Role | When Used |
|------|------|-----------|
| **php-aegis** | Runtime security library | During request handling (validation, sanitization, headers) |
| **sanctify-php** | Static analysis tool | During development/CI (find vulnerabilities before deploy) |

These are **complementary**, not competing tools:
- `sanctify-php` finds the bugs
- `php-aegis` provides the fixes

## Issues Discovered During Integration

### 1. Haskell Toolchain Dependency

**Problem**: `sanctify-php` requires GHC/Cabal to build, which is a significant barrier for PHP developers.

**Impact**: Most PHP teams don't have Haskell expertise or toolchain installed.

**Recommendations**:
- Provide pre-built binaries for Linux (x86_64, aarch64), macOS (Intel, Apple Silicon), Windows
- Create official Docker image: `ghcr.io/hyperpolymath/sanctify-php:latest`
- Consider GitHub Actions integration that runs analysis without local install
- Add installation via common package managers (Homebrew, apt, nix)

**Example Docker usage**:
```bash
docker run --rm -v $(pwd):/workspace ghcr.io/hyperpolymath/sanctify-php analyze /workspace
```

### 2. PHP 8.x Syntax Support

**Problem**: Parser may not handle all PHP 8.x syntax (enums, union types, named arguments, attributes, match expressions, constructor property promotion).

**Test cases needed**:
```php
// Enums (PHP 8.1+)
enum Status: string {
    case Draft = 'draft';
    case Published = 'published';
}

// Union types (PHP 8.0+)
function process(string|int $input): string|false { ... }

// Attributes (PHP 8.0+)
#[Route('/api/users')]
class UserController { ... }

// Constructor property promotion (PHP 8.0+)
class User {
    public function __construct(
        public readonly string $name,
        private int $age = 0,
    ) {}
}

// Named arguments (PHP 8.0+)
htmlspecialchars(string: $input, flags: ENT_QUOTES);

// Match expressions (PHP 8.0+)
$result = match($status) {
    Status::Draft => 'Editing',
    Status::Published => 'Live',
};
```

**Recommendation**: Add PHP 8.x grammar rules and comprehensive test suite.

### 3. RDF/Turtle Output Context Awareness

**Problem**: Static analyzer doesn't detect RDF/Turtle injection vulnerabilities in semantic web themes.

**Background**: Semantic WordPress themes output RDF Turtle format for linked data. Standard XSS detection won't catch Turtle-specific injection vectors.

**Vulnerable pattern** (not currently detected):
```php
// DANGEROUS: addslashes() is insufficient for Turtle
$turtle = '<' . $uri . '> rdfs:label "' . addslashes($label) . '" .';
```

**Attack vectors**:
```turtle
# Turtle escape sequences
\n \r \t \\ \" \uXXXX \UXXXXXXXX

# IRI injection
<http://evil.com> owl:sameAs <http://trusted.com>
```

**Recommendation**: Add detection rules for:
- `addslashes()` used in RDF/Turtle context
- Unescaped variables in Turtle string literals (`"..."`)
- Unescaped IRIs (`<...>`)
- Missing use of proper escaping functions

**Suggested rule signatures**:
```
turtle_string_injection: Detects unescaped user input in Turtle string literals
turtle_iri_injection: Detects unescaped user input in Turtle IRIs
rdf_semantic_injection: Detects potential semantic attacks via RDF
```

### 4. WordPress Integration Documentation

**Problem**: No clear guidance for WordPress-specific vulnerability patterns.

**WordPress-specific patterns to detect**:

```php
// DANGEROUS: Direct $_GET/$_POST usage
echo $_GET['query'];  // XSS

// DANGEROUS: Missing nonce verification
if (isset($_POST['action'])) { ... }  // CSRF

// DANGEROUS: Direct SQL interpolation
$wpdb->query("SELECT * FROM users WHERE id = " . $_GET['id']);  // SQLi

// DANGEROUS: Unescaped output
echo $user_input;  // Should use esc_html(), esc_attr(), etc.

// DANGEROUS: Privileged action without capability check
add_action('wp_ajax_delete_user', 'delete_user_handler');
function delete_user_handler() {
    // Missing: current_user_can('delete_users')
    wp_delete_user($_POST['user_id']);
}
```

**WordPress-specific safe patterns**:
```php
// Safe escaping functions
esc_html($text)
esc_attr($attr)
esc_url($url)
wp_kses($html, $allowed)
wp_kses_post($html)

// Safe nonce verification
wp_verify_nonce($_POST['_wpnonce'], 'action_name')
check_admin_referer('action_name')

// Safe capability checks
current_user_can('edit_posts')
```

**Recommendation**: Create WordPress-specific ruleset that:
- Detects missing `esc_*` function usage
- Detects missing nonce verification in form handlers
- Detects missing capability checks in AJAX handlers
- Recognizes WordPress sanitization functions as safe sinks

### 5. IndieWeb/Micropub Pattern Detection

**Problem**: No awareness of IndieWeb protocols (Micropub, IndieAuth, Webmention).

**Patterns to detect**:

```php
// DANGEROUS: Missing IndieAuth token verification
function handle_micropub($request) {
    $content = $request['content'];  // Unverified!
    create_post($content);
}

// DANGEROUS: Webmention SSRF
function verify_webmention($source) {
    $response = wp_remote_get($source);  // Can hit internal IPs
}

// DANGEROUS: Micropub content injection
$mf2 = Mf2\parse($html, $source);
$content = $mf2['items'][0]['properties']['content'][0];
echo $content;  // Unsanitized from external source
```

**Recommendation**: Add rules for common IndieWeb vulnerability patterns.

## Integration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Development Workflow                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Developer   │───▶│ sanctify-php │───▶│   Fix Code   │  │
│  │  Writes Code │    │  (Analysis)  │    │  (Guidance)  │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                              │                               │
│                              ▼                               │
│                     ┌──────────────┐                        │
│                     │  php-aegis   │                        │
│                     │  (Runtime)   │                        │
│                     └──────────────┘                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Recommended sanctify-php Output Format

When `sanctify-php` detects a vulnerability, it should suggest the `php-aegis` fix:

```
VULNERABILITY: XSS in output context
FILE: theme/template.php:42
CODE: echo $user_input;

RECOMMENDATION:
  Use php-aegis Sanitizer for proper encoding:

  Before: echo $user_input;
  After:  echo \PhpAegis\Sanitizer::html($user_input);

  Install: composer require hyperpolymath/php-aegis
```

## Priority Recommendations Summary

| Priority | Issue | Effort |
|----------|-------|--------|
| P0 | Pre-built binaries / Docker image | Medium |
| P0 | PHP 8.x syntax support | High |
| P0 | Official GitHub Action (`sanctify-php-action`) | Medium |
| P1 | WordPress-specific rulesets | Medium |
| P1 | RDF/Turtle context detection | Medium |
| P1 | SARIF output for GitHub Security tab | Low |
| P2 | Incremental analysis (cache, scan changed files only) | High |
| P2 | IndieWeb protocol patterns | Low |
| P2 | php-aegis fix suggestions in output | Low |

---

## Additional Findings (Report 2)

### 6. GitHub Action Required

**Problem**: No official GitHub Action for CI integration.

**Impact**: Teams must write custom workflow configuration or use Docker manually.

**Recommendation**: Create `hyperpolymath/sanctify-php-action` with:
```yaml
# .github/workflows/security.yml
- uses: hyperpolymath/sanctify-php-action@v1
  with:
    path: ./src
    config: sanctify.yml
    sarif-output: results.sarif
```

### 7. SARIF Output for GitHub Integration

**What Works Well**: SARIF format enables direct GitHub Security tab integration.

**Enhancement**: Ensure SARIF output includes:
- Rule descriptions with OWASP references
- Severity levels mapped to GitHub's critical/high/medium/low
- Fix suggestions linking to php-aegis methods

```json
{
  "runs": [{
    "tool": { "driver": { "name": "sanctify-php" } },
    "results": [{
      "ruleId": "xss-output",
      "level": "error",
      "message": { "text": "Unescaped output" },
      "fixes": [{
        "description": { "text": "Use PhpAegis\\Sanitizer::html()" }
      }]
    }]
  }]
}
```

### 8. Incremental Analysis

**Problem**: Full codebase scans are slow on large projects.

**Recommendation**:
- Cache AST and taint analysis results
- On subsequent runs, only analyze changed files
- Invalidate cache when dependencies change
- Use file modification timestamps or git diff

```bash
# First run: full analysis, build cache
sanctify analyze ./src --cache .sanctify-cache

# Subsequent runs: incremental
sanctify analyze ./src --cache .sanctify-cache --incremental
```

### 9. Composer Plugin Wrapper

**Problem**: PHP developers expect `composer require` installation.

**Recommendation**: Create a Composer plugin that:
1. Downloads pre-built binary for platform
2. Provides `vendor/bin/sanctify` wrapper
3. Handles updates via Composer

```bash
composer require --dev hyperpolymath/sanctify-php
vendor/bin/sanctify analyze ./src
```

---

## Standalone vs Combined Operation

### Minimal Requirements for Each Tool

**php-aegis standalone** (runtime protection):
- Zero dependencies (works everywhere PHP runs)
- Static methods for easy drop-in usage
- Works without sanctify-php installed

**sanctify-php standalone** (static analysis):
- Pre-built binary (no Haskell needed)
- SARIF output for any CI system
- Works without php-aegis (just reports issues)

### Combined Synergies

When both tools are used together:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Combined Workflow                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────┐   ┌─────────────────┐   ┌──────────────────┐   │
│  │   Write    │──▶│  sanctify-php   │──▶│  Fix with        │   │
│  │   Code     │   │  (finds issues) │   │  php-aegis       │   │
│  └────────────┘   └─────────────────┘   └──────────────────┘   │
│                            │                      │              │
│                            ▼                      ▼              │
│                   ┌─────────────────────────────────────┐       │
│                   │  sanctify-php recognizes php-aegis  │       │
│                   │  methods as "safe sinks" in taint   │       │
│                   │  analysis, reducing false positives │       │
│                   └─────────────────────────────────────┘       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Key synergy**: sanctify-php should recognize php-aegis sanitizers as safe:
```haskell
-- sanctify-php taint rules
safeSinks = [
  "PhpAegis\\Sanitizer::html",
  "PhpAegis\\Sanitizer::attr",
  "PhpAegis\\Sanitizer::js",
  "PhpAegis\\Sanitizer::css",
  "PhpAegis\\Sanitizer::url",
  "PhpAegis\\TurtleEscaper::string",
  "PhpAegis\\TurtleEscaper::iri"
]
```

---

## Integration Metrics

| Metric | Before Integration | After Integration |
|--------|-------------------|-------------------|
| Files with `strict_types` | 0 | 24 (100%) |
| PHP version | 7.4+ | 8.2+ |
| WordPress version | 5.8+ | 6.4+ |
| CI security checks | 0 | 4 |

---

## Additional Findings (Report 3: Zotpress Plugin)

### 10. GHC Barrier Confirmed (Critical)

**Problem**: sanctify-php could not run on the Zotpress integration due to missing Haskell toolchain.

**Impact**: This is now confirmed across multiple integration attempts. The Haskell build requirement is the #1 adoption barrier.

**Immediate Recommendations**:
1. Provide pre-built binaries for:
   - Linux x86_64 (static binary)
   - Linux aarch64 (for ARM servers)
   - macOS Intel
   - macOS Apple Silicon
   - Windows x64
2. Publish Docker image: `ghcr.io/hyperpolymath/sanctify-php:latest`
3. Create GitHub Action that uses the Docker image internally

**Workaround Used**: Manual analysis using sanctify-php's documented detection patterns.

### 11. WordPress Security API Overlap

**Finding**: When analyzing mature WordPress plugins (like Zotpress), they already follow WordPress security best practices using core functions.

**WordPress provides equivalent security functions**:

| php-aegis | WordPress Equivalent | Notes |
|-----------|---------------------|-------|
| `Validator::email()` | `is_email()` | WP version is more permissive |
| `Validator::url()` | `wp_http_validate_url()` | WP has SSL enforcement |
| `Sanitizer::html()` | `esc_html()` | Identical functionality |
| `Sanitizer::attr()` | `esc_attr()` | Identical functionality |
| `Sanitizer::js()` | `esc_js()` | WP version is context-aware |
| `Sanitizer::url()` | `esc_url()` | WP handles protocols |
| `Sanitizer::stripTags()` | `wp_strip_all_tags()` | WP handles more edge cases |

**What sanctify-php should detect**:
- Direct use of raw PHP functions instead of WordPress equivalents
- `echo $var` instead of `echo esc_html($var)`
- `header('Location: ...')` instead of `wp_redirect()`
- Missing `exit;` after redirect

**sanctify-php rule suggestions**:
```haskell
-- WordPress-specific rules
wpRules = [
  ("use_wp_redirect", "header\\s*\\(\\s*['\"]Location", "Use wp_redirect() instead of header()"),
  ("missing_exit_redirect", "wp_redirect\\([^;]+\\);(?!\\s*exit)", "Add exit; after wp_redirect()"),
  ("raw_echo", "echo\\s+\\$(?!esc_)", "Escape output with esc_html()/esc_attr()"),
  ("direct_superglobal", "\\$_(GET|POST|REQUEST)\\[", "Sanitize superglobals before use")
]
```

### 12. Target Audience Clarification Needed

**Finding**: php-aegis value proposition is unclear for WordPress users.

**Recommended positioning for sanctify-php**:

When sanctify-php detects issues in WordPress code, suggest:
1. **First choice**: WordPress native function (if available)
2. **Second choice**: php-aegis function (for gaps WordPress doesn't cover)

```
VULNERABILITY: Unescaped output
FILE: plugin.php:42
CODE: echo $user_input;

RECOMMENDATION:
  WordPress: echo esc_html($user_input);
  Or php-aegis: echo \PhpAegis\Sanitizer::html($user_input);
```

### 13. WordPress-Unique Security Patterns

**What sanctify-php should understand about WordPress**:

```php
// WordPress-specific security patterns

// 1. ABSPATH protection (must be at top of every PHP file)
if (!defined('ABSPATH')) exit;

// 2. Nonce verification for forms
check_admin_referer('action_name');
wp_verify_nonce($_POST['nonce'], 'action_name');

// 3. Capability checks for privileged actions
if (!current_user_can('manage_options')) return;

// 4. Prepared statements for database
$wpdb->prepare("SELECT * FROM table WHERE id = %d", $id);

// 5. Safe redirect
wp_safe_redirect($url);
exit;
```

**Detection rules needed**:
- Missing ABSPATH check at file start
- Form handlers without nonce verification
- AJAX handlers without capability checks
- Missing `exit;` after redirects

---

## Additional Findings (Report 4: sinople-theme Full Integration)

### 14. Successful Integration Pattern

**What Worked**: Full integration with WordPress theme including:
- Function wrappers: `sinople_aegis_html()`, `sinople_aegis_attr()`, `sinople_aegis_json()`
- Validation wrappers: `sinople_aegis_validate_*()` functions
- RDF/Turtle feed endpoint using `TurtleEscaper` (unique value!)
- Graceful fallback to WordPress functions when php-aegis unavailable
- Unit tests for the integration

**Key Success**: TurtleEscaper proved its unique value by enabling a `/feed/turtle/` endpoint.

### 15. sanctify-php False Positives Identified

**Issues to address**:

1. **UnsafeRedirect false positive**: When `exit;` is on the next line
```php
// This triggers false positive:
wp_redirect($url);
exit;

// sanctify-php expects:
wp_redirect($url); exit;
```

2. **MissingTextDomain false positive**: Flags WordPress core functions
```php
// This may be flagged incorrectly:
__('Text', 'theme-domain');  // OK
_e('Text', 'theme-domain');  // OK
esc_html__('Text');          // May flag - but sometimes domain is optional
```

**Recommendation**: Add configuration options:
```yaml
# sanctify.yml
rules:
  UnsafeRedirect:
    allow_next_line_exit: true
  MissingTextDomain:
    ignore_core_functions: true
```

### 16. PHP 8.1+ Syntax Verification Needed

**Concern**: Parser may not handle modern PHP syntax.

**Test cases to verify**:
```php
// Nullsafe operator (PHP 8.0+)
$value = $object?->property?->method();

// Match expression (PHP 8.0+)
$result = match($type) {
    'html' => Sanitizer::html($input),
    'js' => Sanitizer::js($input),
    default => $input,
};

// Constructor property promotion (PHP 8.0+)
public function __construct(
    private readonly string $name,
) {}

// First-class callable syntax (PHP 8.1+)
$fn = Sanitizer::html(...);
```

### 17. Guix Export Documentation

**Issue**: Guix package export documentation is incomplete.

**Recommendation**: Add to sanctify-php docs:
```scheme
;; guix.scm
(use-modules (guix packages)
             (guix git-download)
             (guix build-system haskell))

(package
  (name "sanctify-php")
  (version "0.1.0")
  (source (git-reference
           (url "https://github.com/hyperpolymath/sanctify-php")
           (commit (string-append "v" version))))
  (build-system haskell-build-system)
  (synopsis "PHP security static analyzer")
  (license license:agpl3+))
```

---

## php-aegis Self-Identified Issues (Report 4)

These issues were discovered during sinople-theme integration:

| Issue | Status | Resolution |
|-------|--------|------------|
| `Headers::secure()` missing `permissionsPolicy()` | ✅ Fixed | Added in this PR |
| `php-aegis-compat` package doesn't exist | 📋 Planned | Create separate repo |
| Not published on Packagist | 📋 Planned | Publish after v0.2.0 |
| WordPress mu-plugin adapter not implemented | 📋 Planned | Phase 7 roadmap |

---

## Additional Findings (Report 5: Sinople Theme - Critical Vulnerability Fixed)

### 18. TurtleEscaper Fixed Real Vulnerability

**Critical Finding**: The theme was using `addslashes()` for RDF Turtle escaping - this is SQL escaping, NOT Turtle escaping. This was a real RDF injection vulnerability.

**Before (vulnerable)**:
```php
// DANGEROUS: addslashes() is SQL escaping, not Turtle escaping!
$turtle = '"' . addslashes($label) . '"@en';
```

**After (fixed)**:
```php
use PhpAegis\TurtleEscaper;
$turtle = TurtleEscaper::literal($label, language: 'en');
```

**This validates TurtleEscaper as the #1 unique value proposition of php-aegis.**

### 19. Security Fixes Applied in Real Integration

| Severity | Issue | Fix Applied |
|----------|-------|-------------|
| CRITICAL | `addslashes()` for Turtle | `TurtleEscaper::literal()` |
| CRITICAL | IRI interpolation | `Validator::url()` + error handling |
| HIGH | URL validation via `strpos()` | `parse_url()` host comparison |
| HIGH | Unsanitized Micropub input | `sanitize_text_field()` + `wp_kses_post()` |
| MEDIUM | No security headers | `Headers::secure()` equivalent |
| MEDIUM | No rate limiting | 1-min rate limit for Webmentions |
| LOW | Missing `strict_types` | Added to all files |

### 20. New Detection Rules for sanctify-php

**RDF Turtle as Distinct Output Context**:

sanctify-php should recognize Turtle output contexts and flag:
```haskell
-- RDF Turtle detection rules
turtleRules = [
  -- Dangerous: SQL escaping in Turtle context
  ("turtle_addslashes", "addslashes\\s*\\([^)]+\\).*['\"]@[a-z]{2}",
   "Use TurtleEscaper::literal() instead of addslashes() for Turtle"),

  -- Dangerous: String interpolation in Turtle IRI
  ("turtle_iri_interp", "<.*\\$[a-zA-Z_].*>",
   "Use TurtleEscaper::iri() for Turtle IRIs"),

  -- Dangerous: Raw variable in Turtle string
  ("turtle_string_raw", "\"\\$[a-zA-Z_][^\"]*\"@[a-z]",
   "Use TurtleEscaper::string() for Turtle literals")
]
```

**WordPress REST API Pattern Recognition**:
```haskell
-- WordPress REST API rules
restRules = [
  ("rest_missing_permission", "register_rest_route.*permission_callback.*__return_true",
   "REST routes should verify permissions"),

  ("rest_raw_param", "\\$request\\[.*\\](?!.*sanitize)",
   "Sanitize REST API parameters")
]
```

**WordPress Hook Detection** (reduce false positives):
```haskell
-- Functions defined via add_action/add_filter are called by WordPress
wpHookFunctions = extractFunctionsFrom [
  "add_action\\s*\\([^,]+,\\s*['\"]([^'\"]+)",
  "add_filter\\s*\\([^,]+,\\s*['\"]([^'\"]+)"
]
-- These should not be flagged as "unused functions"
```

### 21. php-aegis Enhancement Requests

From this integration:

| Request | Priority | Notes |
|---------|----------|-------|
| WordPress nonce validator | Medium | `Validator::wpNonce($nonce, $action)` |
| WordPress capability checker | Medium | `Validator::wpCapability($cap)` |
| TurtleEscaper case sensitivity docs | Low | Language tags should be lowercase |
| SPDX identifier validator | Low | `Validator::spdx($identifier)` |
| Headers + WordPress integration docs | Medium | How to use with `wp_headers` filter |

---

## Related Project: indieweb2-bastion

The [indieweb2-bastion](https://github.com/hyperpolymath/indieweb2-bastion) repository provides infrastructure-layer security that complements php-aegis and sanctify-php at the application layer.

### What indieweb2-bastion Does

| Feature | Purpose |
|---------|---------|
| Hardened bastion ingress | Secure network entry points |
| Oblivious DNS (IPv6) | Privacy-preserving DNS resolution |
| GraphQL DNS APIs | Programmable domain resolution |
| SurrealDB provenance graphs | Audit trails & data lineage |

### Relationship to IndieWeb Security

While **not** implementing IndieWeb protocols (Micropub, IndieAuth, Webmention), indieweb2-bastion provides foundational security patterns applicable to IndieWeb infrastructure:

| indieweb2-bastion | IndieWeb Application |
|-------------------|---------------------|
| Provenance graphs | Track Webmention verification chains |
| Audit capabilities | Log IndieAuth token usage |
| Bastion pattern | Rate limit Webmention endpoints |
| Policy controls (Nickel) | Define allowed Micropub content |

### Recommended Stack Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Full IndieWeb Stack                    │
├─────────────────────────────────────────────────────────┤
│  indieweb2-bastion    │  Infrastructure layer           │
│  (network, DNS, audit)│  (bastion, provenance)          │
├───────────────────────┼─────────────────────────────────┤
│  php-aegis            │  Application layer              │
│  (validation, escaping)│ (Micropub, IndieAuth, Webmention)│
├───────────────────────┼─────────────────────────────────┤
│  sanctify-php         │  Analysis layer                 │
│  (static analysis)    │  (find vulnerabilities)         │
└─────────────────────────────────────────────────────────┘
```

---

## Final Summary: Integration Value Matrix

| Tool | WordPress Value | Non-WP Value | Unique Capability |
|------|----------------|--------------|-------------------|
| **php-aegis** | Low (WP has `esc_*`) | **High** | RDF/Turtle escaping |
| **sanctify-php** | **High** (finds WP issues) | **High** | Taint tracking |

### Key Learnings Across 5 Reports

1. **TurtleEscaper is the killer feature** - Fixed real vulnerabilities in semantic web themes
2. **GHC barrier is critical** - Confirmed in every sanctify-php integration attempt
3. **WordPress has comprehensive APIs** - php-aegis basic escaping is redundant
4. **php-aegis shines in framework gaps** - Security headers, extended validators, RDF/Turtle
5. **sanctify-php needs WordPress awareness** - Hook detection, REST API patterns

---

## Contact

For questions about this integration or to coordinate between repos:
- php-aegis: https://github.com/hyperpolymath/php-aegis
- sanctify-php: https://github.com/hyperpolymath/sanctify-php
- Integration tested in: wp-sinople-theme, Zotpress, sinople-theme (×2)

---

*Generated from real-world WordPress integration experience (Reports 1-5).*
