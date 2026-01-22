# php-aegis Real-World Validation Plan

## Overview

This document outlines the plan for validating php-aegis against real-world WordPress plugins and themes to ensure compatibility, identify integration issues, and document best practices.

## Validation Goals

1. **Compatibility**: Ensure php-aegis functions work correctly with popular WordPress plugins
2. **Performance**: Verify no significant performance degradation
3. **Security**: Confirm security features function as expected in real scenarios
4. **Integration**: Document integration patterns and common use cases
5. **Issues**: Identify and document any bugs or limitations

## Test Targets

### Popular WordPress Plugins (Top 20)

| Plugin | Active Installs | Test Focus |
|--------|-----------------|------------|
| **WooCommerce** | 5M+ | E-commerce, custom post types, REST API |
| **Yoast SEO** | 5M+ | Meta boxes, admin UI, data sanitization |
| **Contact Form 7** | 5M+ | Form validation, email sanitization |
| **Jetpack** | 5M+ | Security features, API endpoints |
| **Elementor** | 5M+ | Page builder, dynamic content |
| **Wordfence Security** | 4M+ | Security headers, rate limiting |
| **Akismet** | 5M+ | Comment validation, spam detection |
| **WPForms** | 6M+ | Form validation, file uploads |
| **Advanced Custom Fields** | 2M+ | Meta boxes, custom fields validation |
| **All in One SEO** | 3M+ | Meta data sanitization |
| **WP Super Cache** | 2M+ | Headers, caching |
| **Smush** | 1M+ | File validation, media handling |
| **UpdraftPlus** | 3M+ | File operations, validation |
| **MonsterInsights** | 3M+ | Analytics, tracking |
| **WP Mail SMTP** | 2M+ | Email validation |

### Popular Themes (Top 10)

| Theme | Focus |
|-------|-------|
| **Twenty Twenty-Four** | Block theme, modern patterns |
| **Astra** | Performance, customizer |
| **GeneratePress** | Lightweight, hooks |
| **OceanWP** | E-commerce, demos |
| **Kadence** | Blocks, templates |
| **Hello Elementor** | Page builder integration |
| **Neve** | Speed, AMP |
| **Blocksy** | Customizer, dynamic data |
| **Hestia** | Material design |
| **Zakra** | Starter sites |

## Test Scenarios

### Scenario 1: Form Validation & Sanitization
**Plugins**: Contact Form 7, WPForms, Gravity Forms

**Test Cases**:
1. Replace native validation with php-aegis validators
2. Sanitize form output with `aegis_html()`, `aegis_attr()`
3. Validate email addresses with `aegis_validate_email()`
4. Test HTTPS-only URL validation with `aegis_validate_url()`
5. Rate limit form submissions with `RateLimiter::perMinute()`

**Expected Results**:
- Forms validate correctly with php-aegis
- XSS prevention works for user input
- Rate limiting prevents spam
- No conflicts with plugin validation

### Scenario 2: E-commerce Security
**Plugins**: WooCommerce, Easy Digital Downloads

**Test Cases**:
1. Sanitize product titles/descriptions with `aegis_html()`
2. Validate product URLs with `aegis_validate_url()`
3. Sanitize customer meta data with `aegis_attr()`
4. Rate limit checkout/cart operations
5. Validate UUIDs for order/product IDs with `aegis_validate_uuid()`

**Expected Results**:
- Product data safely escaped
- Checkout process secure
- No cart manipulation via XSS
- Rate limiting protects against abuse

### Scenario 3: Meta Boxes & Custom Fields
**Plugins**: Advanced Custom Fields, Custom Post Type UI

**Test Cases**:
1. Validate custom field data types (email, URL, UUID, JSON)
2. Sanitize meta box output with context-appropriate functions
3. Use `aegis_validate_json()` for JSON fields
4. Use `aegis_validate_semver()` for version fields
5. Sanitize file uploads with `aegis_filename()`

**Expected Results**:
- Custom fields validate correctly
- Meta data safely stored and displayed
- JSON/complex data types handled properly
- No injection vulnerabilities

### Scenario 4: REST API Endpoints
**Plugins**: WooCommerce, Jetpack, Custom API plugins

**Test Cases**:
1. Validate API request parameters
2. Sanitize JSON responses with `aegis_json()`
3. Rate limit API endpoints with `RateLimiter::perHour()`
4. Validate HTTPS-only webhooks
5. Use `aegis_validate_uuid()` for API resource IDs

**Expected Results**:
- API parameters validated correctly
- JSON output safe from injection
- Rate limiting prevents API abuse
- Webhook URLs validated for HTTPS

### Scenario 5: Security Headers
**Plugins**: Wordfence, iThemes Security, All-In-One Security

**Test Cases**:
1. Enable `aegis_send_security_headers()` via MU-plugin
2. Configure CSP with `aegis_csp()` for plugin assets
3. Test HSTS with `aegis_hsts()`
4. Verify no conflicts with security plugin headers
5. Test headers on admin vs frontend

**Expected Results**:
- Security headers set correctly
- No conflicts with security plugins
- CSP allows necessary plugin assets
- HSTS enforced properly

### Scenario 6: Admin UI & Settings
**Plugins**: Yoast SEO, All in One SEO, WP Rocket

**Test Cases**:
1. Sanitize settings page output
2. Validate admin form inputs (URLs, emails, domains)
3. Use `aegis_attr()` for input values
4. Validate JSON configuration with `aegis_validate_json()`
5. Test settings save/retrieve cycle

**Expected Results**:
- Settings pages secure from XSS
- Admin input validated correctly
- Settings stored safely
- No data loss or corruption

### Scenario 7: Media & File Handling
**Plugins**: Smush, Regenerate Thumbnails

**Test Cases**:
1. Validate filenames with `aegis_validate_filename()`
2. Sanitize file paths with `aegis_filename()`
3. Validate image URLs
4. Test file upload validation
5. Check for path traversal prevention

**Expected Results**:
- Filenames sanitized correctly
- No path traversal vulnerabilities
- File uploads validated
- Media library operations safe

### Scenario 8: RDF/Semantic Web (UNIQUE)
**Plugins**: Schema Pro, SEO plugins with JSON-LD

**Test Cases**:
1. Generate RDF/Turtle triples with `aegis_turtle_triple()`
2. Escape RDF literals with `aegis_turtle_literal()`
3. Test with malicious input (quotes, newlines, special chars)
4. Validate semantic web output
5. Compare with JSON-LD output

**Expected Results**:
- RDF/Turtle output correctly escaped
- No injection in semantic data
- Valid Turtle syntax
- Integration with existing schema markup

### Scenario 9: IndieWeb Integration
**Plugins**: IndieWeb plugin, Webmention plugin

**Test Cases**:
1. Validate Micropub entries with `Micropub::validateEntry()`
2. Implement SSRF-safe Webmention with `Webmention::validateWebmention()`
3. Test IndieAuth PKCE flow
4. Validate profile URLs with `IndieAuth::validateMe()`
5. Test internal IP blocking

**Expected Results**:
- Micropub entries validated correctly
- SSRF attacks blocked
- IndieAuth flow secure
- No internal network scanning

### Scenario 10: Rate Limiting
**Plugins**: Login LockDown, Limit Login Attempts

**Test Cases**:
1. Rate limit login attempts with `RateLimiter::perMinute(5)`
2. Rate limit comment submissions
3. Rate limit search queries
4. Test FileStore persistence
5. Test MemoryStore for development

**Expected Results**:
- Login attempts properly limited
- Brute force attacks prevented
- Rate limits persist across requests
- No conflicts with existing rate limit plugins

## Testing Methodology

### Environment Setup

1. **Local WordPress Installation**
   - WordPress 6.4+ (latest stable)
   - PHP 8.1+
   - MariaDB/MySQL
   - Apache/Nginx

2. **php-aegis Installation**
   ```bash
   composer require hyperpolymath/php-aegis
   cp vendor/hyperpolymath/php-aegis/docs/wordpress/aegis-mu-plugin.php wp-content/mu-plugins/
   ```

3. **Test Plugins Installation**
   - Install plugins via WP-CLI or admin interface
   - Activate one at a time for isolated testing
   - Document plugin versions used

### Testing Process

1. **Baseline Testing**
   - Install plugin without php-aegis
   - Document normal behavior
   - Note any existing security issues

2. **Integration Testing**
   - Enable php-aegis MU-plugin
   - Replace native functions with php-aegis equivalents
   - Test all plugin functionality
   - Document any issues

3. **Security Testing**
   - Test XSS prevention
   - Test SQL injection prevention (via validation)
   - Test SSRF prevention (IndieWeb)
   - Test rate limiting
   - Test header security

4. **Performance Testing**
   - Benchmark page load times
   - Benchmark database queries
   - Benchmark API response times
   - Compare with/without php-aegis

5. **Compatibility Testing**
   - Test with other plugins enabled
   - Test theme compatibility
   - Test multisite compatibility
   - Test with caching plugins

### Data Collection

For each test scenario, document:

1. **Plugin Information**
   - Name and version
   - Active installations
   - Last updated date

2. **Test Results**
   - Pass/Fail status
   - Specific php-aegis functions used
   - Integration patterns discovered
   - Performance impact (if any)

3. **Issues Found**
   - Description
   - Severity (Critical/High/Medium/Low)
   - Reproduction steps
   - Proposed fix

4. **Best Practices**
   - Recommended usage patterns
   - Common pitfalls
   - Integration tips

## Success Criteria

### Must Have (Critical)
- [ ] No fatal errors or conflicts with any tested plugin
- [ ] XSS prevention works correctly in all contexts
- [ ] Rate limiting functions as expected
- [ ] No data loss or corruption
- [ ] Security headers don't break admin functionality

### Should Have (High Priority)
- [ ] Performance impact < 5% on page load
- [ ] Compatible with top 10 plugins
- [ ] WordPress adapter functions work in all contexts
- [ ] RDF/Turtle escaping prevents injection
- [ ] IndieWeb SSRF prevention blocks internal IPs

### Nice to Have (Medium Priority)
- [ ] Compatible with top 20 plugins
- [ ] Compatible with top 10 themes
- [ ] Multisite compatibility
- [ ] Integration examples for each scenario
- [ ] Performance optimizations identified

## Deliverables

### 1. Validation Report
**File**: `docs/VALIDATION-REPORT.md`

**Contents**:
- Executive summary
- Test environment details
- Test results for each scenario
- Performance benchmarks
- Compatibility matrix
- Issues found and resolutions
- Best practices guide

### 2. Integration Examples
**Directory**: `docs/examples/wordpress/`

**Files**:
- `woocommerce-integration.php` - E-commerce security
- `contact-form-7-integration.php` - Form validation
- `acf-integration.php` - Custom fields validation
- `rest-api-integration.php` - API security
- `indieweb-integration.php` - IndieWeb protocols
- `rate-limiting-integration.php` - Rate limiting examples

### 3. Cerro Torre Container Integration
**File**: `manifests/php-aegis.ctp`

**Contents**:
- Cerro Torre manifest for php-aegis WordPress container
- Cryptographic provenance chain
- Dependencies (PHP 8.1+, WordPress, php-aegis)
- SELinux policy for container isolation
- Integration with Vörðr runtime

**File**: `docs/CERRO-TORRE-INTEGRATION.md`

**Contents**:
- Guide for building php-aegis with Cerro Torre
- Deployment to Vörðr container runtime
- Svalinn gateway integration
- Container verification process
- Multi-container WordPress stack with php-aegis

### 4. Known Issues Document
**File**: `docs/KNOWN-ISSUES.md`

**Contents**:
- List of discovered issues
- Workarounds
- Planned fixes
- Won't-fix items with reasoning

### 5. Updated Documentation
- Add "WordPress Compatibility" section to wiki
- Add "Tested Plugins" list to README
- Add integration examples to Examples.md
- Update User-Guide.md with real-world scenarios
- Add "Cerro Torre Deployment" guide

## Timeline

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| Planning | Complete | This document |
| Environment Setup | 1 day | Local WordPress + plugins |
| Scenario 1-5 Testing | 2 days | 5 scenarios validated |
| Scenario 6-10 Testing | 2 days | 5 scenarios validated |
| Performance Benchmarking | 1 day | Performance data |
| Documentation | 1 day | Validation report |
| **Total** | **~7 days** | Complete validation |

## Risk Assessment

### High Risk
- **Plugin conflicts**: php-aegis MU-plugin may conflict with security plugins
  - Mitigation: Test in isolation, document load order requirements

- **Performance impact**: Rate limiting FileStore may slow down high-traffic sites
  - Mitigation: Benchmark, recommend Redis for production

### Medium Risk
- **Theme incompatibility**: Themes may use unsafe output patterns
  - Mitigation: Document safe theme development practices

- **Plugin dependency**: Plugins may depend on specific WordPress function behavior
  - Mitigation: php-aegis functions should match WordPress behavior exactly

### Low Risk
- **Edge cases**: Unusual plugin configurations may reveal edge cases
  - Mitigation: Comprehensive testing, issue tracking

## Next Steps

1. Set up local WordPress environment
2. Install top 5 plugins for initial testing
3. Run Scenario 1 (Form Validation) tests
4. Document findings
5. Iterate through remaining scenarios
6. Produce validation report

## Contact

For questions about validation process:
- Create issue: https://github.com/hyperpolymath/php-aegis/issues
- Review testing progress in STATE.scm
