<?php

/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\Tests\WordPress;

use PHPUnit\Framework\TestCase;

/**
 * Tests for WordPress adapter functions.
 *
 * These tests verify that the aegis_* functions work correctly
 * and provide the same security as the underlying PhpAegis classes.
 */
class AdapterTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Load WordPress adapter functions
        require_once __DIR__ . '/../../src/WordPress/Adapter.php';
    }

    // ========================================================================
    // Sanitization Functions
    // ========================================================================

    public function testAegisHtmlEscapesXss(): void
    {
        $input = '<script>alert("xss")</script>';
        $output = aegis_html($input);

        $this->assertStringNotContainsString('<script>', $output);
        $this->assertStringContainsString('&lt;script&gt;', $output);
        $this->assertStringContainsString('&quot;', $output);
    }

    public function testAegisAttrEscapesQuotes(): void
    {
        $input = 'value" onload="alert(1)';
        $output = aegis_attr($input);

        $this->assertStringNotContainsString('" onload="', $output);
        $this->assertStringContainsString('&quot;', $output);
    }

    public function testAegisJsEscapesForJavaScript(): void
    {
        $input = "user's input with \"quotes\"";
        $output = aegis_js($input);

        // Should be JSON-encoded string
        $this->assertStringStartsWith('"', $output);
        $this->assertStringEndsWith('"', $output);
        $this->assertStringContainsString('\\"', $output); // Escaped quotes
    }

    public function testAegisUrlEncodesSpaces(): void
    {
        $input = 'path with spaces';
        $output = aegis_url($input);

        $this->assertStringContainsString('%20', $output);
        $this->assertStringNotContainsString(' ', $output);
    }

    public function testAegisCssRemovesDangerousChars(): void
    {
        $input = 'color:red;background:url(javascript:alert(1))';
        $output = aegis_css($input);

        $this->assertStringNotContainsString(':', $output);
        $this->assertStringNotContainsString('(', $output);
        $this->assertStringNotContainsString(')', $output);
    }

    public function testAegisJsonEncodesSecurely(): void
    {
        $input = ['key' => '<script>alert(1)</script>'];
        $output = aegis_json($input);

        $json = json_decode($output, true);
        $this->assertIsArray($json);
        $this->assertArrayHasKey('key', $json);
        // Check that HTML is escaped in JSON
        $this->assertStringContainsString('\\u003C', $output); // <
    }

    public function testAegisStripTagsRemovesAllTags(): void
    {
        $input = '<p>Hello <b>World</b></p>';
        $output = aegis_strip_tags($input);

        $this->assertSame('Hello World', $output);
    }

    public function testAegisFilenameSanitizesPath(): void
    {
        $input = '../../../etc/passwd';
        $output = aegis_filename($input);

        $this->assertStringNotContainsString('..', $output);
        $this->assertStringNotContainsString('/', $output);
        $this->assertSame('etc_passwd', $output);
    }

    // ========================================================================
    // RDF/Turtle Functions (UNIQUE FEATURE)
    // ========================================================================

    public function testAegisTurtleStringEscapesQuotes(): void
    {
        $input = 'Hello "World"';
        $output = aegis_turtle_string($input);

        $this->assertStringContainsString('\\"', $output);
        $this->assertStringNotContainsString('"World"', $output);
    }

    public function testAegisTurtleIriValidatesUri(): void
    {
        $validIri = 'https://example.org/resource#1';
        $output = aegis_turtle_iri($validIri);

        $this->assertIsString($output);
        $this->assertNotEmpty($output);
    }

    public function testAegisTurtleLiteralWithLanguage(): void
    {
        $value = 'Hello World';
        $output = aegis_turtle_literal($value, 'en');

        $this->assertStringContainsString('"Hello World"', $output);
        $this->assertStringContainsString('@en', $output);
    }

    public function testAegisTurtleLiteralWithDatatype(): void
    {
        $value = '42';
        $output = aegis_turtle_literal($value, null, 'http://www.w3.org/2001/XMLSchema#integer');

        $this->assertStringContainsString('"42"', $output);
        $this->assertStringContainsString('^^', $output);
    }

    public function testAegisTurtleTripleBuildsCompleteTriple(): void
    {
        $subject = 'https://example.org/person/1';
        $predicate = 'http://xmlns.com/foaf/0.1/name';
        $object = 'Alice';
        $language = 'en';

        $output = aegis_turtle_triple($subject, $predicate, $object, $language);

        $this->assertStringContainsString('<https://example.org/person/1>', $output);
        $this->assertStringContainsString('<http://xmlns.com/foaf/0.1/name>', $output);
        $this->assertStringContainsString('"Alice"@en', $output);
        $this->assertStringEndsWith(' .', $output);
    }

    /**
     * Test the critical RDF injection vulnerability that was fixed.
     *
     * Before php-aegis: addslashes() was used (SQL escaping, not Turtle)
     * After php-aegis: TurtleEscaper properly escapes for W3C Turtle spec
     */
    public function testAegisTurtlePreventsRdfInjection(): void
    {
        // Attack vector: Inject Turtle escape sequence
        $maliciousInput = 'Normal text\n<http://evil.com> owl:sameAs <http://trusted.com>';

        $output = aegis_turtle_literal($maliciousInput, 'en');

        // Newline should be escaped as \n, not actual newline
        $this->assertStringNotContainsString("\n<http://evil.com>", $output);
        $this->assertStringContainsString('\\n', $output);

        // The entire malicious payload should be escaped
        $this->assertStringNotContainsString('owl:sameAs', $output);
    }

    // ========================================================================
    // Validation Functions
    // ========================================================================

    public function testAegisValidateEmailAcceptsValid(): void
    {
        $this->assertTrue(aegis_validate_email('user@example.com'));
        $this->assertTrue(aegis_validate_email('test+tag@domain.co.uk'));
    }

    public function testAegisValidateEmailRejectsInvalid(): void
    {
        $this->assertFalse(aegis_validate_email('not-an-email'));
        $this->assertFalse(aegis_validate_email('missing@domain'));
        $this->assertFalse(aegis_validate_email('@no-local.com'));
    }

    public function testAegisValidateUrlAcceptsValid(): void
    {
        $this->assertTrue(aegis_validate_url('https://example.com'));
        $this->assertTrue(aegis_validate_url('http://localhost:8080'));
    }

    public function testAegisValidateUrlRejectsInvalid(): void
    {
        $this->assertFalse(aegis_validate_url('not a url'));
        $this->assertFalse(aegis_validate_url('ftp://unsupported.com'));
    }

    public function testAegisValidateUrlHttpsOnly(): void
    {
        $this->assertTrue(aegis_validate_url('https://secure.com', true));
        $this->assertFalse(aegis_validate_url('http://insecure.com', true));
    }

    public function testAegisValidateIpAcceptsValid(): void
    {
        $this->assertTrue(aegis_validate_ip('192.168.1.1'));
        $this->assertTrue(aegis_validate_ip('::1'));
        $this->assertTrue(aegis_validate_ip('2001:db8::1'));
    }

    public function testAegisValidateIpRejectsInvalid(): void
    {
        $this->assertFalse(aegis_validate_ip('256.1.1.1'));
        $this->assertFalse(aegis_validate_ip('not-an-ip'));
    }

    public function testAegisValidateUuidAcceptsValid(): void
    {
        $this->assertTrue(aegis_validate_uuid('550e8400-e29b-41d4-a716-446655440000'));
        $this->assertTrue(aegis_validate_uuid('c73bcdcc-2669-4bf6-81d3-e4ae73fb11fd'));
    }

    public function testAegisValidateUuidRejectsInvalid(): void
    {
        $this->assertFalse(aegis_validate_uuid('not-a-uuid'));
        $this->assertFalse(aegis_validate_uuid('550e8400-e29b-41d4-a716')); // Too short
    }

    public function testAegisValidateSlugAcceptsValid(): void
    {
        $this->assertTrue(aegis_validate_slug('my-post-title'));
        $this->assertTrue(aegis_validate_slug('simple'));
        $this->assertTrue(aegis_validate_slug('multi-word-slug-123'));
    }

    public function testAegisValidateSlugRejectsInvalid(): void
    {
        $this->assertFalse(aegis_validate_slug('Has Spaces'));
        $this->assertFalse(aegis_validate_slug('UPPERCASE'));
        $this->assertFalse(aegis_validate_slug('special!chars'));
    }

    public function testAegisValidateJsonAcceptsValid(): void
    {
        $this->assertTrue(aegis_validate_json('{"valid": true}'));
        $this->assertTrue(aegis_validate_json('[]'));
        $this->assertTrue(aegis_validate_json('"string"'));
    }

    public function testAegisValidateJsonRejectsInvalid(): void
    {
        $this->assertFalse(aegis_validate_json('{invalid}'));
        $this->assertFalse(aegis_validate_json('not json'));
    }

    public function testAegisValidateSemverAcceptsValid(): void
    {
        $this->assertTrue(aegis_validate_semver('1.2.3'));
        $this->assertTrue(aegis_validate_semver('0.1.0'));
        $this->assertTrue(aegis_validate_semver('2.0.0-beta.1'));
        $this->assertTrue(aegis_validate_semver('1.0.0+20130313144700'));
    }

    public function testAegisValidateSemverRejectsInvalid(): void
    {
        $this->assertFalse(aegis_validate_semver('1.2'));
        $this->assertFalse(aegis_validate_semver('v1.2.3'));
        $this->assertFalse(aegis_validate_semver('1.2.3.4'));
    }

    public function testAegisValidateDomainAcceptsValid(): void
    {
        $this->assertTrue(aegis_validate_domain('example.com'));
        $this->assertTrue(aegis_validate_domain('sub.domain.co.uk'));
        $this->assertTrue(aegis_validate_domain('test-hyphen.com'));
    }

    public function testAegisValidateDomainRejectsInvalid(): void
    {
        $this->assertFalse(aegis_validate_domain(''));
        $this->assertFalse(aegis_validate_domain('no-tld'));
        $this->assertFalse(aegis_validate_domain('-invalid.com'));
        $this->assertFalse(aegis_validate_domain('192.168.1.1')); // IP, not domain
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    /**
     * Test that aegis functions can be used interchangeably with WordPress functions.
     */
    public function testAegisFunctionsAreDropInReplacements(): void
    {
        $dangerousInput = '<script>alert("xss")</script>';

        // aegis_html should produce similar output to hypothetical esc_html
        $aegisOutput = aegis_html($dangerousInput);
        $phpOutput = htmlspecialchars($dangerousInput, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        $this->assertSame($phpOutput, $aegisOutput);
    }

    /**
     * Test that multiple sanitization layers work correctly.
     */
    public function testLayeredSanitization(): void
    {
        $input = '<script>alert("xss")</script>';

        // First strip tags, then escape
        $stripped = aegis_strip_tags($input);
        $this->assertSame('alert("xss")', $stripped);

        $escaped = aegis_html($stripped);
        $this->assertStringContainsString('&quot;', $escaped);
    }

    /**
     * Test that validation followed by sanitization provides defense in depth.
     */
    public function testValidationAndSanitizationTogether(): void
    {
        $email = 'test@example.com';
        $url = 'https://example.com?param=<script>';

        // Validate first
        $this->assertTrue(aegis_validate_email($email));
        $this->assertTrue(aegis_validate_url($url));

        // Then sanitize for output
        $safeUrl = aegis_html($url);
        $this->assertStringNotContainsString('<script>', $safeUrl);
    }
}
