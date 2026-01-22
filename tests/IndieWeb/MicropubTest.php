<?php

/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\Tests\IndieWeb;

use PHPUnit\Framework\TestCase;
use PhpAegis\IndieWeb\Micropub;

/**
 * Tests for Micropub content validation and sanitization.
 *
 * Validates W3C Micropub spec compliance and security features.
 */
class MicropubTest extends TestCase
{
    // ========================================================================
    // Entry Validation Tests
    // ========================================================================

    public function testValidateEntryAcceptsValidEntry(): void
    {
        $entry = [
            'type' => ['h-entry'],
            'properties' => [
                'content' => ['Hello World'],
                'name' => ['Test Post'],
            ],
        ];

        $result = Micropub::validateEntry($entry);

        $this->assertTrue($result['valid']);
        $this->assertEmpty($result['errors']);
    }

    public function testValidateEntryRejectsMissingType(): void
    {
        $entry = [
            'properties' => [
                'content' => ['Hello World'],
            ],
        ];

        $result = Micropub::validateEntry($entry);

        $this->assertFalse($result['valid']);
        $this->assertContains('Missing required field: type', $result['errors']);
    }

    public function testValidateEntryRejectsMissingProperties(): void
    {
        $entry = [
            'type' => ['h-entry'],
        ];

        $result = Micropub::validateEntry($entry);

        $this->assertFalse($result['valid']);
        $this->assertContains('Missing required field: properties', $result['errors']);
    }

    public function testValidateEntryRejectsInvalidTypeFormat(): void
    {
        $entry = [
            'type' => 'h-entry', // Should be array
            'properties' => [],
        ];

        $result = Micropub::validateEntry($entry);

        $this->assertFalse($result['valid']);
        $this->assertContains('Field "type" must be a non-empty array', $result['errors']);
    }

    public function testValidateEntryRejectsInvalidPropertiesFormat(): void
    {
        $entry = [
            'type' => ['h-entry'],
            'properties' => 'not-an-array',
        ];

        $result = Micropub::validateEntry($entry);

        $this->assertFalse($result['valid']);
        $this->assertContains('Field "properties" must be an array', $result['errors']);
    }

    // ========================================================================
    // Content Validation Tests (XSS Prevention)
    // ========================================================================

    public function testValidateEntryDetectsScriptTags(): void
    {
        $entry = [
            'type' => ['h-entry'],
            'properties' => [
                'content' => ['<script>alert("xss")</script>'],
            ],
        ];

        $result = Micropub::validateEntry($entry);

        $this->assertFalse($result['valid']);
        $this->assertCount(1, array_filter($result['errors'], fn($e) => str_contains($e, 'script tags')));
    }

    public function testValidateEntryDetectsJavaScriptProtocol(): void
    {
        $entry = [
            'type' => ['h-entry'],
            'properties' => [
                'content' => [
                    [
                        'html' => '<a href="javascript:alert(1)">Click</a>',
                        'value' => 'Click',
                    ],
                ],
            ],
        ];

        $result = Micropub::validateEntry($entry);

        $this->assertFalse($result['valid']);
        $this->assertCount(1, array_filter($result['errors'], fn($e) => str_contains($e, 'javascript:')));
    }

    public function testValidateEntryAcceptsSafeHtmlContent(): void
    {
        $entry = [
            'type' => ['h-entry'],
            'properties' => [
                'content' => [
                    [
                        'html' => '<p>Safe <strong>HTML</strong> content</p>',
                        'value' => 'Safe HTML content',
                    ],
                ],
            ],
        ];

        $result = Micropub::validateEntry($entry);

        $this->assertTrue($result['valid']);
        $this->assertEmpty($result['errors']);
    }

    // ========================================================================
    // URL Validation Tests
    // ========================================================================

    public function testValidateEntryRejectsNonHttpsUrls(): void
    {
        $entry = [
            'type' => ['h-entry'],
            'properties' => [
                'url' => ['http://example.com'], // HTTP not HTTPS
            ],
        ];

        $result = Micropub::validateEntry($entry);

        $this->assertFalse($result['valid']);
        $this->assertCount(1, array_filter($result['errors'], fn($e) => str_contains($e, 'non-HTTPS URL')));
    }

    public function testValidateEntryAcceptsHttpsUrls(): void
    {
        $entry = [
            'type' => ['h-entry'],
            'properties' => [
                'url' => ['https://example.com'],
                'photo' => ['https://example.com/photo.jpg'],
            ],
        ];

        $result = Micropub::validateEntry($entry);

        $this->assertTrue($result['valid']);
        $this->assertEmpty($result['errors']);
    }

    public function testValidateEntryValidatesMediaUrls(): void
    {
        $entry = [
            'type' => ['h-entry'],
            'properties' => [
                'photo' => ['http://example.com/photo.jpg'], // HTTP
                'video' => ['https://example.com/video.mp4'], // HTTPS
                'audio' => ['not-a-url'], // Invalid
            ],
        ];

        $result = Micropub::validateEntry($entry);

        $this->assertFalse($result['valid']);
        $this->assertGreaterThanOrEqual(2, count($result['errors'])); // HTTP photo + invalid audio
    }

    // ========================================================================
    // Sanitization Tests
    // ========================================================================

    public function testSanitizeEntryRemovesScriptTags(): void
    {
        $entry = [
            'type' => ['h-entry'],
            'properties' => [
                'content' => [
                    [
                        'html' => '<p>Safe content</p><script>alert("xss")</script>',
                        'value' => 'Safe content',
                    ],
                ],
            ],
        ];

        $sanitized = Micropub::sanitizeEntry($entry);

        $this->assertStringNotContainsString('<script>', $sanitized['properties']['content'][0]['html']);
        $this->assertStringNotContainsString('alert', $sanitized['properties']['content'][0]['html']);
    }

    public function testSanitizeEntryEscapesHtmlInName(): void
    {
        $entry = [
            'type' => ['h-entry'],
            'properties' => [
                'name' => ['Post with <script>alert("xss")</script>'],
            ],
        ];

        $sanitized = Micropub::sanitizeEntry($entry);

        $this->assertStringNotContainsString('<script>', $sanitized['properties']['name'][0]);
        $this->assertStringContainsString('&lt;script&gt;', $sanitized['properties']['name'][0]);
    }

    public function testSanitizeEntryEscapesHtmlInSummary(): void
    {
        $entry = [
            'type' => ['h-entry'],
            'properties' => [
                'summary' => ['Summary with <b>bold</b> text'],
            ],
        ];

        $sanitized = Micropub::sanitizeEntry($entry);

        $this->assertStringNotContainsString('<b>', $sanitized['properties']['summary'][0]);
        $this->assertStringContainsString('&lt;b&gt;', $sanitized['properties']['summary'][0]);
    }

    public function testSanitizeEntryEscapesHtmlInCategories(): void
    {
        $entry = [
            'type' => ['h-entry'],
            'properties' => [
                'category' => ['tag1', '<script>xss</script>', 'tag2'],
            ],
        ];

        $sanitized = Micropub::sanitizeEntry($entry);

        $this->assertStringNotContainsString('<script>', $sanitized['properties']['category'][1]);
        $this->assertStringContainsString('&lt;script&gt;', $sanitized['properties']['category'][1]);
    }

    public function testSanitizeEntryPreservesValidContent(): void
    {
        $entry = [
            'type' => ['h-entry'],
            'properties' => [
                'name' => ['Valid Post Title'],
                'content' => ['Valid content without HTML'],
                'category' => ['tag1', 'tag2'],
            ],
        ];

        $sanitized = Micropub::sanitizeEntry($entry);

        $this->assertSame('Valid Post Title', $sanitized['properties']['name'][0]);
        $this->assertSame('Valid content without HTML', $sanitized['properties']['content'][0]);
        $this->assertSame(['tag1', 'tag2'], $sanitized['properties']['category']);
    }

    // ========================================================================
    // Token Validation Tests
    // ========================================================================

    public function testValidateTokenFormatAcceptsValidToken(): void
    {
        $token = str_repeat('a', 32); // 32 chars
        $this->assertTrue(Micropub::validateTokenFormat($token));

        $token = bin2hex(random_bytes(32)); // 64 hex chars
        $this->assertTrue(Micropub::validateTokenFormat($token));
    }

    public function testValidateTokenFormatRejectsTooShort(): void
    {
        $token = str_repeat('a', 31); // 31 chars
        $this->assertFalse(Micropub::validateTokenFormat($token));
    }

    public function testValidateTokenFormatRejectsWhitespace(): void
    {
        $token = str_repeat('a', 32) . ' '; // Has whitespace
        $this->assertFalse(Micropub::validateTokenFormat($token));

        $token = str_repeat('a', 16) . "\n" . str_repeat('a', 16);
        $this->assertFalse(Micropub::validateTokenFormat($token));
    }

    public function testValidateTokenFormatRejectsNullBytes(): void
    {
        $token = str_repeat('a', 32) . "\0";
        $this->assertFalse(Micropub::validateTokenFormat($token));
    }

    // ========================================================================
    // Scope Parsing Tests
    // ========================================================================

    public function testParseScopesHandlesSingleScope(): void
    {
        $scopes = Micropub::parseScopes('create');
        $this->assertSame(['create'], $scopes);
    }

    public function testParseScopesHandlesMultipleScopes(): void
    {
        $scopes = Micropub::parseScopes('create update delete');
        $this->assertSame(['create', 'update', 'delete'], $scopes);
    }

    public function testParseScopesHandlesEmptyString(): void
    {
        $scopes = Micropub::parseScopes('');
        $this->assertEmpty($scopes);

        $scopes = Micropub::parseScopes('   ');
        $this->assertEmpty($scopes);
    }

    public function testParseScopesFiltersInvalidScopes(): void
    {
        $scopes = Micropub::parseScopes('create INVALID update 123 delete');
        $this->assertSame(['create', 'update', 'delete'], $scopes);
    }

    public function testParseScopesAllowsUnderscores(): void
    {
        $scopes = Micropub::parseScopes('create_post update_profile');
        $this->assertSame(['create_post', 'update_profile'], $scopes);
    }

    // ========================================================================
    // Scope Checking Tests
    // ========================================================================

    public function testHasScopeReturnsTrueForProfile(): void
    {
        // 'profile' scope is implied for all requests
        $this->assertTrue(Micropub::hasScope([], 'profile'));
        $this->assertTrue(Micropub::hasScope(['create'], 'profile'));
    }

    public function testHasScopeReturnsTrueWhenPresent(): void
    {
        $scopes = ['create', 'update', 'delete'];

        $this->assertTrue(Micropub::hasScope($scopes, 'create'));
        $this->assertTrue(Micropub::hasScope($scopes, 'update'));
        $this->assertTrue(Micropub::hasScope($scopes, 'delete'));
    }

    public function testHasScopeReturnsFalseWhenMissing(): void
    {
        $scopes = ['create', 'update'];

        $this->assertFalse(Micropub::hasScope($scopes, 'delete'));
        $this->assertFalse(Micropub::hasScope($scopes, 'media'));
    }

    public function testHasScopeIsCaseSensitive(): void
    {
        $scopes = ['create'];

        $this->assertTrue(Micropub::hasScope($scopes, 'create'));
        $this->assertFalse(Micropub::hasScope($scopes, 'CREATE'));
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    public function testValidationAndSanitizationTogether(): void
    {
        $entry = [
            'type' => ['h-entry'],
            'properties' => [
                'name' => ['Post with <em>emphasis</em>'],
                'content' => ['Content with <script>alert("xss")</script>'],
                'url' => ['https://example.com'],
            ],
        ];

        // Validate first
        $validation = Micropub::validateEntry($entry);
        $this->assertFalse($validation['valid']); // Has script tag

        // Sanitize to make safe
        $sanitized = Micropub::sanitizeEntry($entry);
        $validation2 = Micropub::validateEntry($sanitized);
        $this->assertTrue($validation2['valid']); // Now safe
    }

    public function testCompleteEntryWorkflow(): void
    {
        // Simulate receiving a Micropub entry
        $entry = [
            'type' => ['h-entry'],
            'properties' => [
                'name' => ['My Blog Post'],
                'content' => [
                    [
                        'html' => '<p>Hello <strong>World</strong></p>',
                        'value' => 'Hello World',
                    ],
                ],
                'category' => ['php', 'indieweb'],
                'url' => ['https://example.com/posts/1'],
            ],
        ];

        // Validate
        $validation = Micropub::validateEntry($entry);
        $this->assertTrue($validation['valid']);

        // Sanitize
        $sanitized = Micropub::sanitizeEntry($entry);

        // Parse scopes
        $scopes = Micropub::parseScopes('create update');

        // Check authorization
        $this->assertTrue(Micropub::hasScope($scopes, 'create'));

        // Validate token format
        $token = bin2hex(random_bytes(32));
        $this->assertTrue(Micropub::validateTokenFormat($token));
    }
}
