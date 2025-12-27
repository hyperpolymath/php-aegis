<?php

/**
 * SPDX-License-Identifier: MIT OR AGPL-3.0-or-later
 * SPDX-FileCopyrightText: 2024-2025 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpAegis\Sanitizer;

#[CoversClass(Sanitizer::class)]
final class SanitizerTest extends TestCase
{
    // =========================================================================
    // HTML Escaping (OWASP A03 - XSS Prevention)
    // =========================================================================

    public function testHtmlEscapesBasicChars(): void
    {
        self::assertSame('&lt;script&gt;', Sanitizer::html('<script>'));
        self::assertSame('&amp;', Sanitizer::html('&'));
        self::assertSame('&quot;', Sanitizer::html('"'));
        self::assertSame('&#039;', Sanitizer::html("'"));
        self::assertSame('&lt;', Sanitizer::html('<'));
        self::assertSame('&gt;', Sanitizer::html('>'));
    }

    #[DataProvider('xssVectorsProvider')]
    public function testHtmlPreventsXss(string $attack, string $context): void
    {
        $sanitized = Sanitizer::html($attack);

        // The sanitized output should not contain unescaped dangerous characters
        self::assertStringNotContainsString('<script', $sanitized);
        self::assertStringNotContainsString('javascript:', $sanitized);
        self::assertStringNotContainsString('onerror=', $sanitized);

        // Verify the original attack pattern is neutralized
        self::assertNotSame($attack, $sanitized, "XSS vector should be modified: {$context}");
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function xssVectorsProvider(): array
    {
        return [
            'basic script' => ['<script>alert("XSS")</script>', 'script tag'],
            'img onerror' => ['<img src=x onerror=alert(1)>', 'event handler'],
            'svg onload' => ['<svg onload=alert(1)>', 'SVG event'],
            'body onload' => ['<body onload=alert(1)>', 'body event'],
            'iframe' => ['<iframe src="javascript:alert(1)">', 'iframe injection'],
            'javascript url' => ['<a href="javascript:alert(1)">click</a>', 'javascript URL'],
            'data url' => ['<a href="data:text/html,<script>alert(1)</script>">x</a>', 'data URL'],
            'encoded' => ['<script>alert(String.fromCharCode(88,83,83))</script>', 'encoded XSS'],
            'nested tags' => ['<<script>script>alert(1)<</script>/script>', 'nested bypass'],
            'null byte' => ["<scr\x00ipt>alert(1)</script>", 'null byte bypass'],
        ];
    }

    public function testHtmlPreservesUtf8(): void
    {
        self::assertSame('日本語', Sanitizer::html('日本語'));
        self::assertSame('émoji 🎉', Sanitizer::html('émoji 🎉'));
        self::assertSame('Ñoño', Sanitizer::html('Ñoño'));
    }

    public function testHtmlHandlesEmptyString(): void
    {
        self::assertSame('', Sanitizer::html(''));
    }

    // =========================================================================
    // HTML Attribute Escaping (OWASP A03 - XSS Prevention)
    // =========================================================================

    public function testAttrEscapesQuotes(): void
    {
        self::assertSame('&quot;', Sanitizer::attr('"'));
        self::assertSame('&#039;', Sanitizer::attr("'"));
    }

    public function testAttrPreventsAttributeBreakout(): void
    {
        // Attempt to break out of attribute
        $attack = '" onclick="alert(1)"';
        $sanitized = Sanitizer::attr($attack);

        self::assertStringNotContainsString('onclick', $sanitized);
        self::assertStringStartsWith('&quot;', $sanitized);
    }

    #[DataProvider('attrXssVectorsProvider')]
    public function testAttrPreventsXss(string $attack): void
    {
        $sanitized = Sanitizer::attr($attack);

        // Should not contain unquoted dangerous patterns
        self::assertStringNotContainsString('" ', $sanitized);
        self::assertStringNotContainsString("' ", $sanitized);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function attrXssVectorsProvider(): array
    {
        return [
            'double quote breakout' => ['" onclick="alert(1)'],
            'single quote breakout' => ["' onclick='alert(1)"],
            'event handler' => ['x" onmouseover="alert(1)'],
            'javascript in attr' => ['javascript:alert(1)'],
        ];
    }

    // =========================================================================
    // Strip Tags (OWASP A03 - XSS Prevention)
    // =========================================================================

    public function testStripTagsRemovesHtml(): void
    {
        self::assertSame('Hello World', Sanitizer::stripTags('<p>Hello World</p>'));
        self::assertSame('alert(1)', Sanitizer::stripTags('<script>alert(1)</script>'));
        self::assertSame('Click here', Sanitizer::stripTags('<a href="http://evil.com">Click here</a>'));
    }

    public function testStripTagsRemovesNestedTags(): void
    {
        self::assertSame('content', Sanitizer::stripTags('<div><p><span>content</span></p></div>'));
    }

    public function testStripTagsPreservesText(): void
    {
        self::assertSame('Plain text', Sanitizer::stripTags('Plain text'));
        self::assertSame('', Sanitizer::stripTags(''));
    }

    // =========================================================================
    // JavaScript Escaping (OWASP A03 - XSS Prevention)
    // =========================================================================

    public function testJsEscapesForJavaScript(): void
    {
        // Result is JSON-encoded string with extra escaping
        $result = Sanitizer::js('Hello "World"');
        self::assertSame('"Hello \u0022World\u0022"', $result);
    }

    public function testJsEscapesScriptTags(): void
    {
        $result = Sanitizer::js('</script><script>alert(1)');

        // Should escape < and > to prevent script breakout
        self::assertStringNotContainsString('</script>', $result);
        self::assertStringContainsString('\u003C', $result);
    }

    public function testJsEscapesSingleQuotes(): void
    {
        $result = Sanitizer::js("It's a test");
        self::assertStringContainsString('\u0027', $result);
    }

    public function testJsEscapesAmpersand(): void
    {
        $result = Sanitizer::js('foo & bar');
        self::assertStringContainsString('\u0026', $result);
    }

    public function testJsHandlesUnicode(): void
    {
        $result = Sanitizer::js('日本語');
        // Unicode should be preserved (JSON_UNESCAPED_UNICODE)
        self::assertStringContainsString('日本語', $result);
    }

    public function testJsReturnsEmptyStringForEmpty(): void
    {
        self::assertSame('""', Sanitizer::js(''));
    }

    // =========================================================================
    // CSS Escaping (OWASP A03 - XSS Prevention)
    // =========================================================================

    public function testCssRemovesDangerousChars(): void
    {
        // Only alphanumeric, spaces, hyphens, underscores allowed
        self::assertSame('red', Sanitizer::css('red'));
        self::assertSame('10px', Sanitizer::css('10px'));
        self::assertSame('my-class', Sanitizer::css('my-class'));
        self::assertSame('my_class', Sanitizer::css('my_class'));
    }

    public function testCssRemovesExpressions(): void
    {
        // CSS expression attacks
        self::assertSame('expressionalert1', Sanitizer::css('expression(alert(1))'));
        self::assertSame('urljavascriptalert1', Sanitizer::css('url(javascript:alert(1))'));
    }

    public function testCssRemovesSpecialChars(): void
    {
        self::assertSame('', Sanitizer::css('{}'));
        self::assertSame('', Sanitizer::css('/**/'));
        self::assertSame('', Sanitizer::css('<>'));
        self::assertSame('', Sanitizer::css('";'));
    }

    public function testCssPreservesWhitespace(): void
    {
        self::assertSame('10 px', Sanitizer::css('10 px'));
    }

    // =========================================================================
    // URL Encoding (OWASP A03, A10 - Injection Prevention)
    // =========================================================================

    public function testUrlEncodesSpecialChars(): void
    {
        self::assertSame('hello%20world', Sanitizer::url('hello world'));
        self::assertSame('%3C%3E', Sanitizer::url('<>'));
        self::assertSame('%22', Sanitizer::url('"'));
        self::assertSame('%26', Sanitizer::url('&'));
    }

    public function testUrlEncodesSlashes(): void
    {
        self::assertSame('%2F', Sanitizer::url('/'));
        self::assertSame('..%2F..%2Fetc%2Fpasswd', Sanitizer::url('../../etc/passwd'));
    }

    public function testUrlPreservesAlphanumeric(): void
    {
        self::assertSame('abc123', Sanitizer::url('abc123'));
        self::assertSame('test-value', Sanitizer::url('test-value'));
    }

    public function testUrlHandlesUnicode(): void
    {
        // rawurlencode encodes Unicode to UTF-8 percent-encoded
        $result = Sanitizer::url('日本語');
        self::assertStringContainsString('%', $result);
    }

    // =========================================================================
    // JSON Encoding (OWASP A03 - Injection Prevention)
    // =========================================================================

    public function testJsonEncodesWithSecurityFlags(): void
    {
        $data = ['key' => '<script>alert(1)</script>'];
        $result = Sanitizer::json($data);

        // Should escape HTML entities
        self::assertStringNotContainsString('<', $result);
        self::assertStringNotContainsString('>', $result);
        self::assertStringContainsString('\u003C', $result);
    }

    public function testJsonEncodesQuotes(): void
    {
        $data = ['quote' => "It's \"quoted\""];
        $result = Sanitizer::json($data);

        self::assertStringContainsString('\u0027', $result); // Single quote
        self::assertStringContainsString('\u0022', $result); // Double quote
    }

    public function testJsonHandlesNestedStructures(): void
    {
        $data = [
            'level1' => [
                'level2' => [
                    'value' => '<xss>'
                ]
            ]
        ];
        $result = Sanitizer::json($data);

        self::assertJson($result);
        self::assertStringNotContainsString('<', $result);
    }

    public function testJsonHandlesEmptyArray(): void
    {
        self::assertSame('[]', Sanitizer::json([]));
    }

    public function testJsonHandlesNull(): void
    {
        self::assertSame('null', Sanitizer::json(null));
    }

    // =========================================================================
    // Null Byte Removal (OWASP A03 - Path Traversal Prevention)
    // =========================================================================

    public function testRemoveNullBytes(): void
    {
        self::assertSame('file.php.jpg', Sanitizer::removeNullBytes("file.php\x00.jpg"));
        self::assertSame('normal', Sanitizer::removeNullBytes('normal'));
        self::assertSame('', Sanitizer::removeNullBytes("\x00\x00\x00"));
    }

    public function testRemoveNullBytesMultiple(): void
    {
        self::assertSame('abc', Sanitizer::removeNullBytes("a\x00b\x00c"));
    }

    // =========================================================================
    // Filename Sanitization (OWASP A03 - Path Traversal Prevention)
    // =========================================================================

    public function testFilenameRemovesPathComponents(): void
    {
        self::assertSame('passwd', Sanitizer::filename('/etc/passwd'));
        self::assertSame('passwd', Sanitizer::filename('../../../etc/passwd'));
        self::assertSame('file.txt', Sanitizer::filename('C:\\Windows\\file.txt'));
    }

    public function testFilenameRemovesDangerousChars(): void
    {
        self::assertSame('file_name.txt', Sanitizer::filename('file<name>.txt'));
        self::assertSame('file_name.txt', Sanitizer::filename('file;name.txt'));
        self::assertSame('file_name.txt', Sanitizer::filename('file|name.txt'));
    }

    public function testFilenameRemovesNullBytes(): void
    {
        self::assertSame('file.txt', Sanitizer::filename("file.php\x00.txt"));
    }

    public function testFilenameRemovesHiddenPrefix(): void
    {
        self::assertSame('htaccess', Sanitizer::filename('.htaccess'));
        self::assertSame('gitignore', Sanitizer::filename('.gitignore'));
    }

    public function testFilenamePreservesValidChars(): void
    {
        self::assertSame('my-file_123.txt', Sanitizer::filename('my-file_123.txt'));
        self::assertSame('document.pdf', Sanitizer::filename('document.pdf'));
    }

    public function testFilenameHandlesSpaces(): void
    {
        // Spaces are converted to underscores
        self::assertSame('my_file.txt', Sanitizer::filename('my file.txt'));
    }

    // =========================================================================
    // Edge Cases and Security Boundary Tests
    // =========================================================================

    public function testAllMethodsHandleEmptyString(): void
    {
        self::assertSame('', Sanitizer::html(''));
        self::assertSame('', Sanitizer::attr(''));
        self::assertSame('', Sanitizer::stripTags(''));
        self::assertSame('""', Sanitizer::js(''));
        self::assertSame('', Sanitizer::css(''));
        self::assertSame('', Sanitizer::url(''));
        self::assertSame('', Sanitizer::removeNullBytes(''));
        self::assertSame('', Sanitizer::filename(''));
    }

    public function testAllMethodsHandleLongStrings(): void
    {
        $longString = str_repeat('a', 100000);

        // Should not throw or truncate unexpectedly
        self::assertSame($longString, Sanitizer::html($longString));
        self::assertSame($longString, Sanitizer::attr($longString));
        self::assertSame($longString, Sanitizer::stripTags($longString));
        self::assertSame($longString, Sanitizer::css($longString));
    }

    public function testHtmlDoubleEncodingPrevention(): void
    {
        // Double encoding: &amp; should become &amp;amp;
        $input = '&amp;';
        $result = Sanitizer::html($input);
        self::assertSame('&amp;amp;', $result);

        // This is correct behavior - we escape what we receive
        // If already escaped, it gets double-escaped (safe but verbose)
    }

    public function testMixedAttackVectors(): void
    {
        // Combined attack attempting multiple vectors
        $attack = '<script>alert("XSS")</script><img src=x onerror=alert(1)>';
        $sanitized = Sanitizer::html($attack);

        // All dangerous patterns should be escaped
        self::assertStringNotContainsString('<script>', $sanitized);
        self::assertStringNotContainsString('<img', $sanitized);
        self::assertStringNotContainsString('onerror', $sanitized);
    }
}
