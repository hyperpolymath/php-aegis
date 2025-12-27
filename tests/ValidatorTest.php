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
use PhpAegis\Validator;

#[CoversClass(Validator::class)]
final class ValidatorTest extends TestCase
{
    // =========================================================================
    // Email Validation (OWASP A03 - Injection Prevention)
    // =========================================================================

    #[DataProvider('validEmailsProvider')]
    public function testValidEmails(string $email): void
    {
        self::assertTrue(Validator::email($email), "Expected '{$email}' to be valid");
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validEmailsProvider(): array
    {
        return [
            'simple' => ['user@example.com'],
            'with subdomain' => ['user@mail.example.com'],
            'with plus' => ['user+tag@example.com'],
            'with dots' => ['first.last@example.com'],
            'with numbers' => ['user123@example.com'],
            'short domain' => ['a@b.co'],
        ];
    }

    #[DataProvider('invalidEmailsProvider')]
    public function testInvalidEmails(string $email): void
    {
        self::assertFalse(Validator::email($email), "Expected '{$email}' to be invalid");
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidEmailsProvider(): array
    {
        return [
            'empty' => [''],
            'no at' => ['userexample.com'],
            'no domain' => ['user@'],
            'no local' => ['@example.com'],
            'spaces' => ['user @example.com'],
            'double at' => ['user@@example.com'],
            'xss attempt' => ['user<script>@example.com'],
            'sql injection' => ["user'; DROP TABLE--@example.com"],
        ];
    }

    // =========================================================================
    // URL Validation (OWASP A03, A10 - Injection, SSRF Prevention)
    // =========================================================================

    #[DataProvider('validUrlsProvider')]
    public function testValidUrls(string $url): void
    {
        self::assertTrue(Validator::url($url), "Expected '{$url}' to be valid");
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validUrlsProvider(): array
    {
        return [
            'http' => ['http://example.com'],
            'https' => ['https://example.com'],
            'with path' => ['https://example.com/path/to/resource'],
            'with query' => ['https://example.com?query=value'],
            'with port' => ['https://example.com:8080'],
            'with fragment' => ['https://example.com#section'],
            'ip address' => ['http://192.168.1.1'],
            'localhost' => ['http://localhost'],
        ];
    }

    #[DataProvider('invalidUrlsProvider')]
    public function testInvalidUrls(string $url): void
    {
        self::assertFalse(Validator::url($url), "Expected '{$url}' to be invalid");
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidUrlsProvider(): array
    {
        return [
            'empty' => [''],
            'no scheme' => ['example.com'],
            'javascript' => ['javascript:alert(1)'],
            'data uri' => ['data:text/html,<script>'],
            'file scheme' => ['file:///etc/passwd'],
            'malformed' => ['http://'],
        ];
    }

    // =========================================================================
    // HTTPS URL Validation (OWASP A02 - Cryptographic Failures)
    // =========================================================================

    public function testHttpsUrlValid(): void
    {
        self::assertTrue(Validator::httpsUrl('https://example.com'));
        self::assertTrue(Validator::httpsUrl('https://example.com/path'));
        self::assertTrue(Validator::httpsUrl('https://sub.example.com:8443'));
    }

    public function testHttpsUrlRejectsHttp(): void
    {
        self::assertFalse(Validator::httpsUrl('http://example.com'));
        self::assertFalse(Validator::httpsUrl('http://localhost'));
    }

    public function testHttpsUrlRejectsInvalid(): void
    {
        self::assertFalse(Validator::httpsUrl(''));
        self::assertFalse(Validator::httpsUrl('ftp://example.com'));
        self::assertFalse(Validator::httpsUrl('javascript:alert(1)'));
    }

    // =========================================================================
    // IP Address Validation (OWASP A10 - SSRF Prevention)
    // =========================================================================

    public function testValidIpv4(): void
    {
        self::assertTrue(Validator::ipv4('192.168.1.1'));
        self::assertTrue(Validator::ipv4('10.0.0.1'));
        self::assertTrue(Validator::ipv4('8.8.8.8'));
        self::assertTrue(Validator::ipv4('0.0.0.0'));
        self::assertTrue(Validator::ipv4('255.255.255.255'));
    }

    public function testInvalidIpv4(): void
    {
        self::assertFalse(Validator::ipv4(''));
        self::assertFalse(Validator::ipv4('256.1.1.1'));
        self::assertFalse(Validator::ipv4('1.2.3'));
        self::assertFalse(Validator::ipv4('1.2.3.4.5'));
        self::assertFalse(Validator::ipv4('::1'));
        self::assertFalse(Validator::ipv4('not-an-ip'));
    }

    public function testValidIpv6(): void
    {
        self::assertTrue(Validator::ipv6('::1'));
        self::assertTrue(Validator::ipv6('2001:db8::1'));
        self::assertTrue(Validator::ipv6('fe80::1'));
        self::assertTrue(Validator::ipv6('::ffff:192.168.1.1'));
    }

    public function testInvalidIpv6(): void
    {
        self::assertFalse(Validator::ipv6(''));
        self::assertFalse(Validator::ipv6('192.168.1.1'));
        self::assertFalse(Validator::ipv6('not-an-ip'));
        self::assertFalse(Validator::ipv6('::gggg'));
    }

    public function testIpAcceptsBoth(): void
    {
        self::assertTrue(Validator::ip('192.168.1.1'));
        self::assertTrue(Validator::ip('::1'));
        self::assertFalse(Validator::ip('not-an-ip'));
    }

    // =========================================================================
    // UUID Validation (OWASP A03 - Injection Prevention)
    // =========================================================================

    public function testValidUuids(): void
    {
        self::assertTrue(Validator::uuid('550e8400-e29b-41d4-a716-446655440000'));
        self::assertTrue(Validator::uuid('6ba7b810-9dad-11d1-80b4-00c04fd430c8'));
        self::assertTrue(Validator::uuid('f47ac10b-58cc-4372-a567-0e02b2c3d479'));
        // Case insensitive
        self::assertTrue(Validator::uuid('550E8400-E29B-41D4-A716-446655440000'));
    }

    public function testInvalidUuids(): void
    {
        self::assertFalse(Validator::uuid(''));
        self::assertFalse(Validator::uuid('not-a-uuid'));
        self::assertFalse(Validator::uuid('550e8400-e29b-41d4-a716')); // Too short
        self::assertFalse(Validator::uuid('550e8400e29b41d4a716446655440000')); // No dashes
        self::assertFalse(Validator::uuid('550e8400-e29b-61d4-a716-446655440000')); // Invalid version
        self::assertFalse(Validator::uuid("550e8400-e29b-41d4-a716-44665544000\x00")); // Null byte
    }

    // =========================================================================
    // Slug Validation (OWASP A03 - Injection Prevention)
    // =========================================================================

    public function testValidSlugs(): void
    {
        self::assertTrue(Validator::slug('hello-world'));
        self::assertTrue(Validator::slug('my-page'));
        self::assertTrue(Validator::slug('page123'));
        self::assertTrue(Validator::slug('a'));
        self::assertTrue(Validator::slug('123'));
    }

    public function testInvalidSlugs(): void
    {
        self::assertFalse(Validator::slug(''));
        self::assertFalse(Validator::slug('Hello-World')); // Uppercase
        self::assertFalse(Validator::slug('-hello')); // Leading dash
        self::assertFalse(Validator::slug('hello-')); // Trailing dash
        self::assertFalse(Validator::slug('hello--world')); // Double dash
        self::assertFalse(Validator::slug('hello world')); // Space
        self::assertFalse(Validator::slug('hello_world')); // Underscore
        self::assertFalse(Validator::slug('../etc/passwd')); // Path traversal
    }

    // =========================================================================
    // Null Byte Validation (OWASP A03 - Path Traversal Prevention)
    // =========================================================================

    public function testNoNullBytes(): void
    {
        self::assertTrue(Validator::noNullBytes('normal string'));
        self::assertTrue(Validator::noNullBytes(''));
        self::assertTrue(Validator::noNullBytes('path/to/file.txt'));
    }

    public function testDetectsNullBytes(): void
    {
        self::assertFalse(Validator::noNullBytes("file.php\x00.jpg"));
        self::assertFalse(Validator::noNullBytes("\x00hidden"));
        self::assertFalse(Validator::noNullBytes("evil\x00payload"));
    }

    // =========================================================================
    // Safe Filename Validation (OWASP A03 - Path Traversal Prevention)
    // =========================================================================

    public function testSafeFilenames(): void
    {
        self::assertTrue(Validator::safeFilename('document.pdf'));
        self::assertTrue(Validator::safeFilename('image.jpg'));
        self::assertTrue(Validator::safeFilename('my-file_123.txt'));
        self::assertTrue(Validator::safeFilename('UPPERCASE.PDF'));
    }

    #[DataProvider('unsafeFilenamesProvider')]
    public function testUnsafeFilenames(string $filename, string $reason): void
    {
        self::assertFalse(
            Validator::safeFilename($filename),
            "Expected '{$filename}' to be unsafe: {$reason}"
        );
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function unsafeFilenamesProvider(): array
    {
        return [
            'path traversal unix' => ['../etc/passwd', 'path traversal'],
            'path traversal windows' => ['..\\windows\\system32', 'path traversal'],
            'absolute unix' => ['/etc/passwd', 'absolute path'],
            'absolute windows' => ['C:\\Windows', 'absolute path'],
            'null byte' => ["file.php\x00.jpg", 'null byte injection'],
            'hidden file' => ['.htaccess', 'hidden file'],
            'dot' => ['.', 'current directory'],
            'dotdot' => ['..', 'parent directory'],
            'empty' => ['', 'empty not allowed - but this might pass safeFilename'],
        ];
    }

    // =========================================================================
    // JSON Validation (OWASP A03 - Injection Prevention)
    // =========================================================================

    public function testValidJson(): void
    {
        self::assertTrue(Validator::json('{}'));
        self::assertTrue(Validator::json('[]'));
        self::assertTrue(Validator::json('{"key": "value"}'));
        self::assertTrue(Validator::json('[1, 2, 3]'));
        self::assertTrue(Validator::json('"string"'));
        self::assertTrue(Validator::json('123'));
        self::assertTrue(Validator::json('true'));
        self::assertTrue(Validator::json('null'));
    }

    public function testInvalidJson(): void
    {
        self::assertFalse(Validator::json(''));
        self::assertFalse(Validator::json('{invalid}'));
        self::assertFalse(Validator::json("{'single': 'quotes'}"));
        self::assertFalse(Validator::json('{key: "no quotes"}'));
        self::assertFalse(Validator::json('[1, 2, 3,]')); // Trailing comma
    }

    // =========================================================================
    // Integer Validation (OWASP A03 - Injection Prevention)
    // =========================================================================

    public function testValidIntegers(): void
    {
        self::assertTrue(Validator::int('0'));
        self::assertTrue(Validator::int('123'));
        self::assertTrue(Validator::int('-456'));
        self::assertTrue(Validator::int('999999999'));
    }

    public function testInvalidIntegers(): void
    {
        self::assertFalse(Validator::int(''));
        self::assertFalse(Validator::int('12.34'));
        self::assertFalse(Validator::int('abc'));
        self::assertFalse(Validator::int('12abc'));
        self::assertFalse(Validator::int('1.0'));
    }

    public function testIntegerWithRange(): void
    {
        self::assertTrue(Validator::int('5', 1, 10));
        self::assertTrue(Validator::int('1', 1, 10));
        self::assertTrue(Validator::int('10', 1, 10));

        self::assertFalse(Validator::int('0', 1, 10));
        self::assertFalse(Validator::int('11', 1, 10));
        self::assertFalse(Validator::int('-1', 0, 100));
    }

    public function testIntegerWithMinOnly(): void
    {
        self::assertTrue(Validator::int('100', 0));
        self::assertTrue(Validator::int('0', 0));
        self::assertFalse(Validator::int('-1', 0));
    }

    public function testIntegerWithMaxOnly(): void
    {
        self::assertTrue(Validator::int('50', null, 100));
        self::assertTrue(Validator::int('100', null, 100));
        self::assertFalse(Validator::int('101', null, 100));
    }

    // =========================================================================
    // Domain Validation (OWASP A10 - SSRF Prevention)
    // =========================================================================

    public function testValidDomains(): void
    {
        self::assertTrue(Validator::domain('example.com'));
        self::assertTrue(Validator::domain('sub.example.com'));
        self::assertTrue(Validator::domain('my-site.co.uk'));
        self::assertTrue(Validator::domain('a.io'));
    }

    public function testInvalidDomains(): void
    {
        self::assertFalse(Validator::domain(''));
        self::assertFalse(Validator::domain('-example.com')); // Leading hyphen
        self::assertFalse(Validator::domain('example-.com')); // Trailing hyphen
        self::assertFalse(Validator::domain('example')); // No TLD
        self::assertFalse(Validator::domain('.com')); // No domain
        self::assertFalse(Validator::domain('exam ple.com')); // Space
        self::assertFalse(Validator::domain('example..com')); // Double dot
        self::assertFalse(Validator::domain(str_repeat('a', 254) . '.com')); // Too long
    }

    // =========================================================================
    // Hostname Validation (OWASP A10 - SSRF Prevention)
    // =========================================================================

    public function testValidHostnames(): void
    {
        // Domains
        self::assertTrue(Validator::hostname('example.com'));
        // IPv4
        self::assertTrue(Validator::hostname('192.168.1.1'));
        // IPv6
        self::assertTrue(Validator::hostname('::1'));
    }

    public function testInvalidHostnames(): void
    {
        self::assertFalse(Validator::hostname(''));
        self::assertFalse(Validator::hostname('not a host'));
    }

    // =========================================================================
    // Printable Validation (OWASP A03 - Injection Prevention)
    // =========================================================================

    public function testPrintableStrings(): void
    {
        self::assertTrue(Validator::printable('Hello World!'));
        self::assertTrue(Validator::printable('Special chars: @#$%^&*()'));
        self::assertTrue(Validator::printable(''));
        self::assertTrue(Validator::printable(' ')); // Space is printable
    }

    public function testNonPrintableStrings(): void
    {
        self::assertFalse(Validator::printable("Hello\x00World")); // Null byte
        self::assertFalse(Validator::printable("Hello\nWorld")); // Newline
        self::assertFalse(Validator::printable("Hello\tWorld")); // Tab
        self::assertFalse(Validator::printable("\x1B[31mRed\x1B[0m")); // ANSI escape
        self::assertFalse(Validator::printable("Hello\x7FWorld")); // DEL character
    }

    // =========================================================================
    // Semver Validation
    // =========================================================================

    public function testValidSemver(): void
    {
        self::assertTrue(Validator::semver('1.0.0'));
        self::assertTrue(Validator::semver('0.0.1'));
        self::assertTrue(Validator::semver('10.20.30'));
        self::assertTrue(Validator::semver('1.0.0-alpha'));
        self::assertTrue(Validator::semver('1.0.0-alpha.1'));
        self::assertTrue(Validator::semver('1.0.0+build'));
        self::assertTrue(Validator::semver('1.0.0-beta+build.123'));
    }

    public function testInvalidSemver(): void
    {
        self::assertFalse(Validator::semver(''));
        self::assertFalse(Validator::semver('1.0'));
        self::assertFalse(Validator::semver('v1.0.0')); // No 'v' prefix
        self::assertFalse(Validator::semver('1.0.0.0'));
        self::assertFalse(Validator::semver('01.0.0')); // Leading zero
    }

    // =========================================================================
    // ISO 8601 Date Validation
    // =========================================================================

    public function testValidIso8601(): void
    {
        self::assertTrue(Validator::iso8601('2024-01-15'));
        self::assertTrue(Validator::iso8601('2024-01-15T10:30:00'));
        self::assertTrue(Validator::iso8601('2024-01-15T10:30:00Z'));
        self::assertTrue(Validator::iso8601('2024-01-15T10:30:00+00:00'));
    }

    public function testInvalidIso8601(): void
    {
        self::assertFalse(Validator::iso8601(''));
        self::assertFalse(Validator::iso8601('2024/01/15'));
        self::assertFalse(Validator::iso8601('01-15-2024'));
        self::assertFalse(Validator::iso8601('not a date'));
        self::assertFalse(Validator::iso8601('2024-13-01')); // Invalid month
        self::assertFalse(Validator::iso8601('2024-01-32')); // Invalid day
    }

    // =========================================================================
    // Hex Color Validation
    // =========================================================================

    public function testValidHexColors(): void
    {
        self::assertTrue(Validator::hexColor('#fff'));
        self::assertTrue(Validator::hexColor('#FFF'));
        self::assertTrue(Validator::hexColor('#ffffff'));
        self::assertTrue(Validator::hexColor('#FFFFFF'));
        self::assertTrue(Validator::hexColor('#000'));
        self::assertTrue(Validator::hexColor('#123456'));
    }

    public function testInvalidHexColors(): void
    {
        self::assertFalse(Validator::hexColor(''));
        self::assertFalse(Validator::hexColor('fff')); // Missing #
        self::assertFalse(Validator::hexColor('#ff')); // Too short
        self::assertFalse(Validator::hexColor('#ffff')); // Wrong length
        self::assertFalse(Validator::hexColor('#gggggg')); // Invalid chars
        self::assertFalse(Validator::hexColor('red')); // Named color
    }
}
