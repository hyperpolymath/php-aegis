<?php

/**
 * SPDX-License-Identifier: MIT OR AGPL-3.0-or-later
 * SPDX-FileCopyrightText: 2024-2025 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpAegis\TurtleEscaper;

/**
 * Tests for RDF Turtle escaping utilities.
 *
 * These tests verify W3C Turtle specification compliance and
 * prevent injection attacks in semantic web applications (OWASP A03).
 *
 * @see https://www.w3.org/TR/turtle/#sec-escapes
 */
#[CoversClass(TurtleEscaper::class)]
final class TurtleEscaperTest extends TestCase
{
    // =========================================================================
    // String Escaping (OWASP A03 - RDF Injection Prevention)
    // =========================================================================

    public function testStringEscapesBackslash(): void
    {
        self::assertSame('\\\\', TurtleEscaper::string('\\'));
        self::assertSame('path\\\\to\\\\file', TurtleEscaper::string('path\\to\\file'));
    }

    public function testStringEscapesQuotes(): void
    {
        self::assertSame('\\"', TurtleEscaper::string('"'));
        self::assertSame("\\'", TurtleEscaper::string("'"));
        self::assertSame('He said \\"Hello\\"', TurtleEscaper::string('He said "Hello"'));
    }

    public function testStringEscapesControlCharacters(): void
    {
        self::assertSame('\\t', TurtleEscaper::string("\t"));
        self::assertSame('\\n', TurtleEscaper::string("\n"));
        self::assertSame('\\r', TurtleEscaper::string("\r"));
        self::assertSame('\\b', TurtleEscaper::string("\x08")); // Backspace
        self::assertSame('\\f', TurtleEscaper::string("\f"));
    }

    public function testStringEscapesOtherControlChars(): void
    {
        // Other control characters should be escaped with \uXXXX
        self::assertSame('\\u0000', TurtleEscaper::string("\x00")); // Null
        self::assertSame('\\u0001', TurtleEscaper::string("\x01")); // SOH
        self::assertSame('\\u007F', TurtleEscaper::string("\x7F")); // DEL
    }

    public function testStringPreservesNormalText(): void
    {
        self::assertSame('Hello World', TurtleEscaper::string('Hello World'));
        self::assertSame('The quick brown fox', TurtleEscaper::string('The quick brown fox'));
    }

    public function testStringPreservesUnicode(): void
    {
        self::assertSame('日本語', TurtleEscaper::string('日本語'));
        self::assertSame('émoji 🎉', TurtleEscaper::string('émoji 🎉'));
        self::assertSame('Ñoño', TurtleEscaper::string('Ñoño'));
    }

    public function testStringHandlesEmpty(): void
    {
        self::assertSame('', TurtleEscaper::string(''));
    }

    public function testStringComplexExample(): void
    {
        $input = "Line 1\nLine 2\twith\ttabs and \"quotes\"";
        $expected = 'Line 1\\nLine 2\\twith\\ttabs and \\"quotes\\"';
        self::assertSame($expected, TurtleEscaper::string($input));
    }

    #[DataProvider('turtleInjectionVectorsProvider')]
    public function testStringPreventsInjection(string $attack, string $description): void
    {
        $escaped = TurtleEscaper::string($attack);

        // The escaped version should not contain unescaped dangerous characters
        // that could break out of a Turtle string literal
        self::assertStringNotContainsString("\n", $escaped, "Unescaped newline in: {$description}");
        self::assertStringNotContainsString("\r", $escaped, "Unescaped CR in: {$description}");

        // Check quotes are escaped
        if (str_contains($attack, '"')) {
            self::assertStringContainsString('\\"', $escaped, "Quote not escaped in: {$description}");
        }
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function turtleInjectionVectorsProvider(): array
    {
        return [
            'newline injection' => ["value\"\n<evil> <pred> <obj> .", 'newline triple injection'],
            'quote breakout' => ['" . <evil> <pred> "', 'quote breakout attempt'],
            'backslash confusion' => ['\\" . <evil>', 'backslash escape confusion'],
            'null byte' => ["value\x00\"", 'null byte injection'],
            'multiline' => ["line1\nline2\nline3", 'multiline injection'],
        ];
    }

    // =========================================================================
    // IRI Escaping (OWASP A03 - IRI Injection Prevention)
    // =========================================================================

    public function testIriEscapesDangerousChars(): void
    {
        self::assertSame('https://example.com/%3Cscript%3E', TurtleEscaper::iri('https://example.com/<script>'));
        self::assertSame('https://example.com/%3E', TurtleEscaper::iri('https://example.com/>'));
        self::assertSame('https://example.com/%22', TurtleEscaper::iri('https://example.com/"'));
    }

    public function testIriEscapesSpaces(): void
    {
        self::assertSame('https://example.com/path%20with%20spaces', TurtleEscaper::iri('https://example.com/path with spaces'));
    }

    public function testIriEscapesBraces(): void
    {
        self::assertSame('https://example.com/%7Bvalue%7D', TurtleEscaper::iri('https://example.com/{value}'));
    }

    public function testIriEscapesControlChars(): void
    {
        self::assertSame('https://example.com/%00', TurtleEscaper::iri("https://example.com/\x00"));
        self::assertSame('https://example.com/%0A', TurtleEscaper::iri("https://example.com/\n"));
    }

    public function testIriPreservesValidUrl(): void
    {
        $url = 'https://example.com/path?query=value#fragment';
        self::assertSame($url, TurtleEscaper::iri($url));
    }

    public function testIriRejectsInvalidWithDangerousChars(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid IRI');

        // Not a valid URL and contains dangerous chars
        TurtleEscaper::iri('not-a-url<>');
    }

    public function testIriAcceptsRelativePaths(): void
    {
        // Relative paths without dangerous chars should work
        self::assertSame('/path/to/resource', TurtleEscaper::iri('/path/to/resource'));
        self::assertSame('#fragment', TurtleEscaper::iri('#fragment'));
    }

    // =========================================================================
    // Language Tag Validation
    // =========================================================================

    public function testLanguageTagValid(): void
    {
        self::assertSame('en', TurtleEscaper::languageTag('en'));
        self::assertSame('en-us', TurtleEscaper::languageTag('en-US'));
        self::assertSame('de-de', TurtleEscaper::languageTag('de-DE'));
        self::assertSame('zh-hans', TurtleEscaper::languageTag('zh-Hans'));
        self::assertSame('pt-br', TurtleEscaper::languageTag('pt-BR'));
    }

    public function testLanguageTagNormalizesToLowercase(): void
    {
        self::assertSame('en-us', TurtleEscaper::languageTag('EN-US'));
        self::assertSame('de', TurtleEscaper::languageTag('DE'));
    }

    public function testLanguageTagRejectsInvalid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid BCP 47 language tag');

        TurtleEscaper::languageTag('not-a-valid-tag-12345');
    }

    #[DataProvider('invalidLanguageTagsProvider')]
    public function testLanguageTagRejectsVariousInvalid(string $tag): void
    {
        $this->expectException(InvalidArgumentException::class);

        TurtleEscaper::languageTag($tag);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidLanguageTagsProvider(): array
    {
        return [
            'empty' => [''],
            'single char' => ['e'],
            'numbers only' => ['123'],
            'special chars' => ['en<script>'],
            'spaces' => ['en US'],
            'too long segment' => ['en-abcdefghij'],
        ];
    }

    // =========================================================================
    // Literal Building
    // =========================================================================

    public function testLiteralPlain(): void
    {
        self::assertSame('"Hello World"', TurtleEscaper::literal('Hello World'));
    }

    public function testLiteralWithEscaping(): void
    {
        self::assertSame('"Hello \\"World\\""', TurtleEscaper::literal('Hello "World"'));
        self::assertSame('"Line 1\\nLine 2"', TurtleEscaper::literal("Line 1\nLine 2"));
    }

    public function testLiteralWithLanguageTag(): void
    {
        self::assertSame('"Hello"@en', TurtleEscaper::literal('Hello', 'en'));
        self::assertSame('"Bonjour"@fr', TurtleEscaper::literal('Bonjour', 'fr'));
        self::assertSame('"Hallo"@de-de', TurtleEscaper::literal('Hallo', 'de-DE'));
    }

    public function testLiteralWithXsdDatatype(): void
    {
        $xsdString = 'http://www.w3.org/2001/XMLSchema#string';
        self::assertSame('"test"^^xsd:string', TurtleEscaper::literal('test', null, $xsdString));

        $xsdInteger = 'http://www.w3.org/2001/XMLSchema#integer';
        self::assertSame('"42"^^xsd:integer', TurtleEscaper::literal('42', null, $xsdInteger));

        $xsdDate = 'http://www.w3.org/2001/XMLSchema#date';
        self::assertSame('"2024-01-15"^^xsd:date', TurtleEscaper::literal('2024-01-15', null, $xsdDate));
    }

    public function testLiteralWithCustomDatatype(): void
    {
        $customType = 'https://example.org/types#custom';
        self::assertSame('"value"^^<https://example.org/types#custom>', TurtleEscaper::literal('value', null, $customType));
    }

    public function testLiteralLanguageHasPrecedence(): void
    {
        // When both language and datatype are provided, language wins
        $result = TurtleEscaper::literal('Hello', 'en', 'http://www.w3.org/2001/XMLSchema#string');
        self::assertSame('"Hello"@en', $result);
    }

    // =========================================================================
    // Triple Building
    // =========================================================================

    public function testTripleBasic(): void
    {
        $result = TurtleEscaper::triple(
            'https://example.org/subject',
            'https://example.org/predicate',
            'Object Value'
        );

        self::assertSame(
            '<https://example.org/subject> <https://example.org/predicate> "Object Value" .',
            $result
        );
    }

    public function testTripleWithLanguage(): void
    {
        $result = TurtleEscaper::triple(
            'https://example.org/subject',
            'http://www.w3.org/2000/01/rdf-schema#label',
            'A Label',
            'en'
        );

        self::assertSame(
            '<https://example.org/subject> <http://www.w3.org/2000/01/rdf-schema#label> "A Label"@en .',
            $result
        );
    }

    public function testTripleEscapesAll(): void
    {
        $result = TurtleEscaper::triple(
            'https://example.org/subject',
            'https://example.org/predicate',
            'Value with "quotes" and newlines' . "\n"
        );

        self::assertStringContainsString('\\"quotes\\"', $result);
        self::assertStringContainsString('\\n', $result);
    }

    // =========================================================================
    // Triple IRI Building
    // =========================================================================

    public function testTripleIri(): void
    {
        $result = TurtleEscaper::tripleIri(
            'https://example.org/subject',
            'http://www.w3.org/1999/02/22-rdf-syntax-ns#type',
            'https://example.org/Class'
        );

        self::assertSame(
            '<https://example.org/subject> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/Class> .',
            $result
        );
    }

    public function testTripleIriEscapesAll(): void
    {
        // All three IRIs should be properly escaped
        $result = TurtleEscaper::tripleIri(
            'https://example.org/subject with spaces',
            'https://example.org/predicate',
            'https://example.org/object'
        );

        self::assertStringContainsString('%20', $result);
    }

    // =========================================================================
    // Edge Cases and Security
    // =========================================================================

    public function testComplexInjectionPrevention(): void
    {
        // Attempt to inject a malicious triple via literal value
        $maliciousValue = "\" .\n<https://evil.org> <https://evil.org/pred> <https://evil.org/obj>";

        $result = TurtleEscaper::literal($maliciousValue);

        // The result should be a single escaped string, not multiple triples
        self::assertStringStartsWith('"', $result);
        self::assertStringEndsWith('"', $result);

        // Count quotes - should only have opening and closing
        // All internal quotes should be escaped
        self::assertStringContainsString('\\"', $result);
        self::assertStringContainsString('\\n', $result);
    }

    public function testIriBreakoutPrevention(): void
    {
        // Attempt to break out of IRI context
        $maliciousIri = 'https://example.org> <https://evil.org';

        $escaped = TurtleEscaper::iri($maliciousIri);

        // > should be percent-encoded
        self::assertStringContainsString('%3E', $escaped);
        self::assertStringContainsString('%3C', $escaped);
    }

    public function testLiteralWithAllSpecialChars(): void
    {
        $input = "\t\b\n\r\f\\\"'";
        $result = TurtleEscaper::literal($input);

        self::assertSame('"\\t\\b\\n\\r\\f\\\\\\"\\\'\"', $result);
    }

    public function testEmptyValues(): void
    {
        self::assertSame('""', TurtleEscaper::literal(''));
        self::assertSame('""@en', TurtleEscaper::literal('', 'en'));
    }

    public function testVeryLongStrings(): void
    {
        $longString = str_repeat('a', 100000);
        $result = TurtleEscaper::string($longString);

        // Should not truncate
        self::assertSame($longString, $result);
    }
}
