<?php

/**
 * SPDX-License-Identifier: MIT OR AGPL-3.0-or-later
 * SPDX-FileCopyrightText: 2024-2025 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis;

/**
 * RDF Turtle escaping utilities.
 *
 * Provides W3C-compliant escaping for RDF Turtle format strings and IRIs.
 * This prevents injection attacks in semantic web applications.
 *
 * @see https://www.w3.org/TR/turtle/#sec-escapes
 */
final class TurtleEscaper
{
    /**
     * Escape a string for use in Turtle string literals.
     *
     * Handles all escape sequences defined in W3C Turtle specification:
     * \t \b \n \r \f \" \' \\ \uXXXX \UXXXXXXXX
     *
     * @param string $input The raw string to escape
     * @return string Safe for use in Turtle "..." or '...' literals
     */
    public static function string(string $input): string
    {
        $replacements = [
            '\\' => '\\\\',  // Backslash must be first
            '"'  => '\\"',   // Double quote
            "'"  => "\\'",   // Single quote
            "\t" => '\\t',   // Tab
            "\b" => '\\b',   // Backspace
            "\n" => '\\n',   // Newline
            "\r" => '\\r',   // Carriage return
            "\f" => '\\f',   // Form feed
        ];

        $escaped = str_replace(
            array_keys($replacements),
            array_values($replacements),
            $input
        );

        // Escape any other control characters using \uXXXX
        $escaped = preg_replace_callback(
            '/[\x00-\x08\x0B\x0E-\x1F\x7F]/',
            static fn(array $matches): string => sprintf('\\u%04X', ord($matches[0])),
            $escaped
        ) ?? $escaped;

        return $escaped;
    }

    /**
     * Escape and validate an IRI for use in Turtle <...> notation.
     *
     * @param string $uri The URI/IRI to escape
     * @return string Safe for use in Turtle <...> IRI references
     * @throws \InvalidArgumentException If the URI is malformed
     */
    public static function iri(string $uri): string
    {
        // Basic validation - must be a valid URL structure
        if (!filter_var($uri, FILTER_VALIDATE_URL)) {
            // Allow relative IRIs, but validate they don't contain dangerous characters
            if (preg_match('/[<>"{}|\\\\^`\x00-\x20]/', $uri)) {
                throw new \InvalidArgumentException('Invalid IRI: contains disallowed characters');
            }
        }

        // Characters that must be escaped in IRIs per RFC 3987
        // < > " { } | ^ ` \ and control characters
        $dangerous = [
            '<'  => '%3C',
            '>'  => '%3E',
            '"'  => '%22',
            '{'  => '%7B',
            '}'  => '%7D',
            '|'  => '%7C',
            '^'  => '%5E',
            '`'  => '%60',
            '\\' => '%5C',
            ' '  => '%20',
        ];

        $escaped = str_replace(
            array_keys($dangerous),
            array_values($dangerous),
            $uri
        );

        // Escape control characters
        $escaped = preg_replace_callback(
            '/[\x00-\x1F\x7F]/',
            static fn(array $matches): string => sprintf('%%%02X', ord($matches[0])),
            $escaped
        ) ?? $escaped;

        return $escaped;
    }

    /**
     * Escape a language tag for Turtle literals.
     *
     * @param string $tag BCP 47 language tag (e.g., "en", "en-US")
     * @return string Validated language tag
     * @throws \InvalidArgumentException If tag is invalid
     */
    public static function languageTag(string $tag): string
    {
        // BCP 47 language tag pattern (simplified)
        // Full spec: https://tools.ietf.org/html/bcp47
        if (!preg_match('/^[a-zA-Z]{2,3}(?:-[a-zA-Z0-9]{2,8})*$/', $tag)) {
            throw new \InvalidArgumentException('Invalid BCP 47 language tag');
        }

        return strtolower($tag);
    }

    /**
     * Build a complete Turtle literal with optional language tag or datatype.
     *
     * @param string $value The string value
     * @param string|null $language Optional language tag (e.g., "en")
     * @param string|null $datatype Optional datatype IRI
     * @return string Complete Turtle literal (e.g., "Hello"@en or "42"^^xsd:integer)
     */
    public static function literal(
        string $value,
        ?string $language = null,
        ?string $datatype = null
    ): string {
        $escaped = self::string($value);
        $literal = '"' . $escaped . '"';

        if ($language !== null) {
            $literal .= '@' . self::languageTag($language);
        } elseif ($datatype !== null) {
            // Common XSD prefixes can use shorthand
            $xsdPrefix = 'http://www.w3.org/2001/XMLSchema#';
            if (str_starts_with($datatype, $xsdPrefix)) {
                $localName = substr($datatype, strlen($xsdPrefix));
                if (preg_match('/^[a-zA-Z][a-zA-Z0-9]*$/', $localName)) {
                    $literal .= '^^xsd:' . $localName;
                } else {
                    $literal .= '^^<' . self::iri($datatype) . '>';
                }
            } else {
                $literal .= '^^<' . self::iri($datatype) . '>';
            }
        }

        return $literal;
    }

    /**
     * Create a safe Turtle triple.
     *
     * @param string $subject Subject IRI
     * @param string $predicate Predicate IRI
     * @param string $object Object (string value, will be escaped as literal)
     * @param string|null $language Optional language tag
     * @return string Complete Turtle triple ending with " ."
     */
    public static function triple(
        string $subject,
        string $predicate,
        string $object,
        ?string $language = null
    ): string {
        return sprintf(
            '<%s> <%s> %s .',
            self::iri($subject),
            self::iri($predicate),
            self::literal($object, $language)
        );
    }

    /**
     * Create a safe Turtle triple with IRI object.
     *
     * @param string $subject Subject IRI
     * @param string $predicate Predicate IRI
     * @param string $objectIri Object IRI
     * @return string Complete Turtle triple ending with " ."
     */
    public static function tripleIri(
        string $subject,
        string $predicate,
        string $objectIri
    ): string {
        return sprintf(
            '<%s> <%s> <%s> .',
            self::iri($subject),
            self::iri($predicate),
            self::iri($objectIri)
        );
    }
}
