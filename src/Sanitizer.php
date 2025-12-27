<?php

/**
 * SPDX-License-Identifier: MIT OR AGPL-3.0-or-later
 * SPDX-FileCopyrightText: 2024-2025 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis;

/**
 * Output sanitization utilities.
 *
 * All methods are static for convenience - no instance state is needed.
 * Use the appropriate method for your output context to prevent injection attacks.
 */
final class Sanitizer
{
    /**
     * Escape for HTML content context (prevents XSS).
     */
    public static function html(string $input): string
    {
        return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * Escape for HTML attribute context.
     */
    public static function attr(string $input): string
    {
        return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * Strip all HTML/PHP tags from input.
     */
    public static function stripTags(string $input): string
    {
        return strip_tags($input);
    }

    /**
     * Escape for JavaScript string context.
     *
     * Safe for use within JS string literals (single or double quoted).
     */
    public static function js(string $input): string
    {
        return json_encode($input, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE) ?: '""';
    }

    /**
     * Escape for CSS string context.
     */
    public static function css(string $input): string
    {
        // Remove any characters that could break out of CSS context
        return preg_replace('/[^a-zA-Z0-9\s\-_]/', '', $input) ?? '';
    }

    /**
     * Encode for URL parameter context.
     */
    public static function url(string $input): string
    {
        return rawurlencode($input);
    }

    /**
     * Safe JSON encoding with security flags.
     */
    public static function json(mixed $input): string
    {
        $result = json_encode(
            $input,
            JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_THROW_ON_ERROR
        );
        return $result !== false ? $result : 'null';
    }

    /**
     * Remove null bytes from input (prevents path traversal in some contexts).
     */
    public static function removeNullBytes(string $input): string
    {
        return str_replace("\0", '', $input);
    }

    /**
     * Sanitize filename (remove path components and dangerous characters).
     */
    public static function filename(string $input): string
    {
        // Remove null bytes
        $input = self::removeNullBytes($input);

        // Get only the filename part (remove any path)
        $input = basename($input);

        // Remove potentially dangerous characters
        $input = preg_replace('/[^a-zA-Z0-9._-]/', '_', $input) ?? '';

        // Prevent hidden files
        $input = ltrim($input, '.');

        return $input;
    }
}
