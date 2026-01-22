<?php

/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\IndieWeb;

use PhpAegis\Validator;
use PhpAegis\Sanitizer;

/**
 * Micropub content validation and sanitization.
 *
 * Micropub is a W3C Recommendation for creating, updating, and deleting posts
 * on websites using simple HTTP requests. This class provides security utilities
 * for Micropub implementations.
 *
 * @link https://www.w3.org/TR/micropub/
 */
final class Micropub
{
    /**
     * Validate Micropub entry (microformats2 format).
     *
     * Checks required fields, validates URLs, and detects dangerous content.
     *
     * @param array<string, mixed> $entry Micropub entry data
     * @return array{valid: bool, errors: string[]}
     */
    public static function validateEntry(array $entry): array
    {
        $errors = [];

        // Check required fields per Micropub spec
        if (!isset($entry['type'])) {
            $errors[] = 'Missing required field: type';
        } elseif (!is_array($entry['type']) || empty($entry['type'])) {
            $errors[] = 'Field "type" must be a non-empty array';
        }

        if (!isset($entry['properties'])) {
            $errors[] = 'Missing required field: properties';
        } elseif (!is_array($entry['properties'])) {
            $errors[] = 'Field "properties" must be an array';
        }

        // If properties exist, validate them
        if (isset($entry['properties']) && is_array($entry['properties'])) {
            $errors = array_merge($errors, self::validateProperties($entry['properties']));
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors,
        ];
    }

    /**
     * Validate Micropub properties.
     *
     * @param array<string, mixed> $properties
     * @return string[]
     */
    private static function validateProperties(array $properties): array
    {
        $errors = [];

        // Validate content if present
        if (isset($properties['content'])) {
            if (!is_array($properties['content'])) {
                $errors[] = 'Property "content" must be an array';
            } else {
                foreach ($properties['content'] as $content) {
                    $contentErrors = self::validateContent($content);
                    $errors = array_merge($errors, $contentErrors);
                }
            }
        }

        // Validate URLs if present
        if (isset($properties['url'])) {
            if (!is_array($properties['url'])) {
                $errors[] = 'Property "url" must be an array';
            } else {
                foreach ($properties['url'] as $url) {
                    if (!is_string($url)) {
                        $errors[] = 'URL must be a string';
                        continue;
                    }

                    if (!Validator::httpsUrl($url)) {
                        $errors[] = "Invalid or non-HTTPS URL: $url";
                    }
                }
            }
        }

        // Validate photo/video URLs if present
        foreach (['photo', 'video', 'audio'] as $mediaType) {
            if (isset($properties[$mediaType])) {
                if (!is_array($properties[$mediaType])) {
                    $errors[] = "Property \"$mediaType\" must be an array";
                } else {
                    foreach ($properties[$mediaType] as $mediaUrl) {
                        if (is_string($mediaUrl) && !Validator::httpsUrl($mediaUrl)) {
                            $errors[] = "Invalid $mediaType URL: $mediaUrl";
                        }
                    }
                }
            }
        }

        // Validate syndication URLs
        if (isset($properties['syndication'])) {
            if (!is_array($properties['syndication'])) {
                $errors[] = 'Property "syndication" must be an array';
            } else {
                foreach ($properties['syndication'] as $syndicationUrl) {
                    if (is_string($syndicationUrl) && !Validator::url($syndicationUrl)) {
                        $errors[] = "Invalid syndication URL: $syndicationUrl";
                    }
                }
            }
        }

        return $errors;
    }

    /**
     * Validate Micropub content field.
     *
     * Content can be a string or an object with 'html' and 'value' fields.
     *
     * @param mixed $content
     * @return string[]
     */
    private static function validateContent($content): array
    {
        $errors = [];

        if (is_array($content)) {
            // Content object format
            if (isset($content['html'])) {
                if (!is_string($content['html'])) {
                    $errors[] = 'Content "html" must be a string';
                } else {
                    // Check for dangerous script tags
                    if (str_contains($content['html'], '<script>') ||
                        str_contains($content['html'], 'javascript:')) {
                        $errors[] = 'Content contains dangerous script tags or javascript: protocol';
                    }
                }
            }

            if (isset($content['value']) && !is_string($content['value'])) {
                $errors[] = 'Content "value" must be a string';
            }
        } elseif (is_string($content)) {
            // Plain text content
            if (str_contains($content, '<script>')) {
                $errors[] = 'Content contains script tags';
            }
        } else {
            $errors[] = 'Content must be a string or object';
        }

        return $errors;
    }

    /**
     * Sanitize Micropub entry for storage.
     *
     * Removes dangerous content while preserving safe HTML.
     *
     * @param array<string, mixed> $entry Micropub entry data
     * @return array<string, mixed> Sanitized entry
     */
    public static function sanitizeEntry(array $entry): array
    {
        $sanitized = $entry;

        if (!isset($sanitized['properties']) || !is_array($sanitized['properties'])) {
            return $sanitized;
        }

        $properties = &$sanitized['properties'];

        // Sanitize name property
        if (isset($properties['name']) && is_array($properties['name'])) {
            $properties['name'] = array_map(
                fn($name) => is_string($name) ? Sanitizer::html($name) : $name,
                $properties['name']
            );
        }

        // Sanitize summary property
        if (isset($properties['summary']) && is_array($properties['summary'])) {
            $properties['summary'] = array_map(
                fn($summary) => is_string($summary) ? Sanitizer::html($summary) : $summary,
                $properties['summary']
            );
        }

        // Sanitize content property
        if (isset($properties['content']) && is_array($properties['content'])) {
            foreach ($properties['content'] as $key => $content) {
                $properties['content'][$key] = self::sanitizeContent($content);
            }
        }

        // Sanitize category/tags (remove dangerous strings)
        if (isset($properties['category']) && is_array($properties['category'])) {
            $properties['category'] = array_map(
                fn($cat) => is_string($cat) ? Sanitizer::html($cat) : $cat,
                $properties['category']
            );
        }

        return $sanitized;
    }

    /**
     * Sanitize Micropub content field.
     *
     * @param mixed $content
     * @return mixed
     */
    private static function sanitizeContent($content)
    {
        if (is_array($content)) {
            $sanitized = $content;

            if (isset($sanitized['html']) && is_string($sanitized['html'])) {
                // Remove script tags and sanitize HTML
                $sanitized['html'] = Sanitizer::stripTags($sanitized['html']);
                $sanitized['html'] = Sanitizer::html($sanitized['html']);
            }

            if (isset($sanitized['value']) && is_string($sanitized['value'])) {
                $sanitized['value'] = Sanitizer::html($sanitized['value']);
            }

            return $sanitized;
        } elseif (is_string($content)) {
            return Sanitizer::html($content);
        }

        return $content;
    }

    /**
     * Validate Micropub access token format.
     *
     * This only validates the format, not the authenticity.
     * You must verify the token with your IndieAuth server.
     *
     * @param string $token Access token
     * @return bool True if format is valid
     */
    public static function validateTokenFormat(string $token): bool
    {
        // Tokens should be at least 32 characters
        if (strlen($token) < 32) {
            return false;
        }

        // Tokens should not contain whitespace or dangerous characters
        if (!Validator::printable($token) || preg_match('/\s/', $token)) {
            return false;
        }

        // Tokens should not contain null bytes
        return Validator::noNullBytes($token);
    }

    /**
     * Extract allowed scopes from Micropub request.
     *
     * @param string $scopeString Space-separated scope string
     * @return string[] Array of individual scopes
     */
    public static function parseScopes(string $scopeString): array
    {
        $scopes = explode(' ', trim($scopeString));

        // Filter out empty strings and validate scope format
        return array_filter($scopes, function ($scope) {
            return $scope !== '' && preg_match('/^[a-z_]+$/', $scope) === 1;
        });
    }

    /**
     * Check if scope allows specific action.
     *
     * @param string[] $scopes User's scopes
     * @param string $requiredScope Required scope (e.g., 'create', 'update', 'delete')
     * @return bool True if authorized
     */
    public static function hasScope(array $scopes, string $requiredScope): bool
    {
        // 'profile' scope is implied for all requests
        if ($requiredScope === 'profile') {
            return true;
        }

        return in_array($requiredScope, $scopes, true);
    }
}
