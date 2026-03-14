;; SPDX-License-Identifier: PMPL-1.0-or-later
;; STATE.scm - Project state for php-aegis
;; Media-Type: application/vnd.state+scm

(state
  (metadata
    (version "0.9.0")
    (schema-version "1.0")
    (created "2026-01-03")
    (updated "2026-03-14")
    (project "php-aegis")
    (repo "github.com/hyperpolymath/php-aegis"))

  (project-context
    (name "php-aegis")
    (tagline "PHP security and hardening toolkit — validation, sanitization, headers, rate limiting, IndieWeb security")
    (tech-stack ("PHP 8.1+" "PHPUnit 10" "PHPStan" "Composer")))

  (current-position
    (phase "production-stabilisation")
    (overall-completion 90)
    (components ("Validator" "Sanitizer" "Headers" "TurtleEscaper" "Crypto"
                 "WordPress/Adapter" "RateLimit" "IndieWeb"))
    (working-features
      ("Validator: strict input validation (core + network + format)"
       "Sanitizer: context-aware HTML/JS/CSS/JSON sanitization"
       "Headers: CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy, CORS"
       "TurtleEscaper: RDF/Turtle output escaping (unique differentiator)"
       "Crypto: 520 lines, cryptographic utilities"
       "WordPress/Adapter: 23 adapter functions for WP integration (80%)"
       "RateLimit: TokenBucket with File/Memory backends (60%)"
       "IndieWeb: Micropub, IndieAuth, Webmention security helpers (40%)"
       "Full PHPUnit test suite (11 test files)"
       "PHPStan static analysis configured"
       "PHP-CS-Fixer formatting configured"
       "Vendored in lcb-website Sinople theme (synced 2026-03-14)")))

  (route-to-mvp
    (milestones
      (("core-security" . "Validator + Sanitizer + Headers + TurtleEscaper — DONE")
       ("wordpress-adapter" . "Full WordPress integration adapter — 80%")
       ("rate-limiting" . "TokenBucket with Redis backend — 60%")
       ("indieweb-security" . "Micropub/IndieAuth/Webmention SSRF prevention — 40%")
       ("v1.0-release" . "Packagist publish with full docs"))))

  (blockers-and-issues
    (critical ())
    (high ())
    (medium ("WordPress Adapter needs final 5 integration hooks"
             "RateLimit needs Redis backend for production use"
             "IndieWeb helpers need full protocol flow testing"))
    (low ("Composer license field says MIT — should be PMPL-1.0-or-later or MPL-2.0 fallback"
          "Autoload SPDX headers updated to PMPL-1.0-or-later")))

  (critical-next-actions
    (immediate ("Finish WordPress Adapter remaining hooks"
                "Add Redis RateLimit backend"))
    (this-week ("Test IndieWeb helpers against live Micropub/Webmention endpoints"
                "Run PHPUnit full suite and fix any failures"))
    (this-month ("Publish to Packagist"
                 "Update SPDX headers to PMPL-1.0-or-later")))

  (session-history
    ((date "2026-03-14")
     (accomplishments
       ("Audited actual codebase: 3,447 lines, 14 source files, 11 test files"
        "Synced vendored copy in lcb-website Sinople theme to match current repo"
        "Updated STATE.scm from blank template to reflect actual ~90% completion"
        "Identified stale SPDX headers in autoload.php and composer.json"))
     (next-session "Finish WordPress Adapter, add Redis RateLimit, test IndieWeb flows"))))
