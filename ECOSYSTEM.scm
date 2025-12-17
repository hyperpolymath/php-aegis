;; SPDX-License-Identifier: AGPL-3.0-or-later
;; SPDX-FileCopyrightText: 2025 Jonathan D.A. Jewell
;; ECOSYSTEM.scm — php-aegis

(ecosystem
  (version "1.0.0")
  (name "php-aegis")
  (type "project")
  (purpose "PHP security and hardening toolkit providing input validation, sanitization, and XSS prevention")

  (position-in-ecosystem
    "Part of hyperpolymath ecosystem. Follows RSR guidelines.")

  (related-projects
    (project (name "rhodium-standard-repositories")
             (url "https://github.com/hyperpolymath/rhodium-standard-repositories")
             (relationship "standard")))

  (what-this-is "A security-focused PHP library for input validation and output sanitization")
  (what-this-is-not "Not a full framework, authentication system, or ORM. PHP exception under RSR for security tooling."))
