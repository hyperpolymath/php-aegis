# Cerro Torre Package Manifest
# php-aegis WordPress Container
# SPDX-License-Identifier: PMPL-1.0-or-later

[package]
name = "php-aegis-wordpress"
version = "0.2.0"
architecture = "x86_64"
description = "WordPress with php-aegis security library for input validation, output sanitization, and IndieWeb protocols"

[metadata]
homepage = "https://github.com/hyperpolymath/php-aegis"
license = "PMPL-1.0-or-later"
maintainer = "Jonathan D.A. Jewell <jonathan@hyperpolymath.org>"
source = "https://github.com/hyperpolymath/php-aegis"
category = "web"
tags = ["wordpress", "security", "php", "indieweb", "rdf", "semantic-web"]

[provenance]
# Cryptographic provenance chain
build-system = "cerro-torre"
build-version = "0.1.0"
source-hash-algorithm = "sha256"
# Will be filled during build
source-hash = ""
built-by = ""
build-timestamp = ""
attestation-format = "in-toto"

[base]
# Base image from Cerro Torre registry
image = "cerro-torre/debian:bookworm-slim"
# Or: image = "cerro-torre/fedora:39"

[dependencies]
# PHP runtime and extensions
packages = [
    "php8.2-cli",
    "php8.2-fpm",
    "php8.2-mysql",
    "php8.2-xml",
    "php8.2-mbstring",
    "php8.2-curl",
    "php8.2-zip",
    "php8.2-gd",
    "php8.2-intl",
    "composer",

    # WordPress dependencies
    "nginx",
    "mariadb-client",

    # System utilities
    "ca-certificates",
    "curl",
    "unzip",
]

# External dependencies with provenance
[dependencies.external]
wordpress = { version = "6.4.2", source = "https://wordpress.org/wordpress-6.4.2.tar.gz", hash = "sha256:..." }
php-aegis = { version = "0.2.0", source = "github:hyperpolymath/php-aegis", hash = "sha256:..." }

[build]
# Build steps (Turing-incomplete, declarative)
steps = [
    # Create directory structure
    { action = "mkdir", path = "/var/www/html", mode = "0755" },
    { action = "mkdir", path = "/var/www/html/wp-content/mu-plugins", mode = "0755" },

    # Download and extract WordPress
    { action = "fetch", url = "{{dependencies.external.wordpress.source}}", dest = "/tmp/wordpress.tar.gz" },
    { action = "verify-hash", file = "/tmp/wordpress.tar.gz", hash = "{{dependencies.external.wordpress.hash}}" },
    { action = "extract", archive = "/tmp/wordpress.tar.gz", dest = "/var/www/html" },

    # Install php-aegis via Composer
    { action = "composer-require", package = "hyperpolymath/php-aegis:^0.2", dir = "/var/www/html" },

    # Copy php-aegis MU-plugin
    { action = "copy",
      src = "/var/www/html/vendor/hyperpolymath/php-aegis/docs/wordpress/aegis-mu-plugin.php",
      dest = "/var/www/html/wp-content/mu-plugins/aegis-mu-plugin.php" },

    # Set permissions
    { action = "chown", path = "/var/www/html", user = "www-data", group = "www-data", recursive = true },
    { action = "chmod", path = "/var/www/html/wp-content", mode = "0755", recursive = true },
]

[runtime]
# Runtime configuration
command = ["/usr/sbin/php-fpm8.2", "--nodaemonize"]
workdir = "/var/www/html"
user = "www-data"
group = "www-data"

[runtime.environment]
# Environment variables
PHP_VERSION = "8.2"
WORDPRESS_VERSION = "6.4.2"
PHP_AEGIS_VERSION = "0.2.0"

# WordPress configuration
WORDPRESS_DB_HOST = "${DB_HOST:-db:3306}"
WORDPRESS_DB_NAME = "${DB_NAME:-wordpress}"
WORDPRESS_DB_USER = "${DB_USER:-wordpress}"
WORDPRESS_DB_PASSWORD = "${DB_PASSWORD}"
WORDPRESS_TABLE_PREFIX = "${TABLE_PREFIX:-wp_}"

# php-aegis configuration
AEGIS_ENABLE_SECURITY_HEADERS = "true"
AEGIS_ENABLE_RATE_LIMITING = "true"
AEGIS_RATELIMIT_STORAGE = "/var/ratelimit"

[runtime.volumes]
# Persistent volumes
data = { mount = "/var/www/html/wp-content", type = "persistent" }
ratelimit = { mount = "/var/ratelimit", type = "persistent" }
uploads = { mount = "/var/www/html/wp-content/uploads", type = "persistent" }

[runtime.ports]
http = { internal = 9000, external = 9000, protocol = "tcp" }

[runtime.healthcheck]
command = ["php", "-r", "echo 'healthy';"]
interval = "30s"
timeout = "3s"
retries = 3

[security]
# Security policies

[security.selinux]
# SELinux policy for php-aegis WordPress container
type = "container_web_t"
categories = ["c0", "c1"]
custom-policy = """
# Allow PHP-FPM to read WordPress files
allow container_web_t wordpress_file_t:file { read getattr open };

# Allow PHP-FPM to write to uploads
allow container_web_t wordpress_uploads_t:dir { write add_name remove_name };
allow container_web_t wordpress_uploads_t:file { create write unlink };

# Allow PHP-FPM to write rate limit data
allow container_web_t ratelimit_data_t:dir { write add_name remove_name };
allow container_web_t ratelimit_data_t:file { create write read unlink };

# Allow PHP to connect to MySQL
allow container_web_t mysqld_port_t:tcp_socket name_connect;

# Allow nginx to connect to PHP-FPM
allow container_web_t self:tcp_socket { create bind listen accept };
"""

[security.capabilities]
# Minimal Linux capabilities
drop = ["ALL"]
add = ["CHOWN", "SETGID", "SETUID", "NET_BIND_SERVICE"]

[security.readonly-root]
# Root filesystem is read-only
enabled = true
exceptions = [
    "/var/www/html/wp-content/uploads",
    "/var/www/html/wp-content/cache",
    "/var/ratelimit",
    "/tmp",
]

[security.network]
# Network isolation
egress-allow = [
    # WordPress.org API
    { host = "api.wordpress.org", port = 443, protocol = "https" },
    { host = "downloads.wordpress.org", port = 443, protocol = "https" },

    # Packagist for Composer
    { host = "packagist.org", port = 443, protocol = "https" },
    { host = "repo.packagist.org", port = 443, protocol = "https" },

    # IndieWeb endpoints (user-configured)
    { pattern = "*.indieweb.org", port = 443, protocol = "https" },
]

ingress-allow = [
    { port = 9000, protocol = "tcp", source = "container:nginx" },
]

[attestations]
# Cryptographic attestations

[attestations.sbom]
# Software Bill of Materials
format = "spdx-2.3"
generator = "cerro-torre-sbom"
# Will be generated during build

[attestations.provenance]
# Build provenance attestation
format = "in-toto"
predicates = [
    "materials",      # Source materials used
    "builder",        # Builder identity
    "recipe",         # Build recipe (this manifest)
    "metadata",       # Build metadata
]

[attestations.signing]
# Threshold signing configuration
algorithm = "ed25519"
threshold = "2-of-3"
keyholders = [
    "maintainer-1",
    "maintainer-2",
    "release-bot",
]

[attestations.transparency]
# Federated transparency logs
logs = [
    { name = "cerro-torre-log", url = "https://log.cerro-torre.org" },
    { name = "sigstore-rekor", url = "https://rekor.sigstore.dev" },
]
threshold-agreement = "2-of-2"

[export]
# Export formats

[export.oci]
# Export as OCI image (for compatibility)
enabled = true
registry = "ghcr.io/hyperpolymath/php-aegis-wordpress"
tags = ["latest", "0.2.0", "wordpress-6.4"]

[export.ostree]
# Export as OSTree commit (for atomicupdates)
enabled = true
repository = "/var/ostree/repo"
branch = "stable/php-aegis-wordpress"

[verification]
# Verification requirements for deployment

[verification.required-signatures]
# Minimum signatures required
minimum = 2
allowed-keyholders = [
    "maintainer-1",
    "maintainer-2",
    "release-bot",
]

[verification.transparency-logs]
# Transparency log verification
require-consensus = true
minimum-logs = 2

[verification.sbom-requirements]
# SBOM must be present and valid
require-sbom = true
allowed-licenses = ["PMPL-1.0-or-later", "MIT", "BSD-3-Clause", "Apache-2.0", "GPL-2.0-or-later", "LGPL-2.1-or-later"]
deny-licenses = ["proprietary", "unknown"]

[verification.vulnerability-scanning]
# Vulnerability scanning requirements
scan-before-deployment = true
max-severity = "medium"
ignore-vulnerabilities = []

# vim: ft=toml
