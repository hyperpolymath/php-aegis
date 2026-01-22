# Cerro Torre Integration Guide

## Overview

This guide explains how to deploy php-aegis WordPress using the **Verified Container Ecosystem**: Cerro Torre (builder), Vörðr (runtime), and Svalinn (gateway).

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    VERIFIED CONTAINER ECOSYSTEM                  │
└─────────────────────────────────────────────────────────────────┘
                                 │
     ┌───────────────────────────┼───────────────────────────────┐
     │                           │                               │
     ▼                           ▼                               ▼
┌──────────────┐        ┌──────────────────┐         ┌─────────────────┐
│   SVALINN    │        │      VÖRÐR       │         │  CERRO TORRE    │
│ Edge Gateway │───────▶│ Container Runtime│◀────────│   Builder       │
│ (Deno/       │delegate│   (Rust/Ada)     │produces │  (Ada/SPARK)    │
│  ReScript)   │        │                  │         │                 │
└──────┬───────┘        └────────┬─────────┘         └────────┬────────┘
       │                         │                            │
       │                         │                            │
       ▼                         ▼                            ▼
┌───────────────────────────────────────────────────────────────────┐
│                      php-aegis WordPress                          │
│   Security Library + WordPress + Verified Container Package      │
└───────────────────────────────────────────────────────────────────┘
```

## Why Cerro Torre over Docker?

| Feature | Cerro Torre | Docker |
|---------|-------------|--------|
| **Formal Verification** | Ada/SPARK verified tooling | No formal verification |
| **Provenance** | Complete cryptographic chain | Limited provenance tracking |
| **Governance** | Multi-stakeholder cooperative | Corporate-controlled |
| **Security** | SELinux enforcing, threshold signing | Optional security features |
| **Transparency** | Federated transparency logs | Centralized registry |
| **Reproducibility** | Built-in reproducible builds | Manual configuration |

## Prerequisites

### 1. Install Cerro Torre

```bash
# Clone Cerro Torre
git clone https://github.com/hyperpolymath/cerro-torre.git
cd cerro-torre

# Build with Alire (Ada package manager)
alr build

# Verify installation
./bin/cerro-torre --version
```

### 2. Install Vörðr

```bash
# Clone Vörðr
git clone https://github.com/hyperpolymath/vordr.git
cd vordr

# Build with Cargo (Rust) + Alire (Ada)
cargo build --release
alr build

# Start Vörðr daemon
./target/release/vordr --daemon
```

### 3. Install Svalinn

```bash
# Clone Svalinn
git clone https://github.com/hyperpolymath/svalinn.git
cd svalinn

# Install with Deno
deno install --allow-all svalinn-compose

# Verify installation
svalinn-compose --version
```

## Building php-aegis WordPress Container

### Step 1: Prepare Manifest

The Cerro Torre manifest is located at:
```
php-aegis/manifests/php-aegis-wordpress.ctp
```

Key sections:
- **[package]**: Package metadata
- **[dependencies]**: PHP 8.2, WordPress 6.4, php-aegis 0.2
- **[build]**: Declarative build steps
- **[runtime]**: Container runtime configuration
- **[security]**: SELinux policy, capabilities, network isolation
- **[attestations]**: SBOM, provenance, threshold signing

### Step 2: Build with Cerro Torre

```bash
# Navigate to php-aegis repo
cd /path/to/php-aegis

# Build container with Cerro Torre
cerro-torre build manifests/php-aegis-wordpress.ctp

# This produces:
# - OCI image: php-aegis-wordpress:0.2.0
# - .ctp bundle with cryptographic provenance
# - SBOM in SPDX format
# - in-toto attestation
# - Threshold signatures (2-of-3 keyholders)
```

### Step 3: Verify Build

```bash
# Verify cryptographic signatures
cerro-torre verify php-aegis-wordpress:0.2.0

# Check SBOM
cerro-torre sbom php-aegis-wordpress:0.2.0

# Verify transparency log consensus
cerro-torre check-transparency php-aegis-wordpress:0.2.0
```

## Deploying with Vörðr

### Single Container Deployment

```bash
# Run php-aegis WordPress container
vordr run \
  --name php-aegis-wp \
  --image php-aegis-wordpress:0.2.0 \
  --port 9000:9000 \
  --volume wp-content:/var/www/html/wp-content \
  --volume ratelimit:/var/ratelimit \
  --env DB_HOST=db:3306 \
  --env DB_NAME=wordpress \
  --env DB_USER=wordpress \
  --env DB_PASSWORD=secure_password \
  --network web \
  --selinux-context container_web_t

# Check container status
vordr ps

# View logs
vordr logs php-aegis-wp
```

### Multi-Container Stack

Create `docker-compose.yml` (Svalinn-compatible):

```yaml
# SPDX-License-Identifier: PMPL-1.0-or-later
# php-aegis WordPress Stack (Svalinn/Vörðr)

version: "3.9"

services:
  db:
    image: cerro-torre/mariadb:11.2
    volumes:
      - db_data:/var/lib/mysql
    environment:
      MARIADB_ROOT_PASSWORD: root_password
      MARIADB_DATABASE: wordpress
      MARIADB_USER: wordpress
      MARIADB_PASSWORD: secure_password
    networks:
      - backend
    security:
      selinux:
        type: container_db_t

  wordpress:
    image: php-aegis-wordpress:0.2.0
    depends_on:
      - db
    volumes:
      - wp_content:/var/www/html/wp-content
      - ratelimit:/var/ratelimit
      - uploads:/var/www/html/wp-content/uploads
    environment:
      DB_HOST: db:3306
      DB_NAME: wordpress
      DB_USER: wordpress
      DB_PASSWORD: secure_password
      AEGIS_ENABLE_SECURITY_HEADERS: "true"
      AEGIS_ENABLE_RATE_LIMITING: "true"
    networks:
      - backend
      - frontend
    security:
      selinux:
        type: container_web_t
      capabilities:
        drop: [ALL]
        add: [CHOWN, SETGID, SETUID]
      readonly_root: true

  nginx:
    image: cerro-torre/nginx:1.25
    depends_on:
      - wordpress
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
      - wp_content:/var/www/html/wp-content:ro
      - uploads:/var/www/html/wp-content/uploads:ro
    networks:
      - frontend
    security:
      selinux:
        type: container_proxy_t

volumes:
  db_data:
  wp_content:
  ratelimit:
  uploads:

networks:
  backend:
    internal: true
  frontend:
```

Deploy with Svalinn:

```bash
# Deploy stack
svalinn-compose up -d

# Check status
svalinn-compose ps

# View logs
svalinn-compose logs -f wordpress

# Stop stack
svalinn-compose down
```

## Security Features

### 1. SELinux Enforcing

php-aegis container runs with SELinux type `container_web_t`:

```bash
# Verify SELinux context
ps -eZ | grep php-fpm
# Output: system_u:system_r:container_web_t:s0:c0,c1 ... php-fpm
```

SELinux policy (auto-generated by Cerro Torre):
- **Read-only WordPress files**: PHP can read but not write WordPress core
- **Writable uploads**: PHP can write to uploads directory only
- **Rate limit storage**: PHP can write rate limit data
- **Network access**: PHP can connect to MySQL only

### 2. Capability Dropping

Container drops all capabilities except:
- `CHOWN` - Change file ownership (for wp-content)
- `SETGID` - Set group ID (for www-data)
- `SETUID` - Set user ID (for www-data)
- `NET_BIND_SERVICE` - Bind to port 9000

### 3. Read-Only Root Filesystem

Root filesystem is read-only except:
- `/var/www/html/wp-content/uploads` (user uploads)
- `/var/www/html/wp-content/cache` (cache)
- `/var/ratelimit` (rate limiting data)
- `/tmp` (temporary files)

### 4. Network Isolation

**Egress (outbound)**:
- WordPress API (api.wordpress.org:443)
- Composer/Packagist (packagist.org:443)
- IndieWeb endpoints (*.indieweb.org:443)

**Ingress (inbound)**:
- Port 9000 (PHP-FPM) from nginx container only

### 5. Threshold Signing

Container requires 2-of-3 signatures:
- maintainer-1
- maintainer-2
- release-bot

No single party can sign releases alone.

### 6. Transparency Logs

Build attestations logged to:
- Cerro Torre transparency log
- Sigstore Rekor

Deployment requires consensus from 2-of-2 logs.

## Integration with Svalinn Gateway

### REST API Access

Svalinn provides REST API for container operations:

```bash
# Start Svalinn gateway
svalinn serve --port 8080 --vordr-socket /var/run/vordr.sock

# Create container via API
curl -X POST http://localhost:8080/v1/containers \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "php-aegis-wp",
    "image": "php-aegis-wordpress:0.2.0",
    "ports": [{"internal": 9000, "external": 9000}],
    "volumes": [
      {"source": "wp-content", "target": "/var/www/html/wp-content"}
    ],
    "environment": {
      "DB_HOST": "db:3306",
      "DB_NAME": "wordpress"
    }
  }'

# List containers
curl http://localhost:8080/v1/containers \
  -H "Authorization: Bearer $TOKEN"

# Get container logs
curl http://localhost:8080/v1/containers/php-aegis-wp/logs \
  -H "Authorization: Bearer $TOKEN"
```

### Policy Enforcement

Svalinn enforces policies before delegating to Vörðr:

```yaml
# /etc/svalinn/policy.yaml
policies:
  - operation: "container.create"
    rules:
      - type: "require-signature"
        threshold: 2
      - type: "require-provenance"
        format: "in-toto"
      - type: "deny-privileged"
        message: "Privileged containers not allowed"
      - type: "require-selinux"
        enforcing: true

  - operation: "container.exec"
    rules:
      - type: "audit-log"
        destination: "syslog"
      - type: "rate-limit"
        requests: 10
        window: "1m"
```

### Authentication

Svalinn supports OAuth2/OIDC + JWT:

```bash
# Configure OAuth2 provider
export SVALINN_OAUTH_ISSUER="https://auth.example.com"
export SVALINN_OAUTH_AUDIENCE="svalinn-api"
export SVALINN_OAUTH_JWKS_URL="https://auth.example.com/.well-known/jwks.json"

# Start with authentication
svalinn serve --auth oauth2
```

## Verification Process

### 1. Build Verification

```bash
# Verify before deployment
cerro-torre verify php-aegis-wordpress:0.2.0

# Checks:
# ✓ Threshold signatures (2-of-3)
# ✓ Transparency log consensus (2-of-2)
# ✓ SBOM present and valid
# ✓ No high/critical vulnerabilities
# ✓ All dependencies have provenance
# ✓ Build reproducible
```

### 2. Runtime Verification

```bash
# Vörðr verifies before running
vordr run php-aegis-wordpress:0.2.0

# Checks:
# ✓ Container signature valid
# ✓ Provenance chain complete
# ✓ SBOM matches deployed files
# ✓ SELinux policy loaded
# ✓ Capabilities set correctly
# ✓ Network isolation active
```

### 3. Continuous Verification

```bash
# Monitor running container
vordr check php-aegis-wp

# Checks:
# ✓ Process tree matches manifest
# ✓ File integrity (no tampering)
# ✓ Network connections allowed
# ✓ Capabilities not escalated
# ✓ SELinux violations (none)
```

## Performance

### Cerro Torre vs Docker

| Metric | Cerro Torre + Vörðr | Docker |
|--------|---------------------|--------|
| Build time | ~5-10 min (first build) | ~3-5 min |
| Build time (cached) | ~30 sec | ~30 sec |
| Container start | ~200ms | ~100ms |
| Memory overhead | ~50MB | ~20MB |
| Verification overhead | ~500ms | N/A |
| Storage per container | ~150MB | ~120MB |

**Trade-off**: Slightly slower for significantly higher security guarantees.

## Troubleshooting

### Build Failures

```bash
# Check Cerro Torre logs
cerro-torre build --verbose manifests/php-aegis-wordpress.ctp

# Common issues:
# - Missing dependencies: Install with alr
# - Network errors: Check firewall rules
# - Signature errors: Verify keyholders available
```

### Runtime Errors

```bash
# Check Vörðr logs
vordr logs php-aegis-wp --tail 100

# Common issues:
# - SELinux denials: Check with ausearch -m avc
# - Permission errors: Verify volume ownership
# - Network errors: Check network policy
```

### Svalinn Gateway Issues

```bash
# Check Svalinn logs
journalctl -u svalinn -f

# Common issues:
# - Authentication: Verify OAuth2 configuration
# - Policy denials: Check /etc/svalinn/policy.yaml
# - Vörðr connection: Verify socket path
```

## Migration from Docker

### 1. Convert Dockerfile to .ctp

Docker:
```dockerfile
FROM php:8.2-fpm
RUN apt-get update && apt-get install -y wordpress
COPY --from=composer /usr/bin/composer /usr/bin/composer
RUN composer require hyperpolymath/php-aegis
```

Cerro Torre (.ctp):
```toml
[base]
image = "cerro-torre/debian:bookworm-slim"

[dependencies]
packages = ["php8.2-fpm", "wordpress", "composer"]

[build]
steps = [
    { action = "composer-require", package = "hyperpolymath/php-aegis" }
]
```

### 2. Convert docker-compose.yml

Docker Compose files work with Svalinn with minimal changes:
- `docker-compose up` → `svalinn-compose up`
- `docker-compose ps` → `svalinn-compose ps`
- `docker-compose logs` → `svalinn-compose logs`

### 3. Migrate Volumes

```bash
# Export Docker volume
docker run --rm -v wp_content:/source -v $(pwd):/backup \
  alpine tar czf /backup/wp_content.tar.gz -C /source .

# Import to Vörðr
vordr volume create wp_content
vordr run --rm -v wp_content:/target -v $(pwd):/backup \
  cerro-torre/alpine tar xzf /backup/wp_content.tar.gz -C /target
```

## Next Steps

1. **Read Cerro Torre docs**: https://github.com/hyperpolymath/cerro-torre
2. **Read Vörðr docs**: https://github.com/hyperpolymath/vordr
3. **Read Svalinn docs**: https://github.com/hyperpolymath/svalinn
4. **Join community**: https://github.com/hyperpolymath/verified-container-spec

## References

- [Verified Container Spec](https://github.com/hyperpolymath/verified-container-spec)
- [Cerro Torre Manifest Format](https://github.com/hyperpolymath/cerro-torre/blob/main/spec/manifest-format.md)
- [in-toto Attestation](https://in-toto.io/)
- [SLSA Provenance](https://slsa.dev/provenance/)
- [SPDX SBOM](https://spdx.dev/)
