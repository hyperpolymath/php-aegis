# php-aegis justfile

default:
    @just --list

# Install dependencies
install:
    composer install

# Run tests
test:
    vendor/bin/phpunit

# Run static analysis
analyze:
    vendor/bin/phpstan analyse src

# Format check
lint:
    vendor/bin/php-cs-fixer fix --dry-run

# Format code
fmt:
    vendor/bin/php-cs-fixer fix

# Run panic-attacker pre-commit scan
assail:
    @command -v panic-attack >/dev/null 2>&1 && panic-attack assail . || echo "panic-attack not found — install from https://github.com/hyperpolymath/panic-attacker"
