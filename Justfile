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
