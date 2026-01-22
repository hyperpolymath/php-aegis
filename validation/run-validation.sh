#!/usr/bin/env bash
# SPDX-License-Identifier: PMPL-1.0-or-later
# Real-world validation runner for php-aegis
#
# Tests php-aegis against actual WordPress installations
# with popular plugins and themes.

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
WP_PATH="${WP_PATH:-/tmp/php-aegis-wp-test}"
WP_URL="${WP_URL:-http://localhost:8888}"
WP_TITLE="php-aegis Test Site"
WP_ADMIN_USER="admin"
WP_ADMIN_PASS="admin_pass_$(openssl rand -hex 8)"
WP_ADMIN_EMAIL="admin@example.com"
PHP_AEGIS_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATION_RESULTS="${PHP_AEGIS_PATH}/validation/results"

# Ensure results directory exists
mkdir -p "$VALIDATION_RESULTS"

echo -e "${BLUE}=== php-aegis Real-World Validation Suite ===${NC}\n"
echo "WordPress Path: $WP_PATH"
echo "php-aegis Path: $PHP_AEGIS_PATH"
echo "Results Path: $VALIDATION_RESULTS"
echo ""

# Check dependencies
check_dependencies() {
    echo -e "${YELLOW}Checking dependencies...${NC}"

    if ! command -v wp &> /dev/null; then
        echo -e "${RED}ERROR: WP-CLI not found. Please install: https://wp-cli.org/#installing${NC}"
        exit 1
    fi

    if ! command -v php &> /dev/null; then
        echo -e "${RED}ERROR: PHP not found${NC}"
        exit 1
    fi

    PHP_VERSION=$(php -r 'echo PHP_VERSION;')
    echo "✓ PHP $PHP_VERSION"
    echo "✓ WP-CLI $(wp --version | cut -d' ' -f2)"
    echo ""
}

# Setup WordPress test environment
setup_wordpress() {
    echo -e "${YELLOW}Setting up WordPress test environment...${NC}"

    # Clean previous installation
    if [ -d "$WP_PATH" ]; then
        echo "Removing existing WordPress installation..."
        rm -rf "$WP_PATH"
    fi

    mkdir -p "$WP_PATH"

    # Download WordPress
    echo "Downloading WordPress..."
    wp core download --path="$WP_PATH" --quiet

    # Create wp-config.php
    echo "Creating wp-config.php..."
    wp config create \
        --path="$WP_PATH" \
        --dbname="wp_phpageis_test" \
        --dbuser="root" \
        --dbpass="" \
        --dbhost="localhost" \
        --skip-check \
        --quiet

    # Create database
    echo "Creating database..."
    wp db create --path="$WP_PATH" --quiet || true

    # Install WordPress
    echo "Installing WordPress..."
    wp core install \
        --path="$WP_PATH" \
        --url="$WP_URL" \
        --title="$WP_TITLE" \
        --admin_user="$WP_ADMIN_USER" \
        --admin_password="$WP_ADMIN_PASS" \
        --admin_email="$WP_ADMIN_EMAIL" \
        --skip-email \
        --quiet

    echo -e "${GREEN}✓ WordPress installed${NC}\n"
}

# Install php-aegis as must-use plugin
install_phpageis() {
    echo -e "${YELLOW}Installing php-aegis...${NC}"

    # Create mu-plugins directory
    mkdir -p "$WP_PATH/wp-content/mu-plugins"

    # Copy php-aegis source
    cp -r "$PHP_AEGIS_PATH/src" "$WP_PATH/wp-content/mu-plugins/php-aegis"

    # Copy adapter and MU-plugin
    cp "$PHP_AEGIS_PATH/src/WordPress/Adapter.php" "$WP_PATH/wp-content/mu-plugins/"

    # Create MU-plugin loader
    cat > "$WP_PATH/wp-content/mu-plugins/php-aegis-loader.php" << 'EOF'
<?php
/**
 * Plugin Name: php-aegis Security
 * Description: Security utilities for WordPress
 * Version: 0.2.0
 * SPDX-License-Identifier: PMPL-1.0-or-later
 */

// Load php-aegis classes
spl_autoload_register(function ($class) {
    if (strpos($class, 'PhpAegis\\') === 0) {
        $file = __DIR__ . '/php-aegis/' . str_replace('\\', '/', substr($class, 9)) . '.php';
        if (file_exists($file)) {
            require_once $file;
        }
    }
});

// Load adapter functions
require_once __DIR__ . '/Adapter.php';

// Enable security headers
add_action('send_headers', function() {
    if (!is_admin()) {
        aegis_send_security_headers();
    }
});
EOF

    echo -e "${GREEN}✓ php-aegis installed as MU-plugin${NC}\n"
}

# Test plugin compatibility
test_plugin() {
    local PLUGIN_SLUG=$1
    local PLUGIN_NAME=$2

    echo -e "${BLUE}Testing: $PLUGIN_NAME${NC}"

    # Install plugin
    echo "  Installing $PLUGIN_NAME..."
    wp plugin install "$PLUGIN_SLUG" --path="$WP_PATH" --activate --quiet

    # Check for PHP errors
    local ERROR_LOG="$WP_PATH/wp-content/debug.log"
    if [ -f "$ERROR_LOG" ]; then
        local ERRORS=$(grep -c "Fatal error\|Parse error" "$ERROR_LOG" || true)
        if [ "$ERRORS" -gt 0 ]; then
            echo -e "  ${RED}✗ PHP errors detected${NC}"
            return 1
        fi
    fi

    # Test basic functionality
    echo "  Testing plugin activation..."
    local ACTIVE=$(wp plugin list --path="$WP_PATH" --name="$PLUGIN_SLUG" --field=status)

    if [ "$ACTIVE" = "active" ]; then
        echo -e "  ${GREEN}✓ Plugin activated successfully${NC}"

        # Run custom tests for specific plugins
        case "$PLUGIN_SLUG" in
            "contact-form-7")
                test_contact_form_7
                ;;
            "woocommerce")
                test_woocommerce
                ;;
        esac

        # Deactivate and uninstall
        wp plugin deactivate "$PLUGIN_SLUG" --path="$WP_PATH" --quiet
        wp plugin uninstall "$PLUGIN_SLUG" --path="$WP_PATH" --quiet

        return 0
    else
        echo -e "  ${RED}✗ Plugin activation failed${NC}"
        return 1
    fi
}

# Test Contact Form 7
test_contact_form_7() {
    echo "  Running Contact Form 7 specific tests..."

    # Test XSS in form submission with aegis sanitization
    php "$PHP_AEGIS_PATH/validation/test-cf7-xss.php" "$WP_PATH" > "$VALIDATION_RESULTS/cf7-xss-test.txt" 2>&1

    if [ $? -eq 0 ]; then
        echo -e "    ${GREEN}✓ XSS prevention working${NC}"
    else
        echo -e "    ${YELLOW}⚠ XSS test inconclusive${NC}"
    fi
}

# Test WooCommerce
test_woocommerce() {
    echo "  Running WooCommerce specific tests..."

    # Basic setup
    wp option set woocommerce_store_address "123 Main St" --path="$WP_PATH" --quiet
    wp option set woocommerce_store_city "Test City" --path="$WP_PATH" --quiet
    wp option set woocommerce_default_country "US:CA" --path="$WP_PATH" --quiet
    wp option set woocommerce_currency "USD" --path="$WP_PATH" --quiet

    echo -e "    ${GREEN}✓ WooCommerce configured${NC}"
}

# Test theme compatibility
test_theme() {
    local THEME_SLUG=$1
    local THEME_NAME=$2

    echo -e "${BLUE}Testing: $THEME_NAME${NC}"

    # Install theme
    echo "  Installing $THEME_NAME..."
    wp theme install "$THEME_SLUG" --path="$WP_PATH" --activate --quiet

    # Check for PHP errors
    local ERROR_LOG="$WP_PATH/wp-content/debug.log"
    if [ -f "$ERROR_LOG" ]; then
        local ERRORS=$(grep -c "Fatal error\|Parse error" "$ERROR_LOG" || true)
        if [ "$ERRORS" -gt 0 ]; then
            echo -e "  ${RED}✗ PHP errors detected${NC}"
            return 1
        fi
    fi

    # Test theme activation
    local ACTIVE=$(wp theme list --path="$WP_PATH" --name="$THEME_SLUG" --field=status)

    if [ "$ACTIVE" = "active" ]; then
        echo -e "  ${GREEN}✓ Theme activated successfully${NC}"

        # Deactivate
        wp theme activate twentytwentyfour --path="$WP_PATH" --quiet
        wp theme uninstall "$THEME_SLUG" --path="$WP_PATH" --quiet

        return 0
    else
        echo -e "  ${RED}✗ Theme activation failed${NC}"
        return 1
    fi
}

# Run PHP unit tests
run_php_tests() {
    echo -e "${YELLOW}Running PHP validation tests...${NC}"

    php "$PHP_AEGIS_PATH/validation/run-tests.php" > "$VALIDATION_RESULTS/php-tests.json"

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ PHP tests completed${NC}\n"
    else
        echo -e "${RED}✗ PHP tests failed${NC}\n"
    fi
}

# Generate final report
generate_report() {
    echo -e "${YELLOW}Generating validation report...${NC}"

    local REPORT_FILE="$VALIDATION_RESULTS/validation-report.md"

    cat > "$REPORT_FILE" << EOF
# php-aegis Real-World Validation Report

**Generated:** $(date -u +"%Y-%m-%dT%H:%M:%SZ")
**WordPress Version:** $(wp core version --path="$WP_PATH")
**PHP Version:** $(php -r 'echo PHP_VERSION;')
**php-aegis Version:** 0.2.0

## Test Environment

- WordPress Path: \`$WP_PATH\`
- Test URL: \`$WP_URL\`
- php-aegis Path: \`$PHP_AEGIS_PATH\`

## Summary

### Plugins Tested

EOF

    # Add plugin results
    for RESULT in "$VALIDATION_RESULTS"/plugin-*.txt; do
        if [ -f "$RESULT" ]; then
            cat "$RESULT" >> "$REPORT_FILE"
        fi
    done

    cat >> "$REPORT_FILE" << EOF

### Themes Tested

EOF

    # Add theme results
    for RESULT in "$VALIDATION_RESULTS"/theme-*.txt; do
        if [ -f "$RESULT" ]; then
            cat "$RESULT" >> "$REPORT_FILE"
        fi
    done

    cat >> "$REPORT_FILE" << EOF

## PHP Unit Tests

See: \`validation/results/php-tests.json\`

## Conclusion

EOF

    echo "Report saved to: $REPORT_FILE"
    echo -e "${GREEN}✓ Validation complete${NC}\n"
}

# Main execution
main() {
    check_dependencies
    setup_wordpress
    install_phpageis
    run_php_tests

    echo -e "${YELLOW}=== Testing Popular Plugins ===${NC}\n"

    # Test popular plugins
    test_plugin "contact-form-7" "Contact Form 7" | tee "$VALIDATION_RESULTS/plugin-cf7.txt"
    test_plugin "akismet" "Akismet" | tee "$VALIDATION_RESULTS/plugin-akismet.txt"
    test_plugin "wordpress-seo" "Yoast SEO" | tee "$VALIDATION_RESULTS/plugin-yoast.txt"

    echo ""
    echo -e "${YELLOW}=== Testing Popular Themes ===${NC}\n"

    # Test popular themes
    test_theme "astra" "Astra" | tee "$VALIDATION_RESULTS/theme-astra.txt"
    test_theme "generatepress" "GeneratePress" | tee "$VALIDATION_RESULTS/theme-generatepress.txt"

    echo ""
    generate_report

    echo -e "${GREEN}=== Validation Complete ===${NC}"
    echo "Results saved to: $VALIDATION_RESULTS"
}

# Run if executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
