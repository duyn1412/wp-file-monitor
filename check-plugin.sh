#!/bin/bash
# ============================================================
# WordPress.org Plugin Check — Local Static Analysis
# Checks for common issues before submitting to WordPress.org
# ============================================================

PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_SLUG="wp-file-monitor"
ERRORS=0
WARNINGS=0
NOTICES=0

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;36m'
GREEN='\033[0;32m'
NC='\033[0m'

error()   { ((ERRORS++));   echo -e "${RED}❌ ERROR:${NC} $1"; }
warning() { ((WARNINGS++)); echo -e "${YELLOW}⚠️  WARNING:${NC} $1"; }
notice()  { ((NOTICES++));  echo -e "${BLUE}ℹ️  NOTICE:${NC} $1"; }
pass()    { echo -e "${GREEN}✅ PASS:${NC} $1"; }

echo "============================================"
echo "  WordPress.org Plugin Check"
echo "  Plugin: $PLUGIN_SLUG"
echo "  Path:   $PLUGIN_DIR"
echo "============================================"
echo ""

# ── 1. readme.txt ──
echo "── 1. readme.txt ──"
if [ -f "$PLUGIN_DIR/readme.txt" ]; then
    pass "readme.txt exists"
    
    # Check required headers
    for header in "Stable tag" "Tested up to" "Requires at least" "Requires PHP" "License"; do
        if grep -qi "^${header}:" "$PLUGIN_DIR/readme.txt"; then
            pass "readme.txt has '$header' header"
        else
            error "readme.txt missing '$header' header"
        fi
    done
    
    # Check sections
    for section in "== Description ==" "== Installation ==" "== Changelog =="; do
        if grep -q "$section" "$PLUGIN_DIR/readme.txt"; then
            pass "readme.txt has '$section' section"
        else
            warning "readme.txt missing '$section' section"
        fi
    done
    
    # Check stable tag matches plugin version
    STABLE_TAG=$(grep -i "^stable tag:" "$PLUGIN_DIR/readme.txt" | sed 's/.*: *//')
    PLUGIN_VER=$(grep -m1 "Version:" "$PLUGIN_DIR/$PLUGIN_SLUG.php" | sed 's/.*Version: *//' | tr -d ' */')
    if [ -n "$STABLE_TAG" ] && [ -n "$PLUGIN_VER" ]; then
        if [ "$STABLE_TAG" = "$PLUGIN_VER" ]; then
            pass "Stable tag ($STABLE_TAG) matches plugin version ($PLUGIN_VER)"
        else
            error "Stable tag ($STABLE_TAG) does NOT match plugin version ($PLUGIN_VER)"
        fi
    fi
else
    error "readme.txt is MISSING (required for WordPress.org)"
fi
echo ""

# ── 2. Plugin Header ──
echo "── 2. Plugin Header ──"
MAIN_FILE="$PLUGIN_DIR/$PLUGIN_SLUG.php"
if [ -f "$MAIN_FILE" ]; then
    for header in "Plugin Name" "Version" "Description" "Author" "License" "Text Domain"; do
        if grep -q "^ \* $header:" "$MAIN_FILE"; then
            pass "Main file has '$header' header"
        else
            error "Main file missing '$header' header"
        fi
    done
    
    # Text Domain must match slug
    TD=$(grep "Text Domain:" "$MAIN_FILE" | sed 's/.*Text Domain: *//' | tr -d ' */')
    if [ "$TD" = "$PLUGIN_SLUG" ]; then
        pass "Text Domain '$TD' matches plugin slug"
    else
        error "Text Domain '$TD' does NOT match slug '$PLUGIN_SLUG'"
    fi
else
    error "Main plugin file not found: $MAIN_FILE"
fi
echo ""

# ── 3. Security Checks ──
echo "── 3. Security Checks ──"

# ABSPATH check in all PHP files
PHP_FILES=$(find "$PLUGIN_DIR" -name "*.php" -not -path "*/.git/*" -not -path "*/vendor/*" -not -path "*/node_modules/*")
for f in $PHP_FILES; do
    REL=$(echo "$f" | sed "s|$PLUGIN_DIR/||")
    if ! grep -q "ABSPATH" "$f"; then
        warning "$REL — missing ABSPATH check (direct access protection)"
    fi
done

# Check for direct file_get_contents on URLs (should use wp_remote_get)
for f in $PHP_FILES; do
    REL=$(echo "$f" | sed "s|$PLUGIN_DIR/||")
    if grep -n "file_get_contents\s*(\s*['\"]http" "$f" 2>/dev/null; then
        error "$REL — uses file_get_contents() for URLs, use wp_remote_get() instead"
    fi
done

# Check for $_GET/$_POST without sanitization
for f in $PHP_FILES; do
    REL=$(echo "$f" | sed "s|$PLUGIN_DIR/||")
    UNSANITIZED=$(grep -n '\$_\(GET\|POST\|REQUEST\|SERVER\)\[' "$f" 2>/dev/null | grep -v 'sanitize\|esc_\|absint\|intval\|wp_unslash\|nonce' | head -5)
    if [ -n "$UNSANITIZED" ]; then
        while IFS= read -r line; do
            warning "$REL:$line — Potential unsanitized superglobal"
        done <<< "$UNSANITIZED"
    fi
done

# Check for echo without escaping
for f in $PHP_FILES; do
    REL=$(echo "$f" | sed "s|$PLUGIN_DIR/||")
    UNESCAPED=$(grep -n "echo \\\$" "$f" 2>/dev/null | grep -v "esc_html\|esc_attr\|esc_url\|wp_kses\|wp_json_encode\|json_encode" | head -5)
    if [ -n "$UNESCAPED" ]; then
        while IFS= read -r line; do
            warning "$REL:$line — echo with variable, ensure proper escaping"
        done <<< "$UNESCAPED"
    fi
done

# Nonce checks for AJAX handlers
for f in $PHP_FILES; do
    REL=$(echo "$f" | sed "s|$PLUGIN_DIR/||")
    AJAX_HANDLERS=$(grep -n "wp_ajax_" "$f" 2>/dev/null)
    if [ -n "$AJAX_HANDLERS" ]; then
        if ! grep -q "check_ajax_referer\|wp_verify_nonce" "$f"; then
            error "$REL — AJAX handlers without nonce verification"
        else
            pass "$REL — AJAX handlers have nonce verification"
        fi
    fi
done

pass "Security checks completed"
echo ""

# ── 4. Internationalization (i18n) ──
echo "── 4. Internationalization ──"

# Check for untranslated strings in admin
UNTRANSLATED=0
for f in $PHP_FILES; do
    REL=$(echo "$f" | sed "s|$PLUGIN_DIR/||")
    # Look for echo/print with hardcoded strings (not in __ or _e)
    COUNT=$(grep -c "echo '[A-Z]" "$f" 2>/dev/null || true)
    if [ "$COUNT" -gt "0" ]; then
        notice "$REL — $COUNT potential untranslated string(s)"
        ((UNTRANSLATED+=COUNT))
    fi
done
if [ "$UNTRANSLATED" -eq "0" ]; then
    pass "No obvious untranslated strings found"
fi
echo ""

# ── 5. Coding Standards ──
echo "── 5. Coding Standards ──"

# Check for short PHP tags — find <? that is NOT <?php or <?=
for f in $PHP_FILES; do
    REL=$(echo "$f" | sed "s|$PLUGIN_DIR/||")
    # Extract all <? occurrences, remove <?php and <?=, check if any remain
    SHORT=$(sed -n 's/<?php//g; s/<?=//g; /<?/p' "$f" 2>/dev/null | head -3)
    if [ -n "$SHORT" ]; then
        error "$REL — uses short PHP tags (use <?php instead)"
    fi
done

# Check for deprecated PHP functions
DEPRECATED="create_function|ereg|eregi|split|mysql_query|mysql_connect"
for f in $PHP_FILES; do
    REL=$(echo "$f" | sed "s|$PLUGIN_DIR/||")
    FOUND=$(grep -nE "\b($DEPRECATED)\s*\(" "$f" 2>/dev/null | head -3)
    if [ -n "$FOUND" ]; then
        while IFS= read -r line; do
            error "$REL:$line — deprecated PHP function"
        done <<< "$FOUND"
    fi
done

# Check for deprecated WordPress functions
WP_DEPRECATED="get_bloginfo\('wpurl'\)|get_bloginfo\('siteurl'\)"
for f in $PHP_FILES; do
    REL=$(echo "$f" | sed "s|$PLUGIN_DIR/||")
    FOUND=$(grep -nE "$WP_DEPRECATED" "$f" 2>/dev/null | head -3)
    if [ -n "$FOUND" ]; then
        warning "$REL — uses deprecated WordPress function"
    fi
done

pass "Coding standards checks completed"
echo ""

# ── 6. Performance ──
echo "── 6. Performance ──"

# Check for scripts/styles loaded on all pages (should be conditional)
for f in $PHP_FILES; do
    REL=$(echo "$f" | sed "s|$PLUGIN_DIR/||")
    HAS_ENQUEUE=$(grep -c "wp_enqueue_script\|wp_enqueue_style" "$f" 2>/dev/null || true)
    if [ "$HAS_ENQUEUE" -gt "0" ]; then
        if grep -q "admin_enqueue_scripts\|wp_enqueue_scripts" "$f"; then
            pass "$REL — enqueues assets conditionally"
        else
            warning "$REL — enqueues assets without hook check"
        fi
    fi
done
echo ""

# ── 7. External Services ──
echo "── 7. External Services ──"

EXT_URLS=$(grep -rn "wp_remote_\|file_get_contents.*http\|curl_init" $PHP_FILES 2>/dev/null | grep -v ".git" | head -20)
if [ -n "$EXT_URLS" ]; then
    echo "  Found external service calls:"
    while IFS= read -r line; do
        notice "External call: $line"
    done <<< "$EXT_URLS"
    echo ""
    warning "WordPress.org requires disclosure of ALL external service connections"
    warning "Add a 'Third-Party Services' section to readme.txt"
else
    pass "No external service calls found"
fi
echo ""

# ── 8. File Structure ──
echo "── 8. File Structure ──"

# Check for unwanted files
UNWANTED=(".DS_Store" "Thumbs.db" ".env" "composer.lock" "package-lock.json" "node_modules" ".vscode" ".idea")
for item in "${UNWANTED[@]}"; do
    FOUND=$(find "$PLUGIN_DIR" -name "$item" -not -path "*/.git/*" 2>/dev/null)
    if [ -n "$FOUND" ]; then
        warning "Found unwanted file/dir: $item (remove before submission)"
    fi
done

# Check .gitignore exists
if [ -f "$PLUGIN_DIR/.gitignore" ]; then
    pass ".gitignore exists"
else
    notice "No .gitignore found"
fi

# Check total size
TOTAL_SIZE=$(du -sh "$PLUGIN_DIR" 2>/dev/null | cut -f1)
echo "  Plugin size: $TOTAL_SIZE"
echo ""

# ── 9. Prefix Check ──
echo "── 9. Prefix/Namespace Check ──"
# Check all functions and classes use WPFM prefix
UNPREFIXED_FUNCS=$(grep -rn "^function [a-z]" $PHP_FILES 2>/dev/null | grep -v "wpfm_\|WPFM_\|__construct\|chld_\|duy_" | head -10)
if [ -n "$UNPREFIXED_FUNCS" ]; then
    while IFS= read -r line; do
        warning "Unprefixed function: $line"
    done <<< "$UNPREFIXED_FUNCS"
else
    pass "All functions/classes use WPFM_ prefix"
fi
echo ""

# ── 10. License ──
echo "── 10. License ──"
if [ -f "$PLUGIN_DIR/LICENSE" ] || [ -f "$PLUGIN_DIR/license.txt" ]; then
    pass "License file exists"
else
    notice "No LICENSE file (recommended but not required if declared in header)"
fi
echo ""

# ── Summary ──
echo "============================================"
echo "  SUMMARY"
echo "============================================"
echo -e "  ${RED}Errors:   $ERRORS${NC}"
echo -e "  ${YELLOW}Warnings: $WARNINGS${NC}"
echo -e "  ${BLUE}Notices:  $NOTICES${NC}"
echo ""

if [ "$ERRORS" -eq "0" ]; then
    echo -e "${GREEN}✅ No blocking errors found. Ready for review!${NC}"
else
    echo -e "${RED}❌ Fix $ERRORS error(s) before submitting to WordPress.org${NC}"
fi
echo ""
