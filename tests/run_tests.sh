#!/bin/bash

# Master test runner for System Enumeration Scripts
# Runs all available tests based on current platform and available tools

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM=$(uname -s)

echo "========================================"
echo "System Enumeration Scripts - Test Suite"
echo "========================================"
echo "Platform: $PLATFORM"
echo "Date: $(date)"
echo ""

TOTAL_PASSED=0
TOTAL_FAILED=0
TOTAL_SKIPPED=0

# Function to run a test and track results
run_test() {
    local test_name="$1"
    local test_script="$2"
    local required_platform="${3:-all}"

    echo ""
    echo "========================================="
    echo "Running: $test_name"
    echo "========================================="

    # Check platform requirement
    if [ "$required_platform" != "all" ] && [ "$required_platform" != "$PLATFORM" ]; then
        echo "⊝ SKIPPED - Requires $required_platform platform"
        TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
        return
    fi

    # Check if test exists
    if [ ! -f "$test_script" ]; then
        echo "⊝ SKIPPED - Test file not found: $test_script"
        TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
        return
    fi

    # Make executable
    chmod +x "$test_script"

    # Run the test
    if bash "$test_script"; then
        echo ""
        echo "✓ PASSED: $test_name"
        TOTAL_PASSED=$((TOTAL_PASSED + 1))
    else
        echo ""
        echo "✗ FAILED: $test_name"
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
}

# Unit Tests
echo ""
echo ">>> UNIT TESTS <<<"
run_test "MacOS Function Tests" "$SCRIPT_DIR/unit/test_macos_functions.sh" "Darwin"

# Integration Tests
echo ""
echo ">>> INTEGRATION TESTS <<<"
run_test "Linux Smoke Test" "$SCRIPT_DIR/integration/test_linux_smoke.sh" "Linux"
run_test "MacOS Smoke Test" "$SCRIPT_DIR/integration/test_macos_smoke.sh" "Darwin"
run_test "Output Validation Test" "$SCRIPT_DIR/integration/test_output_validation.sh"

# Security Tests
echo ""
echo ">>> SECURITY TESTS <<<"
run_test "File Permissions Test" "$SCRIPT_DIR/security/test_file_permissions.sh"
run_test "Command Safety Test" "$SCRIPT_DIR/security/test_command_safety.sh"

# Compatibility Tests (requires Docker)
echo ""
echo ">>> COMPATIBILITY TESTS <<<"
if command -v docker &> /dev/null; then
    run_test "Cross-Distribution Test" "$SCRIPT_DIR/compatibility/docker/test_all_distros.sh" "Linux"
else
    echo "⊝ SKIPPED - Docker tests (Docker not available)"
    TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
fi

# Final Summary
echo ""
echo ""
echo "========================================"
echo "TEST SUMMARY"
echo "========================================"
echo "Total Passed:  $TOTAL_PASSED"
echo "Total Failed:  $TOTAL_FAILED"
echo "Total Skipped: $TOTAL_SKIPPED"
echo "========================================"

if [ $TOTAL_FAILED -eq 0 ]; then
    echo "✓ All tests passed!"
    exit 0
else
    echo "✗ Some tests failed"
    exit 1
fi
