#!/bin/bash

# Unit tests for MacOS run_and_log function
# Tests the function in isolation without running the full script

set -e

TEST_DIR=$(mktemp -d)
OUTPUT_FILE="$TEST_DIR/test_output.txt"

echo "[TEST] MacOS run_and_log Function Unit Tests"
echo "============================================="
echo ""

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Import the run_and_log function from the MacOS script
# We'll define it here for testing purposes
run_and_log() {
    echo "===== $1 =====" >> "$OUTPUT_FILE"
    if command -v ${3:-true} >/dev/null 2>&1; then
        eval "$2" >> "$OUTPUT_FILE" 2>&1
    else
        echo "[Command not found or unsupported on this system]" >> "$OUTPUT_FILE"
    fi
    echo -e "\n" >> "$OUTPUT_FILE"
}

PASSED=0
FAILED=0

# Test 1: Basic command execution
echo -n "[1/6] Testing basic command execution... "
> "$OUTPUT_FILE"
run_and_log "Test Date" "date"

if grep -q "===== Test Date =====" "$OUTPUT_FILE"; then
    if [ $(wc -l < "$OUTPUT_FILE") -gt 1 ]; then
        echo "PASS"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL - No output from command"
        FAILED=$((FAILED + 1))
    fi
else
    echo "FAIL - Section header not found"
    FAILED=$((FAILED + 1))
fi

# Test 2: Command with output
echo -n "[2/6] Testing command with known output... "
> "$OUTPUT_FILE"
run_and_log "Echo Test" "echo 'Hello World'"

if grep -q "Hello World" "$OUTPUT_FILE"; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL - Expected output not found"
    cat "$OUTPUT_FILE"
    FAILED=$((FAILED + 1))
fi

# Test 3: Non-existent command (should show error message)
echo -n "[3/6] Testing non-existent command handling... "
> "$OUTPUT_FILE"
run_and_log "Fake Command" "nonexistentcommand12345" "nonexistentcommand12345"

if grep -q "Command not found or unsupported" "$OUTPUT_FILE"; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL - Expected error message not found"
    cat "$OUTPUT_FILE"
    FAILED=$((FAILED + 1))
fi

# Test 4: Multiple sections in same file
echo -n "[4/6] Testing multiple sections... "
> "$OUTPUT_FILE"
run_and_log "Section 1" "echo 'First'"
run_and_log "Section 2" "echo 'Second'"

SECTION_COUNT=$(grep -c "=====" "$OUTPUT_FILE")
if [ "$SECTION_COUNT" -eq 4 ]; then  # 2 sections * 2 lines each (header + content)
    if grep -q "First" "$OUTPUT_FILE" && grep -q "Second" "$OUTPUT_FILE"; then
        echo "PASS"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL - Content not found"
        FAILED=$((FAILED + 1))
    fi
else
    echo "FAIL - Expected 4 separator lines, found $SECTION_COUNT"
    FAILED=$((FAILED + 1))
fi

# Test 5: Command with error output
echo -n "[5/6] Testing command with stderr... "
> "$OUTPUT_FILE"
run_and_log "Error Test" "ls /nonexistent/path 2>&1"

if grep -q "===== Error Test =====" "$OUTPUT_FILE"; then
    # Should contain error output
    if grep -qi "no such file\|cannot access" "$OUTPUT_FILE"; then
        echo "PASS"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL - Expected error output not found"
        FAILED=$((FAILED + 1))
    fi
else
    echo "FAIL - Section header not found"
    FAILED=$((FAILED + 1))
fi

# Test 6: Section header formatting
echo -n "[6/6] Testing section header format... "
> "$OUTPUT_FILE"
run_and_log "Format Test" "echo 'test'"

HEADER_LINE=$(grep "=====" "$OUTPUT_FILE" | head -1)
if echo "$HEADER_LINE" | grep -q "===== Format Test ====="; then
    echo "PASS"
    PASSED=$((PASSED + 1))
else
    echo "FAIL - Header format incorrect"
    echo "  Expected: ===== Format Test ====="
    echo "  Got: $HEADER_LINE"
    FAILED=$((FAILED + 1))
fi

echo ""
echo "========================================"
echo "Results: $PASSED passed, $FAILED failed"
echo "========================================"

if [ $FAILED -eq 0 ]; then
    echo "✓ All unit tests passed!"
    exit 0
else
    echo "❌ Some tests failed"
    exit 1
fi
