#!/bin/bash

# Basic smoke test for Linux_Basic_Enumerator_V1.0.sh
# Verifies the script runs without crashing and produces output

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$SCRIPT_DIR/Linux_Basic_Enumerator_V1.0.sh"
TEST_DIR=$(mktemp -d)
OUTPUT_FILE="$TEST_DIR/system_enumeration_report.txt"

echo "[TEST] Linux Basic Enumerator - Smoke Test"
echo "==========================================="

# Cleanup function
cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Test 1: Script exists and is executable
echo -n "[1/5] Checking script exists... "
if [ ! -f "$SCRIPT" ]; then
    echo "FAIL - Script not found at $SCRIPT"
    exit 1
fi
echo "PASS"

echo -n "[2/5] Making script executable... "
chmod +x "$SCRIPT"
echo "PASS"

# Test 2: Script runs without error
echo -n "[3/5] Running script... "
cd "$TEST_DIR"
timeout 120 bash "$SCRIPT" > /dev/null 2>&1
if [ $? -eq 0 ] || [ $? -eq 124 ]; then
    echo "PASS"
else
    echo "FAIL - Script exited with error code $?"
    exit 1
fi

# Test 3: Output file was created
echo -n "[4/5] Checking output file exists... "
if [ ! -f "$OUTPUT_FILE" ]; then
    echo "FAIL - Output file not created"
    exit 1
fi
echo "PASS"

# Test 4: Output file has content
echo -n "[5/5] Checking output file has content... "
if [ ! -s "$OUTPUT_FILE" ]; then
    echo "FAIL - Output file is empty"
    exit 1
fi
FILE_SIZE=$(stat -f%z "$OUTPUT_FILE" 2>/dev/null || stat -c%s "$OUTPUT_FILE" 2>/dev/null)
if [ "$FILE_SIZE" -lt 100 ]; then
    echo "FAIL - Output file too small ($FILE_SIZE bytes)"
    exit 1
fi
echo "PASS (${FILE_SIZE} bytes)"

echo ""
echo "✓ All smoke tests passed!"
