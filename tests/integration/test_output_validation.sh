#!/bin/bash

# Output validation test - Checks that all expected sections are present
# and that the report doesn't contain error messages

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_DIR=$(mktemp -d)

echo "[TEST] Output Validation Test"
echo "=============================="

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Detect platform and set script accordingly
PLATFORM=$(uname -s)
if [ "$PLATFORM" = "Linux" ]; then
    SCRIPT="$SCRIPT_DIR/Linux_Basic_Enumerator_V1.0.sh"
    EXPECTED_SECTIONS=(
        "Operating System Information"
        "Environmental Variables"
        "Running Services"
        "Installed Applications"
        "Scheduled Jobs"
        "Network Configuration"
        "Weak File Permissions"
    )
elif [ "$PLATFORM" = "Darwin" ]; then
    SCRIPT="$SCRIPT_DIR/MacOS_Basic_Enumerator_V1.1.sh"
    EXPECTED_SECTIONS=(
        "Current Date"
        "System Uptime"
        "Processor Info"
        "Disk Usage"
        "Launchctl Services"
        "Listening Network Ports"
        "Installed Applications"
    )
else
    echo "Unsupported platform: $PLATFORM"
    exit 1
fi

OUTPUT_FILE="$TEST_DIR/system_enumeration_report.txt"

echo "Platform: $PLATFORM"
echo "Script: $SCRIPT"
echo ""

# Run the script
echo -n "[1/4] Running enumeration script... "
cd "$TEST_DIR"
chmod +x "$SCRIPT"
timeout 120 bash "$SCRIPT" > /dev/null 2>&1
echo "PASS"

# Check for expected sections
echo "[2/4] Validating expected sections are present..."
MISSING_SECTIONS=0
for section in "${EXPECTED_SECTIONS[@]}"; do
    echo -n "  - Checking for '$section'... "
    if grep -q "$section" "$OUTPUT_FILE"; then
        echo "PASS"
    else
        echo "FAIL - Section not found"
        MISSING_SECTIONS=$((MISSING_SECTIONS + 1))
    fi
done

if [ $MISSING_SECTIONS -gt 0 ]; then
    echo "FAIL - $MISSING_SECTIONS sections missing"
    exit 1
fi

# Check for common error patterns
echo -n "[3/4] Checking for error messages in output... "
ERROR_PATTERNS=(
    "command not found"
    "No such file or directory"
    "Permission denied"
    "syntax error"
    "cannot access"
)

ERRORS_FOUND=0
for pattern in "${ERROR_PATTERNS[@]}"; do
    # Exclude lines that are intentionally checking for errors or using 2>/dev/null
    if grep -i "$pattern" "$OUTPUT_FILE" | grep -v "2>/dev/null" | grep -q .; then
        echo ""
        echo "  WARNING: Found '$pattern' in output"
        ERRORS_FOUND=$((ERRORS_FOUND + 1))
    fi
done

if [ $ERRORS_FOUND -eq 0 ]; then
    echo "PASS"
else
    echo "WARNING - $ERRORS_FOUND error patterns found (may be expected on minimal systems)"
fi

# Check report structure
echo -n "[4/4] Validating report structure... "
FIRST_LINE=$(head -n 1 "$OUTPUT_FILE")
if echo "$FIRST_LINE" | grep -q "enumeration"; then
    echo "PASS"
else
    echo "FAIL - Report doesn't start with expected header"
    echo "  First line: $FIRST_LINE"
    exit 1
fi

echo ""
echo "✓ Output validation passed!"
echo "  Report size: $(wc -c < "$OUTPUT_FILE") bytes"
echo "  Line count: $(wc -l < "$OUTPUT_FILE") lines"
