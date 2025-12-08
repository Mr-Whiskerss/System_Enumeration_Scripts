#!/bin/bash

# Security test: Verify output files have appropriate permissions
# Enumeration reports contain sensitive system information and should not be world-readable

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_DIR=$(mktemp -d)

echo "[TEST] File Permission Security Test"
echo "====================================="

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Detect platform
PLATFORM=$(uname -s)
if [ "$PLATFORM" = "Linux" ]; then
    SCRIPT="$SCRIPT_DIR/Linux_Basic_Enumerator_V1.0.sh"
    OUTPUT_FILE="$TEST_DIR/system_enumeration_report.txt"
elif [ "$PLATFORM" = "Darwin" ]; then
    SCRIPT="$SCRIPT_DIR/MacOS_Basic_Enumerator_V1.1.sh"
    OUTPUT_FILE="$TEST_DIR/system_enumeration_report.txt"
else
    echo "Unsupported platform: $PLATFORM"
    exit 1
fi

echo "Platform: $PLATFORM"
echo ""

# Run the script
echo -n "[1/3] Running enumeration script... "
cd "$TEST_DIR"
chmod +x "$SCRIPT"
timeout 120 bash "$SCRIPT" > /dev/null 2>&1
echo "PASS"

# Check file permissions
echo "[2/3] Checking output file permissions..."

if [ ! -f "$OUTPUT_FILE" ]; then
    echo "FAIL - Output file not created"
    exit 1
fi

# Get file permissions in octal format
PERMS=$(stat -c "%a" "$OUTPUT_FILE" 2>/dev/null || stat -f "%A" "$OUTPUT_FILE" 2>/dev/null)
echo "  Current permissions: $PERMS"

# Extract world-readable bit
WORLD_PERMS=${PERMS: -1}

# Check if world-readable (bit 4 is set in others permissions)
if [ $((WORLD_PERMS & 4)) -ne 0 ]; then
    echo "  ⚠️  WARNING: Output file is world-readable!"
    echo "  This file contains sensitive system information."
    echo "  Recommendation: Modify scripts to set permissions to 600 or 640"
    WARNING=1
else
    echo "  ✓ File is NOT world-readable (good)"
    WARNING=0
fi

# Check if world-writable (critical security issue)
echo -n "[3/3] Checking if world-writable... "
if [ $((WORLD_PERMS & 2)) -ne 0 ]; then
    echo "FAIL - Output file is world-writable! This is a security vulnerability."
    exit 1
else
    echo "PASS"
fi

echo ""
if [ $WARNING -eq 1 ]; then
    echo "⚠️  Test completed with warnings"
    echo "   Consider adding 'chmod 600 \"\$OUTPUT\"' to scripts for better security"
else
    echo "✓ Security test passed!"
fi
