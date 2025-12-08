#!/bin/bash

# Cross-distribution compatibility test for Linux enumeration script
# Tests the script on Ubuntu, CentOS, Alpine, and a minimal environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DOCKER_DIR="$(dirname "${BASH_SOURCE[0]}")"
LINUX_SCRIPT="$SCRIPT_DIR/Linux_Basic_Enumerator_V1.0.sh"

echo "========================================"
echo "Linux Cross-Distribution Compatibility Test"
echo "========================================"
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed or not in PATH"
    echo "   Please install Docker to run cross-distribution tests"
    exit 1
fi

# Check if script exists
if [ ! -f "$LINUX_SCRIPT" ]; then
    echo "❌ Linux script not found at: $LINUX_SCRIPT"
    exit 1
fi

# Copy script to docker directory for build context
cp "$LINUX_SCRIPT" "$DOCKER_DIR/"

DISTROS=("ubuntu" "centos" "alpine" "minimal")
PASSED=0
FAILED=0
WARNINGS=0

for distro in "${DISTROS[@]}"; do
    echo "----------------------------------------"
    echo "Testing on: $distro"
    echo "----------------------------------------"

    DOCKERFILE="$DOCKER_DIR/Dockerfile.$distro"
    IMAGE_NAME="enum-test-$distro"

    if [ ! -f "$DOCKERFILE" ]; then
        echo "⚠️  Dockerfile not found: $DOCKERFILE"
        WARNINGS=$((WARNINGS + 1))
        continue
    fi

    # Build the Docker image
    echo -n "Building image... "
    if docker build -f "$DOCKERFILE" -t "$IMAGE_NAME" "$DOCKER_DIR" > /tmp/docker_build_$distro.log 2>&1; then
        echo "✓"
    else
        echo "❌ Build failed"
        echo "See /tmp/docker_build_$distro.log for details"
        FAILED=$((FAILED + 1))
        continue
    fi

    # Run the container
    echo -n "Running enumeration script... "
    if timeout 120 docker run --rm "$IMAGE_NAME" > /tmp/enum_output_$distro.txt 2>&1; then
        echo "✓"
    else
        EXIT_CODE=$?
        if [ $EXIT_CODE -eq 124 ]; then
            echo "⚠️  Timeout (may be expected for minimal systems)"
            WARNINGS=$((WARNINGS + 1))
        else
            echo "❌ Failed with exit code $EXIT_CODE"
            FAILED=$((FAILED + 1))
            continue
        fi
    fi

    # Verify output was created and has content
    echo -n "Checking output... "
    OUTPUT_SIZE=$(wc -c < /tmp/enum_output_$distro.txt)

    if [ "$OUTPUT_SIZE" -lt 100 ]; then
        echo "❌ Output too small ($OUTPUT_SIZE bytes)"
        FAILED=$((FAILED + 1))
        continue
    fi

    # Check for excessive errors
    ERROR_COUNT=$(grep -i "command not found\|no such file" /tmp/enum_output_$distro.txt | wc -l)

    if [ "$distro" = "minimal" ]; then
        # Expect many errors on minimal system
        if [ "$ERROR_COUNT" -gt 50 ]; then
            echo "✓ ($OUTPUT_SIZE bytes, $ERROR_COUNT missing commands - expected)"
        else
            echo "⚠️  Expected more errors on minimal system"
            WARNINGS=$((WARNINGS + 1))
        fi
    else
        # Other systems should have fewer errors
        if [ "$ERROR_COUNT" -gt 20 ]; then
            echo "⚠️  Many commands not found ($ERROR_COUNT errors, $OUTPUT_SIZE bytes)"
            WARNINGS=$((WARNINGS + 1))
        else
            echo "✓ ($OUTPUT_SIZE bytes, $ERROR_COUNT errors)"
        fi
    fi

    PASSED=$((PASSED + 1))

    # Save output for inspection
    mv /tmp/enum_output_$distro.txt "$DOCKER_DIR/output_$distro.txt"
    echo "   Output saved to: $DOCKER_DIR/output_$distro.txt"
done

# Cleanup
rm -f "$DOCKER_DIR/Linux_Basic_Enumerator_V1.0.sh"

echo ""
echo "========================================"
echo "Results Summary"
echo "========================================"
echo "Passed:   $PASSED"
echo "Failed:   $FAILED"
echo "Warnings: $WARNINGS"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "✓ All distribution tests passed!"
    exit 0
else
    echo "❌ Some tests failed"
    exit 1
fi
