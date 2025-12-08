# Test Suite for System Enumeration Scripts

Comprehensive test suite for validating the Linux, MacOS, and Windows enumeration scripts across different environments and configurations.

## Test Coverage Overview

- **Unit Tests**: Test individual functions in isolation
- **Integration Tests**: Test full script execution and output validation
- **Security Tests**: Validate file permissions and command safety
- **Compatibility Tests**: Cross-platform and cross-distribution testing

## Quick Start

### Run All Tests (Linux/MacOS)

```bash
cd tests
chmod +x run_tests.sh
./run_tests.sh
```

### Run Individual Test Categories

```bash
# Unit tests
./unit/test_macos_functions.sh

# Integration tests
./integration/test_linux_smoke.sh
./integration/test_macos_smoke.sh
./integration/test_output_validation.sh

# Security tests
./security/test_file_permissions.sh
./security/test_command_safety.sh

# Docker-based cross-distribution tests (Linux only, requires Docker)
./compatibility/docker/test_all_distros.sh
```

### Windows Tests

```powershell
# Run from PowerShell
.\tests\integration\test_windows_smoke.ps1
```

## Test Categories

### 1. Unit Tests (`unit/`)

**test_macos_functions.sh**
- Tests the `run_and_log` function from MacOS_Basic_Enumerator_V1.1.sh
- Validates section header formatting
- Tests command availability checking
- Verifies error handling for missing commands

**Platform**: macOS

### 2. Integration Tests (`integration/`)

**test_linux_smoke.sh**
- Verifies Linux script runs without crashing
- Checks output file creation
- Validates output has content

**Platform**: Linux

**test_macos_smoke.sh**
- Verifies MacOS script runs without crashing
- Checks output file creation
- Validates output has content
- Cleans up background processes (caffeinate)

**Platform**: macOS

**test_windows_smoke.ps1**
- Verifies Windows script runs without crashing
- Tests both interactive modes (with/without file output)
- Validates PowerShell syntax
- Checks output file creation and content

**Platform**: Windows

**test_output_validation.sh**
- Validates all expected sections are present in reports
- Checks for error messages in output
- Verifies report structure and formatting
- Platform-aware (runs appropriate script for Linux or macOS)

**Platform**: Linux, macOS

### 3. Security Tests (`security/`)

**test_file_permissions.sh**
- Checks output file permissions
- Warns if files are world-readable (contains sensitive info)
- Fails if files are world-writable (security vulnerability)
- Recommends permission improvements

**Platform**: Linux, macOS

**test_command_safety.sh**
- Detects use of `eval` and `Invoke-Expression`
- Checks for unquoted variables
- Validates user input handling
- Assesses command injection risk
- Reports on mitigation strategies

**Platform**: All (analyzes all scripts)

### 4. Compatibility Tests (`compatibility/`)

**docker/test_all_distros.sh**
- Tests Linux script on multiple distributions
- Distributions tested:
  - Ubuntu 22.04 (Debian-based, apt)
  - CentOS 7 (RHEL-based, yum/rpm)
  - Alpine 3.18 (Minimal, apk)
  - Alpine minimal (Intentionally sparse, tests error handling)
- Validates output on each platform
- Checks error rates for missing commands

**Platform**: Linux (requires Docker)

**Dockerfiles**:
- `Dockerfile.ubuntu` - Full-featured Ubuntu environment
- `Dockerfile.centos` - RHEL/CentOS environment
- `Dockerfile.alpine` - Lightweight Alpine Linux
- `Dockerfile.minimal` - Minimal environment (error handling test)

## Test Results Interpretation

### Exit Codes
- `0` - All tests passed
- `1` - One or more tests failed
- `124` - Test timed out (may be expected for certain tests)

### Output Indicators
- `✓ PASS` - Test passed successfully
- `✗ FAIL` - Test failed
- `⊝ SKIPPED` - Test skipped (wrong platform or missing dependencies)
- `⚠️ WARNING` - Test passed but found issues worth reviewing

## Requirements

### All Platforms
- Bash 4.0+ (for shell scripts)
- PowerShell 5.1+ (for Windows tests)
- Write permissions in test directory

### Docker Tests (Optional)
- Docker installed and running
- Permissions to build and run containers
- ~500MB disk space for container images

### MacOS Tests
- macOS 10.14+ recommended
- Standard command-line tools

### Windows Tests
- Windows 10/11 or Windows Server 2016+
- PowerShell execution policy allowing script execution

## Adding New Tests

### 1. Create Test File

```bash
# For shell scripts
touch tests/category/test_name.sh
chmod +x tests/category/test_name.sh

# For PowerShell
touch tests/category/test_name.ps1
```

### 2. Test Template (Shell)

```bash
#!/bin/bash
set -e

echo "[TEST] Test Name"
echo "================"

# Your test logic here
# Exit 0 for success, 1 for failure

echo "✓ Test passed!"
exit 0
```

### 3. Add to Test Runner

Edit `run_tests.sh` and add:

```bash
run_test "Your Test Name" "$SCRIPT_DIR/category/test_name.sh" "Linux"
```

## Continuous Integration

These tests are designed to run in CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Tests
  run: |
    cd tests
    chmod +x run_tests.sh
    ./run_tests.sh
```

## Known Issues & Limitations

1. **File Permissions Test**: Current scripts create world-readable output files. This is flagged as a warning, not a failure. Consider adding `chmod 600 "$OUTPUT"` to scripts.

2. **MacOS caffeinate**: The MacOS script starts `caffeinate &` which may leave processes running. Tests clean this up, but manual runs may need `pkill caffeinate`.

3. **Docker Tests**: Require Docker daemon running. Will be skipped if Docker is unavailable.

4. **Windows Interactive Mode**: Windows script prompts for user input. Tests automate this, but manual testing should verify both modes.

5. **Command Availability**: Scripts are designed to handle missing commands gracefully. Tests verify this but expect some errors on minimal systems.

## Future Test Improvements

### High Priority
- [ ] PowerShell version compatibility tests (5.1 vs 7.x)
- [ ] Performance tests for recursive file operations
- [ ] Report parsing validation (machine-readable output)
- [ ] Extended mode feature tests (Windows)

### Medium Priority
- [ ] macOS version compatibility (Intel vs Apple Silicon)
- [ ] Network isolation tests (offline operation)
- [ ] Large filesystem stress tests
- [ ] Memory usage profiling

### Low Priority
- [ ] Output format validation (structured data)
- [ ] Localization tests (non-English systems)
- [ ] Custom configuration tests
- [ ] Regression test suite for specific bugs

## Contributing

When adding features to the enumeration scripts:

1. Add corresponding tests
2. Run full test suite before committing
3. Update this README if adding new test categories
4. Ensure tests work on target platforms

## Support

For test failures or questions:
- Check test output for specific failure reasons
- Review known issues above
- Ensure platform requirements are met
- Check script permissions and paths
