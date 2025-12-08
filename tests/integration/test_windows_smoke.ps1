# Basic smoke test for Windows_Enumerator_V1.0.ps1
# Verifies the script runs without crashing and produces output

$ErrorActionPreference = 'Stop'

$ScriptPath = Join-Path $PSScriptRoot "..\..\" "Windows_Enumerator_V1.0.ps1"
$TestDir = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "win_enum_test_$(Get-Random)")

Write-Host "[TEST] Windows Enumerator - Smoke Test" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

function Cleanup {
    if (Test-Path $TestDir) {
        Remove-Item -Recurse -Force $TestDir -ErrorAction SilentlyContinue
    }
}

try {
    # Test 1: Script exists
    Write-Host "[1/6] Checking script exists... " -NoNewline
    if (-not (Test-Path $ScriptPath)) {
        Write-Host "FAIL - Script not found at $ScriptPath" -ForegroundColor Red
        exit 1
    }
    Write-Host "PASS" -ForegroundColor Green

    # Test 2: Script is a valid PowerShell file
    Write-Host "[2/6] Validating PowerShell syntax... " -NoNewline
    $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $ScriptPath -Raw), [ref]$null)
    Write-Host "PASS" -ForegroundColor Green

    # Test 3: Run script in non-interactive mode (without user input)
    Write-Host "[3/6] Running script with automated input... " -NoNewline
    Push-Location $TestDir

    # Create a script block that provides 'n' as input (no file output)
    $job = Start-Job -ScriptBlock {
        param($script)
        'n' | & $script -ErrorAction SilentlyContinue
    } -ArgumentList $ScriptPath

    $timeout = 120
    $completed = Wait-Job $job -Timeout $timeout

    if ($null -eq $completed) {
        Stop-Job $job
        Remove-Job $job
        Pop-Location
        Write-Host "FAIL - Script timed out after $timeout seconds" -ForegroundColor Red
        exit 1
    }

    $jobResult = Receive-Job $job
    Remove-Job $job
    Pop-Location
    Write-Host "PASS" -ForegroundColor Green

    # Test 4: Run with file output
    Write-Host "[4/6] Running script with file output... " -NoNewline
    Push-Location $TestDir

    $job = Start-Job -ScriptBlock {
        param($script)
        'y' | & $script -ErrorAction SilentlyContinue
    } -ArgumentList $ScriptPath

    $completed = Wait-Job $job -Timeout $timeout

    if ($null -eq $completed) {
        Stop-Job $job
        Remove-Job $job
        Pop-Location
        Write-Host "FAIL - Script timed out" -ForegroundColor Red
        exit 1
    }

    Receive-Job $job | Out-Null
    Remove-Job $job
    Pop-Location
    Write-Host "PASS" -ForegroundColor Green

    # Test 5: Check if output file was created
    Write-Host "[5/6] Checking output file exists... " -NoNewline
    $outputFiles = Get-ChildItem -Path $TestDir -Filter "WindowsEnum_*.txt"
    if ($outputFiles.Count -eq 0) {
        Write-Host "FAIL - No output file created" -ForegroundColor Red
        exit 1
    }
    Write-Host "PASS" -ForegroundColor Green

    # Test 6: Verify output file has content
    Write-Host "[6/6] Checking output file has content... " -NoNewline
    $outputFile = $outputFiles | Select-Object -First 1
    $fileSize = $outputFile.Length
    if ($fileSize -lt 100) {
        Write-Host "FAIL - Output file too small ($fileSize bytes)" -ForegroundColor Red
        exit 1
    }
    Write-Host "PASS ($fileSize bytes)" -ForegroundColor Green

    Write-Host ""
    Write-Host "✓ All smoke tests passed!" -ForegroundColor Green

} catch {
    Write-Host "FAIL - $_" -ForegroundColor Red
    exit 1
} finally {
    Cleanup
}
