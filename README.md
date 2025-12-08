# System Enumeration Scripts

> **Lightweight, cross-platform system enumeration tools for security assessments**

A collection of PowerShell and Bash scripts designed for penetration testers, security researchers, and system administrators to quickly gather comprehensive system information during security assessments, build reviews, and infrastructure audits.

[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)]()
[![License](https://img.shields.io/badge/License-MIT-green)]()
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen)]()

---

## 📋 Table of Contents

- [Features](#-features)
- [Scripts Overview](#-scripts-overview)
- [Quick Start](#-quick-start)
- [Detailed Usage](#-detailed-usage)
- [What Data is Collected](#-what-data-is-collected)
- [Output & Security](#-output--security)
- [Testing](#-testing)
- [Use Cases](#-use-cases)
- [Limitations](#-limitations)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [Disclaimer](#-disclaimer)
- [Author](#-author)

---

## ✨ Features

### Core Capabilities
- ✅ **OS & System Information** - Kernel version, distribution, architecture
- ✅ **Network Enumeration** - Interfaces, connections, routing tables, firewall rules
- ✅ **Service Discovery** - Running processes, services, startup programs
- ✅ **User & Group Analysis** - Local users, groups, administrators, logged-in users
- ✅ **Software Inventory** - Installed applications, packages, frameworks
- ✅ **Security Analysis** - File permissions, scheduled jobs, privilege escalation vectors
- ✅ **Configuration Files** - Service configs, environment variables, shell profiles
- ✅ **Extended Scanning** - Deep file searches, credential hunting (Windows)

### Technical Features
- 🚀 **No Dependencies** - Uses built-in system commands only
- 🔒 **Secure by Default** - Output files protected with 600 permissions
- 📊 **Comprehensive Reports** - All data saved to timestamped text files
- 🎯 **Non-Intrusive** - Read-only operations, no system modifications
- ⚡ **Fast Execution** - Completes in under 2 minutes on typical systems
- 🧪 **Tested** - Comprehensive test suite with 70% coverage

---

## 📦 Scripts Overview

### Linux_Basic_Enumerator_V1.0.sh
**Platform:** Linux (Ubuntu, Debian, CentOS, RHEL, Arch, Alpine)
**Requirements:** Bash 4.0+
**Privileges:** No root required (some info limited without root)

**Key Features:**
- Distribution detection via `/etc/issue`, `/etc/*-release`
- Package manager detection (apt, yum, rpm)
- Network enumeration (ifconfig, ip, netstat)
- SUID/world-writable file searches
- Cron job and scheduled task enumeration
- Password search in config files

---

### MacOS_Basic_Enumerator_V1.1.sh
**Platform:** macOS 10.14+ (Tested on M1/M2)
**Requirements:** Bash 3.2+
**Privileges:** No root required

**Key Features:**
- System Profiler integration
- Launch daemons and agents enumeration
- Network service configuration
- Clipboard content capture
- Wi-Fi configuration and proxy settings
- Spotlight search for sensitive files
- Automatic process cleanup on exit

---

### Windows_Enumerator_V1.0.ps1
**Platform:** Windows 10/11, Server 2016+
**Requirements:** PowerShell 5.1+
**Privileges:** Works with standard user (elevated recommended)

**Key Features:**
- Interactive mode with file output option
- Extended scan mode with `-Extended` parameter
- Unquoted service path detection
- AlwaysInstallElevated registry check
- Credential Manager enumeration
- Antivirus detection
- UAC configuration analysis
- PowerShell history retrieval

**Extended Mode Additions:**
- SAM backup file checks
- Recent documents enumeration
- Deep file searches (archives, secrets, keys)
- Last modified files tracking

---

## 🚀 Quick Start

### Linux
```bash
# Download and run
chmod +x Linux_Basic_Enumerator_V1.0.sh
./Linux_Basic_Enumerator_V1.0.sh

# Output saved to: system_enumeration_report.txt
```

### macOS
```bash
# Download and run
chmod +x MacOS_Basic_Enumerator_V1.1.sh
./MacOS_Basic_Enumerator_V1.1.sh

# Output saved to: system_enumeration_report.txt
```

### Windows
```powershell
# Standard scan
.\Windows_Enumerator_V1.0.ps1

# Extended deep scan
.\Windows_Enumerator_V1.0.ps1 -Extended
```

**Note:** Windows script will prompt to save output to file (timestamped).

---

## 📖 Detailed Usage

### Linux Script

```bash
# Basic execution
./Linux_Basic_Enumerator_V1.0.sh

# Run with timestamp in output filename
OUTPUT="enum_$(date +%Y%m%d_%H%M%S).txt" ./Linux_Basic_Enumerator_V1.0.sh

# Run and view output in real-time
./Linux_Basic_Enumerator_V1.0.sh | tee -a realtime_output.txt
```

**Output Location:** `./system_enumeration_report.txt`
**File Permissions:** 600 (owner read/write only)
**Typical Size:** 200KB - 2MB depending on system

---

### macOS Script

```bash
# Basic execution
./MacOS_Basic_Enumerator_V1.1.sh

# Background execution
nohup ./MacOS_Basic_Enumerator_V1.1.sh &

# Check progress
tail -f system_enumeration_report.txt
```

**Output Location:** `./system_enumeration_report.txt`
**File Permissions:** 600 (owner read/write only)
**Typical Size:** 300KB - 5MB depending on installed software

**Note:** Script automatically cleans up `caffeinate` process on exit.

---

### Windows Script

```powershell
# Interactive mode (prompts for file output)
.\Windows_Enumerator_V1.0.ps1

# Extended scan with all features
.\Windows_Enumerator_V1.0.ps1 -Extended

# Run with execution policy bypass (if needed)
PowerShell -ExecutionPolicy Bypass -File .\Windows_Enumerator_V1.0.ps1

# Run as Administrator for full enumeration
# Right-click PowerShell -> "Run as Administrator"
.\Windows_Enumerator_V1.0.ps1 -Extended
```

**Output Location:** `.\WindowsEnum_YYYYMMDD_HHMMSS.txt` (if saving to file)
**Typical Size:** 100KB - 1MB depending on system

**Extended Mode:** Adds ~30 seconds to execution time, searches for:
- SAM backup files
- Recent documents
- Sensitive file types (.zip, .rar, .kdbx, .pem, .ppk, .rdp)
- Recently modified files

---

## 🔍 What Data is Collected

### System Information
- Operating system name, version, build number
- Kernel/OS version and architecture
- System uptime and current date/time
- Hostname and domain information
- CPU and memory information

### Network Configuration
- Network interfaces and IP addresses
- Routing tables and ARP cache
- Active network connections (LISTEN, ESTABLISHED)
- DNS configuration
- Firewall rules and status
- Wi-Fi configurations (macOS)
- Proxy settings

### User & Authentication
- Local user accounts
- Group memberships
- Currently logged-in users
- Administrator/sudo users
- User home directories
- Login history (last, w)
- Credential manager entries (Windows)
- Autologon registry keys (Windows)

### Software & Services
- Installed applications and packages
- Running processes and services
- Startup programs and launch items
- Scheduled tasks and cron jobs
- Service configuration files

### Security Analysis
- World-writable files
- SUID/SGID files (Linux)
- Unquoted service paths (Windows)
- AlwaysInstallElevated settings (Windows)
- File permissions on sensitive directories
- Environment variables
- PowerShell history (Windows)

### Files & Directories
- Contents of /etc/ (Linux)
- Service configuration files
- Recently accessed files (Extended mode)
- Files containing "password" keyword
- Backup files (.bak, .old)
- Certificate files (.pem, .crt, .key)

**⚠️ Sensitive Information:** These scripts collect system configuration data that may include:
- Usernames and group memberships
- Network topology
- Installed software versions
- Service configurations
- File paths and permissions

---

## 🔒 Output & Security

### File Permissions

All scripts now set **secure file permissions** on output files:

```bash
# Linux/macOS: 600 (owner read/write only)
-rw------- 1 user user 245678 Dec 08 10:30 system_enumeration_report.txt

# Windows: Output files inherit current directory permissions
# Recommend storing in user-only accessible directory
```

**Security Implications:**
- Output files contain **sensitive system information**
- Files are **not world-readable** by default
- Store outputs in encrypted directories for long-term retention
- Delete outputs after transferring to secure storage
- **Never commit output files to version control**

### Secure Usage Practices

```bash
# Create secure directory for outputs
mkdir -p ~/enum_outputs
chmod 700 ~/enum_outputs

# Run script in secure directory
cd ~/enum_outputs
~/path/to/Linux_Basic_Enumerator_V1.0.sh

# Transfer securely (SCP example)
scp system_enumeration_report.txt user@secure-host:/encrypted/storage/

# Securely delete local copy
shred -vfz -n 3 system_enumeration_report.txt
```

---

## 🧪 Testing

This repository includes a comprehensive test suite with **~70% coverage**.

### Run All Tests

```bash
cd tests
chmod +x run_tests.sh
./run_tests.sh
```

### Test Categories

- **Unit Tests:** Function-level testing (MacOS)
- **Integration Tests:** Full script execution on all platforms
- **Security Tests:** File permissions and command safety validation
- **Compatibility Tests:** Cross-distribution testing via Docker

### Individual Tests

```bash
# Quick smoke test (Linux)
./tests/integration/test_linux_smoke.sh

# Security validation
./tests/security/test_file_permissions.sh
./tests/security/test_command_safety.sh

# Cross-distribution (requires Docker)
./tests/compatibility/docker/test_all_distros.sh
```

**See [tests/README.md](tests/README.md) for complete testing documentation.**

---

## 💼 Use Cases

### Penetration Testing
- Initial foothold enumeration
- Privilege escalation reconnaissance
- Network mapping and service discovery
- Quick system profiling

### Security Audits
- Build review assessments
- Compliance validation
- Security posture evaluation
- Configuration review

### Incident Response
- Rapid system state capture
- Baseline comparison
- Compromise assessment
- Forensic data collection

### System Administration
- Inventory management
- Configuration documentation
- Migration planning
- Troubleshooting

---

## ⚠️ Limitations

### By Design
- **Read-only operations** - No system modifications
- **No privilege escalation** - Scripts don't attempt to gain elevated access
- **Limited stealth** - Commands may be logged by security tools
- **Point-in-time snapshot** - Data is collected at execution time only

### Technical Limitations
- Some information requires elevated privileges
- Command availability varies by distribution/version
- Network scanning is local only (no remote enumeration)
- Large filesystems may cause extended execution times
- Some commands may not exist on minimal installations

### Not a Replacement For
- **LinPEAS / WinPEAS** - More comprehensive privilege escalation tools
- **LinEnum** - Deeper Linux enumeration
- **Nmap** - Network scanning and service detection
- **Bloodhound** - Active Directory enumeration
- **OSINT tools** - External reconnaissance

**These scripts are designed for quick, basic enumeration during assessments.**

---

## 🔧 Troubleshooting

### Common Issues

#### "Permission denied" when running script
```bash
# Solution: Make script executable
chmod +x Linux_Basic_Enumerator_V1.0.sh
```

#### "Command not found" errors in output
This is **expected behavior** on minimal systems. Scripts attempt multiple commands for compatibility across different distributions. Missing commands are logged but don't halt execution.

#### Script hangs or takes too long
```bash
# Timeout Linux/macOS scripts after 5 minutes
timeout 300 ./Linux_Basic_Enumerator_V1.0.sh

# For Windows, use Ctrl+C to interrupt
```

Common causes:
- Large filesystem searches (`find /`)
- Many installed packages
- Slow network connections (DNS lookups)

#### Windows: "Execution policy" error
```powershell
# Solution 1: Bypass policy for this execution
PowerShell -ExecutionPolicy Bypass -File .\Windows_Enumerator_V1.0.ps1

# Solution 2: Set policy for current user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### macOS: "Caffeinate" process remains after script
This should be automatically cleaned up. If not:
```bash
pkill -f caffeinate
```

#### Output file is empty or very small
- Check script completed successfully (no errors)
- Verify you have read permissions on system directories
- Some commands may require elevated privileges
- Check disk space

---

## 🤝 Contributing

Contributions are welcome! This project is designed for educational and authorized security testing.

### Ways to Contribute
- 🐛 Report bugs or issues
- 💡 Suggest new enumeration checks
- 🧪 Add test cases
- 📖 Improve documentation
- 🔧 Submit pull requests

### Development Guidelines
1. **Test your changes** - Run the test suite
2. **Maintain compatibility** - Support multiple OS versions
3. **Follow coding style** - Match existing script patterns
4. **Document changes** - Update README and comments
5. **Security first** - Never weaken security controls

### Adding New Enumeration Checks

```bash
# Linux/macOS
echo "New Section Title" | tee -a "$OUTPUT"
your_command_here | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# Windows - add to $commands dictionary
$commands['New Check Name'] = 'PowerShell-Command-Here'
```

### Running Tests Before Committing

```bash
cd tests
./run_tests.sh

# All tests should pass before submitting PR
```

---

## 📜 Disclaimer

**IMPORTANT LEGAL NOTICE:**

These scripts are intended **ONLY** for:
- ✅ Authorized security assessments
- ✅ Penetration testing engagements with written permission
- ✅ Educational purposes in controlled environments
- ✅ Personal systems you own or have explicit permission to test
- ✅ Security research in isolated lab environments
- ✅ CTF competitions and authorized challenges

**UNAUTHORIZED USE IS ILLEGAL.**

- ❌ Do NOT use on systems you do not own
- ❌ Do NOT use without explicit written authorization
- ❌ Do NOT use for malicious purposes
- ❌ Do NOT use to violate privacy or security policies

**Legal Responsibility:**
- Users are solely responsible for compliance with applicable laws
- Unauthorized access to computer systems is illegal in most jurisdictions
- Always obtain proper authorization before testing
- The author assumes no liability for misuse of these tools

**By using these scripts, you agree to use them ethically and legally.**

---

## 📄 License

This project is licensed under the MIT License - see below for details.

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 👤 Author

**MrWhiskers**

- GitHub: [@Mr-Whiskerss](https://github.com/Mr-Whiskerss)
- Purpose: Created for penetration testing and security assessments
- Feedback: Open issues or pull requests on GitHub

### Acknowledgments
- Inspired by LinPEAS, LinEnum, and HackTricks
- Community contributions and feedback
- Security researchers and penetration testers

---

## 🔗 Related Projects

- [LinPEAS](https://github.com/carlospolop/PEASS-ng) - Advanced Linux privilege escalation
- [WinPEAS](https://github.com/carlospolop/PEASS-ng) - Advanced Windows privilege escalation
- [LinEnum](https://github.com/rebootuser/LinEnum) - Linux enumeration
- [HackTricks](https://book.hacktricks.xyz/) - Security knowledge base

---

## 📊 Project Status

- ✅ **Active Development** - Scripts maintained and tested
- ✅ **Production Ready** - Suitable for security assessments
- ✅ **Comprehensive Tests** - 70% test coverage
- ✅ **Security Hardened** - Secure file permissions and practices
- ✅ **Cross-Platform** - Windows, Linux, macOS support

**Last Updated:** December 2024
**Version:** 1.0 (Linux), 1.1 (macOS), 1.0 (Windows)

---

<div align="center">

**⭐ Star this repository if you find it useful!**

**🐛 Found a bug? [Open an issue](https://github.com/Mr-Whiskerss/System_Enumeration_Scripts/issues)**

**📖 Questions? Check the [Troubleshooting](#-troubleshooting) section**

---

*Made with ❤️ for the cybersecurity community*

</div>
