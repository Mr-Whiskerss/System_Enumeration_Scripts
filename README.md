<div align="center">

```
███████╗██╗   ██╗███████╗███████╗███╗   ██╗██╗   ██╗███╗   ███╗
██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝████╗  ██║██║   ██║████╗ ████║
█████╗   ╚████╔╝ ███████╗█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
██╔══╝    ╚██╔╝  ╚════██║██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
███████╗   ██║   ███████║███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
```

# System Enumeration Scripts

**Rapid, cross-platform system enumeration for security professionals**

[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue?style=flat-square)](#scripts)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.0%2B-5391FE?style=flat-square&logo=powershell&logoColor=white)](#windows)
[![Shell](https://img.shields.io/badge/Shell-Bash%204.0%2B-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)](#linux--macos)
[![License](https://img.shields.io/badge/license-Educational%20Use-orange?style=flat-square)](#legal-disclaimer)
[![Authorised Use Only](https://img.shields.io/badge/%E2%9A%A0%EF%B8%8F-Authorised%20Use%20Only-red?style=flat-square)](#legal-disclaimer)

</div>

---

## Overview

A collection of lightweight, standalone enumeration scripts designed to give penetration testers and security professionals a rapid, consistent picture of a target system — with no dependencies, no installations, and no external tools required.

Built for **build reviews**, **post-exploitation enumeration**, and **privilege escalation triage** across Windows, Linux, and macOS.

---

## Scripts

| Script | Platform | Version | Format | Notes |
|--------|----------|---------|--------|-------|
| [`Windows_Enumerator_V2.0.ps1`](Windows_Enumerator_V2.0.ps1) | Windows | 2.0 | PowerShell | Full-featured, recommended |
| [`Windows_Enumerator_V2.0.bat`](Windows_Enumerator_V2.0.bat) | Windows | 2.0 | Batch (self-contained) | Embeds PS payload — single file, no .ps1 needed |
| [`Linux_Basic_Enumerator_V1.0.sh`](Linux_Basic_Enumerator_V1.0.sh) | Linux | 1.0 | Bash | |
| [`MacOS_Basic_Enumerator_V1.1.sh`](MacOS_Basic_Enumerator_V1.1.sh) | macOS | 1.1 | Bash | |

---

## What Gets Enumerated

<details>
<summary><b>🪟 Windows (V2.0)</b> — click to expand</summary>

### System Information
- OS version, build number, architecture
- Installed hotfixes / patch dates — flags if last patch > 90 days
- PowerShell version (flags downgrade risk)
- .NET framework versions

### User & Privilege Enumeration
- `whoami /all` — full token, groups, and privileges
- **Dangerous privilege detection** — `SeImpersonate`, `SeDebug`, `SeBackup`, `SeRestore`, `SeLoadDriver`, and more, with ENABLED/Disabled state
- Local users, groups, administrators, RDP users
- All logged-on users (`query user`)
- PowerShell command history — current user and **all user profiles**

### Network
- Network interfaces, IP addresses, DNS servers
- ARP cache, routing table
- Active connections (Established) and listening ports
- Hosts file — flags non-default entries
- SMB shares — flags non-default shares
- **WiFi saved passwords** (`netsh wlan show profile key=clear`)
- Named pipes

### Credential & Secret Hunting
- Windows Credential Manager entries
- **Autologon registry keys** — flags if cleartext password is stored
- **AlwaysInstallElevated** — both HKCU and HKLM, with exploitation callout
- **Unattend / Sysprep files** — all common locations
- **LAPS** configuration status
- **WSUS** — flags HTTP WSUS (hijack vector)
- **IIS** — `applicationHost.config` and `web.config` credential strings
- WDigest — flags `UseLogonCredential = 1` (cleartext in LSASS)

### Privilege Escalation Vectors
- **UAC** — flags `EnableLUA = 0` and `LocalAccountTokenFilterPolicy = 1`
- **Unquoted service paths** — all non-disabled, non-Windows services
- **Writable service binaries** — ACL check against `Everyone`, `BUILTIN\Users`, `Authenticated Users`
- **Writable PATH directories** — live write test, not just ACL inspection
- **Writable scheduled task binaries** — action executable ACL check
- **SAM / SYSTEM backup files** — repair and regback paths
- **DLL hijacking hints** — user-writable temp/app directories

### Services, Processes & Software
- All services sorted by status
- Running processes (excl. svchost) sorted by CPU, with paths
- **Processes running as SYSTEM**
- Startup programs
- Installed software from registry (HKLM 32/64 + HKCU)
- Program Files directory listings

### Security Configuration
- **AV/EDR detection** via SecurityCenter2 WMI with state decoding
- **Windows Defender** — real-time status, `ExclusionPath`, `ExclusionProcess`
- Firewall status (all profiles)
- **AppLocker** — effective policy and enforcement mode per collection
- **PowerShell security** — ScriptBlock logging, module logging, transcription, Language Mode
- **LSA Protection (PPL)** — flags if LSASS is unprotected
- **Credential Guard** status
- World-writable directories in Program Files

### Active Directory (auto-detected, domain-joined hosts)
- Domain info, DCs, trust relationships
- All domain users with last logon timestamps
- Domain groups
- Domain Admins membership
- **Kerberoastable accounts** (users with SPNs)
- **AS-REP Roastable accounts** (pre-auth disabled)
- Domain password policy

### Extended Mode (`-Extended`)
- Interesting files: `.zip`, `.rar`, `.kdbx`, `.ppk`, `.rdp`, `.pem`, `.pfx`, `.ovpn`, and more
- Password string grep across common paths (`inetpub`, `Documents`, `C:\Scripts`)
- 20 most recently modified files under `C:\Users`
- Recent documents
- SSH key files across all user profiles
- Registry Run / RunOnce keys

</details>

<details>
<summary><b>🐧 Linux (V1.0)</b> — click to expand</summary>

- OS, kernel, hostname, uptime
- Network interfaces, routing, ARP, listening ports, firewall rules
- Local users, groups, sudo permissions, recently logged-in users
- Installed packages and running services
- SUID / SGID binaries
- World-writable directories
- Cron jobs and scheduled tasks
- Environment variables and PATH
- Interesting files and credential locations

</details>

<details>
<summary><b>🍎 macOS (V1.1)</b> — click to expand</summary>

- OS version, hardware info, uptime
- Network interfaces, routing, ARP, firewall status
- Local users and group memberships, sudo access
- Running processes and launch daemons / agents
- Installed applications
- SUID binaries and weak permissions
- Keychain references, interesting files
- Environment variables

</details>

---

## Quick Start

### Windows

**Option 1 — PowerShell script (recommended)**
```powershell
# Basic enumeration
powershell -ep bypass -f .\Windows_Enumerator_V2.0.ps1

# With extended file hunting
powershell -ep bypass -f .\Windows_Enumerator_V2.0.ps1 -Extended

# Save output directly (no prompt)
powershell -ep bypass -f .\Windows_Enumerator_V2.0.ps1 -OutputFile C:\Temp\enum.txt

# Force domain enumeration + extended + save
powershell -ep bypass -f .\Windows_Enumerator_V2.0.ps1 -Extended -Domain -OutputFile C:\Temp\enum.txt

# Suppress banner (CI/pipeline use)
powershell -ep bypass -f .\Windows_Enumerator_V2.0.ps1 -NoBanner
```

**Option 2 — Self-contained `.bat` (no separate .ps1 needed)**
```cmd
Windows_Enumerator_V2.0.bat
Windows_Enumerator_V2.0.bat -Extended
Windows_Enumerator_V2.0.bat -OutputFile C:\Temp\enum.txt
```

**Download and run (one-liner)**
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Mr-Whiskerss/System_Enumeration_Scripts/main/Windows_Enumerator_V2.0.ps1')
```

---

### Linux

```bash
# Download
wget https://raw.githubusercontent.com/Mr-Whiskerss/System_Enumeration_Scripts/main/Linux_Basic_Enumerator_V1.0.sh

# Make executable and run
chmod +x Linux_Basic_Enumerator_V1.0.sh && ./Linux_Basic_Enumerator_V1.0.sh

# Save output
./Linux_Basic_Enumerator_V1.0.sh | tee linux_enum_$(hostname).txt

# One-liner
curl -s https://raw.githubusercontent.com/Mr-Whiskerss/System_Enumeration_Scripts/main/Linux_Basic_Enumerator_V1.0.sh | bash
```

---

### macOS

```bash
# Download
curl -O https://raw.githubusercontent.com/Mr-Whiskerss/System_Enumeration_Scripts/main/MacOS_Basic_Enumerator_V1.1.sh

# Make executable and run
chmod +x MacOS_Basic_Enumerator_V1.1.sh && ./MacOS_Basic_Enumerator_V1.1.sh

# Save output
./MacOS_Basic_Enumerator_V1.1.sh | tee macos_enum_$(hostname).txt
```

---

## Requirements

| Platform | Requirement | Notes |
|----------|-------------|-------|
| Windows | PowerShell 5.0+ | Ships with Windows 10 / Server 2016+ |
| Windows | Admin rights | Optional — some checks require elevation |
| Linux | Bash 4.0+ | Standard on most distros |
| Linux | `sudo` access | Optional — needed for privileged checks |
| macOS | Bash 3.2+ | Built-in on all supported versions |
| macOS | macOS 10.10+ | |

> No external tools, modules, or internet access required at runtime. Everything uses built-in OS commands.

---

## Output

All scripts produce structured, section-delimited output with consistent formatting:

- Colour-coded section headers and findings
- `[!] HIGH / MEDIUM / LOW` severity callouts for notable findings
- Timestamp, hostname, and user context printed at the top
- Optional transcript / log file output
- Non-interactive mode auto-saves output (useful in reverse shells)

---

## Changelog

### Windows Enumerator

**V2.0** *(current)*
- Added dangerous privilege detection with ENABLED/Disabled state
- Writable service binary, PATH directory, and task binary ACL checks
- Credential hunting: Unattend/Sysprep files, IIS configs, WiFi passwords, WDigest
- Full AD enumeration: Kerberoastable + AS-REP accounts, domain users/groups/trusts
- AV/EDR detection with state decoding; Defender exclusions enumeration
- LSA Protection, Credential Guard, and WDigest status checks
- AppLocker effective policy, PowerShell security settings
- LAPS and WSUS detection
- Non-interactive mode (no hanging prompts in reverse shells)
- `-OutputFile`, `-Domain`, `-NoBanner` parameters
- `Get-WmiObject` → `Get-CimInstance` (PS7 compatible)
- Self-contained `.bat` wrapper with argument pass-through

**V1.0**
- Initial release

### Linux Enumerator — V1.0
- Initial release

### macOS Enumerator — V1.1
- Enhanced user enumeration
- Improved compatibility with recent macOS versions

---

## Security Notes

> ⚠️ **These scripts are for authorised security assessments only.**

- Always obtain explicit written authorisation before running enumeration tools on any system
- Some checks (privilege enumeration, AV detection, LSASS status) may trigger EDR/SIEM alerts
- Output files contain sensitive data including credential references, patch levels, and user details — handle and store appropriately, delete after the engagement
- Scripts do **not** make any changes to the target system

---

## Contributing

Contributions are welcome — new checks, OS support, bug fixes, or output improvements.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-check`
3. Commit your changes: `git commit -m 'Add: description of new check'`
4. Push and open a Pull Request

---

## Legal Disclaimer

These tools are provided for **educational purposes and authorised security testing only**. Unauthorised access to computer systems is illegal in the UK under the Computer Misuse Act 1990 and equivalent legislation in other jurisdictions. The author accepts no liability for misuse or damage caused by these scripts. You are solely responsible for ensuring you have appropriate authorisation before running any enumeration tool.

---

<div align="center">

**Author:** [MrWhiskers](https://github.com/Mr-Whiskerss)  
⭐ If you find these scripts useful, a star is appreciated!

</div>
