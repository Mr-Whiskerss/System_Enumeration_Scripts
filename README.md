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
[![Shell](https://img.shields.io/badge/Shell-Bash%204.0%2B-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)](#linux)
[![License](https://img.shields.io/badge/license-Educational%20Use-orange?style=flat-square)](#legal-disclaimer)
[![Authorised Use Only](https://img.shields.io/badge/%E2%9A%A0%EF%B8%8F-Authorised%20Use%20Only-red?style=flat-square)](#legal-disclaimer)

</div>

---

## Overview

A collection of lightweight, standalone enumeration scripts designed to give penetration testers and security professionals a rapid, structured picture of a target system — with no dependencies, no installations, and no external tools required.

Built for **build reviews**, **post-exploitation enumeration**, and **privilege escalation triage** across Windows, Linux, and macOS. All scripts output consistent, colour-coded, severity-rated findings.

---

## Scripts

| Script | Platform | Version | Format | Notes |
|--------|----------|---------|--------|-------|
| [`Windows_Enumerator_V2.0.ps1`](Windows_Enumerator_V2.0.ps1) | Windows | 2.0 | PowerShell | Full-featured, recommended |
| [`Windows_Enumerator_V2.0.bat`](Windows_Enumerator_V2.0.bat) | Windows | 2.0 | Batch (self-contained) | Embeds PS payload — single file, no `.ps1` needed |
| [`Linux_Enumerator_V2.0.sh`](Linux_Enumerator_V2.0.sh) | Linux | 2.0 | Bash | Supports `-e` extended mode |
| [`MacOS_Enumerator_V2.0.sh`](MacOS_Enumerator_V2.0.sh) | macOS | 2.0 | Bash | Intel + Apple Silicon, supports `-e` extended mode |

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
- Domain groups and Domain Admins membership
- **Kerberoastable accounts** (users with SPNs)
- **AS-REP Roastable accounts** (pre-auth disabled)
- Domain password policy

### Extended Mode (`-Extended`)
- Interesting files: `.zip`, `.rar`, `.kdbx`, `.ppk`, `.rdp`, `.pem`, `.pfx`, `.ovpn`, and more
- Password string grep across common paths (`inetpub`, `Documents`, `C:\Scripts`)
- 20 most recently modified files under `C:\Users`
- Recent documents and SSH keys across all user profiles
- Registry Run / RunOnce persistence keys

</details>

<details>
<summary><b>🐧 Linux (V2.0)</b> — click to expand</summary>

### System Information
- OS, kernel version, hostname, uptime, CPU, memory, disk
- Installed kernels, loaded modules
- Environment variables and shell config files (current user + system-wide)

### User & Privilege Enumeration
- **`sudo -l`** — full sudo privilege listing with privesc callout
- Sudoers file and `/etc/sudoers.d/` contents
- `/etc/passwd`, `/etc/shadow` (flags if readable), `/etc/group`
- Users with interactive shells — flags non-service accounts
- **Privileged group membership** — `sudo`, `wheel`, `docker`, `lxd`, `disk`, `shadow`
- `/root` directory access check — flags if accessible
- Command history for current user and all accessible user profiles
- Last logins, currently logged-on users

### Network
- Interfaces via `ip addr` (falls back to `ifconfig`)
- Routing table, ARP cache, DNS config (`resolv.conf` + `resolvectl`)
- Listening ports (`ss`/`netstat`) and all active connections
- Firewall rules: `iptables`, `ip6tables`, `nftables`, `ufw`
- **NFS exports** — flags `no_root_squash` / `no_all_squash`
- SMB/Samba config, hosts file (flags non-default entries)
- NetworkManager saved connections

### Credential & Secret Hunting
- SSH keys (all types), `authorized_keys`, `known_hosts`, `config`
- SSH daemon config — flags `PermitRootLogin yes`, `PasswordAuthentication yes`, `PermitEmptyPasswords yes`
- Web app configs: `wp-config.php`, `.env`, `config.php`, phpMyAdmin
- Database configs: MySQL, PostgreSQL `pg_hba.conf`, Redis, MongoDB
- Password strings in readable `/etc/` files

### Privilege Escalation Vectors
- **SUID / SGID binaries** with GTFOBins callout
- **Linux capabilities** (`getcap -r /`) — flags dangerous caps (`cap_setuid`, `cap_sys_admin`, `cap_net_raw`, `cap_dac_override`)
- World-writable files and directories (excluding `/tmp`, `/proc`, `/sys`)
- **Writable PATH directories** — live write test
- **Writable cron scripts** — parses cron files and checks referenced script writability
- **Writable systemd unit files**
- Writable `/etc/passwd` or `/etc/shadow` — immediate HIGH flag
- Non-root UID 0 entries in `/etc/passwd`
- Docker / LXD / disk group membership detection
- Password backup files (`/etc/passwd-`, `/etc/shadow-`)

### Services & Software
- Running processes sorted by CPU, processes running as root
- Systemd enabled/running services
- Installed packages: `dpkg`, `rpm`, Snap, Flatpak
- Compiler and scripting language availability
- Interesting binaries in PATH (`nc`, `socat`, `python`, `gcc`, etc.)

### Security Configuration
- **SELinux** — mode check, flags permissive/disabled
- **AppArmor** — profile listing
- Password policy (`/etc/login.defs`) and PAM configuration
- Fail2ban status
- AV/HIDS tool detection (ClamAV, rkhunter, chkrootkit, OSSEC, Wazuh, Lynis, AIDE)

### Container Detection
- `/proc/1/cgroup` docker/lxc/k8s/containerd detection
- `/.dockerenv` presence check
- `systemd-detect-virt` virtualisation check

### Extended Mode (`-e`)
- Password string grep across `/home`, `/var/www`, `/opt`, `/srv`, `/etc`
- PHP credential file scanning
- `.env` file hunting across the filesystem
- Recently modified files (7-day and 30-day windows)
- Full SUID binary scan with `ls -la`
- All-user crontab dump (root only)
- Archive file discovery

</details>

<details>
<summary><b>🍎 macOS (V2.0)</b> — click to expand</summary>

### System Information
- macOS version, build, architecture (Intel vs Apple Silicon), Rosetta 2 detection
- Hardware model, CPU, memory, disk usage, mounted volumes
- Uptime, kernel parameters (`sysctl -a`)

### User & Privilege Enumeration
- **`sudo -l`** — privilege listing with privesc callout
- Full user enumeration via `dscl` — all non-system accounts with shell, UID, home
- **Admin group membership** — explicitly flagged
- Logged-on users, last logins, finger info
- Command history for current user and all accessible user profiles
- Environment variables and shell config files

### Security Configuration (macOS-specific)
- **SIP** (`csrutil status`) — flags if disabled
- **Gatekeeper** (`spctl --status`) — flags if disabled
- **FileVault** (`fdesetup status`) — flags if disk is unencrypted
- **Application Firewall** — state and stealth mode, flags disabled
- **Screen lock** — `askForPassword` setting, flags if not enforced
- **Automatic Login** — flags if enabled (high severity)
- **Remote Login (SSH)** — enabled/disabled state
- **Remote Management (ARD/VNC)** — launchctl detection
- **MDM Enrollment** — `profiles status`, flags managed devices
- **TCC Database** — user and system permission grants (camera, mic, Full Disk Access, etc.)
- **XProtect / MRT** — version info
- Audit daemon config
- AV/EDR detection: Defender, SentinelOne, CrowdStrike, Sophos, Carbon Black, Malwarebytes

### Network
- Interfaces, IP addresses per interface, DNS (`scutil --dns`)
- Routing table, ARP cache
- Listening ports (`lsof -i -P -n`) and all connections
- Hosts file — flags non-default entries
- Wi-Fi info, proxy settings
- SMB/NFS mounts
- Bluetooth and Ethernet device info

### Credential & Secret Hunting
- SSH keys (all types), `known_hosts`, `authorized_keys`, `sshd_config` analysis
- **Keychain** — listing, default keychain, certificate enumeration
- **Clipboard contents** — automatically flags passwords, tokens, or private keys
- AWS / GCP / Azure credential files
- `.env` files across the home tree
- Git credential files (`~/.git-credentials`, `~/.gitconfig`)

### Privilege Escalation Vectors
- SUID / SGID binaries with GTFOBins callout
- Writable PATH directories — live write test
- World-writable files (properly scoped)
- **Writable LaunchAgent / LaunchDaemon plists** — flags immediately
- **Writable scripts referenced in Launch plists** — parses plist paths and checks writability
- Cron jobs and AT jobs

### Extended Mode (`-e`)
- Spotlight search for files named `*password*`, `*secret*`, `*credential*`
- Interesting file extensions: `.key`, `.pem`, `.p12`, `.ppk`, `.kdbx`, `.ovpn`, `.rdp`
- Password string grep across home directory files
- **Safari History DB** — last 50 URLs
- **Chrome Login Data** — saved username/URL pairs
- **Firefox `logins.json`** — saved credential metadata
- Recently modified files (7-day window, home dir)
- Archive file discovery

</details>

---

## Quick Start

### Windows

**Option 1 — PowerShell script (recommended)**
```powershell
# Basic enumeration
powershell -ep bypass -f .\Windows_Enumerator_V2.0.ps1

# Extended file hunting
powershell -ep bypass -f .\Windows_Enumerator_V2.0.ps1 -Extended

# Save output directly (no interactive prompt)
powershell -ep bypass -f .\Windows_Enumerator_V2.0.ps1 -OutputFile C:\Temp\enum.txt

# Extended + force domain enumeration + save
powershell -ep bypass -f .\Windows_Enumerator_V2.0.ps1 -Extended -Domain -OutputFile C:\Temp\enum.txt

# Suppress banner
powershell -ep bypass -f .\Windows_Enumerator_V2.0.ps1 -NoBanner
```

**Option 2 — Self-contained `.bat` (single file, no `.ps1` needed)**
```cmd
Windows_Enumerator_V2.0.bat
Windows_Enumerator_V2.0.bat -Extended
Windows_Enumerator_V2.0.bat -OutputFile C:\Temp\enum.txt
Windows_Enumerator_V2.0.bat -Extended -Domain -OutputFile C:\Temp\enum.txt
```

**Download and run (one-liner)**
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Mr-Whiskerss/System_Enumeration_Scripts/main/Windows_Enumerator_V2.0.ps1')
```

---

### Linux

```bash
# Download
wget https://raw.githubusercontent.com/Mr-Whiskerss/System_Enumeration_Scripts/main/Linux_Enumerator_V2.0.sh

# Make executable and run
chmod +x Linux_Enumerator_V2.0.sh && ./Linux_Enumerator_V2.0.sh

# Extended mode
./Linux_Enumerator_V2.0.sh -e

# Save output to specific file
./Linux_Enumerator_V2.0.sh -o /tmp/linux_enum.txt

# Extended + save + no colour
./Linux_Enumerator_V2.0.sh -e -n -o /tmp/linux_enum.txt

# One-liner (output auto-saved to current directory)
curl -s https://raw.githubusercontent.com/Mr-Whiskerss/System_Enumeration_Scripts/main/Linux_Enumerator_V2.0.sh | bash
```

---

### macOS

```bash
# Download
curl -O https://raw.githubusercontent.com/Mr-Whiskerss/System_Enumeration_Scripts/main/MacOS_Enumerator_V2.0.sh

# Make executable and run
chmod +x MacOS_Enumerator_V2.0.sh && ./MacOS_Enumerator_V2.0.sh

# Extended mode (includes browser history, deep file hunting)
./MacOS_Enumerator_V2.0.sh -e

# Save output to specific file
./MacOS_Enumerator_V2.0.sh -o /tmp/macos_enum.txt

# Extended + save + no colour
./MacOS_Enumerator_V2.0.sh -e -n -o /tmp/macos_enum.txt

# One-liner
curl -s https://raw.githubusercontent.com/Mr-Whiskerss/System_Enumeration_Scripts/main/MacOS_Enumerator_V2.0.sh | bash
```

---

## Parameters & Flags

All V2.0 scripts share a consistent flag convention:

| Flag | Windows | Linux | macOS | Description |
|------|---------|-------|-------|-------------|
| `-Extended` / `-e` | ✅ | ✅ | ✅ | Deep file hunting, credential grep, browser history |
| `-OutputFile` / `-o` | ✅ | ✅ | ✅ | Specify output file path (skips prompt) |
| `-NoBanner` / `-n` | ✅ | ✅ | ✅ | Suppress banner / disable colour output |
| `-Domain` | ✅ | — | — | Force AD enumeration on domain-joined hosts |
| `-h` | — | ✅ | ✅ | Show help and usage |

> If `-o` / `-OutputFile` is not specified, output is auto-saved as `<os>_enum_<hostname>_<timestamp>.txt` in the current directory.

---

## Requirements

| Platform | Requirement | Notes |
|----------|-------------|-------|
| Windows | PowerShell 5.0+ | Ships with Windows 10 / Server 2016+ |
| Windows | Admin rights | Optional — some checks require elevation |
| Linux | Bash 4.0+ | Standard on all major distros |
| Linux | `sudo` access | Optional — needed for firewall rules and some privesc checks |
| macOS | Bash 3.2+ | Built-in. Tested on Ventura and Sonoma (Intel + Apple Silicon) |
| macOS | Admin rights | Optional — some checks need elevation |

> No external tools, modules, or internet access required at runtime. Everything uses native OS commands.

---

## Output Format

All scripts produce consistent, structured output:

- **Colour-coded section headers** — cyan for sections, dark cyan for subsections
- **`[!] HIGH / MEDIUM / LOW`** severity callouts — red, yellow, green respectively
- **Context block at the top** — timestamp, hostname, current user, OS, admin/root status
- **Auto-saved output file** — named with hostname and timestamp, `chmod 600` applied immediately
- **Non-interactive safe** — no hanging prompts in reverse shells or automated pipelines
- **GTFOBins / remediation tips** printed at the footer of each run

---

## Changelog

### Windows Enumerator

**V2.0** *(current)*
- Dangerous token privilege detection with ENABLED/Disabled state
- Writable service binary, PATH directory, and task binary ACL checks
- Credential hunting: Unattend/Sysprep, IIS configs, WiFi passwords, WDigest
- Full AD enumeration: Kerberoastable + AS-REP accounts, users/groups/trusts
- AV/EDR detection with state decoding; Defender exclusions enumeration
- LSA Protection (PPL), Credential Guard, and WDigest status
- AppLocker effective policy, PowerShell security settings
- LAPS and WSUS detection
- Non-interactive mode — auto-saves output, no hanging prompts
- `-OutputFile`, `-Domain`, `-NoBanner` parameters
- `Get-WmiObject` → `Get-CimInstance` (PS7 compatible)
- Self-contained `.bat` wrapper with full argument pass-through

**V1.0** — Initial release

---

### Linux Enumerator

**V2.0** *(current)*
- Fixed shebang position (was on line 8, not line 1 — broke `/bin/sh` fallback)
- `sudo -l` added — absent from V1.0
- SUID / SGID enumeration with GTFOBins callout
- Linux capabilities (`getcap`) with automatic dangerous cap flagging
- Writable PATH directory live write test
- Writable cron script and writable systemd unit file detection
- Container detection via `/proc/1/cgroup`, `/.dockerenv`, `systemd-detect-virt`
- Docker/LXD/disk group membership flagging
- SSH key enumeration across all user profiles; `sshd_config` analysis
- Web app and database credential file checks
- SELinux, AppArmor, PAM, Fail2ban, AV/HIDS detection
- NFS `no_root_squash` detection
- `ip`/`ss` preferred over deprecated `ifconfig`/`netstat` (with fallback)
- `-e`, `-o`, `-n`, `-h` flags; auto-named timestamped output file
- Colour-coded output with `[!] HIGH/MEDIUM/LOW` severity callouts

**V1.0** — Initial release

---

### macOS Enumerator

**V2.0** *(current)*
- SIP, Gatekeeper, FileVault, and Application Firewall status with severity flagging
- Screen lock, automatic login, Remote Login, Remote Management, Screen Sharing detection
- MDM/device enrollment detection via `profiles`
- TCC database enumeration (camera, mic, Full Disk Access permissions)
- AV/EDR detection: Defender, SentinelOne, CrowdStrike, Sophos, Carbon Black, Malwarebytes
- Admin group enumeration via `dscl`; full user listing with shell/UID/home
- Keychain listing, certificate enumeration, cloud credential files (AWS/GCP/Azure)
- Clipboard analysis — flags credential patterns automatically
- Writable LaunchAgent/LaunchDaemon plist and script detection
- Apple Silicon / Rosetta 2 detection
- `-e` extended mode: Safari/Chrome/Firefox history, Spotlight search, credential grep
- Removed `caffeinate &` bug (was logging a background process as output)
- Fixed `cat /etc/resolvectl` bug (replaced with `resolvectl status`)
- `-e`, `-o`, `-n`, `-h` flags; auto-named timestamped output file
- Colour-coded output with `[!] HIGH/MEDIUM/LOW` severity callouts

**V1.1** — Enhanced user enumeration, improved macOS compatibility

**V1.0** — Initial release

---

## Security Notes

> ⚠️ **These scripts are for authorised security assessments only.**

- Always obtain explicit written authorisation before running any enumeration tool
- Some checks (privilege enumeration, AV/EDR detection, TCC access, LSASS status) may trigger security monitoring
- Output files contain sensitive data — restrict access, encrypt in transit, and delete after the engagement
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
