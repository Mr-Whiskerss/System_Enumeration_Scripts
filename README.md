# System Enumeration Scripts

A collection of PowerShell and Bash scripts designed for comprehensive system enumeration across Windows, Linux, and macOS environments. Built for penetration testers and security professionals to rapidly gather system information during assessments.

## 🎯 Overview

These scripts automate the collection of critical system information including OS details, network configuration, user accounts, installed software, running services, and potential privilege escalation vectors. Each script is tailored to its respective operating system while maintaining a consistent enumeration methodology.

## 📋 Features

- **System Information**
  - OS version, architecture, and hostname
  - System uptime and boot time
  - Kernel/build information
  - Environment variables

- **Network Enumeration**
  - Active network interfaces and IP addressing
  - Routing tables and ARP cache
  - Active connections and listening ports
  - DNS configuration
  - Firewall rules and status

- **User & Group Discovery**
  - Local users and groups
  - User privileges and group memberships
  - Recently logged-in users
  - Sudo/administrator permissions

- **Software & Services**
  - Installed applications and packages
  - Running processes and services
  - Startup programs and scheduled tasks
  - Software versions for vulnerability research

- **Security Assessment**
  - SUID/SGID binaries (Linux/macOS)
  - Weak file permissions
  - Password policy information
  - Potential privilege escalation vectors
  - Security features status (SELinux, AppArmor, etc.)

- **Extended Scanning**
  - Optional deep scan mode for comprehensive enumeration
  - Automated output formatting for easy analysis

## 📦 Scripts Included

| Script | Platform | Version | Description |
|--------|----------|---------|-------------|
| `Windows_Enumerator_V1.0.ps1` | Windows | 1.0 | PowerShell-based Windows enumeration |
| `Linux_Basic_Enumerator_V1.0.sh` | Linux | 1.0 | Bash-based Linux enumeration |
| `MacOS_Basic_Enumerator_V1.1.sh` | macOS | 1.1 | Bash-based macOS enumeration |

## 🚀 Quick Start

### Linux

```bash
# Download the script
wget https://raw.githubusercontent.com/Mr-Whiskerss/System_Enumeration_Scripts/main/Linux_Basic_Enumerator_V1.0.sh

# Make executable
chmod +x Linux_Basic_Enumerator_V1.0.sh

# Run basic enumeration
./Linux_Basic_Enumerator_V1.0.sh

# Run with extended scan (if supported)
./Linux_Basic_Enumerator_V1.0.sh --extended
```

### macOS

```bash
# Download the script
curl -O https://raw.githubusercontent.com/Mr-Whiskerss/System_Enumeration_Scripts/main/MacOS_Basic_Enumerator_V1.1.sh

# Make executable
chmod +x MacOS_Basic_Enumerator_V1.1.sh

# Run enumeration
./MacOS_Basic_Enumerator_V1.1.sh
```

### Windows

```powershell
# Download the script (PowerShell)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Mr-Whiskerss/System_Enumeration_Scripts/main/Windows_Enumerator_V1.0.ps1" -OutFile "Windows_Enumerator_V1.0.ps1"

# If execution policy blocks the script
powershell -ExecutionPolicy Bypass -File .\Windows_Enumerator_V1.0.ps1

# Alternative: Set execution policy for current session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\Windows_Enumerator_V1.0.ps1
```

## 💡 Usage Examples

### Saving Output to File

**Linux/macOS:**
```bash
./Linux_Basic_Enumerator_V1.0.sh | tee enumeration_results.txt
```

**Windows:**
```powershell
.\Windows_Enumerator_V1.0.ps1 | Out-File -FilePath enumeration_results.txt
```

### Running Remotely

**Linux/macOS (one-liner):**
```bash
curl -s https://raw.githubusercontent.com/Mr-Whiskerss/System_Enumeration_Scripts/main/Linux_Basic_Enumerator_V1.0.sh | bash
```

**Windows (from remote host):**
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Mr-Whiskerss/System_Enumeration_Scripts/main/Windows_Enumerator_V1.0.ps1')
```

## 🔒 Security Considerations

**⚠️ Important Notes:**

- These scripts are intended for **authorized security assessments only**
- Always obtain proper authorization before running enumeration tools
- Some commands may trigger security monitoring/EDR solutions
- Output may contain sensitive information - handle appropriately
- Scripts may require elevated privileges for complete enumeration

## 📊 Output Format

Scripts generate organized, readable output with clear section headers. Results include:
- Timestamp and system identification
- Categorized enumeration data
- Highlighted findings (when applicable)
- Summary of potential security concerns

## 🛠️ Requirements

### Linux
- Bash 4.0+
- Standard GNU utilities (most distributions)
- Optional: `sudo` access for privileged information

### macOS
- Bash 3.2+ (built-in)
- macOS 10.10+
- Optional: Administrator privileges

### Windows
- PowerShell 5.0+ (Windows 10/Server 2016+)
- PowerShell 3.0+ supported with limited features
- Optional: Administrator privileges for complete enumeration

## 🤝 Contributing

Contributions are welcome! If you have improvements or additional enumeration checks:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add new enumeration check'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

## 📝 Changelog

### Windows_Enumerator_V1.0
- Initial release with core enumeration features

### Linux_Basic_Enumerator_V1.0
- Initial release with comprehensive Linux checks

### MacOS_Basic_Enumerator_V1.1
- Enhanced user enumeration
- Improved compatibility with recent macOS versions

## ⚖️ Legal Disclaimer

These tools are provided for educational and authorized security testing purposes only. Unauthorized access to computer systems is illegal. The author assumes no liability for misuse or damage caused by these scripts. Always ensure you have explicit permission before conducting any security assessment.

## 📧 Contact

**Author:** MrWhiskers  
**GitHub:** [@Mr-Whiskerss](https://github.com/Mr-Whiskerss)

## 📄 License

This project is available for use in security assessments and educational purposes. Please use responsibly.

---

**⭐ If you find these scripts useful, consider starring the repository!**
