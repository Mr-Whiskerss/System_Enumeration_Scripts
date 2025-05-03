### System Enumeration Scripts
A collection of PowerShell and Bash scripts for system enumeration on Windows, Linux, and macOS. Designed for penetration testers to quickly gather system, network, user, and privilege-related information.

🔧 Features
✅ OS & system info
✅ Network & service enumeration
✅ User & group discovery
✅ Installed software & startup programs
✅ Privilege escalation checks
✅ Supports extended deep scans

📁 Scripts Included
Windows_Enumerator_V1.0.ps1 – Windows enumeration (PowerShell)
Linux_Basic_Enumerator_V1.0.sh – Linux enumeration (Bash)
MacOS_Basic_Enumerator_V1.1.sh – macOS enumeration (Bash)

⚙️ Usage
🔹 Linux/macOS
chmod +x Linux_Basic_Enumerator_V1.0.sh
./Linux_Basic_Enumerator_V1.0.sh

chmod +x MacOS_Basic_Enumerator_V1.1.sh
./MacOS_Basic_Enumerator_V1.1.sh

🔹 Windows (Run in PowerShell)
.\Windows_Enumerator_V1.0.ps1

# Optional extended scan:
.\Windows_Enumerator_V1.0.ps1 -Extended
