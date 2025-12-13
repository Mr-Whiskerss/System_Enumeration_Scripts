@echo off
setlocal enabledelayedexpansion

REM Header line for visual separation
set "line=------------------------------------------------------------"

REM Ask if user wants to save output to file
set /p saveToFile="Would you like to save the output to a text file? (y/n): "
if /i "%saveToFile%"=="y" (
    set "timestamp=%date:~-4%%date:~3,2%%date:~0,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
    set "timestamp=!timestamp: =0!"
    set "logPath=%~dp0WindowsEnum_!timestamp!.txt"
    echo [*] Logging output to: !logPath! > "!logPath!"
    echo [*] Note: Output file contains sensitive system information - restrict access appropriately >> "!logPath!"
    call :RunEnumeration >> "!logPath!" 2>&1
    echo.
    echo [*] Output was saved to: !logPath!
    pause
    exit /b
) else (
    call :RunEnumeration
    pause
    exit /b
)

:RunEnumeration
echo.
echo [***] Script started at: %date% %time% ***
echo.

REM OS Detection
echo [*] Detected Operating System on %COMPUTERNAME%:
systeminfo | findstr /C:"OS Name"
echo.

REM Basic System Information
echo.
echo %line%
echo  Basic System Information
echo %line%
systeminfo
echo.

REM Environment Variables
echo.
echo %line%
echo  Environment Variables
echo %line%
set
echo.

REM Network Configuration
echo.
echo %line%
echo  Network Configuration
echo %line%
ipconfig /all
echo.

REM ARP Cache
echo.
echo %line%
echo  ARP Cache
echo %line%
arp -a
echo.

REM Routing Table
echo.
echo %line%
echo  Routing Table
echo %line%
route print
echo.

REM Open Network Connections
echo.
echo %line%
echo  Open Network Connections
echo %line%
netstat -ano
echo.

REM Mapped and Local Drives
echo.
echo %line%
echo  Mapped and Local Drives
echo %line%
wmic logicaldisk get caption,description,providername
echo.

REM Firewall Configuration
echo.
echo %line%
echo  Firewall Configuration
echo %line%
netsh advfirewall show allprofiles
echo.

REM Credential Manager Entries
echo.
echo %line%
echo  Credential Manager Entries
echo %line%
cmdkey /list
echo.

REM Autologon Registry Entries
echo.
echo %line%
echo  Autologon Registry Entries
echo %line%
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultUserName 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultPassword 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" /v AutoAdminLogon 2>nul
echo.

REM Local Users
echo.
echo %line%
echo  Local Users
echo %line%
net user
echo.

REM Local Groups
echo.
echo %line%
echo  Local Groups
echo %line%
net localgroup
echo.

REM Local Administrators
echo.
echo %line%
echo  Local Administrators
echo %line%
net localgroup Administrators
echo.

REM User Home Directories
echo.
echo %line%
echo  User Home Directories
echo %line%
dir C:\Users
echo.

REM Installed Programs
echo.
echo %line%
echo  Installed Programs (Program Files)
echo %line%
dir "C:\Program Files" /s /b 2>nul | findstr /v /i "\.dll \.exe \.sys"
dir "C:\Program Files (x86)" /s /b 2>nul | findstr /v /i "\.dll \.exe \.sys"
echo.

REM Registry Software Entries
echo.
echo %line%
echo  Registry Software Entries
echo %line%
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s 2>nul | findstr DisplayName
echo.

REM AlwaysInstallElevated
echo.
echo %line%
echo  AlwaysInstallElevated (User)
echo %line%
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
echo.
echo %line%
echo  AlwaysInstallElevated (Machine)
echo %line%
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
echo.

REM Services
echo.
echo %line%
echo  Running Services
echo %line%
sc query type= service state= all
echo.

REM Scheduled Tasks
echo.
echo %line%
echo  Scheduled Tasks (Non-Microsoft)
echo %line%
schtasks /query /fo LIST /v 2>nul | findstr /v /i "Microsoft"
echo.

REM Startup Programs
echo.
echo %line%
echo  Startup Programs
echo %line%
wmic startup get caption,command
echo.

REM Hosts File
echo.
echo %line%
echo  Hosts File Content
echo %line%
type %windir%\System32\drivers\etc\hosts
echo.

REM Hotfixes
echo.
echo %line%
echo  Hotfixes / Patches
echo %line%
wmic qfe list
echo.

REM Logged-On Users
echo.
echo %line%
echo  Logged-On Users
echo %line%
query user
echo.

REM Current User
echo.
echo %line%
echo  Current Logged-In User
echo %line%
echo %USERDOMAIN%\%USERNAME%
echo.

REM User Privileges
echo.
echo %line%
echo  User Privileges (Token Rights)
echo %line%
whoami /priv
echo.

REM Running Processes
echo.
echo %line%
echo  Running Processes
echo %line%
tasklist /v
echo.

REM UAC Configuration
echo.
echo %line%
echo  UAC Configuration
echo %line%
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
echo.

REM PowerShell History
echo.
echo %line%
echo  PowerShell History (if available)
echo %line%
type "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>nul
echo.

REM Antivirus
echo.
echo %line%
echo  Antivirus Product Detection
echo %line%
wmic /namespace:\\root\securitycenter2 path antivirusproduct get displayname,pathToSignedProductExe 2>nul
echo.

echo.
echo %line%
echo  Enumeration Complete
echo %line%
echo Script finished successfully at %date% %time%
echo.

exit /b
