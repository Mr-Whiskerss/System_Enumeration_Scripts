<#
.SYNOPSIS
    Windows System Enumerator V2.0 - Penetration Testing / Build Review Tool
    Improved from V1.0 by Dan (via Claude)

.DESCRIPTION
    Comprehensive Windows enumeration script for security assessments.
    Covers system info, network, credentials, privilege escalation vectors,
    AV/EDR detection, domain enumeration, and more.

.PARAMETER Extended
    Run extended checks including file hunting, recent docs, SAM backups.

.PARAMETER OutputFile
    Specify output file path directly (skips interactive prompt). Useful in non-interactive shells.

.PARAMETER Domain
    Force domain enumeration even if auto-detection fails.

.PARAMETER NoBanner
    Suppress the ASCII banner (useful in automated/CI pipelines).

.EXAMPLE
    .\Windows_Enumerator_V2.0.ps1
    .\Windows_Enumerator_V2.0.ps1 -Extended
    .\Windows_Enumerator_V2.0.ps1 -OutputFile C:\Temp\enum.txt
    .\Windows_Enumerator_V2.0.ps1 -Extended -OutputFile C:\Temp\enum.txt -Domain
    powershell -ep bypass -f .\Windows_Enumerator_V2.0.ps1 -OutputFile .\out.txt

.NOTES
    For authorised security assessments only.
    Handle output files carefully - they contain sensitive system data.
#>

param (
    [switch]$Extended,
    [string]$OutputFile  = "",
    [switch]$Domain,
    [switch]$NoBanner
)

# ─────────────────────────────────────────────────────────────────
# REGION: Output / Transcript Setup
# ─────────────────────────────────────────────────────────────────

# Detect if running interactively (not in a piped/reverse shell)
$IsInteractive = [Environment]::UserInteractive -and $Host.Name -ne 'ServerRemoteHost'

if ($OutputFile -eq "" -and $IsInteractive) {
    $saveToFile = Read-Host "Save output to file? (y/n)"
    if ($saveToFile -match '^(y|yes)$') {
        $timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
        $OutputFile = "$PSScriptRoot\WindowsEnum_$timestamp.txt"
    }
} elseif ($OutputFile -eq "" -and -not $IsInteractive) {
    # Non-interactive default: always save with timestamp
    $timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputFile = "$PSScriptRoot\WindowsEnum_$timestamp.txt"
}

$transcribing = $false
if ($OutputFile -ne "") {
    try {
        Start-Transcript -Path $OutputFile -NoClobber -ErrorAction Stop
        $transcribing = $true
        Write-Output "[*] Logging to: $OutputFile"
        Write-Output "[!] Output contains sensitive data - restrict access appropriately`n"
    } catch {
        Write-Warning "Could not start transcript: $_"
    }
}

# ─────────────────────────────────────────────────────────────────
# REGION: Helpers
# ─────────────────────────────────────────────────────────────────

$line   = '=' * 65
$subline= '-' * 65

function Write-SectionHeader {
    param ([string]$Title, [string]$Colour = 'Cyan')
    Write-Host "`n$line"            -ForegroundColor $Colour
    Write-Host "  [*] $Title"       -ForegroundColor $Colour
    Write-Host "$line"              -ForegroundColor $Colour
}

function Write-SubHeader {
    param ([string]$Title)
    Write-Host "`n  $subline"       -ForegroundColor DarkCyan
    Write-Host "    >> $Title"      -ForegroundColor DarkCyan
    Write-Host "  $subline"         -ForegroundColor DarkCyan
}

function Write-Finding {
    param ([string]$Message, [string]$Severity = 'INFO')
    $colour = switch ($Severity) {
        'HIGH'   { 'Red'    }
        'MEDIUM' { 'Yellow' }
        'LOW'    { 'Green'  }
        default  { 'White'  }
    }
    Write-Host "  [!] $Message" -ForegroundColor $colour
}

function Safe-Invoke {
    param ([string]$Label, [scriptblock]$Block)
    try {
        & $Block
    } catch {
        Write-Host "  [-] $Label failed: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

# ─────────────────────────────────────────────────────────────────
# REGION: Banner
# ─────────────────────────────────────────────────────────────────

if (-not $NoBanner) {
    Write-Host @"
`n
  ██╗    ██╗██╗███╗   ██╗    ███████╗███╗   ██╗██╗   ██╗███╗   ███╗
  ██║    ██║██║████╗  ██║    ██╔════╝████╗  ██║██║   ██║████╗ ████║
  ██║ █╗ ██║██║██╔██╗ ██║    █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
  ██║███╗██║██║██║╚██╗██║    ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
  ╚███╔███╔╝██║██║ ╚████║    ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
   ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝    ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
  Windows Enumerator V2.0  |  For authorised assessments only
"@ -ForegroundColor Cyan
}

# ─────────────────────────────────────────────────────────────────
# REGION: Context / Pre-flight
# ─────────────────────────────────────────────────────────────────

Write-SectionHeader "Enumeration Context" 'Yellow'
$runTime      = Get-Date
$currentUser  = "$env:UserDomain\$env:UserName"
$computerName = $env:COMPUTERNAME
$osInfo       = Get-CimInstance Win32_OperatingSystem
$isDomainJoined = (Get-CimInstance Win32_ComputerSystem).PartOfDomain

Write-Output "  Started        : $runTime"
Write-Output "  Host           : $computerName"
Write-Output "  User           : $currentUser"
Write-Output "  OS             : $($osInfo.Caption) [$($osInfo.OSArchitecture)]"
Write-Output "  Build          : $($osInfo.BuildNumber)"
Write-Output "  Domain Joined  : $isDomainJoined"
Write-Output "  Extended Mode  : $($Extended.IsPresent)"
Write-Output "  Interactive    : $IsInteractive"

# Check if admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if ($isAdmin) {
    Write-Finding "Running as LOCAL ADMINISTRATOR - full enumeration available" 'HIGH'
} else {
    Write-Finding "Running as standard user - some checks may be limited" 'LOW'
}

# ─────────────────────────────────────────────────────────────────
# REGION: 1 - System Information
# ─────────────────────────────────────────────────────────────────

Write-SectionHeader "1. System Information"

Write-SubHeader "systeminfo"
Safe-Invoke "systeminfo" { systeminfo }

Write-SubHeader "Environment Variables"
Safe-Invoke "Environment vars" { Get-ChildItem Env: | Sort-Object Key | Format-Table Key,Value -AutoSize }

Write-SubHeader "Hotfixes / Patches (Sorted by Date)"
Safe-Invoke "Hotfixes" {
    $patches = Get-HotFix | Sort-Object InstalledOn -Descending
    $patches | Format-Table HotFixID, Description, InstalledOn -AutoSize
    $latestPatch = $patches | Select-Object -First 1
    if ($latestPatch.InstalledOn) {
        $daysSince = (New-TimeSpan -Start $latestPatch.InstalledOn -End (Get-Date)).Days
        if ($daysSince -gt 90) {
            Write-Finding "Last patch was $daysSince days ago - system may be missing critical updates" 'HIGH'
        }
    }
}

Write-SubHeader "PowerShell Version"
Safe-Invoke "PS Version" {
    $PSVersionTable | Format-Table
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Finding "PowerShell v$($PSVersionTable.PSVersion) - downgrade may allow ScriptBlock logging bypass" 'MEDIUM'
    }
}

Write-SubHeader ".NET Versions Installed"
Safe-Invoke ".NET versions" {
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
    Get-ItemProperty -Name Version -ErrorAction SilentlyContinue |
    Where-Object { $_.Version -match '^\d' } |
    Select-Object PSChildName, Version | Sort-Object Version -Descending | Format-Table -AutoSize
}

# ─────────────────────────────────────────────────────────────────
# REGION: 2 - User & Privilege Enumeration
# ─────────────────────────────────────────────────────────────────

Write-SectionHeader "2. User & Privilege Enumeration"

Write-SubHeader "Current User & Groups"
Safe-Invoke "whoami /all" { whoami /all }

Write-SubHeader "Dangerous Privilege Check"
Safe-Invoke "Token privs" {
    $privOutput = whoami /priv
    $dangerousPrivs = @(
        'SeImpersonatePrivilege',
        'SeAssignPrimaryTokenPrivilege',
        'SeBackupPrivilege',
        'SeRestorePrivilege',
        'SeDebugPrivilege',
        'SeTakeOwnershipPrivilege',
        'SeLoadDriverPrivilege',
        'SeCreateTokenPrivilege',
        'SeTcbPrivilege'
    )
    foreach ($priv in $dangerousPrivs) {
        if ($privOutput -match $priv) {
            $state = if ($privOutput -match "$priv.*Enabled") { "ENABLED" } else { "Disabled (may be activatable)" }
            Write-Finding "DANGEROUS PRIVILEGE FOUND: $priv [$state]" 'HIGH'
        }
    }
}

Write-SubHeader "Local Users"
Safe-Invoke "Local users" {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordExpires, Description | Format-Table -AutoSize
}

Write-SubHeader "Local Groups"
Safe-Invoke "Local groups" { Get-LocalGroup | Format-Table Name, Description -AutoSize }

Write-SubHeader "Local Administrators"
Safe-Invoke "Local admins" {
    Get-LocalGroupMember -Group Administrators | Format-Table Name, PrincipalSource, ObjectClass -AutoSize
}

Write-SubHeader "Remote Desktop Users"
Safe-Invoke "RDP users" {
    Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue | Format-Table Name, PrincipalSource -AutoSize
}

Write-SubHeader "User Home Directories"
Safe-Invoke "User homes" { Get-ChildItem C:\Users | Format-Table Name, LastWriteTime -AutoSize }

Write-SubHeader "Logged-On Users"
Safe-Invoke "Logged on" { query user 2>$null }

Write-SubHeader "PowerShell History"
Safe-Invoke "PS history" {
    $histPath = (Get-PSReadlineOption -ErrorAction SilentlyContinue).HistorySavePath
    if ($histPath -and (Test-Path $histPath)) {
        Write-Finding "PowerShell history file found: $histPath" 'MEDIUM'
        Get-Content $histPath | Select-Object -Last 50
    } else {
        Write-Output "  No history file found or PSReadline not available."
    }
}

# Check all user PS history files
Write-SubHeader "PowerShell History (All Users)"
Safe-Invoke "All user PS history" {
    Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
    ForEach-Object {
        Write-Finding "History file: $($_.FullName)" 'MEDIUM'
        Get-Content $_.FullName | Select-Object -Last 20
    }
}

# ─────────────────────────────────────────────────────────────────
# REGION: 3 - Network Enumeration
# ─────────────────────────────────────────────────────────────────

Write-SectionHeader "3. Network Enumeration"

Write-SubHeader "Network Interfaces"
Safe-Invoke "NICs" { Get-NetIPConfiguration | Format-Table InterfaceAlias, IPv4Address, IPv6Address, DNSServer -AutoSize }

Write-SubHeader "All IP Addresses"
Safe-Invoke "IP addrs" { Get-NetIPAddress | Where-Object AddressFamily -eq 'IPv4' | Format-Table InterfaceAlias, IPAddress, PrefixLength -AutoSize }

Write-SubHeader "DNS Server Configuration"
Safe-Invoke "DNS" { Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, ServerAddresses -AutoSize }

Write-SubHeader "ARP Cache"
Safe-Invoke "ARP" { Get-NetNeighbor -AddressFamily IPv4 | Format-Table ifIndex, IPAddress, LinkLayerAddress, State -AutoSize }

Write-SubHeader "Routing Table"
Safe-Invoke "Routes" { Get-NetRoute -AddressFamily IPv4 | Format-Table DestinationPrefix, NextHop, RouteMetric, ifIndex -AutoSize }

Write-SubHeader "Active Network Connections (Established)"
Safe-Invoke "netstat" {
    netstat -ano | Select-String "ESTABLISHED"
}

Write-SubHeader "Listening Ports"
Safe-Invoke "Listening" {
    netstat -ano | Select-String "LISTENING"
}

Write-SubHeader "Hosts File"
Safe-Invoke "Hosts" {
    $hostsContent = Get-Content "$env:windir\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch '^\s*#' -and $_ -ne "" }
    if ($hostsContent) {
        Write-Finding "Non-default hosts file entries found:" 'MEDIUM'
        $hostsContent | ForEach-Object { Write-Output "    $_" }
    } else {
        Write-Output "  Hosts file contains only default/commented entries."
    }
}

Write-SubHeader "Network Shares"
Safe-Invoke "Shares" {
    Get-SmbShare | Format-Table Name, Path, Description -AutoSize
    # Flag non-default shares
    $nonDefault = Get-SmbShare | Where-Object { $_.Name -notmatch '^(ADMIN\$|C\$|IPC\$|print\$)$' }
    if ($nonDefault) {
        foreach ($share in $nonDefault) {
            Write-Finding "Non-default share: $($share.Name) -> $($share.Path)" 'MEDIUM'
        }
    }
}

Write-SubHeader "WiFi Profiles & Saved Keys"
Safe-Invoke "WiFi" {
    $profiles = netsh wlan show profiles 2>$null
    if ($profiles) {
        $profileNames = $profiles | Select-String "All User Profile" | ForEach-Object { ($_ -split ":")[1].Trim() }
        foreach ($p in $profileNames) {
            $detail = netsh wlan show profile name="$p" key=clear 2>$null
            if ($detail -match "Key Content") {
                Write-Finding "WiFi password found for profile: $p" 'HIGH'
            }
            $detail
        }
    } else {
        Write-Output "  No WiFi profiles found or WLAN service not running."
    }
}

Write-SubHeader "Named Pipes"
Safe-Invoke "Named pipes" {
    Get-ChildItem \\.\pipe\ -ErrorAction SilentlyContinue | Select-Object Name | Format-Table -AutoSize
}

# ─────────────────────────────────────────────────────────────────
# REGION: 4 - Credential & Secret Hunting
# ─────────────────────────────────────────────────────────────────

Write-SectionHeader "4. Credential & Secret Hunting"

Write-SubHeader "Credential Manager Entries"
Safe-Invoke "cmdkey" {
    $creds = cmdkey /list
    $creds
    if ($creds -match "Target:") { Write-Finding "Stored credentials found in Credential Manager" 'HIGH' }
}

Write-SubHeader "Autologon Registry"
Safe-Invoke "Autologon" {
    $autologon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -ErrorAction SilentlyContinue |
                 Select-Object DefaultUserName, DefaultPassword, AutoAdminLogon, DefaultDomainName
    if ($autologon.DefaultPassword) {
        Write-Finding "AUTOLOGON PASSWORD FOUND IN REGISTRY" 'HIGH'
    }
    $autologon | Format-List
}

Write-SubHeader "AlwaysInstallElevated Check"
Safe-Invoke "AlwaysInstallElevated" {
    $hkcu = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
    $hklm = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
    if ($hkcu.AlwaysInstallElevated -eq 1 -and $hklm.AlwaysInstallElevated -eq 1) {
        Write-Finding "AlwaysInstallElevated is ENABLED - MSI privesc possible!" 'HIGH'
    } else {
        Write-Output "  AlwaysInstallElevated not set or not vulnerable."
    }
    Write-Output "  HKCU: $($hkcu.AlwaysInstallElevated)  |  HKLM: $($hklm.AlwaysInstallElevated)"
}

Write-SubHeader "Unattend / Sysprep Files (Cleartext Credentials)"
Safe-Invoke "Unattend files" {
    $unattendPaths = @(
        "C:\unattend.xml",
        "C:\Windows\Panther\Unattend.xml",
        "C:\Windows\Panther\Unattended.xml",
        "C:\Windows\system32\sysprep\sysprep.xml",
        "C:\Windows\system32\sysprep\sysprep.inf",
        "C:\Windows\system32\sysprep\Panther\Unattend.xml"
    )
    foreach ($p in $unattendPaths) {
        if (Test-Path $p) {
            Write-Finding "Unattend file found: $p" 'HIGH'
            Get-Content $p | Select-String -Pattern "password|Username|AdministratorPassword" -CaseSensitive:$false
        }
    }
}

Write-SubHeader "LAPS Status"
Safe-Invoke "LAPS" {
    $laps = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -ErrorAction SilentlyContinue
    if ($laps) {
        Write-Output "  LAPS policy registry key exists"
        $laps | Format-List
    } else {
        Write-Finding "LAPS does not appear to be configured (no policy key found)" 'MEDIUM'
    }
}

Write-SubHeader "WSUS Configuration"
Safe-Invoke "WSUS" {
    $wsus = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
    if ($wsus) {
        $wsus | Format-List
        if ($wsus.WUServer -match "^http://") {
            Write-Finding "WSUS using HTTP (not HTTPS) - potential WSUS hijack vector!" 'HIGH'
        }
    } else {
        Write-Output "  No WSUS policy found."
    }
}

Write-SubHeader "IIS Configuration / App Pool Credentials"
Safe-Invoke "IIS" {
    if (Test-Path "C:\Windows\System32\inetsrv\config\applicationHost.config") {
        Write-Finding "IIS applicationHost.config found - checking for credentials" 'MEDIUM'
        Select-String -Path "C:\Windows\System32\inetsrv\config\applicationHost.config" -Pattern "password" -CaseSensitive:$false
    }
    Get-ChildItem "C:\inetpub\" -Recurse -Include web.config -ErrorAction SilentlyContinue |
    ForEach-Object {
        Write-Finding "web.config found: $($_.FullName)" 'MEDIUM'
        Select-String -Path $_.FullName -Pattern "password|connectionString" -CaseSensitive:$false
    }
}

# ─────────────────────────────────────────────────────────────────
# REGION: 5 - Privilege Escalation Vectors
# ─────────────────────────────────────────────────────────────────

Write-SectionHeader "5. Privilege Escalation Vectors"

Write-SubHeader "UAC Configuration"
Safe-Invoke "UAC" {
    $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |
           Select-Object EnableLUA, ConsentPromptBehaviorAdmin, ConsentPromptBehaviorUser, LocalAccountTokenFilterPolicy
    $uac | Format-List
    if ($uac.EnableLUA -eq 0) {
        Write-Finding "UAC is DISABLED" 'HIGH'
    }
    if ($uac.LocalAccountTokenFilterPolicy -eq 1) {
        Write-Finding "LocalAccountTokenFilterPolicy = 1 - Remote admin without UAC prompt possible" 'HIGH'
    }
}

Write-SubHeader "Unquoted Service Paths"
Safe-Invoke "Unquoted service paths" {
    $vulnerable = Get-CimInstance Win32_Service |
        Where-Object {
            $_.StartMode -ne 'Disabled' -and
            $_.PathName -notlike '"*' -and
            $_.PathName -notlike 'C:\Windows*' -and
            $_.PathName -match ' '
        } | Select-Object Name, StartMode, State, PathName
    if ($vulnerable) {
        foreach ($svc in $vulnerable) {
            Write-Finding "Unquoted path: [$($svc.Name)] $($svc.PathName)" 'HIGH'
        }
        $vulnerable | Format-Table -AutoSize
    } else {
        Write-Output "  No unquoted service paths found."
    }
}

Write-SubHeader "Writable Service Binaries"
Safe-Invoke "Writable service binaries" {
    Get-CimInstance Win32_Service | Where-Object { $_.PathName -ne $null } | ForEach-Object {
        $bin = ($_.PathName -replace '"','') -split ' ' | Select-Object -First 1
        if ($bin -and (Test-Path $bin -ErrorAction SilentlyContinue)) {
            $acl = Get-Acl $bin -ErrorAction SilentlyContinue
            if ($acl) {
                $writable = $acl.Access | Where-Object {
                    $_.FileSystemRights -match 'Write|FullControl|Modify' -and
                    $_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users'
                }
                if ($writable) {
                    Write-Finding "WRITABLE SERVICE BINARY: $bin [$($_.Name)]" 'HIGH'
                }
            }
        }
    }
}

Write-SubHeader "Writable Directories in System PATH"
Safe-Invoke "Writable PATH dirs" {
    $pathDirs = $env:PATH -split ';' | Where-Object { $_ -ne '' }
    foreach ($dir in $pathDirs) {
        if (Test-Path $dir -ErrorAction SilentlyContinue) {
            try {
                $testFile = Join-Path $dir "pentest_write_test_$([guid]::NewGuid().ToString('N')).tmp"
                [IO.File]::Create($testFile).Close()
                Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                Write-Finding "WRITABLE PATH DIRECTORY: $dir (DLL/binary hijacking possible)" 'HIGH'
            } catch {}
        }
    }
}

Write-SubHeader "Scheduled Tasks (Non-Microsoft, with Script Paths)"
Safe-Invoke "Scheduled tasks" {
    Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' } |
    ForEach-Object {
        $task = $_
        $actions = $task.Actions | Where-Object { $_.Execute -ne $null }
        foreach ($action in $actions) {
            $execPath = $action.Execute -replace '"', ''
            if ($execPath -and (Test-Path $execPath -ErrorAction SilentlyContinue)) {
                $acl = Get-Acl $execPath -ErrorAction SilentlyContinue
                $writable = $acl.Access | Where-Object {
                    $_.FileSystemRights -match 'Write|FullControl|Modify' -and
                    $_.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users'
                }
                if ($writable) {
                    Write-Finding "WRITABLE TASK BINARY: $execPath [$($task.TaskName)]" 'HIGH'
                }
            }
        }
        $task | Select-Object TaskName, TaskPath, State | Format-Table -AutoSize
    }
}

Write-SubHeader "SAM / SYSTEM Backup Files"
Safe-Invoke "SAM backups" {
    $samPaths = @(
        "$env:SystemRoot\repair\SAM",
        "$env:SystemRoot\system32\config\regback\SAM",
        "$env:SystemRoot\repair\SYSTEM",
        "$env:SystemRoot\system32\config\regback\SYSTEM"
    )
    foreach ($p in $samPaths) {
        if (Test-Path $p) { Write-Finding "SAM/SYSTEM backup found: $p" 'HIGH' }
    }
}

Write-SubHeader "DLL Hijacking - Missing DLLs (Procmon-style hint)"
Safe-Invoke "DLL hints" {
    # Check common DLL hijack paths in user-writable directories
    $dllHijackPaths = @("C:\Windows\Temp", "$env:TEMP", "$env:APPDATA")
    foreach ($path in $dllHijackPaths) {
        if (Test-Path $path) {
            $acl = Get-Acl $path -ErrorAction SilentlyContinue
            if ($acl) {
                $writable = $acl.Access | Where-Object {
                    $_.FileSystemRights -match 'Write|FullControl|Modify' -and
                    $_.IdentityReference -match $env:UserName
                }
                if ($writable) {
                    Write-Output "  [~] User-writable: $path (may be useful for DLL drops)"
                }
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────────
# REGION: 6 - Services, Processes & Software
# ─────────────────────────────────────────────────────────────────

Write-SectionHeader "6. Services, Processes & Software"

Write-SubHeader "Running Services"
Safe-Invoke "Services" {
    Get-Service | Sort-Object Status | Format-Table Name, DisplayName, Status -AutoSize
}

Write-SubHeader "Running Processes (Excluding svchost)"
Safe-Invoke "Processes" {
    Get-Process | Where-Object { $_.Name -ne 'svchost' } |
    Select-Object Name, Id, Path, CPU, WorkingSet |
    Sort-Object CPU -Descending | Format-Table -AutoSize
}

Write-SubHeader "Processes Running as SYSTEM"
Safe-Invoke "SYSTEM processes" {
    Get-CimInstance Win32_Process | ForEach-Object {
        $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue
        if ($owner.User -eq 'SYSTEM') {
            [PSCustomObject]@{ PID=$_.ProcessId; Name=$_.Name; Path=$_.ExecutablePath; Owner="$($owner.Domain)\$($owner.User)" }
        }
    } | Format-Table -AutoSize
}

Write-SubHeader "Startup Programs"
Safe-Invoke "Startup" { Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Format-List }

Write-SubHeader "Installed Programs (Registry)"
Safe-Invoke "Installed software" {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $paths | ForEach-Object {
        Get-ItemProperty $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName | Format-Table -AutoSize
}

Write-SubHeader "Installed Programs (Program Files Directories)"
Safe-Invoke "Program files" {
    Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" -ErrorAction SilentlyContinue |
    Format-Table Name, LastWriteTime -AutoSize
}

# ─────────────────────────────────────────────────────────────────
# REGION: 7 - Security Configuration
# ─────────────────────────────────────────────────────────────────

Write-SectionHeader "7. Security Configuration"

Write-SubHeader "Antivirus / EDR Detection"
Safe-Invoke "AV detection" {
    $avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
    if ($avProducts) {
        $avProducts | ForEach-Object {
            $state = switch ($_.productState.ToString("X6").Substring(2,2)) {
                "10" { "ENABLED" } "11" { "ENABLED" } "00" { "DISABLED" } "01" { "SNOOZED" } default { "UNKNOWN" }
            }
            Write-Output "  AV Product : $($_.displayName)"
            Write-Output "  State      : $state"
            Write-Output "  Path       : $($_.pathToSignedProductExe)"
        }
    } else {
        Write-Finding "No AV detected via SecurityCenter2 WMI (may indicate server OS or security gap)" 'MEDIUM'
    }
}

Write-SubHeader "Windows Defender Status"
Safe-Invoke "Defender" {
    $defPref = Get-MpPreference -ErrorAction SilentlyContinue
    if ($defPref) {
        Write-Output "  Real-time monitoring  : $($defPref.DisableRealtimeMonitoring -eq $false)"
        Write-Output "  Script block logging  : $($defPref.DisableScriptScanning)"
        Write-Output "  IOAV protection       : $($defPref.DisableIOAVProtection -eq $false)"
        if ($defPref.ExclusionPath) {
            Write-Finding "Defender exclusion paths configured:" 'MEDIUM'
            $defPref.ExclusionPath | ForEach-Object { Write-Output "    Excluded: $_" }
        }
        if ($defPref.ExclusionProcess) {
            Write-Finding "Defender exclusion processes configured:" 'MEDIUM'
            $defPref.ExclusionProcess | ForEach-Object { Write-Output "    Excluded: $_" }
        }
    }
}

Write-SubHeader "Firewall Status (All Profiles)"
Safe-Invoke "Firewall" { netsh advfirewall show allprofiles }

Write-SubHeader "AppLocker Policy"
Safe-Invoke "AppLocker" {
    $alPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
    if ($alPolicy) {
        Write-Finding "AppLocker policy is configured" 'LOW'
        $alPolicy.RuleCollections | ForEach-Object {
            Write-Output "  RuleCollection: $($_.RuleCollectionType) [Enforcement: $($_.EnforcementMode)]"
        }
    } else {
        Write-Finding "No AppLocker policy found" 'MEDIUM'
    }
}

Write-SubHeader "PowerShell Security Settings (AMSI / ScriptBlock / Transcription)"
Safe-Invoke "PS security settings" {
    # ScriptBlock Logging
    $sbLog = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
    Write-Output "  ScriptBlock Logging Enabled : $($sbLog.EnableScriptBlockLogging)"
    if ($sbLog.EnableScriptBlockLogging -ne 1) {
        Write-Finding "ScriptBlock logging is NOT enabled" 'MEDIUM'
    }

    # Transcription
    $trans = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
    Write-Output "  Transcription Enabled       : $($trans.EnableTranscripting)"

    # Module Logging
    $modLog = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
    Write-Output "  Module Logging Enabled      : $($modLog.EnableModuleLogging)"

    # Constrained Language Mode
    Write-Output "  Language Mode               : $($ExecutionContext.SessionState.LanguageMode)"
    if ($ExecutionContext.SessionState.LanguageMode -eq 'ConstrainedLanguage') {
        Write-Finding "PowerShell is in ConstrainedLanguage mode" 'LOW'
    }
}

Write-SubHeader "LSA Protection & Credential Guard"
Safe-Invoke "LSA / Credential Guard" {
    $lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
    Write-Output "  RunAsPPL (LSA Protection)      : $($lsa.RunAsPPL)"
    if ($lsa.RunAsPPL -ne 1) {
        Write-Finding "LSA Protection (PPL) is NOT enabled - LSASS may be dumpable" 'HIGH'
    }

    $wdReg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ErrorAction SilentlyContinue
    Write-Output "  Credential Guard               : $($wdReg.EnableVirtualizationBasedSecurity)"

    # Check for WDigest (cleartext creds in memory)
    $wdigest = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue
    if ($wdigest.UseLogonCredential -eq 1) {
        Write-Finding "WDigest UseLogonCredential = 1 - CLEARTEXT PASSWORDS IN MEMORY" 'HIGH'
    } else {
        Write-Output "  WDigest cleartext creds        : $($wdigest.UseLogonCredential) (0 = protected)"
    }
}

Write-SubHeader "Folders with World-Writable / Everyone Access (Program Files)"
Safe-Invoke "World-writable folders" {
    Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
            $worldWrite = $acl.Access | Where-Object {
                $_.FileSystemRights -match 'Write|FullControl|Modify' -and
                $_.IdentityReference -match 'Everyone|BUILTIN\\Users|Authenticated Users'
            }
            if ($worldWrite) {
                Write-Finding "Weak ACL: $($_.FullName)" 'HIGH'
            }
        } catch {}
    }
}

# ─────────────────────────────────────────────────────────────────
# REGION: 8 - Domain Enumeration (if joined)
# ─────────────────────────────────────────────────────────────────

if ($isDomainJoined -or $Domain) {
    Write-SectionHeader "8. Active Directory / Domain Enumeration"
    Write-Output "  [*] Domain joined - performing AD enumeration..."

    Write-SubHeader "Domain Info"
    Safe-Invoke "Domain info" { [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() }

    Write-SubHeader "Domain Controllers"
    Safe-Invoke "DCs" { nltest /dclist:$env:UserDomain 2>$null }

    Write-SubHeader "Current Domain Trusts"
    Safe-Invoke "Domain trusts" { nltest /domain_trusts 2>$null }

    Write-SubHeader "Domain Users (samAccountName)"
    Safe-Invoke "Domain users" {
        $searcher = [ADSISearcher]"(&(objectCategory=user)(objectClass=user))"
        $searcher.PageSize = 1000
        $searcher.FindAll() | ForEach-Object {
            [PSCustomObject]@{
                SAMAccount  = $_.Properties['samaccountname'][0]
                DisplayName = $_.Properties['displayname'][0]
                Description = $_.Properties['description'][0]
                LastLogon   = [datetime]::FromFileTime([int64]$_.Properties['lastlogontimestamp'][0]) 2>$null
            }
        } | Format-Table -AutoSize
    }

    Write-SubHeader "Domain Groups"
    Safe-Invoke "Domain groups" {
        $searcher = [ADSISearcher]"(objectCategory=group)"
        $searcher.PageSize = 1000
        $searcher.FindAll() | ForEach-Object { $_.Properties['name'][0] } | Sort-Object | Format-Table -AutoSize
    }

    Write-SubHeader "Domain Admins Members"
    Safe-Invoke "Domain Admins" {
        $searcher = [ADSISearcher]"(&(objectCategory=group)(cn=Domain Admins))"
        $group = $searcher.FindOne()
        if ($group) {
            $group.Properties['member'] | ForEach-Object { Write-Output "  $_" }
        }
    }

    Write-SubHeader "Kerberoastable Accounts (SPNs)"
    Safe-Invoke "SPNs" {
        $searcher = [ADSISearcher]"(&(objectCategory=user)(servicePrincipalName=*)(!samAccountName=krbtgt))"
        $searcher.PageSize = 1000
        $results = $searcher.FindAll()
        if ($results.Count -gt 0) {
            Write-Finding "$($results.Count) Kerberoastable account(s) found!" 'HIGH'
            $results | ForEach-Object {
                [PSCustomObject]@{
                    Account = $_.Properties['samaccountname'][0]
                    SPNs    = ($_.Properties['serviceprincipalname'] -join '; ')
                }
            } | Format-Table -AutoSize
        } else {
            Write-Output "  No Kerberoastable accounts found."
        }
    }

    Write-SubHeader "AS-REP Roastable Accounts (No Preauth)"
    Safe-Invoke "AS-REP roast" {
        $searcher = [ADSISearcher]"(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        $results = $searcher.FindAll()
        if ($results.Count -gt 0) {
            Write-Finding "$($results.Count) AS-REP Roastable account(s) found!" 'HIGH'
            $results | ForEach-Object { Write-Output "  $($_.Properties['samaccountname'][0])" }
        } else {
            Write-Output "  No AS-REP roastable accounts found."
        }
    }

    Write-SubHeader "Domain Password Policy"
    Safe-Invoke "Password policy" { net accounts /domain 2>$null }

} else {
    Write-SectionHeader "8. Active Directory / Domain Enumeration"
    Write-Output "  [~] Host is not domain-joined. Use -Domain switch to force. Skipping."
}

# ─────────────────────────────────────────────────────────────────
# REGION: 9 - Extended / File Hunting
# ─────────────────────────────────────────────────────────────────

if ($Extended) {
    Write-SectionHeader "9. Extended - File & Credential Hunting"

    Write-SubHeader "Interesting Files (Archives, Keys, Config, Creds)"
    Safe-Invoke "Interesting files" {
        $extensions = @('*.zip','*.rar','*.7z','*.kdbx','*.kdb','*.conf','*.config',
                        '*.pem','*.ppk','*.key','*.rdp','*.vnc','*.cred',
                        '*.pfx','*.p12','*.ovpn','*.cfg','*.ini')
        $searchRoots = @("C:\Users", "C:\inetpub", "C:\temp", "C:\Windows\Temp")
        foreach ($root in $searchRoots) {
            if (Test-Path $root) {
                Get-ChildItem $root -Recurse -Include $extensions -ErrorAction SilentlyContinue |
                Select-Object FullName, LastWriteTime, Length | Format-Table -AutoSize
            }
        }
    }

    Write-SubHeader "Password Strings in Common Locations"
    Safe-Invoke "Password grep" {
        $grepPaths = @("C:\inetpub","C:\Users\$env:UserName\Documents","C:\Scripts","C:\Tools")
        foreach ($p in $grepPaths) {
            if (Test-Path $p) {
                Get-ChildItem $p -Recurse -Include *.txt,*.xml,*.ini,*.config,*.ps1,*.bat,*.cmd -ErrorAction SilentlyContinue |
                Select-String -Pattern "password|passwd|pwd|secret|credential" -CaseSensitive:$false -ErrorAction SilentlyContinue |
                Select-Object Path, LineNumber, Line | Format-Table -AutoSize
            }
        }
    }

    Write-SubHeader "Recently Modified Files (Last 10, C:\Users)"
    Safe-Invoke "Recent files" {
        Get-ChildItem "C:\Users" -Recurse -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 20 FullName, LastWriteTime | Format-Table -AutoSize
    }

    Write-SubHeader "Recent Documents"
    Safe-Invoke "Recent docs" {
        Get-ChildItem "C:\Users\$env:UserName\AppData\Roaming\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue |
        Select-Object Name, LastWriteTime | Format-Table -AutoSize
    }

    Write-SubHeader "SSH Keys"
    Safe-Invoke "SSH keys" {
        Get-ChildItem "C:\Users\*\.ssh\*" -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Finding "SSH key/config: $($_.FullName)" 'HIGH'
        }
    }

    Write-SubHeader "Registry Run Keys"
    Safe-Invoke "Run keys" {
        $runKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        foreach ($key in $runKeys) {
            if (Test-Path $key) {
                Write-Output "  $key"
                Get-ItemProperty $key -ErrorAction SilentlyContinue |
                Get-Member -MemberType NoteProperty | Where-Object { $_.Name -notmatch '^PS' } |
                ForEach-Object { Write-Output "    $($_.Name) = $((Get-ItemProperty $key).$($_.Name))" }
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────────
# REGION: Footer
# ─────────────────────────────────────────────────────────────────

Write-SectionHeader "Enumeration Complete" 'Green'
Write-Output "`n  Finished at  : $(Get-Date)"
Write-Output "  Host         : $computerName"
Write-Output "  User         : $currentUser"
Write-Output "  Admin        : $isAdmin"
if ($OutputFile -ne "") { Write-Output "  Output saved : $OutputFile" }
Write-Output ""

if ($transcribing) {
    Stop-Transcript
}

if ($IsInteractive -and -not $transcribing) {
    Read-Host "`n  Press Enter to exit"
}
