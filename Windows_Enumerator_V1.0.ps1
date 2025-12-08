param (
    [switch]$Extended
)

# Header line for visual separation
$line = '-' * 60

function Write-SectionHeader {
    param ([string]$Title)
    Write-Host "`n$line" -ForegroundColor Yellow
    Write-Host " $Title" -ForegroundColor Yellow
    Write-Host "$line" -ForegroundColor Yellow
}

# Ask if user wants to save output to file
$saveToFile = Read-Host "Would you like to save the output to a text file? (y/n)"
if ($saveToFile -match '^(y|yes)$') {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logPath = "$PSScriptRoot\WindowsEnum_$timestamp.txt"
    Start-Transcript -Path $logPath -NoClobber
    Write-Output "`n[*] Logging output to: $logPath`n"
    Write-Output "[*] Note: Output file contains sensitive system information - restrict access appropriately`n"
}

# Timestamp
$runTime = Get-Date
Write-Output "`n[***] Script started at: $runTime ***`n"

# OS Detection
$computerName = $env:COMPUTERNAME
$osInfo = Get-WmiObject Win32_OperatingSystem
$osCaption = $osInfo.Caption
Write-Output "[*] Detected Operating System on $computerName: $osCaption`n"

# Core command dictionary
$commands = [ordered]@{
    'Basic System Information'                        = 'systeminfo';
    'Environment Variables'                           = 'Get-ChildItem Env: | Format-Table Key,Value -AutoSize';
    'Network Interfaces'                              = 'Get-NetIPConfiguration | Format-Table InterfaceAlias,IPv4Address -AutoSize';
    'DNS Server Configuration'                        = 'Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table';
    'ARP Cache'                                       = 'Get-NetNeighbor -AddressFamily IPv4 | Format-Table ifIndex,IPAddress,LinkLayerAddress,State -AutoSize';
    'Routing Table'                                   = 'Get-NetRoute -AddressFamily IPv4 | Format-Table DestinationPrefix,NextHop,RouteMetric -AutoSize';
    'Open Network Connections'                        = 'netstat -ano';
    'Mapped and Local Drives'                         = 'Get-PSDrive | Where-Object {$_.Provider -like "*FileSystem*"} | Format-Table Name,Root,Used,Free -AutoSize';
    'Firewall Configuration'                          = 'netsh advfirewall show allprofiles';
    'Credential Manager Entries'                      = 'cmdkey /list';
    'Autologon Registry Entries'                      = 'Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" | Select DefaultUserName,DefaultPassword,AutoAdminLogon';
    'Local Groups'                                    = 'Get-LocalGroup | Format-Table Name';
    'Local Administrators'                            = 'Get-LocalGroupMember -Group Administrators | Format-Table Name, PrincipalSource -AutoSize';
    'User Home Directories'                           = 'Get-ChildItem C:\Users | Format-Table Name';
    'Installed Programs (Program Files)'              = 'Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" | Format-Table Parent,Name,LastWriteTime';
    'Registry Software Entries'                       = 'Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | ForEach-Object {Get-ItemProperty $_.PsPath} | Select DisplayName, DisplayVersion | Sort DisplayName | Format-Table -AutoSize';
    'Folders with Everyone Access'                    = 'Get-ChildItem "C:\Program Files\*" -Recurse -ErrorAction SilentlyContinue | ForEach-Object { try { Get-Acl $_.FullName } catch {} } | Where-Object { $_.AccessToString -match "Everyone" }';
    'AlwaysInstallElevated (User)'                    = 'Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue';
    'AlwaysInstallElevated (Machine)'                 = 'Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue';
    'Unquoted Service Paths'                          = 'Get-WmiObject Win32_Service | Where-Object { $_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike ''"*'' } | Select DisplayName, PathName | Format-Table';
    'Scheduled Tasks (Non-Microsoft)'                 = 'Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\\Microsoft*"} | Format-Table TaskName,TaskPath,State';
    'Startup Programs'                                = 'Get-CimInstance Win32_StartupCommand | Select Name, Command, Location, User | Format-List';
    'Hosts File Content'                              = 'Get-Content "$env:windir\System32\drivers\etc\hosts"';
    'Running Services'                                = 'Get-Service | Sort-Object Status | Format-Table Name, DisplayName, Status -AutoSize';
    'Hotfixes / Patches'                              = 'Get-HotFix | Sort InstalledOn | Format-Table HotFixID, InstalledOn';
    'Local Users'                                     = 'Get-LocalUser | Format-Table Name,Enabled,LastLogon';
    'Logged-On Users'                                 = 'Get-CimInstance Win32_LoggedOnUser | Format-Table';
    'Current Logged-In User'                          = '$env:UserDomain\$env:UserName';
    'User Privileges (Token Rights)'                  = 'whoami /priv';
    'Running Processes (non-svchost)'                 = 'Get-Process | Where-Object {$_.Name -ne "svchost"} | Select Name, Id, Path | Format-Table -AutoSize';
    'UAC Configuration'                               = 'Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select EnableLUA, ConsentPromptBehaviorAdmin';
    'PowerShell History (if available)'               = 'Get-Content (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue';
    'Antivirus Product Detection'                     = 'Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select displayName, pathToSignedProductExe';
}

# Add extended/optional commands
if ($Extended) {
    $commands['SAM Backup File Check']                = 'Test-Path "$env:SystemRoot\repair\SAM"; Test-Path "$env:SystemRoot\system32\config\regback\SAM"';
    $commands['Recent Documents']                     = 'Get-ChildItem "C:\Users\$env:UserName\AppData\Roaming\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue | Select Name';
    $commands['Interesting Files (Archives/Secrets)'] = 'Get-ChildItem "C:\Users" -Recurse -Include *.zip,*.rar,*.kdbx,*.conf,*.pem,*.ppk,*.rdp,*.vnc,*.txt,*.ps1 -ErrorAction SilentlyContinue | Select FullName';
    $commands['Last 10 Modified Files in Users']      = 'Get-ChildItem "C:\Users" -Recurse -ErrorAction SilentlyContinue | Sort LastWriteTime | Select -Last 10 FullName';
}

# Run all commands with headers
# SECURITY NOTE: Uses Invoke-Expression with hardcoded commands from dictionary only
# Never modify this function to accept user input directly
function Run-Commands {
    param ($cmds)
    foreach ($entry in $cmds.GetEnumerator()) {
        Write-SectionHeader $entry.Key
        try {
            Invoke-Expression $entry.Value
        }
        catch {
            Write-Warning "Error running [$($entry.Key)]: $_"
        }
    }
}

Run-Commands $commands

Write-SectionHeader "Enumeration Complete"
Write-Output "Script finished successfully at $(Get-Date)."

if ($saveToFile -match '^(y|yes)$') {
    Stop-Transcript
    Write-Output "`n[*] Output was saved to: $logPath"
}
else {
    Read-Host "`nPress Enter to exit"
}
