param (
    [switch]$Extended
)

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
}

# Timestamp
$runTime = Get-Date
Write-Output "`n[***] Script started at: $runTime ***`n"

# OS Detection
$computerName = $env:COMPUTERNAME
$osInfo = Get-WmiObject Win32_OperatingSystem
$osCaption = $osInfo.Caption
Write-Output "[*] Detected Operating System on ${computerName}: ${osCaption}`n"


# Command dictionary
$commands = [ordered]@{
    # === 01 - Overview ===
    'Hostname'                       = 'hostname';
    'Current Username'              = '$env:USERNAME';
    'OS Name and Version'           = 'systeminfo | findstr /B /C:"OS Name" /C:"OS Version"';
    'System PATH'                   = '$env:PATH';
    'Environment Variables'         = 'Get-ChildItem Env: | Format-Table Key,Value -AutoSize';

    # === 02 - System Summary Information ===
    'Full System Info'              = 'systeminfo';
    'MSInfo32 System Summary'       = 'msinfo32 /report "$hostnamefolder\logs\02-MSinfo32.txt" /categories +systemsummary';
    'Driver List'                   = 'driverquery';
    'Installed Programs' = 'Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -and $_.DisplayName -notlike ''*${{*'' } | Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName';
    'Mapped and Local Drives'       = 'Get-PSDrive | Where-Object {$_.Provider -like "*FileSystem*"} | Format-Table Name,Root,Used,Free -AutoSize'
    'Shares'                        = 'Get-SmbShare | Select-Object Name, Path, Description';
    'LAPS Check'                    = 'Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ErrorAction SilentlyContinue';
    'Autologon - DefaultUsername'   = 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUsername';
    'Autologon - DefaultPassword'   = 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword';
    'Autologon - DefaultDomain'     = 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomain';
    'Autologon - ForceAutoLogon'    = 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ForceAutoLogon';
    'Registry Software Entries'     = 'Get-ChildItem "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" | ForEach-Object {Get-ItemProperty $_.PsPath} | Select DisplayName, DisplayVersion | Sort DisplayName | Format-Table -AutoSize';
    'Folders with Everyone Access'  = 'Get-ChildItem "C:\\Program Files\\*" -Recurse -ErrorAction SilentlyContinue | ForEach-Object { try { Get-Acl $_.FullName } catch {} } | Where-Object { $_.AccessToString -match "Everyone" }';
    'User Home Directories'         = 'Get-ChildItem C:\\Users | Format-Table Name';

    # === 03 - Network Information ===
    'IP Configuration'              = 'ipconfig /all';
    'Route Table'                   = 'route print';
    'ARP Cache'                     = 'arp -A';
    'Netstat Connections'           = 'netstat -ano';
    'Wireless Configuration'        = 'netsh wlan show';
    'Proxy Check'                   = 'Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Select-Object ProxyEnable, ProxyServer';
    'NetBIOS Options'               = 'powershell.exe -exec bypass "Get-ChildItem ''HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces'' | foreach {Get-ItemProperty -Path ''HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\$($_.pschildname)'' -Name NetbiosOptions} | Sort-Object netbiosoptions | Format-Table -Property netbiosOptions,PSchildname"';
    'Network Interfaces' = 'Get-NetIPConfiguration | Format-Table InterfaceAlias,IPv4Address -AutoSize';
    'DNS Server Configuration' = 'Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table';

    # === 03 - Firewall Status ===
    'Legacy Firewall - State'       = 'netsh firewall show state';
    'Legacy Firewall - Config'      = 'netsh firewall show config';
    'Advanced Firewall - Profiles'  = 'netsh advfirewall show allprofiles';
	
	
    # === 04 - User and Group Information ===
    'List Local Users'                     = 'net users';
    'Local Administrator Details'          = 'net user administrator';
    'List Local Groups'                    = 'net localgroup';
    'Administrators Group Members'         = 'net localgroup administrators';
    'Local Password Policy'                = 'net accounts';

    # === 05 - Scheduled Tasks ===
    'Scheduled Tasks (Verbose List)'       = 'schtasks /query /fo LIST /v';

    # === 06 - Running Tasks and Services ===
    'Running Tasks with Services'          = 'tasklist /SVC';

    # === 07 - Patch Information ===
    'Installed Hotfixes'                   = 'wmic qfe get Caption,Description,HotFixID,InstalledOn';
    'Defined KB Hotfixes (Filtered)'       = 'wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."';

    # === 08 - Registry Checks for Weak Configs ===
    'AlwaysInstallElevated - HKLM'       = 'reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated';
    'AlwaysInstallElevated - HKCU'       = 'reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated';

    # SCHANNEL Cipher and Protocol Checks
    'SCHANNEL Cipher: DES 56/56'         = 'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56"';
    'SCHANNEL Cipher: NULL'              = 'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL"';
    'SCHANNEL Cipher: RC2 Variants'      = @(
                                            'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128"',
                                            'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128"',
                                            'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128"'
                                          );
    'SCHANNEL Cipher: RC4 Variants'      = @(
                                            'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128"',
                                            'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128"',
                                            'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128"',
                                            'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128"'
                                          );
    'SCHANNEL Protocols: Deprecated'     = @(
                                            'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client"',
                                            'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server"',
                                            'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client"',
                                            'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server"',
                                            'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"',
                                            'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"',
                                            'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"',
                                            'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"',
                                            'reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"'
                                          );

    # === 09 - Windows Services Access Checks ===
    'AccessChk - Authenticated Users'    = 'cmd /c accesschk.exe -uwcqv "Authenticated Users" * /accepteula';
    'AccessChk - Everyone'               = 'cmd /c accesschk.exe -uwcqv "Everyone" * /accepteula';
    'AccessChk - All Services'           = 'cmd /c accesschk.exe -ucqv * /accepteula';

    'Service Paths (Non-System32)'       = 'wmic service list full | find /i "pathname" | find /i /v "system32"';
    'Service ACL Dump via ICACLS'        = '<loop through service paths and run icacls> # Requires dynamic logic';
    'Unquoted Service Paths'             = 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """"';

    # === 11 - Additional Domain Info (via Script) ===
    'Domain Controller Checks'           = 'Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, Site, IsGlobalCatalog';

    # === 12 - Time Synchronisation ===
    'Time Sync Status'                   = 'w32tm /query /status';

    # === 13 - Privilege Escalation Checks (Optional) ===
    #'PowerUp All Checks'                = 'powershell.exe -ExecutionPolicy Bypass -File "$workingdir\scripts\PowerUp.ps1"; Invoke-AllChecks';

    # === 14 - Interesting File Discovery ===
    'Search: Passwords in Files'           = 'findstr /si password *.xml *.ini *.txt';
    'Registry Search: Passwords (HKLM)'    = 'reg query HKLM /f password /t REG_SZ /s';
    'Registry Search: Passwords (HKCU)'    = 'reg query HKCU /f password /t REG_SZ /s';

    # === File Scraping: Sensitive Deployment Files ===
    'Copy: sysprep.inf'                    = 'if exist c:\sysprep.inf copy c:\sysprep.inf "$hostnamefolder\logs\files\sysprep.inf"';
    'Copy: sysprep.xml'                    = 'if exist c:\sysprep\sysprep.xml copy c:\sysprep\sysprep.xml "$hostnamefolder\logs\files\sysprep1.inf"';
    'Copy: Unattended.xml (Panther)'       = 'if exist $env:WINDIR\Panther\Unattend\Unattended.xml copy $env:WINDIR\Panther\Unattend\Unattended.xml "$hostnamefolder\logs\files\Unattended.xml"';
    'Copy: Unattended1.xml (Panther)'      = 'if exist $env:WINDIR\Panther\Unattended.xml copy $env:WINDIR\Panther\Unattended.xml "$hostnamefolder\logs\files\Unattended1.xml"';

    'Search: Files with "password" in Name' = 'dir /s *password.txt == *passwords.txt*';

    # === Group Policy & Domain Enumeration ===
    'Export: Group Policy (HTML)'          = 'gpresult /h "$hostnamefolder\logs\domain\gpresult.html"';
    'Domain Password Policy'               = 'net accounts /domain';
    'Domain Trusts'                        = 'nltest /domain_trusts';
    'AD Group: Domain Admins'              = 'net group "Domain Admins" /domain';
    'AD Group: Schema Admins'              = 'net group "Schema Admins" /domain';
    'AD Group: Enterprise Admins'          = 'net group "Enterprise Admins" /domain';

    # === Local Security Policy Export ===
    'Export: Local Security Policy'        = 'secedit /export /areas SECURITYPOLICY /cfg "$hostnamefolder\logs\sec-pol.txt"';

    # === EGRESS Filtering Test ===
    'Run: EGRESS PortScan'                 = 'powershell.exe -ExecutionPolicy Bypass -File "$workingdir\PortScan-Top128.ps1"';

    # === Antivirus Status ===
    'AV Status: Get-MpComputerStatus'      = 'powershell.exe -ExecutionPolicy Bypass -Command "(Get-MpComputerStatus)"';
    'AV Status: Get-MpPreference'          = 'powershell.exe -ExecutionPolicy Bypass -Command "(Get-MpPreference)"';

    # === .NET Version Registry Hint ===
    'Registry Hint: .NET Versions'         = 'reg query "HKLM\SOFTWARE\Microsoft\.NETFramework"';
}



# Add extended/optional commands
if ($Extended) {
    $commands['SAM Backup File Check']                = 'Test-Path "$env:SystemRoot\repair\SAM"; Test-Path "$env:SystemRoot\system32\config\regback\SAM"';
    $commands['Recent Documents']                     = 'Get-ChildItem "C:\Users\$env:UserName\AppData\Roaming\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue | Select Name';
    $commands['Interesting Files (Archives/Secrets)'] = 'Get-ChildItem "C:\Users" -Recurse -Include *.zip,*.rar,*.kdbx,*.conf,*.pem,*.ppk,*.rdp,*.vnc,*.txt,*.ps1 -ErrorAction SilentlyContinue | Select FullName';
    $commands['Last 10 Modified Files in Users']      = 'Get-ChildItem "C:\Users" -Recurse -ErrorAction SilentlyContinue | Sort LastWriteTime | Select -Last 10 FullName';
}

function Run-Commands {
    param ($cmds)
    foreach ($entry in $cmds.GetEnumerator()) {
        Write-SectionHeader $entry.Key
        try {
            $output = Invoke-Expression $entry.Value | Out-String -Stream
            if ($output) {
                $output | ForEach-Object { Write-Output $_ }
            } else {
                Write-Output "[!] No output returned."
            }
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
} else {
    Read-Host "`nPress Enter to exit"
}
