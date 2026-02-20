#!/usr/bin/env bash
# ==============================================================================
#  macOS Enumerator V2.0
#  Author  : MrWhiskers
#  Purpose : Rapid macOS system enumeration for build reviews and pentests.
#            Not a replacement for MacPEAS - designed for fast, structured,
#            human-readable output during macOS security assessments.
#
#  Usage   : ./MacOS_Enumerator_V2.0.sh [OPTIONS]
#
#  Options:
#    -o <file>    Save output to file (default: auto-named in current dir)
#    -e           Extended mode: file hunting, password grep, browser history
#    -n           No colour output (useful for piping / logging)
#    -h           Show this help
#
#  Examples:
#    ./MacOS_Enumerator_V2.0.sh
#    ./MacOS_Enumerator_V2.0.sh -e
#    ./MacOS_Enumerator_V2.0.sh -o /tmp/enum.txt
#    ./MacOS_Enumerator_V2.0.sh -e -o /tmp/enum.txt -n
#
#  Note: Does not require root. Run as current user.
#        Some checks require sudo or Full Disk Access (FDA) - noted inline.
#        Tested on macOS Ventura, Sonoma (Intel + Apple Silicon).
# ==============================================================================

# ── Bail on undefined variables ───────────────────────────────────────────────
set -o nounset

# ── Defaults ──────────────────────────────────────────────────────────────────
EXTENDED=false
NO_COLOUR=false
OUTPUT_FILE=""

# ── Argument Parsing ──────────────────────────────────────────────────────────
while getopts "o:enh" opt; do
    case $opt in
        o) OUTPUT_FILE="$OPTARG" ;;
        e) EXTENDED=true ;;
        n) NO_COLOUR=true ;;
        h)
            sed -n '3,20p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown option. Use -h for help." >&2; exit 1 ;;
    esac
done

# ── Auto-name output file if not specified ────────────────────────────────────
if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="./macos_enum_$(hostname -s)_$(date +%Y%m%d_%H%M%S).txt"
fi

# ── Colour Definitions ────────────────────────────────────────────────────────
if [[ "$NO_COLOUR" == false ]] && [[ -t 1 ]]; then
    C_RESET='\033[0m'
    C_CYAN='\033[0;36m'
    C_DCYAN='\033[0;34m'
    C_YELLOW='\033[0;33m'
    C_RED='\033[0;31m'
    C_GREEN='\033[0;32m'
    C_WHITE='\033[1;37m'
    C_GREY='\033[0;90m'
else
    C_RESET=''; C_CYAN=''; C_DCYAN=''; C_YELLOW=''
    C_RED=''; C_GREEN=''; C_WHITE=''; C_GREY=''
fi

# ── Output Helpers ────────────────────────────────────────────────────────────
# Pipe all stdout/stderr through tee into the output file
exec > >(tee -a "$OUTPUT_FILE") 2>&1
chmod 600 "$OUTPUT_FILE" 2>/dev/null

LINE='================================================================='
SUBLINE='-----------------------------------------------------------------'

section() {
    echo -e "\n${C_CYAN}${LINE}${C_RESET}"
    echo -e "${C_CYAN}  [*] $1${C_RESET}"
    echo -e "${C_CYAN}${LINE}${C_RESET}"
}

subsection() {
    echo -e "\n${C_DCYAN}  ${SUBLINE}${C_RESET}"
    echo -e "${C_DCYAN}    >> $1${C_RESET}"
    echo -e "${C_DCYAN}  ${SUBLINE}${C_RESET}"
}

finding() {
    local msg="$1"
    local sev="${2:-INFO}"
    case "$sev" in
        HIGH)   echo -e "  ${C_RED}[!] HIGH   : $msg${C_RESET}" ;;
        MEDIUM) echo -e "  ${C_YELLOW}[!] MEDIUM : $msg${C_RESET}" ;;
        LOW)    echo -e "  ${C_GREEN}[!] LOW    : $msg${C_RESET}" ;;
        *)      echo -e "  ${C_WHITE}[*] $msg${C_RESET}" ;;
    esac
}

# Safe command runner — checks binary exists, swallows errors gracefully
run() {
    local label="$1"; shift
    local bin
    bin=$(echo "$1" | awk '{print $1}')
    if command -v "$bin" &>/dev/null; then
        local out
        out=$(eval "$@" 2>/dev/null)
        if [[ -n "$out" ]]; then
            echo "$out"
        else
            echo -e "${C_GREY}  [-] $label: no output${C_RESET}"
        fi
    else
        echo -e "${C_GREY}  [-] $label: $bin not found${C_RESET}"
    fi
}

cmd_exists() { command -v "$1" &>/dev/null; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${C_CYAN}"
cat << 'EOF'

  ███╗   ███╗ █████╗  ██████╗ ██████╗ ███████╗
  ████╗ ████║██╔══██╗██╔════╝██╔═══██╗██╔════╝
  ██╔████╔██║███████║██║     ██║   ██║███████╗
  ██║╚██╔╝██║██╔══██║██║     ██║   ██║╚════██║
  ██║ ╚═╝ ██║██║  ██║╚██████╗╚██████╔╝███████║
  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
  macOS Enumerator V2.0  |  For authorised assessments only

EOF
echo -e "${C_RESET}"

# ── Context / Pre-flight ──────────────────────────────────────────────────────
section "Enumeration Context"

CURRENT_USER=$(id)
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
START_TIME=$(date)
IS_ROOT=false
[[ $EUID -eq 0 ]] && IS_ROOT=true

MACOS_VER=$(sw_vers -productVersion 2>/dev/null)
MACOS_NAME=$(sw_vers -productName 2>/dev/null)
BUILD_VER=$(sw_vers -buildVersion 2>/dev/null)
ARCH=$(uname -m)

echo "  Started      : $START_TIME"
echo "  Host         : $HOSTNAME_VAL"
echo "  User         : $CURRENT_USER"
echo "  OS           : $MACOS_NAME $MACOS_VER ($BUILD_VER)"
echo "  Architecture : $ARCH"
echo "  Extended     : $EXTENDED"
echo "  Output file  : $OUTPUT_FILE"

if [[ "$IS_ROOT" == true ]]; then
    finding "Running as ROOT - full enumeration available" HIGH
else
    finding "Running as non-root - some checks will be limited" LOW
fi

# Apple Silicon vs Intel
if [[ "$ARCH" == "arm64" ]]; then
    finding "Apple Silicon (arm64) detected" LOW
else
    finding "Intel (x86_64) detected" LOW
fi

# Rosetta check
if [[ "$ARCH" == "arm64" ]] && /usr/bin/pgrep -q oahd 2>/dev/null; then
    finding "Rosetta 2 is installed (x86 translation active)" LOW
fi

# ── SECTION 1: System Information ─────────────────────────────────────────────
section "1. System Information"

subsection "OS & Version Details"
run "sw_vers" "sw_vers"
run "uname" "uname -a"
run "kern.osversion" "sysctl kern.osversion kern.ostype kern.hostname"

subsection "Hardware Info"
run "CPU" "sysctl -n machdep.cpu.brand_string 2>/dev/null || sysctl -n hw.model"
run "hw.model" "sysctl -n hw.model"
run "Physical CPUs" "sysctl -n hw.physicalcpu"
run "Logical CPUs" "sysctl -n hw.logicalcpu"
run "Memory size" "sysctl -n hw.memsize | awk '{printf \"%.0f GB\n\", \$1/1073741824}'"
run "vm_stat" "vm_stat"

subsection "Disk & Filesystems"
run "df" "df -h"
run "diskutil list" "diskutil list"
run "mounted volumes" "mount | grep -v 'devfs\|map '"

subsection "Uptime & Load"
run "uptime" "uptime"

subsection "System Profiler - Software"
run "system_profiler software" "system_profiler SPSoftwareDataType"

subsection "All Kernel Parameters (sysctl)"
run "sysctl -a" "sysctl -a 2>/dev/null"

# ── SECTION 2: User & Privilege Enumeration ───────────────────────────────────
section "2. User & Privilege Enumeration"

subsection "Current User Identity"
run "id" "id"
run "whoami" "whoami"
run "groups" "groups"

subsection "sudo -l (Privilege Check)"
SUDO_OUT=$(sudo -n -l 2>/dev/null)
if [[ -n "$SUDO_OUT" ]]; then
    finding "sudo -l returned output - review for privesc vectors" HIGH
    echo "$SUDO_OUT"
else
    # Try with password prompt suppressed
    SUDO_OUT2=$(sudo -l 2>&1 | head -5)
    echo "  [-] sudo -l output: $SUDO_OUT2"
fi

subsection "All Local Users (dscl)"
run "dscl users" "dscl . -list /Users"
USERS=$(dscl . -list /Users 2>/dev/null | grep -v '^_')
echo "--- Non-system users ---"
echo "$USERS" | grep -v '^daemon\|^nobody\|^root\|^www\|^ftp'

subsection "User Details (dscl)"
for u in $(dscl . -list /Users 2>/dev/null | grep -v '^_' | grep -v '^daemon\|^nobody\|^www'); do
    echo "=== $u ==="
    dscl . -read /Users/"$u" NFSHomeDirectory RealName PrimaryGroupID UniqueID UserShell 2>/dev/null
done

subsection "Admin Group Members"
ADMINS=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null)
if [[ -n "$ADMINS" ]]; then
    finding "Admin group members: $ADMINS" HIGH
fi

subsection "All Groups"
run "dscl groups" "dscl . -list /Groups PrimaryGroupID 2>/dev/null | sort -k2 -n"

subsection "Logged-in Users"
run "who" "who"
run "w" "w"
run "last" "last -20"

subsection "Finger Info"
run "finger" "finger $(whoami) 2>/dev/null"

subsection "User Home Directories"
run "home dirs" "ls -la /Users/ 2>/dev/null"

subsection "Command History (current user)"
for hf in ~/.bash_history ~/.zsh_history ~/.python_history ~/.mysql_history; do
    if [[ -f "$hf" ]]; then
        finding "History file: $hf" MEDIUM
        tail -50 "$hf"
    fi
done

subsection "Command History (all users, if accessible)"
find /Users -name ".*_history" -readable 2>/dev/null | while read -r hf; do
    finding "Readable history: $hf" HIGH
    tail -20 "$hf"
done

subsection "Environment Variables"
env | sort

subsection "Shell Config Files (current user)"
for f in ~/.bash_profile ~/.bashrc ~/.zshrc ~/.zprofile ~/.profile; do
    [[ -f "$f" ]] && echo "=== $f ===" && cat "$f"
done

# ── SECTION 3: Security Configuration ────────────────────────────────────────
section "3. Security Configuration"

subsection "System Integrity Protection (SIP)"
SIP_STATUS=$(csrutil status 2>/dev/null)
echo "  $SIP_STATUS"
if echo "$SIP_STATUS" | grep -q "disabled"; then
    finding "SIP is DISABLED - system protections are off" HIGH
elif echo "$SIP_STATUS" | grep -qi "enabled"; then
    finding "SIP is enabled" LOW
fi

subsection "Gatekeeper Status"
GK=$(spctl --status 2>/dev/null)
echo "  $GK"
if echo "$GK" | grep -q "disabled"; then
    finding "Gatekeeper is DISABLED - unsigned apps can run freely" HIGH
fi

subsection "FileVault (Full Disk Encryption)"
FV=$(fdesetup status 2>/dev/null)
echo "  $FV"
if echo "$FV" | grep -qi "off\|not enabled\|disabled"; then
    finding "FileVault is DISABLED - disk is unencrypted" HIGH
elif echo "$FV" | grep -qi "on\|enabled"; then
    finding "FileVault is enabled" LOW
fi

subsection "Firewall Status"
FW=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null)
case "$FW" in
    0) finding "Application Firewall is DISABLED" HIGH ;;
    1) finding "Application Firewall is ON (allow signed apps)" LOW ;;
    2) finding "Application Firewall is ON (essential only)" LOW ;;
    *) echo "  [-] Could not determine firewall state" ;;
esac
run "socketfilterfw" "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null"
run "system_profiler firewall" "system_profiler SPFirewallDataType 2>/dev/null"

subsection "Firewall Stealth Mode"
STEALTH=$(defaults read /Library/Preferences/com.apple.alf stealthenabled 2>/dev/null)
[[ "$STEALTH" == "0" ]] && finding "Firewall stealth mode is DISABLED" MEDIUM

subsection "Screen Lock / Screen Saver Settings"
LOCK=$(defaults read com.apple.screensaver askForPassword 2>/dev/null)
[[ "$LOCK" != "1" ]] && finding "Screen saver password NOT required on wake" MEDIUM
DELAY=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)
echo "  askForPassword: $LOCK | delay: ${DELAY:-N/A} seconds"

subsection "Automatic Login"
AUTOLOGIN=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
if [[ -n "$AUTOLOGIN" ]]; then
    finding "Automatic login is ENABLED for user: $AUTOLOGIN" HIGH
else
    finding "Automatic login is disabled" LOW
fi

subsection "Remote Login (SSH)"
SSH_STATUS=$(systemsetup -getremotelogin 2>/dev/null)
echo "  $SSH_STATUS"
if echo "$SSH_STATUS" | grep -qi "on\|enabled"; then
    finding "Remote Login (SSH) is ENABLED" MEDIUM
fi

subsection "Remote Management (ARD / VNC)"
ARD=$(launchctl list com.apple.RemoteDesktop 2>/dev/null)
if [[ -n "$ARD" ]]; then
    finding "Apple Remote Desktop (ARD) appears to be active" HIGH
fi
run "remote management" "systemsetup -getremoteappleevents 2>/dev/null"

subsection "Screen Sharing / VNC"
VNC=$(launchctl list com.apple.screensharing 2>/dev/null)
if [[ -n "$VNC" ]]; then
    finding "Screen Sharing / VNC is active" HIGH
fi

subsection "Sharing Preferences"
run "sharing services" "sharing -l 2>/dev/null"
run "system_profiler sharing" "system_profiler SPSharingDataType 2>/dev/null"

subsection "MDM / Device Enrollment"
MDM_PROFILE=$(profiles status -type enrollment 2>/dev/null)
echo "  $MDM_PROFILE"
if echo "$MDM_PROFILE" | grep -qi "enrolled"; then
    finding "Device is MDM ENROLLED - managed device" MEDIUM
fi
run "profiles list" "profiles -P 2>/dev/null || profiles list 2>/dev/null"

subsection "TCC Database (Transparency, Consent & Control)"
TCC_DB=~/Library/Application\ Support/com.apple.TCC/TCC.db
if [[ -f "$TCC_DB" ]]; then
    finding "User TCC database found: $TCC_DB" LOW
    run "TCC user DB" "sqlite3 '$TCC_DB' 'SELECT service, client, auth_value FROM access ORDER BY service;' 2>/dev/null"
fi
SYSTEM_TCC="/Library/Application Support/com.apple.TCC/TCC.db"
if [[ -f "$SYSTEM_TCC" ]]; then
    finding "System TCC database accessible" MEDIUM
    run "TCC system DB" "sqlite3 '$SYSTEM_TCC' 'SELECT service, client, auth_value FROM access ORDER BY service;' 2>/dev/null"
fi

subsection "Antivirus / Security Tools"
for tool in mdatp sentinelctl jamf munki cbsecurity CrowdStrike; do
    if pgrep -i "$tool" &>/dev/null || cmd_exists "$tool"; then
        finding "Security tool detected: $tool" LOW
    fi
done
# Check running security processes
ps aux | grep -iE 'sentinelone|crowdstrike|defender|sophos|norton|avast|kaspersky|malwarebytes|cylance|carbon.?black' 2>/dev/null | grep -v grep

subsection "XProtect & MRT"
run "XProtect version" "defaults read /System/Library/CoreServices/XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist 2>/dev/null | head -5"
find /System/Library/CoreServices -name 'XProtect*' 2>/dev/null | head -5

subsection "Audit Daemon (auditd)"
run "audit status" "audit -s 2>/dev/null"
run "audit config" "cat /etc/security/audit_control 2>/dev/null"

# ── SECTION 4: Network Enumeration ────────────────────────────────────────────
section "4. Network Enumeration"

subsection "Network Interfaces"
run "ifconfig" "ifconfig"
run "ip addr (if available)" "ip addr 2>/dev/null"

subsection "All Network Services"
run "networksetup services" "networksetup -listallnetworkservices"
run "networksetup hardware" "networksetup -listallhardwareports"

subsection "IP Addresses"
run "ipconfig getiflist" "ipconfig getiflist 2>/dev/null"
for iface in $(networksetup -listallhardwareports 2>/dev/null | awk '/Device:/{print $2}'); do
    IP=$(ipconfig getifaddr "$iface" 2>/dev/null)
    [[ -n "$IP" ]] && echo "  $iface: $IP"
done

subsection "DNS Configuration"
run "scutil dns" "scutil --dns 2>/dev/null | head -30"
run "resolv.conf" "cat /etc/resolv.conf 2>/dev/null"

subsection "Routing Table"
run "netstat -rn" "netstat -rn"

subsection "ARP Cache"
run "arp -a" "arp -a"

subsection "Listening Ports"
LISTENING=$(lsof -i -P -n 2>/dev/null | grep LISTEN)
if [[ -n "$LISTENING" ]]; then
    echo "$LISTENING"
else
    run "netstat listen" "netstat -an 2>/dev/null | grep LISTEN"
fi

subsection "All Network Connections"
run "lsof -i" "lsof -i -P -n 2>/dev/null"

subsection "Hosts File"
HOSTS_EXTRA=$(grep -vE '^\s*#|^$|^127\.|^::1|^fe80|^255' /etc/hosts 2>/dev/null)
if [[ -n "$HOSTS_EXTRA" ]]; then
    finding "Non-default /etc/hosts entries found:" MEDIUM
    echo "$HOSTS_EXTRA"
fi
run "/etc/hosts" "cat /etc/hosts"

subsection "Wi-Fi Configuration"
run "Wi-Fi info" "networksetup -getinfo Wi-Fi 2>/dev/null"
run "Wi-Fi proxy" "networksetup -getwebproxy Wi-Fi 2>/dev/null"
run "Wi-Fi auto proxy" "networksetup -getautoproxyurl Wi-Fi 2>/dev/null"
run "Wi-Fi FTP proxy" "networksetup -getftpproxy Wi-Fi 2>/dev/null"
run "system_profiler WiFi" "system_profiler SPAirPortDataType 2>/dev/null"

subsection "Saved Wi-Fi Networks (Keychain - requires FDA)"
run "airport prefs" "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null"

subsection "SMB Shares"
run "smbutil statshares" "smbutil statshares -a 2>/dev/null"
run "system_profiler network" "system_profiler SPNetworkDataType 2>/dev/null"
run "NFS mounts" "nfsd status 2>/dev/null; showmount -e localhost 2>/dev/null"

subsection "Bluetooth"
run "system_profiler bluetooth" "system_profiler SPBluetoothDataType 2>/dev/null"

subsection "Ethernet Info"
run "system_profiler ethernet" "system_profiler SPEthernetDataType 2>/dev/null"

# ── SECTION 5: Credential & Secret Hunting ────────────────────────────────────
section "5. Credential & Secret Hunting"

subsection "SSH Keys & Config (current user)"
for f in ~/.ssh/id_rsa ~/.ssh/id_ecdsa ~/.ssh/id_ed25519 ~/.ssh/id_dsa \
          ~/.ssh/authorized_keys ~/.ssh/known_hosts ~/.ssh/config; do
    if [[ -f "$f" ]]; then
        finding "SSH file found: $f" HIGH
        cat "$f"
    fi
done

subsection "SSH Daemon Configuration"
SSH_CONF=$(cat /etc/ssh/sshd_config 2>/dev/null)
if [[ -n "$SSH_CONF" ]]; then
    echo "$SSH_CONF"
    echo "$SSH_CONF" | grep -iE 'PermitRootLogin\s+yes' && finding "SSH PermitRootLogin YES" HIGH
    echo "$SSH_CONF" | grep -iE 'PasswordAuthentication\s+yes' && finding "SSH PasswordAuthentication YES" MEDIUM
    echo "$SSH_CONF" | grep -iE 'PermitEmptyPasswords\s+yes' && finding "SSH PermitEmptyPasswords YES" HIGH
fi

subsection "Keychain Summary (current user)"
run "keychain list" "security list-keychains 2>/dev/null"
run "default keychain" "security default-keychain 2>/dev/null"
# Note: Dumping keychain passwords requires user password prompt - not automated

subsection "Certificates in Keychain"
run "keychain certs" "security find-certificate -a 2>/dev/null | grep 'alis\|labl' | head -40"

subsection "Generic Passwords in Keychain (no auth - metadata only)"
run "generic passwords" "security dump-keychain 2>/dev/null | grep -E 'acct|svce|desc' | head -40"

subsection "AWS / Cloud Credentials"
for f in ~/.aws/credentials ~/.aws/config \
          ~/.config/gcloud/credentials.db \
          ~/.config/gcloud/application_default_credentials.json \
          ~/.azure/credentials; do
    if [[ -f "$f" ]]; then
        finding "Cloud credential file: $f" HIGH
        cat "$f"
    fi
done

subsection "Clipboard Contents"
run "pbpaste" "pbpaste 2>/dev/null"
CLIP=$(pbpaste 2>/dev/null)
if echo "$CLIP" | grep -iqE 'password|secret|token|key|BEGIN.*PRIVATE'; then
    finding "Clipboard contains potentially sensitive data" HIGH
fi

subsection "Recently Accessed Files (recent items)"
run "recent files" "ls -lt ~/Desktop ~/Documents ~/Downloads 2>/dev/null | head -30"

subsection ".env and Config Files (current user tree)"
find ~ -maxdepth 5 -name '.env' -o -name '*.env' 2>/dev/null | while read -r f; do
    finding ".env file: $f" HIGH
    cat "$f"
done

subsection "Git Config Credentials"
run "~/.gitconfig" "cat ~/.gitconfig 2>/dev/null"
find ~ -maxdepth 5 -name '.git-credentials' -readable 2>/dev/null | while read -r f; do
    finding "Git credentials file: $f" HIGH
    cat "$f"
done

# ── SECTION 6: Privilege Escalation Vectors ───────────────────────────────────
section "6. Privilege Escalation Vectors"

subsection "SUID Binaries"
SUID=$(find / -perm -4000 -type f 2>/dev/null | sort)
if [[ -n "$SUID" ]]; then
    finding "SUID binaries found - compare against known macOS defaults:" MEDIUM
    echo "$SUID"
fi

subsection "SGID Binaries"
SGID=$(find / -perm -2000 -type f 2>/dev/null | sort)
if [[ -n "$SGID" ]]; then
    finding "SGID binaries found:" MEDIUM
    echo "$SGID"
fi

subsection "Writable Files in PATH Directories"
IFS=':' read -ra PATH_DIRS <<< "$PATH"
for dir in "${PATH_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        WP=$(find "$dir" -writable 2>/dev/null)
        if [[ -n "$WP" ]]; then
            finding "WRITABLE PATH DIRECTORY: $dir" HIGH
            echo "$WP"
        fi
    fi
done

subsection "World-Writable Files (excluding /private/tmp, /dev)"
WW=$(find / -writable -type f \
    ! -path '/private/tmp/*' ! -path '/dev/*' \
    ! -path '/System/*' ! -path '/proc/*' 2>/dev/null | \
    grep -vE '/Library/Caches|\.Trash' | head -40)
if [[ -n "$WW" ]]; then
    finding "World-writable files found (first 40):" MEDIUM
    echo "$WW"
fi

subsection "Writable LaunchAgents / LaunchDaemons"
for dir in /Library/LaunchDaemons /Library/LaunchAgents \
            ~/Library/LaunchAgents /System/Library/LaunchDaemons; do
    if [[ -d "$dir" ]]; then
        find "$dir" -writable -name '*.plist' 2>/dev/null | while read -r plist; do
            finding "WRITABLE LAUNCH PLIST: $plist" HIGH
            cat "$plist" 2>/dev/null
        done
    fi
done

subsection "LaunchDaemons / LaunchAgents (all)"
for dir in /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents; do
    echo "--- $dir ---"
    ls -la "$dir" 2>/dev/null
done

subsection "Writable Scripts Referenced in Launch Plists"
for dir in /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents; do
    [[ -d "$dir" ]] || continue
    grep -r '<string>/' "$dir"/*.plist 2>/dev/null | \
    grep -oE '/[^<]+' | sort -u | while read -r script; do
        if [[ -f "$script" ]] && [[ -w "$script" ]]; then
            finding "WRITABLE SCRIPT in LaunchPlist: $script" HIGH
        fi
    done
done

subsection "Cron Jobs"
run "crontab -l" "crontab -l 2>/dev/null"
run "/etc/crontab" "cat /etc/crontab 2>/dev/null"
run "/etc/cron.d" "ls -la /etc/cron.d/ 2>/dev/null && cat /etc/cron.d/* 2>/dev/null"
run "/etc/periodic" "ls -la /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly 2>/dev/null"

subsection "AT Jobs"
run "at -l" "at -l 2>/dev/null"

subsection "Installed Applications (non-App Store / unusual)"
run "system_profiler apps" "system_profiler SPApplicationsDataType 2>/dev/null"

subsection "Startup Items"
run "system_profiler startup" "system_profiler SPStartupItemDataType 2>/dev/null"
run "/Library/StartupItems" "ls -la /Library/StartupItems/ 2>/dev/null"

# ── SECTION 7: Running Services & Software ────────────────────────────────────
section "7. Running Services & Software"

subsection "Running Processes"
run "ps aux" "ps aux 2>/dev/null | sort -k3 -rn | head -40"

subsection "Processes with Elevated Privileges"
PRIV_PROCS=$(ps aux 2>/dev/null | awk '$1=="root" && $11!~/^\/sbin\/launchd/ && NR>1' | head -30)
if [[ -n "$PRIV_PROCS" ]]; then
    finding "Processes running as root (review for hijacking opportunities):" MEDIUM
    echo "$PRIV_PROCS"
fi

subsection "Launchctl Service List"
run "launchctl list" "launchctl list 2>/dev/null | head -80"

subsection "Installed Packages (Homebrew)"
if cmd_exists brew; then
    finding "Homebrew is installed" LOW
    run "brew list" "brew list --versions 2>/dev/null"
    run "brew outdated" "brew outdated 2>/dev/null"
else
    echo "  [-] Homebrew not installed"
fi

subsection "Installed Packages (MacPorts)"
if cmd_exists port; then
    finding "MacPorts is installed" LOW
    run "port installed" "port installed 2>/dev/null | head -50"
fi

subsection "Developer Tools Installed"
run "xcode-select" "xcode-select -p 2>/dev/null"
run "system_profiler devtools" "system_profiler SPDeveloperToolsDataType 2>/dev/null"

subsection "Compilers & Scripting Interpreters"
for lang in gcc g++ cc clang python python3 python2 perl ruby php node nodejs lua go; do
    cmd_exists "$lang" && finding "$lang is available: $(which $lang)" MEDIUM
done

subsection "Interesting Binaries Available"
for bin in nc ncat nmap curl wget socat openssl ssh scp rsync git vim nano base64 xxd; do
    cmd_exists "$bin" && echo "  [+] $bin: $(which $bin)"
done

subsection "Installed Frameworks"
run "system_profiler frameworks" "system_profiler SPFrameworksDataType 2>/dev/null"

subsection "Printers"
run "system_profiler printers" "system_profiler SPPrintersDataType 2>/dev/null"
run "lpstat" "lpstat -a 2>/dev/null"

subsection "USB Devices"
run "system_profiler USB" "system_profiler SPUSBDataType 2>/dev/null"

# ── SECTION 8: Sensitive Files & Directories ──────────────────────────────────
section "8. Sensitive Files & Directories"

subsection "Sudoers (if readable)"
run "sudoers" "cat /etc/sudoers 2>/dev/null"
run "sudoers.d" "ls -la /etc/sudoers.d/ 2>/dev/null && cat /etc/sudoers.d/* 2>/dev/null"

subsection "/etc/passwd and /etc/master.passwd"
run "/etc/passwd" "cat /etc/passwd 2>/dev/null"
run "/etc/master.passwd" "cat /etc/master.passwd 2>/dev/null"

subsection "Network Location Profiles"
run "system_profiler network locations" "system_profiler SPNetworkLocationDataType 2>/dev/null"

subsection "mDNS / Bonjour"
run "dns-sd services" "dns-sd -B _ssh._tcp . 2>/dev/null &"; sleep 2; kill $! 2>/dev/null

subsection "Interesting File Locations"
for f in ~/Library/Keychains /Library/Keychains \
          ~/Library/Application\ Support/Google/Chrome/Default/Login\ Data \
          ~/Library/Application\ Support/Firefox/Profiles \
          ~/Library/Safari/History.db \
          ~/Library/Messages; do
    [[ -e "$f" ]] && finding "Interesting path exists: $f" MEDIUM && ls -la "$f" 2>/dev/null
done

subsection "Recent Network Locations"
run "recent servers" "defaults read com.apple.recentitems Servers 2>/dev/null"

subsection "Known Hosts"
run "known_hosts" "cat ~/.ssh/known_hosts 2>/dev/null"

# ── SECTION 9: Extended Mode ──────────────────────────────────────────────────
if [[ "$EXTENDED" == true ]]; then
    section "9. Extended - Deep File & Credential Hunting"

    subsection "Spotlight Search: files named *password*"
    run "mdfind password" "mdfind password 2>/dev/null | grep -viE '(\.app|Library/Caches|\.lproj|CoreServices)' | head -30"

    subsection "Find: files named *password* or *secret* or *credential*"
    find ~ /private/tmp /opt 2>/dev/null -maxdepth 6 \
        \( -name '*password*' -o -name '*secret*' -o -name '*credential*' -o -name '*cred*' \) \
        -not -path '*/Library/Caches/*' -not -path '*/.Trash/*' 2>/dev/null | while read -r f; do
        finding "Named match: $f" MEDIUM
    done

    subsection "Interesting File Extensions"
    find ~ /opt /private/tmp -maxdepth 6 \
        \( -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' \
        -o -name '*.ppk' -o -name '*.kdbx' -o -name '*.ovpn' \
        -o -name '*.rdp' -o -name '*.bak' -o -name '*.old' \) \
        -readable 2>/dev/null | while read -r f; do
        finding "Interesting file: $f" MEDIUM
    done

    subsection "Password Strings in Home Directory Files"
    grep -rliE 'password|passwd|secret|api.?key|token' ~ 2>/dev/null | \
    grep -vE '(\.app|Library/Caches|\.lproj|\.ttf|\.png|\.jpg|\.gif)' | \
    head -30 | while read -r f; do
        finding "Password string in: $f" MEDIUM
        grep -inE 'password|passwd|secret|api.?key|token' "$f" 2>/dev/null | head -5
    done

    subsection "Browser History (Safari)"
    SAFARI_DB=~/Library/Safari/History.db
    if [[ -f "$SAFARI_DB" ]]; then
        finding "Safari History DB accessible" MEDIUM
        run "Safari history" "sqlite3 '$SAFARI_DB' 'SELECT url, visit_time FROM history_visits INNER JOIN history_items ON history_visits.history_item = history_items.id ORDER BY visit_time DESC LIMIT 50;' 2>/dev/null"
    fi

    subsection "Browser History (Chrome - Login Data)"
    CHROME_DB=~/Library/Application\ Support/Google/Chrome/Default/Login\ Data
    if [[ -f "$CHROME_DB" ]]; then
        finding "Chrome Login Data DB accessible" HIGH
        run "Chrome logins" "sqlite3 '$CHROME_DB' 'SELECT origin_url, username_value FROM logins;' 2>/dev/null"
    fi

    subsection "Browser History (Firefox)"
    FF_PROFILE=$(find ~/Library/Application\ Support/Firefox/Profiles -name 'logins.json' 2>/dev/null | head -1)
    if [[ -f "$FF_PROFILE" ]]; then
        finding "Firefox logins.json found: $FF_PROFILE" HIGH
        cat "$FF_PROFILE" 2>/dev/null
    fi

    subsection "iCloud Keychain Access (metadata only)"
    run "icloud keychains" "security list-keychains -d user 2>/dev/null"

    subsection "Recently Modified Files (last 7 days, home dir)"
    find ~ -type f -mtime -7 -readable 2>/dev/null | \
    grep -vE '(Library/Caches|\.Trash|\.DS_Store|\.localized)' | \
    sort | head -40

    subsection "Archive Files"
    find ~ /opt /private/tmp -type f \
        \( -name '*.zip' -o -name '*.tar' -o -name '*.tar.gz' \
        -o -name '*.tgz' -o -name '*.7z' -o -name '*.rar' \) \
        -readable 2>/dev/null | while read -r f; do
        finding "Archive: $f" LOW
    done

    subsection "Messages / Notes (metadata)"
    [[ -d ~/Library/Messages ]] && finding "Messages DB exists at ~/Library/Messages" LOW && ls -la ~/Library/Messages/
    [[ -d ~/Library/Containers/com.apple.Notes ]] && finding "Notes data exists" LOW
fi

# ── Footer ────────────────────────────────────────────────────────────────────
section "Enumeration Complete"
echo -e "\n  Finished at  : $(date)"
echo    "  Host         : $HOSTNAME_VAL"
echo    "  OS           : $MACOS_NAME $MACOS_VER"
echo    "  User         : $(id)"
echo    "  Root         : $IS_ROOT"
echo    "  Extended     : $EXTENDED"
echo    "  Output saved : $OUTPUT_FILE"
echo ""
echo -e "${C_YELLOW}  [*] Review all HIGH findings first.${C_RESET}"
echo -e "${C_YELLOW}  [*] SIP, Gatekeeper, FileVault, Firewall should all be enabled on hardened hosts.${C_RESET}"
echo -e "${C_YELLOW}  [*] Check SUID binaries against: https://gtfobins.github.io${C_RESET}"
echo ""
