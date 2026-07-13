#!/usr/bin/env bash
# ==============================================================================
#  macOS Enumerator V3.0
#  Author  : MrWhiskers  (V3 pentest/evidence enhancements)
#  Purpose : Rapid, passive macOS system enumeration for build reviews and
#            authorised penetration tests. Inspired by LinPEAS / WinPEAS but
#            tuned for macOS-specific privesc and misconfiguration vectors.
#
#            Read-only by design. It does NOT modify system state, plant files,
#            or exploit anything - it collects evidence and flags weaknesses.
#
#  Usage   : ./MacOS_Basic_Enumerator_V3.0.sh [OPTIONS]
#
#  Options:
#    -o <file>    Save combined transcript to file (default: auto-named)
#    -e           Extended mode: deep file/credential hunting, browser data
#    -n           No colour output (useful for piping / logging)
#    -E <dir>     Evidence directory (default: alongside output file)
#    -X           Disable evidence-artifact collection (transcript only)
#    -h           Show this help
#
#  Examples:
#    ./MacOS_Basic_Enumerator_V3.0.sh
#    ./MacOS_Basic_Enumerator_V3.0.sh -e
#    ./MacOS_Basic_Enumerator_V3.0.sh -e -o /tmp/enum.txt
#
#  Deliverables produced per run:
#    <output>.txt              Full human-readable transcript (this console)
#    <evidence_dir>/           Per-check raw evidence artifacts
#    <evidence_dir>/findings.json   Machine-readable findings (severity/PoC/evidence)
#    <evidence_dir>/findings.csv    Same, for spreadsheets / report import
#    <evidence_dir>/manifest.sha256 SHA256 of every artifact + transcript
#
#  Note: Does not require root. Run as current user. Some checks require sudo
#        or Full Disk Access (FDA) - noted inline. All sudo calls are
#        non-interactive (sudo -n) and will NOT hang waiting for a password.
#        Tested targets: macOS Ventura, Sonoma, Sequoia (Intel + Apple Silicon).
#
#  Authorised use only. Cross-reference SUID/PoC hits with GTFOBins.
# ==============================================================================

set -o nounset

# ── Defaults ──────────────────────────────────────────────────────────────────
EXTENDED=false
NO_COLOUR=false
OUTPUT_FILE=""
EVIDENCE_DIR=""
COLLECT_EVIDENCE=true
ART_LAST=""          # last evidence artifact path (relative), consumed by finding()
ART_INDEX=0          # monotonically increasing artifact counter
SUDO="sudo -n"       # non-interactive sudo; never prompts / hangs

# ── Argument Parsing ──────────────────────────────────────────────────────────
while getopts "o:E:enXh" opt; do
    case $opt in
        o) OUTPUT_FILE="$OPTARG" ;;
        E) EVIDENCE_DIR="$OPTARG" ;;
        e) EXTENDED=true ;;
        n) NO_COLOUR=true ;;
        X) COLLECT_EVIDENCE=false ;;
        h)
            sed -n '3,30p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown option. Use -h for help." >&2; exit 1 ;;
    esac
done

# ── Auto-name output / evidence paths ─────────────────────────────────────────
RUN_TAG="$(hostname -s 2>/dev/null || echo host)_$(date +%Y%m%d_%H%M%S)"
if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="./macos_enum_${RUN_TAG}.txt"
fi
if [[ -z "$EVIDENCE_DIR" ]]; then
    EVIDENCE_DIR="./macos_enum_${RUN_TAG}_evidence"
fi

if [[ "$COLLECT_EVIDENCE" == true ]]; then
    mkdir -p "$EVIDENCE_DIR" 2>/dev/null || COLLECT_EVIDENCE=false
    chmod 700 "$EVIDENCE_DIR" 2>/dev/null
fi
FINDINGS_TSV="$EVIDENCE_DIR/.findings.tsv"
[[ "$COLLECT_EVIDENCE" == true ]] && : > "$FINDINGS_TSV"

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
    C_MAG='\033[0;35m'
else
    C_RESET=''; C_CYAN=''; C_DCYAN=''; C_YELLOW=''
    C_RED=''; C_GREEN=''; C_WHITE=''; C_GREY=''; C_MAG=''
fi

# ── Output plumbing: mirror everything to the transcript ──────────────────────
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

# ── Evidence artifact writer ──────────────────────────────────────────────────
# save_evidence <slug> <content>  -> writes file, sets ART_LAST to relative path
save_evidence() {
    local slug="$1"; local content="$2"
    ART_LAST=""
    [[ "$COLLECT_EVIDENCE" != true ]] && return 1
    [[ -z "$content" ]] && return 1
    slug=$(echo "$slug" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-60)
    ART_INDEX=$((ART_INDEX + 1))
    local name; name=$(printf '%03d_%s.txt' "$ART_INDEX" "$slug")
    printf '%s\n' "$content" > "$EVIDENCE_DIR/$name" 2>/dev/null
    ART_LAST="$name"
    return 0
}

# ── Findings recorder ─────────────────────────────────────────────────────────
# finding <msg> [SEVERITY] [poc-command]
#   Prints coloured line, echoes PoC (grey), and records to TSV for JSON/CSV.
#   Evidence link is taken from the most recent save_evidence (ART_LAST).
record_finding() {
    [[ "$COLLECT_EVIDENCE" != true ]] && return 0
    local sev="$1" msg="$2" poc="$3" ev="$4"
    # sanitise field separators
    msg=$(printf '%s' "$msg" | tr '\t\n' '  ')
    poc=$(printf '%s' "$poc" | tr '\t\n' '  ')
    ev=$(printf '%s'  "$ev"  | tr '\t\n' '  ')
    printf '%s\t%s\t%s\t%s\n' "$sev" "$msg" "$poc" "$ev" >> "$FINDINGS_TSV"
}

finding() {
    local msg="$1"
    local sev="${2:-INFO}"
    local poc="${3:-}"
    local ev="$ART_LAST"
    case "$sev" in
        HIGH)     echo -e "  ${C_RED}[!] HIGH   : $msg${C_RESET}" ;;
        MEDIUM)   echo -e "  ${C_YELLOW}[!] MEDIUM : $msg${C_RESET}" ;;
        LOW)      echo -e "  ${C_GREEN}[!] LOW    : $msg${C_RESET}" ;;
        CRITICAL) echo -e "  ${C_MAG}[!!] CRIT  : $msg${C_RESET}" ;;
        *)        echo -e "  ${C_WHITE}[*] $msg${C_RESET}" ; sev="INFO" ;;
    esac
    [[ -n "$poc" ]] && echo -e "      ${C_GREY}PoC> $poc${C_RESET}"
    [[ -n "$ev"  ]] && echo -e "      ${C_GREY}evidence: $ev${C_RESET}"
    record_finding "$sev" "$msg" "$poc" "$ev"
    ART_LAST=""
}

# ── Safe command runner ───────────────────────────────────────────────────────
# run <label> <command...>  — checks binary, swallows errors, optional evidence.
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

# capture <slug> <label> <command...> — like run(), but also saves an evidence
# artifact (sets ART_LAST) so a following finding() links to it.
capture() {
    local slug="$1" label="$2"; shift 2
    local bin out
    bin=$(echo "$1" | awk '{print $1}')
    ART_LAST=""
    if command -v "$bin" &>/dev/null; then
        out=$(eval "$@" 2>/dev/null)
        if [[ -n "$out" ]]; then
            echo "$out"
            save_evidence "$slug" "$out"
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
  macOS Enumerator V3.0  |  For authorised assessments only

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

echo "  Started       : $START_TIME"
echo "  Host          : $HOSTNAME_VAL"
echo "  User          : $CURRENT_USER"
echo "  OS            : $MACOS_NAME $MACOS_VER ($BUILD_VER)"
echo "  Architecture  : $ARCH"
echo "  Extended      : $EXTENDED"
echo "  Transcript    : $OUTPUT_FILE"
echo "  Evidence dir  : $EVIDENCE_DIR (collect=$COLLECT_EVIDENCE)"

if [[ "$IS_ROOT" == true ]]; then
    finding "Running as ROOT - full enumeration available" HIGH
else
    finding "Running as non-root - some checks will be limited" LOW
fi

if [[ "$ARCH" == "arm64" ]]; then
    finding "Apple Silicon (arm64) detected" LOW
else
    finding "Intel (x86_64) detected" LOW
fi

if [[ "$ARCH" == "arm64" ]] && /usr/bin/pgrep -q oahd 2>/dev/null; then
    finding "Rosetta 2 installed (x86 translation active)" LOW
fi

# Non-interactive sudo availability (does the current ticket already grant sudo?)
if $SUDO true 2>/dev/null; then
    finding "Passwordless sudo currently available to this session (cached ticket or NOPASSWD)" HIGH "$SUDO -l"
fi

# ── SECTION 1: System Information ─────────────────────────────────────────────
section "1. System Information"

subsection "OS & Version Details"
capture "sw_vers" "sw_vers" "sw_vers"
run "uname" "uname -a"
run "kern.osversion" "sysctl kern.osversion kern.ostype kern.hostname"

# Flag EOL / unpatched-looking major versions (informational; verify against
# Apple's current support matrix at assessment time).
MAJOR=$(echo "${MACOS_VER:-0}" | cut -d. -f1)
if [[ "$MAJOR" =~ ^[0-9]+$ ]] && [[ "$MAJOR" -lt 13 ]]; then
    finding "macOS major version $MACOS_VER may be end-of-life / unpatched - verify against Apple support matrix" MEDIUM
fi

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

subsection "NVRAM / boot-args (SIP & AMFI tampering)"
BOOTARGS=$($SUDO nvram boot-args 2>/dev/null || nvram boot-args 2>/dev/null)
echo "  ${BOOTARGS:-<none>}"
if echo "$BOOTARGS" | grep -qiE 'amfi_get_out_of_my_way|amfi=0x'; then
    finding "boot-args disable AMFI (Apple Mobile File Integrity) - code-signing enforcement weakened" HIGH "nvram boot-args"
fi
if echo "$BOOTARGS" | grep -qiE 'cs_enforcement_disable|csr-active-config'; then
    finding "boot-args weaken code-signing / SIP enforcement" HIGH "nvram boot-args"
fi

# ── SECTION 2: User & Privilege Enumeration ───────────────────────────────────
section "2. User & Privilege Enumeration"

subsection "Current User Identity"
run "id" "id"
run "whoami" "whoami"
run "groups" "groups"

subsection "sudo -l (Privilege Check, non-interactive)"
SUDO_OUT=$($SUDO -l 2>/dev/null)
if [[ -n "$SUDO_OUT" ]]; then
    save_evidence "sudo_l" "$SUDO_OUT"
    finding "sudo -l returned output without a password prompt - review for privesc vectors" HIGH "$SUDO -l"
    echo "$SUDO_OUT"
    # Parse NOPASSWD entries and highlight
    echo "$SUDO_OUT" | grep -iE 'NOPASSWD' | while read -r np; do
        ART_LAST="sudo_l evidence saved above"
        finding "NOPASSWD sudo rule: ${np#*NOPASSWD: }" HIGH
    done
    echo "$SUDO_OUT" | grep -qiE '\(ALL(\s*:\s*ALL)?\)\s*ALL' && finding "User has full '(ALL) ALL' sudo rights" HIGH
else
    echo "  [-] sudo -l produced no non-interactive output (likely needs a password)"
fi

# sudo version -> Baron Samedit (CVE-2021-3156) heap overflow range
SUDO_VER=$(sudo --version 2>/dev/null | awk '/Sudo version/{print $3}')
if [[ -n "$SUDO_VER" ]]; then
    echo "  Sudo version: $SUDO_VER"
    if echo "$SUDO_VER" | grep -qE '^1\.(8\.(2|[3-9]|[12][0-9]|3[01])|9\.[0-5])'; then
        finding "Sudo $SUDO_VER is in the CVE-2021-3156 (Baron Samedit) vulnerable range - verify patch level" HIGH "sudoedit -s '\\' \$(python3 -c 'print(\"A\"*1000)')"
    fi
fi

subsection "All Local Users (dscl)"
capture "dscl_users" "dscl users" "dscl . -list /Users"
USERS=$(dscl . -list /Users 2>/dev/null | grep -v '^_')
echo "--- Non-system users ---"
echo "$USERS" | grep -v '^daemon\|^nobody\|^root\|^www\|^ftp'

subsection "User Details (dscl)"
USER_DETAILS=""
for u in $(dscl . -list /Users 2>/dev/null | grep -v '^_' | grep -v '^daemon\|^nobody\|^www'); do
    D=$(printf '=== %s ===\n%s\n' "$u" "$(dscl . -read /Users/"$u" NFSHomeDirectory RealName PrimaryGroupID UniqueID UserShell 2>/dev/null)")
    echo "$D"
    USER_DETAILS+="$D"$'\n'
done
save_evidence "user_details" "$USER_DETAILS"

subsection "Hidden Users (UID < 500, non-underscore)"
dscl . -list /Users UniqueID 2>/dev/null | awk '$2 < 500 && $1 !~ /^_/ {print}' | while read -r line; do
    finding "Hidden/low-UID account: $line" MEDIUM "dscl . -read /Users/$(echo "$line"|awk '{print $1}')"
done

subsection "Root Account Status"
ROOT_AUTH=$(dscl . -read /Users/root AuthenticationAuthority 2>/dev/null)
if echo "$ROOT_AUTH" | grep -qi 'DisabledUser'; then
    finding "Root account is disabled" LOW
elif [[ -n "$ROOT_AUTH" ]]; then
    finding "Root account appears ENABLED (has AuthenticationAuthority) - verify" MEDIUM "dscl . -read /Users/root AuthenticationAuthority"
fi

subsection "Guest Account"
GUEST=$($SUDO defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
[[ "$GUEST" == "1" ]] && finding "Guest login account is ENABLED" MEDIUM

subsection "Accounts With Empty / No Password"
for u in $(dscl . -list /Users 2>/dev/null | grep -v '^_'); do
    AA=$(dscl . -read /Users/"$u" Password 2>/dev/null)
    if echo "$AA" | grep -qE 'Password:\s*$|Password:\s*\*?$'; then
        : # inconclusive on modern macOS (ShadowHashData); skip noise
    fi
done
echo "  (Password hashes live in ShadowHashData; requires root to inspect - see /var/db/dslocal)"

subsection "Secure Token / Bootstrap Token (FileVault unlock rights)"
run "diskutil apfs users" "diskutil apfs listUsers / 2>/dev/null"
for u in $(dscl . -list /Users 2>/dev/null | grep -v '^_' | grep -vE '^daemon$|^nobody$'); do
    ST=$(sysadminctl -secureTokenStatus "$u" 2>&1 | grep -io 'ENABLED\|DISABLED' | head -1)
    [[ -n "$ST" ]] && echo "  $u : SecureToken=$ST"
done

subsection "Password Policy"
run "global pwpolicy" "pwpolicy getaccountpolicies 2>/dev/null | tail -n +2"

subsection "Admin Group Members"
ADMINS=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null)
if [[ -n "$ADMINS" ]]; then
    save_evidence "admin_members" "$ADMINS"
    finding "Admin group members: ${ADMINS#GroupMembership: }" HIGH
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
for hf in ~/.bash_history ~/.zsh_history ~/.python_history ~/.mysql_history ~/.psql_history ~/.node_repl_history ~/.irb_history; do
    if [[ -f "$hf" ]]; then
        finding "History file: $hf" MEDIUM "grep -iE 'passw|secret|token|key|-p ' $hf"
        tail -50 "$hf"
    fi
done

subsection "Command History (all users, if accessible)"
find /Users -name ".*_history" -readable 2>/dev/null | while read -r hf; do
    finding "Readable history from another user: $hf" HIGH "cat $hf"
    tail -20 "$hf"
done

subsection "Environment Variables"
env | sort
# Dangerous dynamic-linker variables in the environment
env | grep -E '^(DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH|DYLD_FRAMEWORK_PATH|LD_PRELOAD)=' | while read -r e; do
    finding "Dynamic-linker injection variable set in environment: $e" HIGH
done

subsection "Shell Config Files (current user)"
for f in ~/.bash_profile ~/.bashrc ~/.zshrc ~/.zprofile ~/.zshenv ~/.profile ~/.bash_login; do
    [[ -f "$f" ]] && echo "=== $f ===" && cat "$f"
done

# ── SECTION 3: Security Configuration ────────────────────────────────────────
section "3. Security Configuration"

subsection "System Integrity Protection (SIP)"
SIP_STATUS=$(csrutil status 2>/dev/null)
echo "  $SIP_STATUS"
save_evidence "sip_status" "$SIP_STATUS"
if echo "$SIP_STATUS" | grep -q "disabled"; then
    finding "SIP is DISABLED - system protections are off" HIGH "csrutil status"
elif echo "$SIP_STATUS" | grep -qi "enabled"; then
    finding "SIP is enabled" LOW
fi

subsection "Gatekeeper Status"
GK=$(spctl --status 2>/dev/null)
echo "  $GK"
if echo "$GK" | grep -q "disabled"; then
    finding "Gatekeeper is DISABLED - unsigned apps run freely" HIGH "spctl --status"
fi
run "gatekeeper assessments" "spctl --list 2>/dev/null | head -20"

subsection "FileVault (Full Disk Encryption)"
FV=$(fdesetup status 2>/dev/null)
echo "  $FV"
save_evidence "filevault" "$FV"
if echo "$FV" | grep -qi "off\|not enabled\|disabled"; then
    finding "FileVault is DISABLED - disk is unencrypted (offline data theft possible)" HIGH "fdesetup status"
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
run "socketfilterfw" "$SUDO /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null"
run "system_profiler firewall" "system_profiler SPFirewallDataType 2>/dev/null"

subsection "Firewall Stealth Mode"
STEALTH=$(defaults read /Library/Preferences/com.apple.alf stealthenabled 2>/dev/null)
[[ "$STEALTH" == "0" ]] && finding "Firewall stealth mode is DISABLED" MEDIUM

subsection "Screen Lock / Screen Saver Settings"
LOCK=$(defaults read com.apple.screensaver askForPassword 2>/dev/null)
[[ "$LOCK" != "1" ]] && finding "Screen saver password NOT required on wake" MEDIUM
DELAY=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)
echo "  askForPassword: ${LOCK:-N/A} | delay: ${DELAY:-N/A} seconds"

subsection "Automatic Login"
AUTOLOGIN=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
if [[ -n "$AUTOLOGIN" ]]; then
    finding "Automatic login is ENABLED for user: $AUTOLOGIN" HIGH "defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser"
else
    finding "Automatic login is disabled" LOW
fi

subsection "Login / Logout Hooks (legacy persistence)"
for hook in LoginHook LogoutHook; do
    H=$($SUDO defaults read /Library/Preferences/com.apple.loginwindow "$hook" 2>/dev/null || defaults read /Library/Preferences/com.apple.loginwindow "$hook" 2>/dev/null)
    if [[ -n "$H" ]]; then
        finding "$hook configured: $H" HIGH "defaults read /Library/Preferences/com.apple.loginwindow $hook"
        [[ -w "$H" ]] && finding "$hook target is WRITABLE by current user: $H" CRITICAL
    fi
done

subsection "Remote Login (SSH)"
SSH_STATUS=$(systemsetup -getremotelogin 2>/dev/null)
echo "  $SSH_STATUS"
if echo "$SSH_STATUS" | grep -qi "on\|enabled"; then
    finding "Remote Login (SSH) is ENABLED" MEDIUM
fi

subsection "Remote Management (ARD) & Screen Sharing (VNC)"
ARD=$(launchctl list com.apple.RemoteDesktop.agent 2>/dev/null || launchctl list com.apple.RemoteDesktop 2>/dev/null)
[[ -n "$ARD" ]] && finding "Apple Remote Desktop (ARD) appears active" HIGH
VNC=$(launchctl list com.apple.screensharing 2>/dev/null)
[[ -n "$VNC" ]] && finding "Screen Sharing / VNC is active" HIGH
run "remote apple events" "systemsetup -getremoteappleevents 2>/dev/null"
# Legacy ARD/VNC obfuscated password file (trivially reversible XOR)
if [[ -f /Library/Preferences/com.apple.VNCSettings.txt ]]; then
    finding "Legacy VNC password file present (weak XOR-obfuscated): /Library/Preferences/com.apple.VNCSettings.txt" HIGH "cat /Library/Preferences/com.apple.VNCSettings.txt"
fi

subsection "Sharing Preferences"
run "sharing services" "sharing -l 2>/dev/null"
run "system_profiler sharing" "system_profiler SPSharingDataType 2>/dev/null"

subsection "MDM / Device Enrollment"
MDM_PROFILE=$(profiles status -type enrollment 2>/dev/null)
echo "  $MDM_PROFILE"
echo "$MDM_PROFILE" | grep -qi "enrolled" && finding "Device is MDM ENROLLED - managed device" MEDIUM

subsection "Configuration Profiles Installed"
capture "profiles" "profiles show" "$SUDO profiles show 2>/dev/null || profiles -P 2>/dev/null || profiles list 2>/dev/null"

subsection "User-Added Trusted Root Certificates (MITM risk)"
USER_CERTS=$(security dump-trust-settings -d 2>/dev/null; security dump-trust-settings 2>/dev/null)
if [[ -n "$USER_CERTS" ]]; then
    save_evidence "trust_settings" "$USER_CERTS"
    finding "Custom certificate trust settings present - review for rogue root CAs (interception)" MEDIUM "security dump-trust-settings -d"
    echo "$USER_CERTS" | grep -i 'Cert ' | head -20
fi

subsection "PAM Configuration (sudo/auth)"
run "/etc/pam.d/sudo" "cat /etc/pam.d/sudo 2>/dev/null"
if grep -q 'pam_tid.so' /etc/pam.d/sudo 2>/dev/null; then
    finding "Touch ID for sudo (pam_tid) is enabled" LOW
fi
run "pam.d listing" "ls -la /etc/pam.d/ 2>/dev/null"

subsection "Kernel Extensions (kexts)"
run "kextstat 3rd-party" "kextstat 2>/dev/null | grep -v com.apple | tail -n +2"

subsection "System Extensions"
run "systemextensionsctl" "systemextensionsctl list 2>/dev/null"

subsection "TCC Database (Transparency, Consent & Control)"
TCC_DB=~/Library/Application\ Support/com.apple.TCC/TCC.db
if [[ -f "$TCC_DB" ]]; then
    finding "User TCC database found: $TCC_DB" LOW "sqlite3 '$TCC_DB' 'SELECT service, client, auth_value FROM access;'"
    capture "tcc_user" "TCC user DB" "sqlite3 '$TCC_DB' 'SELECT service, client, auth_value FROM access ORDER BY service;' 2>/dev/null"
fi
SYSTEM_TCC="/Library/Application Support/com.apple.TCC/TCC.db"
if [[ -r "$SYSTEM_TCC" ]]; then
    finding "System TCC database is READABLE (implies Full Disk Access / root)" MEDIUM "sqlite3 '$SYSTEM_TCC' 'SELECT service, client, auth_value FROM access;'"
    capture "tcc_system" "TCC system DB" "sqlite3 '$SYSTEM_TCC' 'SELECT service, client, auth_value FROM access ORDER BY service;' 2>/dev/null"
fi

subsection "Antivirus / EDR / Security Tooling"
for tool in mdatp sentinelctl jamf munki cbsecurity CrowdStrike falconctl; do
    if pgrep -i "$tool" &>/dev/null || cmd_exists "$tool"; then
        finding "Security tool detected: $tool" LOW
    fi
done
ps aux 2>/dev/null | grep -iE 'sentinelone|crowdstrike|falcon|defender|mdatp|sophos|norton|avast|kaspersky|malwarebytes|cylance|carbon.?black|jamf|osquery' | grep -v grep

subsection "XProtect & Malware Removal"
run "XProtect version" "defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null || defaults read /System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null"
find /System/Library/CoreServices /Library/Apple/System/Library/CoreServices -name 'XProtect*' 2>/dev/null | head -5

subsection "Audit Daemon (auditd)"
run "audit status" "$SUDO audit -s 2>/dev/null"
run "audit config" "cat /etc/security/audit_control 2>/dev/null"

# ── SECTION 4: Network Enumeration ────────────────────────────────────────────
section "4. Network Enumeration"

subsection "Network Interfaces"
capture "ifconfig" "ifconfig" "ifconfig"
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

subsection "Proxy Configuration (all services)"
for svc in $(networksetup -listallnetworkservices 2>/dev/null | tail -n +2); do
    P=$(networksetup -getwebproxy "$svc" 2>/dev/null | grep -i 'Enabled: Yes')
    [[ -n "$P" ]] && finding "HTTP proxy enabled on '$svc' (possible interception): $(networksetup -getwebproxy "$svc" 2>/dev/null | tr '\n' ' ')" MEDIUM
    AP=$(networksetup -getautoproxyurl "$svc" 2>/dev/null | grep -i 'Enabled: Yes')
    [[ -n "$AP" ]] && finding "Auto-proxy (PAC) enabled on '$svc': $(networksetup -getautoproxyurl "$svc" 2>/dev/null | grep URL)" MEDIUM
done

subsection "Routing Table"
run "netstat -rn" "netstat -rn"

subsection "ARP Cache"
run "arp -a" "arp -a"

subsection "Listening Ports"
LISTENING=$(lsof -i -P -n 2>/dev/null | grep LISTEN)
if [[ -n "$LISTENING" ]]; then
    echo "$LISTENING"
    save_evidence "listening_ports" "$LISTENING"
    finding "Listening services enumerated - review for unexpected/local-only-should-be daemons" LOW "lsof -i -P -n | grep LISTEN"
else
    run "netstat listen" "netstat -an 2>/dev/null | grep LISTEN"
fi

subsection "All Network Connections"
run "lsof -i" "lsof -i -P -n 2>/dev/null"

subsection "Hosts File"
HOSTS_EXTRA=$(grep -vE '^\s*#|^$|^127\.|^::1|^fe80|^255' /etc/hosts 2>/dev/null)
if [[ -n "$HOSTS_EXTRA" ]]; then
    save_evidence "hosts_extra" "$HOSTS_EXTRA"
    finding "Non-default /etc/hosts entries found (possible redirection/pinning):" MEDIUM "cat /etc/hosts"
    echo "$HOSTS_EXTRA"
fi
run "/etc/hosts" "cat /etc/hosts"

subsection "Wi-Fi Configuration"
run "Wi-Fi info" "networksetup -getinfo Wi-Fi 2>/dev/null"
run "system_profiler WiFi" "system_profiler SPAirPortDataType 2>/dev/null"

subsection "SMB / NFS Shares"
run "smbutil statshares" "smbutil statshares -a 2>/dev/null"
run "system_profiler network" "system_profiler SPNetworkDataType 2>/dev/null"
run "NFS exports" "cat /etc/exports 2>/dev/null; showmount -e localhost 2>/dev/null"
[[ -s /etc/exports ]] && finding "/etc/exports present - NFS shares defined" MEDIUM "cat /etc/exports"

subsection "Kerberos Tickets"
run "klist" "klist 2>/dev/null"

subsection "Time Machine Destinations (may hold creds/paths)"
run "tmutil destinationinfo" "tmutil destinationinfo 2>/dev/null"

subsection "Bluetooth / Ethernet"
run "system_profiler bluetooth" "system_profiler SPBluetoothDataType 2>/dev/null"
run "system_profiler ethernet" "system_profiler SPEthernetDataType 2>/dev/null"

# ── SECTION 5: Credential & Secret Hunting ────────────────────────────────────
section "5. Credential & Secret Hunting"

subsection "SSH Keys & Config (current user)"
for f in ~/.ssh/id_rsa ~/.ssh/id_ecdsa ~/.ssh/id_ed25519 ~/.ssh/id_dsa \
          ~/.ssh/authorized_keys ~/.ssh/known_hosts ~/.ssh/config; do
    if [[ -f "$f" ]]; then
        # Flag unencrypted private keys specifically
        if [[ "$f" == *id_* ]] && grep -qE 'BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY' "$f" 2>/dev/null && ! grep -q 'ENCRYPTED' "$f" 2>/dev/null; then
            save_evidence "ssh_privkey_$(basename "$f")" "$(cat "$f")"
            finding "UNENCRYPTED SSH private key: $f (usable as-is)" HIGH "ssh -i $f user@target"
        else
            finding "SSH file found: $f" MEDIUM "cat $f"
        fi
        cat "$f"
    fi
done

subsection "SSH Daemon Configuration"
SSH_CONF=$(cat /etc/ssh/sshd_config 2>/dev/null)
if [[ -n "$SSH_CONF" ]]; then
    save_evidence "sshd_config" "$SSH_CONF"
    echo "$SSH_CONF"
    echo "$SSH_CONF" | grep -iqE '^\s*PermitRootLogin\s+yes'        && finding "SSH PermitRootLogin yes" HIGH "grep PermitRootLogin /etc/ssh/sshd_config"
    echo "$SSH_CONF" | grep -iqE '^\s*PasswordAuthentication\s+yes' && finding "SSH PasswordAuthentication yes (brute-force surface)" MEDIUM
    echo "$SSH_CONF" | grep -iqE '^\s*PermitEmptyPasswords\s+yes'   && finding "SSH PermitEmptyPasswords yes" HIGH
fi

subsection "Keychain Summary (current user)"
run "keychain list" "security list-keychains 2>/dev/null"
run "default keychain" "security default-keychain 2>/dev/null"
echo "  (Extracting secrets: security find-generic-password -wa <svc>  — prompts for user auth, not automated)"
finding "Keychain secret extraction is possible with user auth (PoC listed)" LOW "security find-generic-password -a \$USER -s 'AirPort network password' -w"

subsection "Certificates in Keychain"
run "keychain certs" "security find-certificate -a 2>/dev/null | grep 'alis\|labl' | head -40"

subsection "Cloud / Service Credential Files"
for f in ~/.aws/credentials ~/.aws/config \
          ~/.config/gcloud/credentials.db \
          ~/.config/gcloud/application_default_credentials.json \
          ~/.azure/credentials ~/.azure/accessTokens.json \
          ~/.docker/config.json ~/.kube/config \
          ~/.netrc ~/.pgpass ~/.npmrc ~/.pypirc \
          ~/.config/gh/hosts.yml ~/.git-credentials; do
    if [[ -f "$f" ]]; then
        save_evidence "cred_$(basename "$f")" "$(cat "$f" 2>/dev/null)"
        finding "Credential/config file: $f" HIGH "cat $f"
        cat "$f" 2>/dev/null
    fi
done

subsection "Clipboard Contents"
CLIP=$(pbpaste 2>/dev/null)
if [[ -n "$CLIP" ]]; then
    echo "$CLIP" | head -5
    if echo "$CLIP" | grep -iqE 'password|secret|token|api.?key|BEGIN.*PRIVATE'; then
        finding "Clipboard contains potentially sensitive data" HIGH "pbpaste"
    fi
fi

subsection "Recently Accessed Files"
run "recent files" "ls -lt ~/Desktop ~/Documents ~/Downloads 2>/dev/null | head -30"

subsection ".env and Config Files (current user tree)"
find ~ -maxdepth 5 \( -name '.env' -o -name '*.env' \) -type f 2>/dev/null | \
  grep -vE '/(node_modules|Library/Caches)/' | while read -r f; do
    save_evidence "env_$(basename "$f")" "$(cat "$f" 2>/dev/null)"
    finding ".env file: $f" HIGH "cat $f"
    cat "$f"
done

subsection "Git Config"
run "~/.gitconfig" "cat ~/.gitconfig 2>/dev/null"

# ── SECTION 6: Privilege Escalation Vectors ───────────────────────────────────
section "6. Privilege Escalation Vectors"

# Known-exploitable SUID basenames (GTFOBins subset relevant on macOS/BSD)
GTFO_SUID="bash sh zsh env find awk gawk perl python python3 ruby php lua vi vim view nano ed sed tar cp mv chmod chown make gdb nmap tclsh expect socat nc ncat rsync rlwrap xargs less more man dmesg mount umount pkexec cpan"

subsection "SUID Binaries (with GTFOBins cross-reference)"
SUID=$(find / -perm -4000 -type f 2>/dev/null | sort)
if [[ -n "$SUID" ]]; then
    save_evidence "suid_binaries" "$SUID"
    finding "SUID binaries enumerated - compare against known macOS defaults" MEDIUM "ls -la <path>"
    echo "$SUID"
    echo "$SUID" | while read -r s; do
        base=$(basename "$s")
        for g in $GTFO_SUID; do
            if [[ "$base" == "$g" ]]; then
                finding "SUID binary matches GTFOBins: $s" HIGH "https://gtfobins.github.io/gtfobins/$base/#suid"
                break
            fi
        done
    done
fi

subsection "SGID Binaries"
SGID=$(find / -perm -2000 -type f 2>/dev/null | sort)
if [[ -n "$SGID" ]]; then
    save_evidence "sgid_binaries" "$SGID"
    finding "SGID binaries enumerated" MEDIUM
    echo "$SGID"
fi

subsection "PATH Analysis"
echo "  PATH = $PATH"
case ":$PATH:" in
    *:.:*|*::*) finding "PATH contains '.' or an empty element - relative-path hijack risk" HIGH ;;
esac
IFS=':' read -ra PATH_DIRS <<< "$PATH"
for dir in ${PATH_DIRS[@]+"${PATH_DIRS[@]}"}; do
    [[ -z "$dir" ]] && continue
    if [[ -d "$dir" && -w "$dir" ]]; then
        finding "WRITABLE directory in PATH: $dir (plant a trojaned binary)" HIGH "echo 'id' > $dir/<name>; chmod +x $dir/<name>"
    fi
    # Writable individual files inside PATH dirs
    WP=$(find "$dir" -maxdepth 1 -type f -writable 2>/dev/null)
    if [[ -n "$WP" ]]; then
        finding "Writable file(s) in PATH dir $dir" HIGH
        echo "$WP"
    fi
done

subsection "PATH Definition Files (/etc/paths, /etc/paths.d)"
for pf in /etc/paths /etc/paths.d/* /etc/manpaths /etc/manpaths.d/*; do
    [[ -f "$pf" ]] || continue
    if [[ -w "$pf" ]]; then
        finding "WRITABLE PATH-definition file: $pf (inject into system PATH)" HIGH "echo '/tmp/evil' >> $pf"
    fi
done

subsection "Dynamic Library (dylib) Hijacking Surface"
# DYLD env injection points inside launchd plists
for dir in /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents; do
    [[ -d "$dir" ]] || continue
    grep -rl 'DYLD_INSERT_LIBRARIES\|DYLD_LIBRARY_PATH' "$dir" 2>/dev/null | while read -r p; do
        finding "launchd plist sets DYLD_* variable (injection vector): $p" HIGH "grep -A2 DYLD $p"
    done
done
# Writable directories commonly on the dylib search path
for d in /usr/local/lib /opt/homebrew/lib /Library/Frameworks; do
    [[ -d "$d" && -w "$d" ]] && finding "Writable dylib search directory: $d (plant proxy dylib)" HIGH
done

subsection "Writable Application Bundles in /Applications (code injection / TCC theft)"
find /Applications -maxdepth 2 -name '*.app' -prune 2>/dev/null | while read -r app; do
    if [[ -w "$app/Contents/MacOS" ]] 2>/dev/null || [[ -w "$app" ]]; then
        finding "WRITABLE app bundle: $app (replace binary to inherit its TCC grants)" HIGH "ls -la '$app/Contents/MacOS'"
    fi
done

subsection "Homebrew Directory Writability (privesc if in root's PATH / used by admin)"
for bd in /usr/local/bin /usr/local/Homebrew /opt/homebrew/bin /opt/homebrew; do
    [[ -d "$bd" && -w "$bd" ]] && finding "Writable Homebrew path: $bd" MEDIUM "echo 'id' > $bd/<binary>"
done

subsection "World-Writable Files (excluding transient dirs)"
WW=$(find / -type f -perm -0002 \
    ! -path '/private/tmp/*' ! -path '/private/var/tmp/*' ! -path '/dev/*' \
    ! -path '/System/*' ! -path '/private/var/folders/*' 2>/dev/null | \
    grep -vE '/Library/Caches|\.Trash' | head -40)
if [[ -n "$WW" ]]; then
    save_evidence "world_writable_files" "$WW"
    finding "World-writable files found (first 40):" MEDIUM
    echo "$WW"
fi

subsection "World-Writable Directories Without Sticky Bit"
find / -type d -perm -0002 ! -perm -1000 \
    ! -path '/System/*' ! -path '/private/var/folders/*' 2>/dev/null | head -20 | while read -r d; do
    finding "World-writable dir without sticky bit: $d" MEDIUM
done

subsection "Files/Dirs With Non-default ACLs (writable by you)"
run "acl scan (home + /Applications)" "ls -le ~ /Applications 2>/dev/null | grep -A1 '+' | head -30"

subsection "Writable LaunchAgents / LaunchDaemons (persistence + privesc)"
for dir in /Library/LaunchDaemons /Library/LaunchAgents \
            ~/Library/LaunchAgents /System/Library/LaunchDaemons; do
    [[ -d "$dir" ]] || continue
    find "$dir" -name '*.plist' -writable 2>/dev/null | while read -r plist; do
        finding "WRITABLE launch plist: $plist (edit Program to run as its load context)" HIGH "cat '$plist'"
        cat "$plist" 2>/dev/null
    done
done

subsection "LaunchDaemons / LaunchAgents (inventory)"
for dir in /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents; do
    echo "--- $dir ---"
    ls -la "$dir" 2>/dev/null
done

subsection "Writable Program/Script Targets Referenced in Launch Plists"
for dir in /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents; do
    [[ -d "$dir" ]] || continue
    for plist in "$dir"/*.plist; do
        [[ -f "$plist" ]] || continue
        # Extract Program and ProgramArguments paths
        /usr/libexec/PlistBuddy -c 'Print :Program' "$plist" 2>/dev/null
        /usr/libexec/PlistBuddy -c 'Print :ProgramArguments' "$plist" 2>/dev/null | grep -oE '/[^ ]+'
    done 2>/dev/null | grep -oE '^/[^ ]+' | sort -u | while read -r target; do
        if [[ -f "$target" && -w "$target" ]]; then
            finding "WRITABLE target referenced by a launch plist: $target" CRITICAL "echo 'id' >> '$target'"
        fi
    done
done

subsection "Cron Jobs"
run "crontab -l" "crontab -l 2>/dev/null"
run "/etc/crontab" "cat /etc/crontab 2>/dev/null"
run "/etc/cron.d" "ls -la /etc/cron.d/ 2>/dev/null && cat /etc/cron.d/* 2>/dev/null"
for pd in /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly; do
    [[ -d "$pd" ]] || continue
    find "$pd" -type f -writable 2>/dev/null | while read -r pf; do
        finding "WRITABLE periodic script (runs as root on schedule): $pf" CRITICAL "echo 'id' >> '$pf'"
    done
done
run "/etc/periodic listing" "ls -la /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly 2>/dev/null"

subsection "AT Jobs"
run "at -l" "at -l 2>/dev/null"

subsection "Startup Items (legacy)"
run "system_profiler startup" "system_profiler SPStartupItemDataType 2>/dev/null"
for si in /Library/StartupItems ~/Library/StartupItems; do
    [[ -d "$si" ]] || continue
    ls -la "$si" 2>/dev/null
    find "$si" -writable 2>/dev/null | while read -r w; do
        finding "Writable StartupItem path: $w" HIGH
    done
done

# ── SECTION 7: Running Services & Software ────────────────────────────────────
section "7. Running Services & Software"

subsection "Running Processes (top by CPU)"
capture "ps_aux" "ps aux" "ps aux 2>/dev/null | sort -k3 -rn | head -40"

subsection "Processes Running as root (hijack targets)"
PRIV_PROCS=$(ps -axo user,pid,ppid,command 2>/dev/null | awk '$1=="root"' | grep -vE '/sbin/launchd$' | head -40)
if [[ -n "$PRIV_PROCS" ]]; then
    save_evidence "root_processes" "$PRIV_PROCS"
    finding "Processes running as root enumerated - inspect for writable binaries/args" MEDIUM "ps -axo user,pid,command | grep root"
    echo "$PRIV_PROCS"
    # Flag root processes whose executable is user-writable
    echo "$PRIV_PROCS" | awk '{print $4}' | sort -u | while read -r exe; do
        [[ -f "$exe" && -w "$exe" ]] && finding "Root process executable is WRITABLE by you: $exe" CRITICAL
    done
fi

subsection "Launchctl Service List"
run "launchctl list" "launchctl list 2>/dev/null | head -80"

subsection "Docker / Containers"
if cmd_exists docker; then
    finding "Docker CLI present" LOW
    run "docker ps" "docker ps 2>/dev/null"
    [[ -S /var/run/docker.sock && -w /var/run/docker.sock ]] && finding "Writable Docker socket /var/run/docker.sock (container-to-host privesc)" HIGH "docker run -v /:/host -it alpine chroot /host sh"
fi

subsection "Installed Packages (Homebrew)"
if cmd_exists brew; then
    finding "Homebrew is installed" LOW
    run "brew list" "brew list --versions 2>/dev/null"
    run "brew outdated" "brew outdated 2>/dev/null"
else
    echo "  [-] Homebrew not installed"
fi

subsection "Installed Packages (MacPorts / pkgutil)"
cmd_exists port && run "port installed" "port installed 2>/dev/null | head -50"
run "pkgutil receipts" "pkgutil --pkgs 2>/dev/null | head -40"

subsection "Developer Tools"
run "xcode-select" "xcode-select -p 2>/dev/null"

subsection "Compilers & Interpreters (LOLbins for privesc/exfil)"
for lang in gcc g++ cc clang python python3 python2 perl ruby php node nodejs lua go swift osascript; do
    cmd_exists "$lang" && finding "$lang available: $(command -v "$lang")" MEDIUM
done

subsection "Interesting Binaries Available"
for bin in nc ncat nmap curl wget socat openssl ssh scp sftp rsync git vim nano base64 xxd sqlite3 defaults plutil codesign spctl; do
    cmd_exists "$bin" && echo "  [+] $bin: $(command -v "$bin")"
done

subsection "USB & Printers"
run "system_profiler USB" "system_profiler SPUSBDataType 2>/dev/null"
run "lpstat" "lpstat -a 2>/dev/null"

# ── SECTION 8: Sensitive Files & Directories ──────────────────────────────────
section "8. Sensitive Files & Directories"

subsection "Sudoers"
capture "sudoers" "sudoers" "$SUDO cat /etc/sudoers 2>/dev/null"
run "sudoers.d" "$SUDO ls -la /etc/sudoers.d/ 2>/dev/null && $SUDO cat /etc/sudoers.d/* 2>/dev/null"
# Flag writable sudoers include dir
[[ -w /etc/sudoers.d ]] && finding "/etc/sudoers.d is WRITABLE - drop a NOPASSWD rule" CRITICAL "echo '$USER ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/x"

subsection "/etc/passwd and /etc/master.passwd"
capture "passwd" "/etc/passwd" "cat /etc/passwd 2>/dev/null"
run "/etc/master.passwd" "$SUDO cat /etc/master.passwd 2>/dev/null"

subsection "Local Directory Shadow Data (root only)"
run "dslocal users" "$SUDO ls -la /var/db/dslocal/nodes/Default/users/ 2>/dev/null"

subsection "Interesting File Locations"
for f in ~/Library/Keychains /Library/Keychains \
          ~/Library/Application\ Support/Google/Chrome/Default/Login\ Data \
          ~/Library/Application\ Support/Firefox/Profiles \
          ~/Library/Safari/History.db \
          ~/Library/Messages; do
    [[ -e "$f" ]] && finding "Interesting path exists: $f" MEDIUM && ls -la "$f" 2>/dev/null
done

subsection "Recent Servers / Known Hosts"
run "recent servers" "defaults read com.apple.recentitems Servers 2>/dev/null"
run "known_hosts" "cat ~/.ssh/known_hosts 2>/dev/null"

# ── SECTION 9: Extended Mode ──────────────────────────────────────────────────
if [[ "$EXTENDED" == true ]]; then
    section "9. Extended - Deep File & Credential Hunting"

    subsection "Spotlight: files named *password*"
    run "mdfind password" "mdfind password 2>/dev/null | grep -viE '(\.app|Library/Caches|\.lproj|CoreServices)' | head -30"

    subsection "Find: *password* / *secret* / *credential*"
    find ~ /private/tmp /opt 2>/dev/null -maxdepth 6 \
        \( -name '*password*' -o -name '*secret*' -o -name '*credential*' -o -name '*cred*' \) \
        -not -path '*/Library/Caches/*' -not -path '*/.Trash/*' 2>/dev/null | while read -r f; do
        finding "Named match: $f" MEDIUM
    done

    subsection "Interesting File Extensions"
    find ~ /opt /private/tmp -maxdepth 6 \
        \( -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' \
        -o -name '*.ppk' -o -name '*.kdbx' -o -name '*.ovpn' \
        -o -name '*.rdp' -o -name '*.mobileconfig' -o -name '*.bak' -o -name '*.old' \) \
        -readable 2>/dev/null | while read -r f; do
        finding "Interesting file: $f" MEDIUM "file '$f'"
    done

    subsection "Secret Strings in Home Directory Files"
    grep -rliE 'password|passwd|secret|api.?key|token|BEGIN (RSA|OPENSSH|EC) PRIVATE' ~ 2>/dev/null | \
    grep -vE '(\.app|Library/Caches|\.lproj|\.ttf|\.png|\.jpg|\.gif|node_modules)' | \
    head -30 | while read -r f; do
        finding "Secret string in: $f" MEDIUM "grep -inE 'password|secret|api.?key|token' '$f'"
        grep -inE 'password|passwd|secret|api.?key|token' "$f" 2>/dev/null | head -5
    done

    subsection "Browser Data (Safari / Chrome / Firefox)"
    SAFARI_DB=~/Library/Safari/History.db
    [[ -f "$SAFARI_DB" ]] && finding "Safari History DB accessible" MEDIUM "sqlite3 '$SAFARI_DB' 'SELECT url FROM history_items LIMIT 50;'" && \
        run "Safari history" "sqlite3 '$SAFARI_DB' 'SELECT url, visit_time FROM history_visits JOIN history_items ON history_visits.history_item = history_items.id ORDER BY visit_time DESC LIMIT 50;' 2>/dev/null"
    CHROME_DB=~/Library/Application\ Support/Google/Chrome/Default/Login\ Data
    [[ -f "$CHROME_DB" ]] && finding "Chrome Login Data DB accessible (passwords AES-GCM, key in keychain)" HIGH "sqlite3 '$CHROME_DB' 'SELECT origin_url, username_value FROM logins;'" && \
        run "Chrome logins" "sqlite3 '$CHROME_DB' 'SELECT origin_url, username_value FROM logins;' 2>/dev/null"
    FF_LOGINS=$(find ~/Library/Application\ Support/Firefox/Profiles -name 'logins.json' 2>/dev/null | head -1)
    if [[ -n "$FF_LOGINS" && -f "$FF_LOGINS" ]]; then
        save_evidence "firefox_logins" "$(cat "$FF_LOGINS" 2>/dev/null)"
        finding "Firefox logins.json found: $FF_LOGINS" HIGH "cat '$FF_LOGINS'"
        cat "$FF_LOGINS" 2>/dev/null
    fi

    subsection "Recently Modified Files (last 7 days, home dir)"
    find ~ -type f -mtime -7 2>/dev/null | \
    grep -vE '(Library/Caches|\.Trash|\.DS_Store|\.localized|node_modules)' | \
    sort | head -40

    subsection "Archive Files"
    find ~ /opt /private/tmp -type f \
        \( -name '*.zip' -o -name '*.tar' -o -name '*.tar.gz' \
        -o -name '*.tgz' -o -name '*.7z' -o -name '*.rar' \) \
        2>/dev/null | while read -r f; do
        finding "Archive: $f" LOW
    done
fi

# ── Findings Export: JSON + CSV ───────────────────────────────────────────────
generate_reports() {
    [[ "$COLLECT_EVIDENCE" != true ]] && return 0
    [[ -f "$FINDINGS_TSV" ]] || return 0

    local json="$EVIDENCE_DIR/findings.json"
    local csv="$EVIDENCE_DIR/findings.csv"

    # CSV
    printf 'severity,title,poc,evidence\n' > "$csv"
    while IFS=$'\t' read -r sev title poc ev; do
        # CSV-escape (double quotes)
        sev=${sev//\"/\"\"}; title=${title//\"/\"\"}
        poc=${poc//\"/\"\"};  ev=${ev//\"/\"\"}
        printf '"%s","%s","%s","%s"\n' "$sev" "$title" "$poc" "$ev" >> "$csv"
    done < "$FINDINGS_TSV"

    # JSON
    {
        echo '{'
        echo "  \"host\": \"$(printf '%s' "$HOSTNAME_VAL" | sed 's/\\/\\\\/g; s/"/\\"/g')\","
        echo "  \"os\": \"$MACOS_NAME $MACOS_VER ($BUILD_VER)\","
        echo "  \"generated\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
        echo "  \"findings\": ["
        local first=1
        while IFS=$'\t' read -r sev title poc ev; do
            # JSON-escape backslash then quote
            sev=$(printf '%s' "$sev"   | sed 's/\\/\\\\/g; s/"/\\"/g')
            title=$(printf '%s' "$title" | sed 's/\\/\\\\/g; s/"/\\"/g')
            poc=$(printf '%s' "$poc"   | sed 's/\\/\\\\/g; s/"/\\"/g')
            ev=$(printf '%s' "$ev"     | sed 's/\\/\\\\/g; s/"/\\"/g')
            [[ $first -eq 0 ]] && echo ','
            first=0
            printf '    {"severity": "%s", "title": "%s", "poc": "%s", "evidence": "%s"}' \
                "$sev" "$title" "$poc" "$ev"
        done < "$FINDINGS_TSV"
        echo ''
        echo '  ]'
        echo '}'
    } > "$json"

    echo "  [+] Wrote $json"
    echo "  [+] Wrote $csv"
}

# ── Evidence Integrity Manifest (SHA256) ──────────────────────────────────────
generate_manifest() {
    [[ "$COLLECT_EVIDENCE" != true ]] && return 0
    local man="$EVIDENCE_DIR/manifest.sha256"
    : > "$man"
    if cmd_exists shasum; then
        # hash the transcript
        shasum -a 256 "$OUTPUT_FILE" 2>/dev/null >> "$man"
        # hash each artifact (exclude the manifest and hidden findings tsv)
        find "$EVIDENCE_DIR" -type f ! -name 'manifest.sha256' 2>/dev/null | sort | while read -r f; do
            shasum -a 256 "$f" 2>/dev/null >> "$man"
        done
        echo "  [+] Wrote $man ($(wc -l < "$man" | tr -d ' ') entries)"
    else
        echo "  [-] shasum not available; skipped manifest"
    fi
}

# ── Findings Summary (PEAS-style) ─────────────────────────────────────────────
print_summary() {
    section "Findings Summary"
    if [[ "$COLLECT_EVIDENCE" != true || ! -f "$FINDINGS_TSV" ]]; then
        echo "  (evidence collection disabled - no aggregated findings)"
        return 0
    fi
    local nc nh nm nl
    nc=$(awk -F'\t' '$1=="CRITICAL"' "$FINDINGS_TSV" | wc -l | tr -d ' ')
    nh=$(awk -F'\t' '$1=="HIGH"'     "$FINDINGS_TSV" | wc -l | tr -d ' ')
    nm=$(awk -F'\t' '$1=="MEDIUM"'   "$FINDINGS_TSV" | wc -l | tr -d ' ')
    nl=$(awk -F'\t' '$1=="LOW"'      "$FINDINGS_TSV" | wc -l | tr -d ' ')
    echo -e "  ${C_MAG}CRITICAL: $nc${C_RESET}   ${C_RED}HIGH: $nh${C_RESET}   ${C_YELLOW}MEDIUM: $nm${C_RESET}   ${C_GREEN}LOW: $nl${C_RESET}"
    echo ""
    echo -e "  ${C_RED}Top priority (CRITICAL + HIGH):${C_RESET}"
    awk -F'\t' '$1=="CRITICAL" || $1=="HIGH" {printf "    [%s] %s\n", $1, $2}' "$FINDINGS_TSV" | sort -u
}

section "Generating Reports & Evidence Manifest"
generate_reports
generate_manifest

print_summary

# ── Footer ────────────────────────────────────────────────────────────────────
section "Enumeration Complete"
echo -e "\n  Finished at   : $(date)"
echo    "  Host          : $HOSTNAME_VAL"
echo    "  OS            : $MACOS_NAME $MACOS_VER"
echo    "  User          : $(id)"
echo    "  Root          : $IS_ROOT"
echo    "  Extended      : $EXTENDED"
echo    "  Transcript    : $OUTPUT_FILE"
echo    "  Evidence dir  : $EVIDENCE_DIR"
echo ""
echo -e "${C_YELLOW}  [*] Review CRITICAL and HIGH findings first (see Findings Summary).${C_RESET}"
echo -e "${C_YELLOW}  [*] SIP, Gatekeeper, FileVault, Firewall should all be enabled on hardened hosts.${C_RESET}"
echo -e "${C_YELLOW}  [*] Cross-reference SUID hits with https://gtfobins.github.io${C_RESET}"
echo -e "${C_YELLOW}  [*] findings.json / findings.csv are ready for your report tooling.${C_RESET}"
echo ""

# Flush the tee subshell before exit
exec 1>&- 2>&-
wait 2>/dev/null
exit 0
