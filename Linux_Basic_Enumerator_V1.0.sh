#!/usr/bin/env bash
# ==============================================================================
#  Linux Enumerator V2.0
#  Author  : MrWhiskers
#  Purpose : Rapid Linux system enumeration for build reviews and pentests.
#            Not a replacement for linPEAS/LinEnum - designed for fast,
#            structured, human-readable output during build review assessments.
#  Usage   : ./Linux_Enumerator_V2.0.sh [OPTIONS]
#
#  Options:
#    -o <file>    Save output to file (default: auto-named in current dir)
#    -e           Extended mode: file hunting, password grep, deep SUID scan
#    -n           No colour output (useful for piping / logging)
#    -h           Show this help
#
#  Examples:
#    ./Linux_Enumerator_V2.0.sh
#    ./Linux_Enumerator_V2.0.sh -e
#    ./Linux_Enumerator_V2.0.sh -o /tmp/enum.txt
#    ./Linux_Enumerator_V2.0.sh -e -o /tmp/enum.txt
#    curl -s http://<host>/Linux_Enumerator_V2.0.sh | bash
#
#  Note: Does not require root. Run as current user - some checks will be
#        limited without elevated privileges (noted inline).
# ==============================================================================

# ── Defaults ─────────────────────────────────────────────────────────────────
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
            sed -n '2,20p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown option. Use -h for help." >&2; exit 1 ;;
    esac
done

# ── Auto-name output file if not specified ────────────────────────────────────
if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="./linux_enum_$(hostname -s)_$(date +%Y%m%d_%H%M%S).txt"
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

# ── Output helpers ────────────────────────────────────────────────────────────
# All output goes to both screen and file via tee
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

run() {
    # run <label> <command string>
    local label="$1"; shift
    local output
    output=$(eval "$@" 2>/dev/null)
    if [[ -n "$output" ]]; then
        echo "$output"
    else
        echo -e "${C_GREY}  [-] $label: no output / not available${C_RESET}"
    fi
}

cmd_exists() { command -v "$1" &>/dev/null; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${C_CYAN}"
cat << 'EOF'

  ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗
  ██║     ██║████╗  ██║██║   ██║╚██╗██╔╝
  ██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝
  ██║     ██║██║╚██╗██║██║   ██║ ██╔██╗
  ███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗
  ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
  Linux Enumerator V2.0  |  For authorised assessments only

EOF
echo -e "${C_RESET}"

# ── Context / Pre-flight ──────────────────────────────────────────────────────
section "Enumeration Context"

CURRENT_USER=$(id)
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
START_TIME=$(date)
IS_ROOT=false
[[ $EUID -eq 0 ]] && IS_ROOT=true

echo "  Started      : $START_TIME"
echo "  Host         : $HOSTNAME_VAL"
echo "  User         : $CURRENT_USER"
echo "  Extended     : $EXTENDED"
echo "  Output file  : $OUTPUT_FILE"

if [[ "$IS_ROOT" == true ]]; then
    finding "Running as ROOT - full enumeration available" HIGH
else
    finding "Running as non-root user - some checks will be limited" LOW
fi

# Container / VM detection
if [[ -f /proc/1/cgroup ]] && grep -qE 'docker|lxc|kubepods|containerd' /proc/1/cgroup 2>/dev/null; then
    finding "CONTAINER DETECTED (docker/lxc/k8s) - check for escape vectors" HIGH
elif [[ -f /.dockerenv ]]; then
    finding "CONTAINER DETECTED (/.dockerenv present)" HIGH
fi

if systemd-detect-virt --quiet 2>/dev/null; then
    VIRT=$(systemd-detect-virt 2>/dev/null)
    finding "Virtualisation detected: $VIRT" LOW
fi

# ── SECTION 1: System Information ─────────────────────────────────────────────
section "1. System Information"

subsection "OS & Distribution"
run "OS release" "cat /etc/os-release 2>/dev/null || cat /etc/issue"
run "Kernel" "uname -a"
run "Kernel modules loaded" "lsmod | head -30"

# Flag kernel version for quick reference
KERNEL=$(uname -r)
finding "Kernel version: $KERNEL (check against kernel exploits)" LOW

subsection "Hostname & Domain"
run "hostname" "hostname -f 2>/dev/null; hostname"
run "dnsdomainname" "dnsdomainname 2>/dev/null"

subsection "Uptime & Load"
run "uptime" "uptime"
run "who" "who"
run "last logins" "last -n 20 2>/dev/null"
run "currently logged on" "w 2>/dev/null"

subsection "Installed Kernels (boot)"
run "vmlinuz files" "ls /boot/vmlinuz-* 2>/dev/null"

subsection "CPU & Memory"
run "CPU info" "grep -E 'model name|cpu cores|siblings' /proc/cpuinfo | sort -u"
run "Memory" "free -h"
run "Disk usage" "df -h 2>/dev/null"

subsection "Environment Variables"
run "env" "env | sort"

subsection "Shell Config Files (current user)"
for f in ~/.bash_profile ~/.bashrc ~/.bash_logout ~/.zshrc ~/.profile; do
    [[ -f "$f" ]] && echo "=== $f ===" && cat "$f"
done

subsection "System-wide Profile"
run "/etc/profile" "cat /etc/profile"
[[ -d /etc/profile.d ]] && run "profile.d scripts" "ls -la /etc/profile.d/ && cat /etc/profile.d/*.sh 2>/dev/null"

# ── SECTION 2: User & Privilege Enumeration ───────────────────────────────────
section "2. User & Privilege Enumeration"

subsection "Current User Identity"
run "id" "id"
run "groups" "groups"

subsection "Sudo Privileges (sudo -l)"
SUDO_OUT=$(sudo -l 2>/dev/null)
if [[ -n "$SUDO_OUT" ]]; then
    finding "sudo -l returned output - review for privesc vectors" HIGH
    echo "$SUDO_OUT"
else
    echo "  [-] No sudo access or sudo not available"
fi

subsection "Sudoers File (if readable)"
run "sudoers" "cat /etc/sudoers 2>/dev/null"
run "sudoers.d" "ls -la /etc/sudoers.d/ 2>/dev/null && cat /etc/sudoers.d/* 2>/dev/null"

subsection "/etc/passwd - All Users"
run "passwd" "cat /etc/passwd"

# Flag users with interactive shells
subsection "Users with Interactive Shells"
SHELL_USERS=$(grep -vE '(/false|/nologin|/sync|/halt|/shutdown)$' /etc/passwd | cut -d: -f1,6,7)
if [[ -n "$SHELL_USERS" ]]; then
    finding "Users with interactive shells found:" MEDIUM
    echo "$SHELL_USERS"
fi

subsection "/etc/shadow (if readable)"
SHADOW=$(cat /etc/shadow 2>/dev/null)
if [[ -n "$SHADOW" ]]; then
    finding "/etc/shadow IS READABLE by current user" HIGH
    echo "$SHADOW"
else
    echo "  [-] /etc/shadow not readable (expected)"
fi

subsection "/etc/group"
run "groups" "cat /etc/group"

# Flag members of privileged groups
subsection "Privileged Group Memberships"
for grp in sudo wheel admin docker lxd disk shadow root; do
    MEMBERS=$(grep "^$grp:" /etc/group 2>/dev/null | cut -d: -f4)
    if [[ -n "$MEMBERS" ]]; then
        finding "Group '$grp' members: $MEMBERS" HIGH
    fi
done

subsection "Home Directories"
run "home dirs" "ls -la /home/ 2>/dev/null"

subsection "Root Directory (if accessible)"
ROOT_LS=$(ls -la /root 2>/dev/null)
if [[ -n "$ROOT_LS" ]]; then
    finding "/root is accessible by current user" HIGH
    echo "$ROOT_LS"
else
    echo "  [-] /root not accessible (expected)"
fi

subsection "Command History (current user)"
for hf in ~/.bash_history ~/.zsh_history ~/.python_history ~/.mysql_history ~/.psql_history; do
    if [[ -f "$hf" ]]; then
        finding "History file found: $hf" MEDIUM
        tail -50 "$hf"
    fi
done

subsection "Command History (all users, if accessible)"
find /home /root -name ".*_history" -readable 2>/dev/null | while read -r hf; do
    finding "Readable history: $hf" HIGH
    tail -20 "$hf"
done

# ── SECTION 3: Network Enumeration ────────────────────────────────────────────
section "3. Network Enumeration"

subsection "Network Interfaces"
if cmd_exists ip; then
    run "ip addr" "ip addr show"
    run "ip link" "ip link show"
else
    run "ifconfig" "/sbin/ifconfig -a 2>/dev/null"
fi

subsection "Routing Table"
if cmd_exists ip; then
    run "ip route" "ip route show"
else
    run "route" "/sbin/route -n 2>/dev/null"
fi

subsection "ARP Cache"
if cmd_exists ip; then
    run "ip neigh" "ip neigh show"
else
    run "arp" "arp -en 2>/dev/null"
fi

subsection "DNS Configuration"
run "resolv.conf" "cat /etc/resolv.conf 2>/dev/null"
if cmd_exists resolvectl; then
    run "resolvectl" "resolvectl status 2>/dev/null"
fi

subsection "Hosts File"
HOSTS_EXTRA=$(grep -vE '^\s*#|^$|^127\.|^::1|^ff' /etc/hosts 2>/dev/null)
if [[ -n "$HOSTS_EXTRA" ]]; then
    finding "Non-default /etc/hosts entries:" MEDIUM
    echo "$HOSTS_EXTRA"
fi
run "/etc/hosts" "cat /etc/hosts"

subsection "Listening Ports"
if cmd_exists ss; then
    run "ss listening" "ss -tlnup"
elif cmd_exists netstat; then
    run "netstat listening" "netstat -tlnup 2>/dev/null"
fi

subsection "All Connections"
if cmd_exists ss; then
    run "ss all" "ss -anp 2>/dev/null"
elif cmd_exists netstat; then
    run "netstat all" "netstat -antp 2>/dev/null"
fi

subsection "Firewall Rules"
if [[ "$IS_ROOT" == true ]]; then
    run "iptables" "iptables -L -n -v 2>/dev/null"
    run "ip6tables" "ip6tables -L -n -v 2>/dev/null"
    if cmd_exists nft; then
        run "nftables" "nft list ruleset 2>/dev/null"
    fi
    if cmd_exists ufw; then
        run "ufw status" "ufw status verbose 2>/dev/null"
    fi
else
    finding "Not root - firewall rules may not be fully visible" LOW
    run "iptables (partial)" "iptables -L 2>/dev/null"
fi

subsection "Network Shares (NFS)"
run "/etc/exports" "cat /etc/exports 2>/dev/null"
run "showmount" "showmount -e localhost 2>/dev/null"
NOROOT_EXPORTS=$(grep -E 'no_root_squash|no_all_squash' /etc/exports 2>/dev/null)
if [[ -n "$NOROOT_EXPORTS" ]]; then
    finding "NFS export with no_root_squash or no_all_squash found - potential UID 0 mount attack!" HIGH
    echo "$NOROOT_EXPORTS"
fi

subsection "SMB / Samba Configuration"
run "smb.conf" "cat /etc/samba/smb.conf 2>/dev/null"

subsection "Network Interfaces (additional)"
run "/etc/network/interfaces" "cat /etc/network/interfaces 2>/dev/null"
run "NetworkManager connections" "ls -la /etc/NetworkManager/system-connections/ 2>/dev/null"

# ── SECTION 4: Credential & Secret Hunting ────────────────────────────────────
section "4. Credential & Secret Hunting"

subsection "SSH Keys & Config (current user)"
for f in ~/.ssh/id_rsa ~/.ssh/id_ecdsa ~/.ssh/id_ed25519 ~/.ssh/id_dsa \
          ~/.ssh/authorized_keys ~/.ssh/known_hosts ~/.ssh/config; do
    if [[ -f "$f" ]]; then
        finding "SSH file found: $f" HIGH
        cat "$f"
    fi
done

subsection "SSH Keys (all users, if accessible)"
find /home /root -path '*/.ssh/*' -readable 2>/dev/null | while read -r f; do
    finding "Readable SSH file: $f" HIGH
    cat "$f"
done

subsection "SSH Host Keys"
run "ssh host keys" "ls -la /etc/ssh/ 2>/dev/null"
# Flag weak host key permissions
find /etc/ssh -name '*_key' -not -name '*.pub' -perm /o+r 2>/dev/null | while read -r k; do
    finding "SSH private host key world-readable: $k" HIGH
done

subsection "SSH Daemon Configuration"
SSH_CONF=$(cat /etc/ssh/sshd_config 2>/dev/null)
if [[ -n "$SSH_CONF" ]]; then
    echo "$SSH_CONF"
    echo "$SSH_CONF" | grep -iE 'PermitRootLogin\s+yes' && finding "SSH PermitRootLogin is YES" HIGH
    echo "$SSH_CONF" | grep -iE 'PasswordAuthentication\s+yes' && finding "SSH PasswordAuthentication is YES" MEDIUM
    echo "$SSH_CONF" | grep -iE 'PermitEmptyPasswords\s+yes' && finding "SSH PermitEmptyPasswords is YES" HIGH
fi

subsection "Web Application Config Files (credential strings)"
for conf in /var/www/html/wp-config.php \
            /var/www/html/config.php \
            /var/www/html/.env \
            /var/www/.env \
            /etc/phpmyadmin/config.inc.php \
            /etc/roundcube/config.inc.php; do
    if [[ -f "$conf" ]]; then
        finding "Web config found: $conf" HIGH
        grep -iE 'password|passwd|secret|key|token|DB_' "$conf" 2>/dev/null
    fi
done

subsection "Database Config Files"
for conf in /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf \
            /etc/postgresql/*/main/pg_hba.conf /root/.my.cnf ~/.my.cnf \
            /etc/redis/redis.conf /etc/mongodb.conf; do
    if [[ -f "$conf" ]]; then
        finding "DB config found: $conf" MEDIUM
        grep -iE 'password|passwd|requirepass|auth' "$conf" 2>/dev/null
    fi
done

subsection "Service / App Config Files (credentials)"
for conf in /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf \
            /etc/nginx/nginx.conf /etc/lighttpd/lighttpd.conf \
            /etc/cups/cupsd.conf /etc/syslog.conf \
            /opt/lampp/etc/httpd.conf; do
    if [[ -f "$conf" ]]; then
        echo "=== $conf ==="
        cat "$conf" 2>/dev/null
    fi
done

subsection "Readable /etc files containing 'password'"
grep -ril 'password\|passwd' /etc/ 2>/dev/null | while read -r f; do
    finding "Password string in: $f" MEDIUM
    grep -iE 'password|passwd' "$f" 2>/dev/null | head -5
done

# ── SECTION 5: Privilege Escalation Vectors ───────────────────────────────────
section "5. Privilege Escalation Vectors"

subsection "SUID Binaries"
SUID_BINS=$(find / -perm -4000 -type f 2>/dev/null | sort)
if [[ -n "$SUID_BINS" ]]; then
    finding "SUID binaries found - check against GTFOBins:" HIGH
    echo "$SUID_BINS"
fi

subsection "SGID Binaries"
SGID_BINS=$(find / -perm -2000 -type f 2>/dev/null | sort)
if [[ -n "$SGID_BINS" ]]; then
    finding "SGID binaries found - check against GTFOBins:" MEDIUM
    echo "$SGID_BINS"
fi

subsection "Linux Capabilities"
if cmd_exists getcap; then
    CAPS=$(getcap -r / 2>/dev/null)
    if [[ -n "$CAPS" ]]; then
        finding "Binaries with capabilities set:" HIGH
        echo "$CAPS"
        # Flag dangerous caps
        echo "$CAPS" | grep -iE 'cap_setuid|cap_net_raw|cap_sys_admin|cap_dac_override' | while read -r c; do
            finding "DANGEROUS CAPABILITY: $c" HIGH
        done
    fi
else
    echo "  [-] getcap not available"
fi

subsection "World-Writable Files (excluding /proc, /sys, /dev)"
finding "Searching for world-writable files (this may take a moment)..." INFO
WW_FILES=$(find / -writable -type f \
    ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' \
    ! -path '/run/*' 2>/dev/null | grep -vE '(/tmp/|/var/tmp/)' | head -50)
if [[ -n "$WW_FILES" ]]; then
    finding "World-writable files found (first 50):" MEDIUM
    echo "$WW_FILES"
fi

subsection "World-Writable Directories"
WW_DIRS=$(find / -writable -type d \
    ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' \
    ! -path '/run/*' ! -path '/tmp' ! -path '/var/tmp' 2>/dev/null | head -30)
if [[ -n "$WW_DIRS" ]]; then
    finding "World-writable directories (excluding /tmp):" MEDIUM
    echo "$WW_DIRS"
fi

subsection "Writable Files in PATH Directories"
IFS=':' read -ra PATH_DIRS <<< "$PATH"
for dir in "${PATH_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        WP=$(find "$dir" -writable 2>/dev/null)
        if [[ -n "$WP" ]]; then
            finding "WRITABLE PATH ENTRY: $dir (binary hijacking possible)" HIGH
            echo "$WP"
        fi
    fi
done

subsection "Cron Jobs"
echo "--- Current user crontab ---"
crontab -l 2>/dev/null || echo "  [-] No crontab for current user"

echo "--- /etc/crontab ---"
cat /etc/crontab 2>/dev/null

echo "--- /etc/cron.d ---"
ls -la /etc/cron.d/ 2>/dev/null && cat /etc/cron.d/* 2>/dev/null

echo "--- /etc/cron.{daily,weekly,monthly,hourly} ---"
for crondir in /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.hourly; do
    [[ -d "$crondir" ]] && ls -la "$crondir"
done

echo "--- /var/spool/cron ---"
ls -la /var/spool/cron/ 2>/dev/null
[[ "$IS_ROOT" == true ]] && cat /var/spool/cron/crontabs/* 2>/dev/null

echo "--- /etc/anacrontab ---"
cat /etc/anacrontab 2>/dev/null

echo "--- at.allow / at.deny ---"
cat /etc/at.allow 2>/dev/null
cat /etc/at.deny 2>/dev/null
cat /etc/cron.allow 2>/dev/null
cat /etc/cron.deny 2>/dev/null

# Check for writable scripts referenced in cron
subsection "Writable Cron Script Check"
for cronfile in /etc/crontab /etc/anacrontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
    [[ -f "$cronfile" ]] || continue
    grep -vE '^\s*#|^\s*$' "$cronfile" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i~/^\//){print $i}}' | while read -r script; do
        if [[ -f "$script" ]] && [[ -w "$script" ]]; then
            finding "WRITABLE CRON SCRIPT: $script (referenced in $cronfile)" HIGH
        fi
    done
done

subsection "Systemd Timers"
run "systemd timers" "systemctl list-timers --all 2>/dev/null"

subsection "Writable /etc/passwd or /etc/shadow"
[[ -w /etc/passwd ]] && finding "/etc/passwd IS WRITABLE - can add root user!" HIGH
[[ -w /etc/shadow ]] && finding "/etc/shadow IS WRITABLE" HIGH

subsection "Docker / LXD / LXC Group Membership"
id | grep -qE '\bdocker\b' && finding "Current user is in 'docker' group - trivial root via docker run" HIGH
id | grep -qE '\blxd\b|\blxc\b' && finding "Current user is in 'lxd/lxc' group - potential host escape" HIGH
id | grep -qE '\bdisk\b' && finding "Current user is in 'disk' group - raw disk read access possible" HIGH

subsection "Docker Status & Configuration"
if cmd_exists docker; then
    run "docker info" "docker info 2>/dev/null"
    run "docker images" "docker images 2>/dev/null"
    run "running containers" "docker ps 2>/dev/null"
fi

subsection "Interesting /etc/passwd Entries (non-standard UID 0)"
awk -F: '$3 == 0 {print}' /etc/passwd 2>/dev/null | grep -v '^root:' | while read -r line; do
    finding "UID 0 entry that is not root: $line" HIGH
done

subsection "Passwd / Shadow Backup Files"
for f in /etc/passwd- /etc/shadow- /etc/passwd.bak /etc/shadow.bak; do
    [[ -f "$f" ]] && finding "Password backup file found: $f" HIGH && cat "$f" 2>/dev/null
done

# ── SECTION 6: Running Services & Software ────────────────────────────────────
section "6. Running Services & Software"

subsection "Running Processes"
run "ps aux" "ps aux --sort=-%cpu 2>/dev/null | head -40"

subsection "Processes Running as Root"
ROOT_PROCS=$(ps aux 2>/dev/null | awk '$1=="root" && $11!~/^\[/' | grep -v 'ps aux')
if [[ -n "$ROOT_PROCS" ]]; then
    finding "Processes running as root (review for privesc):" MEDIUM
    echo "$ROOT_PROCS"
fi

subsection "Systemd Services (enabled)"
run "systemd enabled" "systemctl list-units --type=service --state=running 2>/dev/null"

subsection "Installed Packages (Debian/Ubuntu)"
run "dpkg" "dpkg -l 2>/dev/null"

subsection "Installed Packages (RHEL/CentOS/Fedora)"
run "rpm" "rpm -qa --last 2>/dev/null | head -50"

subsection "Snap / Flatpak"
run "snap" "snap list 2>/dev/null"
run "flatpak" "flatpak list 2>/dev/null"

subsection "Interesting Binaries in PATH"
for bin in nc ncat nmap curl wget python python3 perl ruby gcc g++ make \
           socat tftp ftp telnet ssh scp rsync git vim nano \
           base64 xxd od strace ltrace gdb; do
    cmd_exists "$bin" && echo "  [+] $bin: $(which $bin)"
done

subsection "Compiler / Scripting Availability"
for lang in gcc g++ cc python python3 python2 perl ruby php node nodejs lua; do
    cmd_exists "$lang" && finding "$lang is available on this system" MEDIUM
done

# ── SECTION 7: Scheduled Jobs & Startup ──────────────────────────────────────
section "7. Scheduled Jobs & Startup"

subsection "Init / Startup Scripts"
run "/etc/init.d" "ls -la /etc/init.d/ 2>/dev/null"
run "/etc/rc.local" "cat /etc/rc.local 2>/dev/null"
run "/etc/rc.d" "ls -la /etc/rc.d/ 2>/dev/null"

subsection "Systemd Unit Files (user-writable)"
find /etc/systemd /usr/lib/systemd /run/systemd -name '*.service' -writable 2>/dev/null | while read -r f; do
    finding "WRITABLE SYSTEMD UNIT: $f" HIGH
    cat "$f"
done

# ── SECTION 8: Security Configuration ────────────────────────────────────────
section "8. Security Configuration"

subsection "SELinux Status"
if cmd_exists sestatus; then
    run "sestatus" "sestatus"
    SELINUX_MODE=$(sestatus 2>/dev/null | grep 'Current mode' | awk '{print $3}')
    [[ "$SELINUX_MODE" == "permissive" ]] && finding "SELinux is in PERMISSIVE mode" MEDIUM
    [[ "$SELINUX_MODE" == "disabled" ]] && finding "SELinux is DISABLED" MEDIUM
else
    echo "  [-] SELinux not installed"
fi

subsection "AppArmor Status"
if cmd_exists aa-status; then
    run "aa-status" "aa-status 2>/dev/null"
elif [[ -f /sys/kernel/security/apparmor/profiles ]]; then
    run "apparmor profiles" "cat /sys/kernel/security/apparmor/profiles 2>/dev/null | head -20"
else
    echo "  [-] AppArmor not detected"
fi

subsection "Password Policy (/etc/login.defs)"
run "login.defs" "cat /etc/login.defs 2>/dev/null | grep -vE '^\s*#|^\s*$'"

subsection "PAM Configuration"
run "pam.d common-password" "cat /etc/pam.d/common-password 2>/dev/null"
run "pam.d sshd" "cat /etc/pam.d/sshd 2>/dev/null"

subsection "Fail2ban Status"
if cmd_exists fail2ban-client; then
    run "fail2ban" "fail2ban-client status 2>/dev/null"
else
    echo "  [-] Fail2ban not installed"
fi

subsection "Antivirus / AV Detection"
for av in clamd clamscan rkhunter chkrootkit lynis aide ossec wazuh; do
    cmd_exists "$av" && finding "AV/security tool found: $av" LOW
done

subsection "Unattended Upgrades"
run "unattended-upgrades" "cat /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null | head -20"

# ── SECTION 9: Sensitive Files & Directories ──────────────────────────────────
section "9. Sensitive Files & Directories"

subsection "Common Sensitive File Locations"
for f in /etc/passwd /etc/group /etc/hostname /etc/hosts /etc/fstab \
         /etc/exports /proc/version /proc/net/tcp /proc/net/udp; do
    [[ -f "$f" ]] && echo "=== $f ===" && cat "$f" 2>/dev/null
done

subsection "Interesting File Extensions (keys, certs, backups)"
find /home /root /etc /opt /var/www /srv /tmp -maxdepth 6 \
    \( -name "*.key" -o -name "*.pem" -o -name "*.crt" -o -name "*.cert" \
    -o -name "*.p12" -o -name "*.pfx" -o -name "*.ppk" -o -name "*.bak" \
    -o -name "*.old" -o -name "*.orig" -o -name "*.kdbx" -o -name "*.ovpn" \
    -o -name "*.rdp" -o -name "*.conf" -o -name "*.config" \) \
    -readable 2>/dev/null | while read -r f; do
    finding "Interesting file: $f" MEDIUM
done

subsection "Files with Weak Permissions in /etc"
find /etc -maxdepth 2 -type f -perm /o+r 2>/dev/null | \
    grep -vE '(hosts|hostname|fstab|os-release|timezone|localtime|group|passwd|protocols|services|shells|nsswitch)' | \
    head -30

# ── SECTION 10: Extended Mode ──────────────────────────────────────────────────
if [[ "$EXTENDED" == true ]]; then
    section "10. Extended - Deep File & Credential Hunting"

    subsection "Password String Grep (/home, /var/www, /opt, /srv)"
    for search_dir in /home /var/www /opt /srv /etc; do
        [[ -d "$search_dir" ]] && \
        grep -rliE 'password|passwd|secret|api.?key|token|credential' \
            "$search_dir" 2>/dev/null | while read -r f; do
            finding "Password string in file: $f" MEDIUM
            grep -inE 'password|passwd|secret|api.?key|token' "$f" 2>/dev/null | head -5
        done
    done

    subsection "PHP Files with DB Credentials"
    find /var/www /srv /opt -name '*.php' -readable 2>/dev/null | \
    xargs grep -liE '\$password|\$pass|\$db_pass|mysqli_connect|PDO' 2>/dev/null | \
    while read -r f; do
        finding "PHP cred file: $f" HIGH
        grep -inE '\$password|\$pass|\$db_pass|host.*=|user.*=|pass.*=' "$f" 2>/dev/null | head -10
    done

    subsection ".env Files"
    find / -name '.env' -readable \
        ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | while read -r f; do
        finding ".env file found: $f" HIGH
        cat "$f"
    done

    subsection "Recently Modified Files (/home, /tmp, /var, /opt - last 7 days)"
    find /home /tmp /var/tmp /opt -type f -mtime -7 -readable 2>/dev/null | \
    sort | head -40

    subsection "Recently Modified Files in /etc (last 30 days)"
    find /etc -type f -mtime -30 -readable 2>/dev/null | sort | head -30

    subsection "Writable Files Outside /tmp (deep scan)"
    find / -writable -type f \
        ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' \
        ! -path '/tmp/*' ! -path '/var/tmp/*' ! -path '/run/*' \
        2>/dev/null | sort | head -100

    subsection "SUID Binaries (full path scan)"
    find / -perm -4000 -type f 2>/dev/null | sort | xargs ls -la 2>/dev/null

    subsection "All User Crontabs (root access required)"
    if [[ "$IS_ROOT" == true ]]; then
        for u in $(cut -d: -f1 /etc/passwd); do
            CTAB=$(crontab -u "$u" -l 2>/dev/null)
            [[ -n "$CTAB" ]] && echo "=== $u ===" && echo "$CTAB"
        done
    else
        echo "  [-] Root required to read all user crontabs"
    fi

    subsection "Archive Files (.zip, .tar, .gz, .7z)"
    find /home /root /opt /srv /var/www -type f \
        \( -name '*.zip' -o -name '*.tar' -o -name '*.tar.gz' \
        -o -name '*.tgz' -o -name '*.7z' -o -name '*.rar' \) \
        -readable 2>/dev/null | while read -r f; do
        finding "Archive found: $f" LOW
    done
fi

# ── Footer ────────────────────────────────────────────────────────────────────
section "Enumeration Complete"
echo -e "\n  Finished at  : $(date)"
echo    "  Host         : $HOSTNAME_VAL"
echo    "  User         : $(id)"
echo    "  Root         : $IS_ROOT"
echo    "  Extended     : $EXTENDED"
echo    "  Output saved : $OUTPUT_FILE"
echo ""
echo -e "${C_YELLOW}  [*] Tip: Review all HIGH findings above before manual analysis.${C_RESET}"
echo -e "${C_YELLOW}  [*] Cross-reference SUID/SGID results at: https://gtfobins.github.io${C_RESET}"
echo ""
